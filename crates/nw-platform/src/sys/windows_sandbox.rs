//! Win32 ownership boundary for a one-shot offline parser. No shell or named IPC.
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, RawHandle},
    },
    path::{Path, PathBuf},
    ptr,
    time::Duration,
};
use windows_sys::Win32::System::StationsAndDesktops::*;
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Isolation::*, *},
    Storage::FileSystem::*,
    System::{
        Com::CoTaskMemFree, JobObjects::*, Pipes::*, Threading::*,
        WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
    },
};
use zeroize::Zeroizing;
fn failed() -> io::Error {
    io::Error::other(format!("appcontainer_unavailable_{}", unsafe {
        GetLastError()
    }))
}
fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
impl Handle {
    fn file(mut self) -> File {
        let raw = self.0;
        self.0 = ptr::null_mut();
        unsafe { File::from_raw_handle(raw as RawHandle) }
    }
}
struct Profile {
    name: Vec<u16>,
    sid: PSID,
    directory: PathBuf,
}
#[cfg(test)]
mod ownership_tests {
    use super::*;
    #[test]
    #[ignore = "requires actual Windows AppContainer creation; CI runs it explicitly"]
    fn fresh_profile_has_user_owned_storage_before_worker_execution() {
        let profile = Profile::new().unwrap();
        super::super::private_directory(profile.directory.parent().unwrap()).unwrap();
        super::super::private_directory(&profile.directory).unwrap();
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        unsafe {
            DeleteAppContainerProfile(self.name.as_ptr());
            FreeSid(self.sid);
        }
    }
}
impl Profile {
    fn new() -> io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| failed())?
            .as_nanos();
        let name = wide(std::ffi::OsStr::new(&format!(
            "NymWrap.Import.{}.{clock:x}.{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )));
        let mut sid = ptr::null_mut();
        let result = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                ptr::null(),
                0,
                &mut sid,
            )
        };
        if result < 0 {
            return Err(io::Error::other(format!(
                "appcontainer_profile_{result:08x}"
            )));
        }
        let mut profile = Self {
            name,
            sid,
            directory: PathBuf::new(),
        };
        let mut folder = ptr::null_mut();
        let sid_text = profile.sid_text()?;
        if unsafe {
            GetAppContainerFolderPath(wide(std::ffi::OsStr::new(&sid_text)).as_ptr(), &mut folder)
        } < 0
        {
            return Err(failed());
        }
        let mut length = 0;
        while length < 32768 && unsafe { *folder.add(length) } != 0 {
            length += 1;
        }
        let path = if length < 32768 {
            Some(PathBuf::from(OsString::from_wide(unsafe {
                std::slice::from_raw_parts(folder, length)
            })))
        } else {
            None
        };
        unsafe {
            CoTaskMemFree(folder.cast());
        }
        profile.directory = path.ok_or_else(failed)?;
        let package = profile.directory.parent().ok_or_else(failed)?;
        let moniker = OsString::from_wide(&profile.name[..profile.name.len() - 1]);
        if profile
            .directory
            .file_name()
            .is_none_or(|n| !n.eq_ignore_ascii_case("AC"))
            || package
                .file_name()
                .is_none_or(|n| !n.eq_ignore_ascii_case(&moniker))
        {
            return Err(io::Error::other("appcontainer_profile_layout"));
        }
        // This fresh profile has never executed untrusted code. Limit its SID to
        // read/execute in every initial directory, including siblings of AC.
        // The parser has no need for writable temporary storage.
        deny_profile_storage(package, &profile)
            .map_err(|e| io::Error::other(format!("appcontainer_profile_acl:{e}")))?;
        Ok(profile)
    }
    fn sid_text(&self) -> io::Result<String> {
        let mut out = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(self.sid, &mut out) } == 0 {
            return Err(failed());
        }
        let mut length = 0;
        while length < 256 && unsafe { *out.add(length) } != 0 {
            length += 1;
        }
        let result = if length < 256 {
            String::from_utf16(unsafe { std::slice::from_raw_parts(out, length) })
                .map_err(|_| failed())
        } else {
            Err(failed())
        };
        unsafe {
            LocalFree(out.cast());
        }
        result
    }
}
fn deny_profile_storage(root: &Path, profile: &Profile) -> io::Result<()> {
    if !root.is_absolute() {
        return Err(failed());
    }
    let mut paths = vec![root.to_owned()];
    let mut count = 0;
    while let Some(path) = paths.pop() {
        count += 1;
        if count > 256 {
            return Err(failed());
        }
        use std::os::windows::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(failed());
        }
        super::private_directory(&path)?;
        Stage::protect(&[&path], profile)?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                paths.push(entry?.path());
            }
        }
    }
    Ok(())
}
struct Stage {
    directory: PathBuf,
    binary: PathBuf,
}
struct Desktop(HDESK);
impl Drop for Desktop {
    fn drop(&mut self) {
        unsafe {
            CloseDesktop(self.0);
        }
    }
}
impl Desktop {
    fn new(profile: &Profile) -> io::Result<Self> {
        let user = super::current_user_id()?;
        let sid = profile.sid_text()?;
        let text = wide(std::ffi::OsStr::new(&format!(
            "D:P(A;;GA;;;{user})(A;;0x000200c7;;;{sid})S:(ML;;NW;;;LW)"
        )));
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(failed());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateDesktopExW(
                profile.name.as_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                0x000f01ff,
                &attributes,
                256,
                ptr::null(),
            )
        };
        unsafe {
            LocalFree(descriptor);
        }
        if handle.is_null() {
            return Err(io::Error::other(format!(
                "appcontainer_desktop:{}",
                unsafe { GetLastError() }
            )));
        }
        Ok(Self(handle))
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.binary);
        let _ = std::fs::remove_dir(&self.directory);
    }
}
impl Stage {
    fn new(program: &Path, profile: &Profile) -> io::Result<Self> {
        // All ancestors of the package path are traversable by its token;
        // no ACE is added to the user's real application-data directories.
        let directory = profile.directory.join("Code");
        super::create_private_directory(&directory)?;
        let stage = Self {
            binary: directory.join("worker.exe"),
            directory,
        };
        std::fs::copy(program, &stage.binary)?;
        Self::protect(&[&stage.directory, &stage.binary], profile)?;
        Ok(stage)
    }
    fn protect(paths: &[&Path], profile: &Profile) -> io::Result<()> {
        let user = super::current_user_id()?;
        let sid = profile.sid_text()?;
        let descriptor = wide(std::ffi::OsStr::new(&format!(
            "D:P(A;OICI;FA;;;{user})(A;OICI;GRGX;;;{sid})"
        )));
        let mut sd = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                1,
                &mut sd,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(failed());
        }
        let mut dacl = ptr::null_mut();
        let (mut present, mut defaulted) = (0, 0);
        let valid =
            unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) } != 0
                && present != 0;
        let result = if valid {
            let mut code = ERROR_SUCCESS;
            // Explicitly set both objects: the file already exists when inheritance is changed.
            for path in paths {
                let path = wide(path.as_os_str());
                code = unsafe {
                    SetNamedSecurityInfoW(
                        path.as_ptr(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        dacl,
                        ptr::null_mut(),
                    )
                };
                if code != ERROR_SUCCESS {
                    break;
                }
            }
            if code == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(failed())
            }
        } else {
            Err(failed())
        };
        unsafe {
            LocalFree(sd);
        }
        result
    }
}
struct Attributes<'a> {
    memory: Vec<usize>,
    borrowed: std::marker::PhantomData<&'a ()>,
}
impl<'a> Attributes<'a> {
    fn new(count: u32) -> io::Result<Self> {
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut size);
        }
        if size == 0 || size > 65536 {
            return Err(failed());
        }
        let mut memory = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(memory.as_mut_ptr().cast(), count, 0, &mut size)
        } == 0
        {
            return Err(failed());
        }
        Ok(Self {
            memory,
            borrowed: std::marker::PhantomData,
        })
    }
    fn add<T: ?Sized + 'a>(&mut self, key: u32, value: &'a T) -> io::Result<()> {
        if unsafe {
            UpdateProcThreadAttribute(
                self.memory.as_mut_ptr().cast(),
                0,
                key as usize,
                (value as *const T).cast(),
                std::mem::size_of_val(value),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            Err(failed())
        } else {
            Ok(())
        }
    }
}
impl Drop for Attributes<'_> {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.memory.as_mut_ptr().cast());
        }
    }
}
fn pipe(profile: &Profile) -> io::Result<(Handle, Handle)> {
    let user = super::current_user_id()?;
    let sid = profile.sid_text()?;
    let text = wide(std::ffi::OsStr::new(&format!(
        "D:P(A;;GA;;;{user})(A;;GRGW;;;{sid})S:(ML;;NW;;;LW)"
    )));
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(failed());
    }
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
    let success = unsafe { CreatePipe(&mut read, &mut write, &security, 0) };
    let code = unsafe { GetLastError() };
    unsafe {
        LocalFree(descriptor);
    }
    if success == 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok((Handle(read), Handle(write)))
}
fn quote(argument: &std::ffi::OsStr, out: &mut Vec<u16>) -> io::Result<()> {
    out.push(34);
    let mut slashes = 0;
    for c in argument.encode_wide() {
        if c == 0 {
            return Err(failed());
        }
        if c == 92 {
            slashes += 1;
            continue;
        }
        out.extend(std::iter::repeat_n(
            92,
            if c == 34 { slashes * 2 + 1 } else { slashes },
        ));
        slashes = 0;
        out.push(c);
    }
    out.extend(std::iter::repeat_n(92, slashes * 2));
    out.push(34);
    Ok(())
}
pub fn is_appcontainer() -> io::Result<bool> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(failed());
    }
    let token = Handle(token);
    let mut value = 0u32;
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenIsAppContainer,
            (&mut value as *mut u32).cast(),
            4,
            &mut length,
        )
    } == 0
    {
        return Err(failed());
    }
    Ok(value != 0)
}
pub struct SandboxOutput {
    pub stdout: Zeroizing<Vec<u8>>,
    pub exit_code: u32,
}
/// Blocking, bounded one-shot stdio exchange in an offline AppContainer. Only the code
/// asset is granted to the child. Its fresh profile and temp storage are denied.
pub fn appcontainer_exchange(
    program: &Path,
    args: &[OsString],
    input: Zeroizing<Vec<u8>>,
    output_limit: usize,
    timeout: Duration,
) -> io::Result<SandboxOutput> {
    if timeout > Duration::from_secs(120) {
        return Err(failed());
    }
    appcontainer_exchange_with_files(
        program,
        args,
        &[],
        input,
        output_limit,
        timeout,
        512 * 1024 * 1024,
    )
}
/// Offline one-shot worker with explicitly inherited read-only disk handles.
/// Arguments equal to `@handle:LABEL` are replaced with the corresponding handle.
/// No model path or access to its containing directory is granted to the child.
pub fn appcontainer_exchange_with_files(
    program: &Path,
    args: &[OsString],
    files: &[(&str, &File)],
    input: Zeroizing<Vec<u8>>,
    output_limit: usize,
    timeout: Duration,
    memory_limit: u64,
) -> io::Result<SandboxOutput> {
    exchange_with_policy(
        program,
        args,
        files,
        input,
        output_limit,
        timeout,
        WorkerPolicy {
            memory_limit,
            lpac: true,
        },
    )
}
struct WorkerPolicy {
    memory_limit: u64,
    lpac: bool,
}
/// Trusted device inventory only; no capabilities, network or home directory.
pub fn appcontainer_probe_exchange(
    program: &Path,
    args: &[OsString],
    files: &[(&str, &File)],
    input: Zeroizing<Vec<u8>>,
) -> io::Result<SandboxOutput> {
    exchange_with_policy(
        program,
        args,
        files,
        input,
        128 * 1024 + 4,
        Duration::from_secs(30),
        WorkerPolicy {
            memory_limit: 128 * 1024 * 1024,
            lpac: false,
        },
    )
}
fn exchange_with_policy(
    program: &Path,
    args: &[OsString],
    files: &[(&str, &File)],
    input: Zeroizing<Vec<u8>>,
    output_limit: usize,
    timeout: Duration,
    policy: WorkerPolicy,
) -> io::Result<SandboxOutput> {
    let memory_limit = policy.memory_limit;
    if !program.is_absolute()
        || !program.is_file()
        || input.len() > 16 * 1024 * 1024
        || output_limit > 16 * 1024 * 1024
        || timeout > Duration::from_secs(240)
        || args.len() > 32
        || files.len() > 4
        || !(64 * 1024 * 1024..=8 * 1024 * 1024 * 1024).contains(&memory_limit)
        || usize::try_from(memory_limit).is_err()
    {
        return Err(failed());
    }
    let mut read_handles = Vec::new();
    for (index, (label, file)) in files.iter().enumerate() {
        if label.is_empty()
            || label.len() > 32
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || files[..index].iter().any(|(other, _)| other == label)
        {
            return Err(failed());
        }
        read_handles.push(duplicate_read_file(file.as_raw_handle(), true)?);
    }
    let profile = Profile::new()?;
    let stage = Stage::new(program, &profile)
        .map_err(|e| io::Error::other(format!("appcontainer_stage:{e}")))?;
    let _desktop = Desktop::new(&profile)?;
    let job = Handle(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) });
    if job.0.is_null() {
        return Err(failed());
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = memory_limit as usize;
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
    {
        return Err(failed());
    }
    let (child_input, parent_input) = pipe(&profile)?;
    let (parent_output, child_output) = pipe(&profile)?;
    for handle in [&parent_input, &parent_output] {
        if unsafe { SetHandleInformation(handle.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(failed());
        }
    }
    let mut handles = vec![child_input.0, child_output.0];
    handles.extend(read_handles.iter().map(|h| h.0));
    let jobs = [job.0];
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid,
        Capabilities: ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    let mut attributes = Attributes::new(4)?;
    attributes.add(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities)?;
    attributes.add(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.as_slice())?;
    attributes.add(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
    if policy.lpac {
        attributes.add(
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            &packages_policy,
        )?;
    }
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of_val(&startup) as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.lpDesktop = profile.name.as_ptr().cast_mut();
    startup.StartupInfo.hStdInput = child_input.0;
    startup.StartupInfo.hStdOutput = child_output.0;
    startup.StartupInfo.hStdError = child_output.0;
    startup.lpAttributeList = attributes.memory.as_mut_ptr().cast();
    let application = wide(stage.binary.as_os_str());
    let mut command = vec![];
    quote(stage.binary.as_os_str(), &mut command)?;
    for argument in args {
        command.push(32);
        if let Some(label) = argument.to_str().and_then(|a| a.strip_prefix("@handle:")) {
            let index = files
                .iter()
                .position(|(name, _)| *name == label)
                .ok_or_else(failed)?;
            quote(
                std::ffi::OsStr::new(&format!("{}", read_handles[index].0 as usize)),
                &mut command,
            )?;
        } else {
            quote(argument, &mut command)?;
        }
    }
    command.push(0);
    if command.len() > 32768 {
        return Err(failed());
    }
    let system = std::env::var_os("SystemRoot").ok_or_else(failed)?;
    let mut environment = vec![];
    let temp = profile.directory.join("Temp");
    for (name, value) in [
        ("LOCALAPPDATA", profile.directory.as_os_str()),
        ("SystemRoot", system.as_os_str()),
        ("TEMP", temp.as_os_str()),
        ("TMP", temp.as_os_str()),
        ("WINDIR", system.as_os_str()),
    ] {
        environment.extend(
            wide(std::ffi::OsStr::new(name))
                .into_iter()
                .take(name.len()),
        );
        environment.push(61);
        environment.extend(value.encode_wide());
        environment.push(0);
    }
    environment.push(0);
    let directory = wide(PathBuf::from(&system).join("System32").as_os_str());
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            &startup.StartupInfo,
            &mut process,
        )
    } == 0
    {
        return Err(io::Error::other(format!(
            "appcontainer_process:{}",
            unsafe { GetLastError() }
        )));
    }
    let process_handle = Handle(process.hProcess);
    let _thread = Handle(process.hThread);
    drop(child_input);
    drop(child_output);
    let mut input_file = parent_input.file();
    let output_file = parent_output.file();
    let writer = std::thread::spawn(move || input_file.write_all(&input));
    let reader = std::thread::spawn(move || {
        let mut bytes = Zeroizing::new(Vec::new());
        output_file
            .take(output_limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > output_limit {
            return Err(failed());
        }
        Ok(bytes)
    });
    let status =
        unsafe { WaitForSingleObject(process_handle.0, timeout.as_millis().max(1) as u32) };
    if status != WAIT_OBJECT_0 {
        unsafe {
            TerminateJobObject(job.0, 1);
            WaitForSingleObject(process_handle.0, 5000);
        }
    }
    let wrote = writer.join().map_err(|_| failed())?;
    let output = reader.join().map_err(|_| failed())?;
    let mut exit = 1;
    if status != WAIT_OBJECT_0 || unsafe { GetExitCodeProcess(process_handle.0, &mut exit) } == 0 {
        return Err(io::Error::other(format!(
            "appcontainer_exit_{exit:08x}_wait_{status:08x}"
        )));
    }
    if exit == 0 {
        wrote?;
    }
    Ok(SandboxOutput {
        stdout: output?,
        exit_code: exit,
    })
}
fn duplicate_read_file(raw: RawHandle, inherit: bool) -> io::Result<Handle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE || unsafe { GetFileType(raw) } != FILE_TYPE_DISK
    {
        return Err(failed());
    }
    let mut copy = ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut copy,
            FILE_GENERIC_READ,
            i32::from(inherit),
            0,
        )
    } == 0
    {
        return Err(failed());
    }
    Ok(Handle(copy))
}
/// Borrows an inherited disk handle only inside an AppContainer and returns an
/// owned read-only duplicate. Arbitrary numeric handles are never adopted.
pub fn inherited_read_file(value: usize) -> io::Result<File> {
    if !is_appcontainer()? {
        return Err(failed());
    }
    let raw = value as RawHandle;
    let mut flags = 0;
    if unsafe { GetHandleInformation(raw, &mut flags) } == 0 || flags & HANDLE_FLAG_INHERIT == 0 {
        return Err(failed());
    }
    Ok(duplicate_read_file(raw, false)?.file())
}
