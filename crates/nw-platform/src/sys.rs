//! SAFETY: pointers come from live owned Rust allocations or Win32-owned buffers;
//! each OS allocation/handle is released exactly once. No borrowed pointer escapes.
use std::io;
mod device;
pub use device::*;
#[cfg(windows)]
mod windows_sandbox;
#[cfg(windows)]
pub use windows_sandbox::{
    SandboxOutput, appcontainer_exchange, appcontainer_exchange_with_files,
    appcontainer_probe_exchange, inherited_read_file, is_appcontainer,
};
fn failed() -> io::Error {
    io::Error::other("platform_security_operation_failed")
}

/// An administrative launcher may drop to a non-root identity, never to root.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub struct ChildIdentity {
    uid: libc::uid_t,
    gid: libc::gid_t,
}
#[cfg(target_os = "linux")]
impl ChildIdentity {
    pub fn new(uid: u32, gid: u32) -> io::Result<Self> {
        if uid == 0 || gid == 0 || uid == u32::MAX || gid == u32::MAX {
            return Err(failed());
        }
        Ok(Self { uid, gid })
    }
}
/// Prepare a trusted command in an already provisioned netns. This grants no
/// privilege: the caller must already be root and setns must pass the kernel's
/// namespace checks. No shell, path lookup, sudo or fallback is involved.
#[cfg(target_os = "linux")]
pub fn enter_child_network_namespace(
    command: &mut std::process::Command,
    namespace: &std::fs::File,
    identity: ChildIdentity,
) -> io::Result<()> {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    if unsafe { libc::geteuid() } != 0
        || unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } != 0
    {
        return Err(failed());
    }
    let namespace = namespace.try_clone()?;
    // SAFETY: after fork, only direct Linux syscalls and errno capture run.
    // The owned CLOEXEC descriptor remains live until exec; no allocation,
    // environment access, locks or libc thread-synchronizing setxid wrappers.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) != 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            if libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) != 0
                || libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_setgroups, 0usize, std::ptr::null::<libc::gid_t>()) != 0
                || libc::syscall(
                    libc::SYS_setresgid,
                    libc::c_ulong::from(identity.gid),
                    libc::c_ulong::from(identity.gid),
                    libc::c_ulong::from(identity.gid),
                ) != 0
                || libc::syscall(
                    libc::SYS_setresuid,
                    libc::c_ulong::from(identity.uid),
                    libc::c_ulong::from(identity.uid),
                    libc::c_ulong::from(identity.uid),
                ) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}
/// One-way identity transition in the administrative coordinator, before it
/// handles test data. libc setxid wrappers synchronize the process's threads.
#[cfg(target_os = "linux")]
pub fn drop_process_identity(identity: ChildIdentity) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0
        || unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } != 0
    {
        return Err(failed());
    }
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } != 0
        || unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setresgid(identity.gid, identity.gid, identity.gid) } != 0
        || unsafe { libc::setresuid(identity.uid, identity.uid, identity.uid) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(failed());
    }
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } != 0
        || (real, effective, saved) != (identity.uid, identity.uid, identity.uid)
        || unsafe { libc::getresgid(&mut real, &mut effective, &mut saved) } != 0
        || (real, effective, saved) != (identity.gid, identity.gid, identity.gid)
    {
        return Err(failed());
    }
    Ok(())
}
#[cfg(all(test, target_os = "linux"))]
#[path = "../../../tests/leak/src/netns_identity.rs"]
mod namespace_tests;

/// Own a CLOEXEC duplicate of the read pipe without std::io::Stdin's persistent
/// shared buffer retaining a second, unlocked copy of the bootstrap key.
#[cfg(unix)]
pub fn inherited_stdin_pipe() -> io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(failed());
    }
    // SAFETY: this descriptor was just allocated and has exactly one File owner.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(failed());
    }
    // SAFETY: fstat succeeded and initialized the complete stat allocation.
    let metadata = unsafe { metadata.assume_init() };
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFIFO
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(failed());
    }
    Ok(file)
}
/// Supply public, immutable sandbox identity files without filesystem staging.
/// Descriptors stay CLOEXEC in the parent and are inherited only by this command.
#[cfg(target_os = "linux")]
pub fn sandbox_data_files(
    command: &mut std::process::Command,
    data: &[(&str, &[u8])],
) -> io::Result<()> {
    use std::{
        fs::File,
        io::{Seek, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::process::CommandExt,
        },
    };
    let mut files = Vec::new();
    for (destination, contents) in data {
        if !destination.starts_with('/') || destination.contains("..") || contents.len() > 4096 {
            return Err(failed());
        }
        // SAFETY: a static C string; successful descriptor has exactly one File owner.
        let fd = unsafe {
            libc::memfd_create(
                c"nw-sandbox-public-data".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(failed());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(contents)?;
        file.rewind()?;
        if unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
        {
            return Err(failed());
        }
        command.args([
            "--perms",
            "0444",
            "--ro-bind-data",
            &fd.to_string(),
            destination,
        ]);
        files.push(file);
    }
    // SAFETY: after fork only async-signal-safe fcntl calls; captured File owners
    // keep descriptors alive for every spawn and close them on Command drop.
    unsafe {
        command.pre_exec(move || {
            for file in &files {
                if libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}
/// Inherit only explicitly opened read-only regular files into one bwrap command.
#[cfg(target_os = "linux")]
pub fn sandbox_read_files(
    command: &mut std::process::Command,
    sources: &[(&str, &std::fs::File)],
) -> io::Result<()> {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    let mut files = vec![];
    for (destination, source) in sources {
        if !destination.starts_with('/')
            || destination.contains("..")
            || !source.metadata()?.is_file()
            || unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
                != libc::O_RDONLY
        {
            return Err(failed());
        }
        let file = source.try_clone()?;
        let fd = file.as_raw_fd();
        command.args(["--ro-bind", &format!("/proc/self/fd/{fd}"), destination]);
        files.push(file);
    }
    // SAFETY: only fcntl after fork; captured owners retain the CLOEXEC parent
    // descriptors until Command drop. No other command inherits these handles.
    unsafe {
        command.pre_exec(move || {
            for file in &files {
                if libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}
#[cfg(unix)]
pub fn current_group_id() -> String {
    unsafe { libc::getegid() }.to_string()
}
/// Apply to every current thread and inherit across future threads/exec.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn deny_remote_sockets() -> io::Result<()> {
    offline_filter(false)
}
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn confine_import_worker() -> io::Result<()> {
    offline_filter(true)
}
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn offline_filter(block_namespaces: bool) -> io::Result<()> {
    use libc::{sock_filter, sock_fprog};
    let statement = |code, k| sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k, jt, jf| sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    #[cfg(target_arch = "x86_64")]
    let arch = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    let arch = 0xc00000b7;
    let allow = 0x7fff0000;
    let deny = 0x00050000 | libc::EPERM as u32;
    let mut filter = vec![
        statement(0x20, 4),
        jump(arch, 1, 0),
        statement(0x06, 0x80000000),
        statement(0x20, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        filter.push(sock_filter {
            code: 0x35,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        });
        filter.push(statement(0x06, 0x80000000));
    }
    for number in [libc::SYS_socket, libc::SYS_socketpair] {
        if !block_namespaces && number == libc::SYS_socket {
            // bwrap sets up loopback in its fresh netns using NETLINK_ROUTE.
            // This family cannot carry provider TCP/UDP payloads.
            filter.extend([
                jump(number as u32, 0, 7),
                statement(0x20, 16),
                jump(libc::AF_UNIX as u32, 4, 0),
                jump(libc::AF_NETLINK as u32, 0, 2),
                statement(0x20, 32),
                jump(libc::NETLINK_ROUTE as u32, 1, 0),
                statement(0x06, deny),
                statement(0x06, allow),
            ]);
            continue;
        }
        filter.extend([
            jump(number as u32, 0, 4),
            statement(0x20, 16),
            jump(libc::AF_UNIX as u32, 1, 0),
            statement(0x06, deny),
            statement(0x06, allow),
        ]);
    }
    for number in [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_userfaultfd,
        libc::SYS_open_by_handle_at,
        libc::SYS_keyctl,
    ] {
        filter.extend([jump(number as u32, 0, 1), statement(0x06, deny)]);
    }
    if block_namespaces {
        for number in [
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_mount,
            libc::SYS_umount2,
        ] {
            filter.extend([jump(number as u32, 0, 1), statement(0x06, deny)]);
        }
    }
    // Modern libc falls back to clone when clone3 reports ENOSYS.
    filter.extend([
        jump(libc::SYS_clone3 as u32, 0, 1),
        statement(0x06, 0x00050000 | libc::ENOSYS as u32),
        statement(0x06, allow),
    ]);
    let program = sock_fprog {
        len: u16::try_from(filter.len()).map_err(|_| failed())?,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(failed());
    }
    if unsafe { libc::syscall(libc::SYS_seccomp, 1, 1, &program) } != 0 {
        return Err(failed());
    }
    Ok(())
}
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub fn deny_remote_sockets() -> io::Result<()> {
    Err(failed())
}
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub fn confine_import_worker() -> io::Result<()> {
    Err(failed())
}
#[cfg(windows)]
pub fn verify_directory_encryption(path: &std::path::Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{EncryptFileW, FileEncryptionStatusW};
    let text: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut status = 0;
    if unsafe { FileEncryptionStatusW(text.as_ptr(), &mut status) } == 0 {
        return Err(failed());
    }
    if status != 1 {
        // Never silently convert an existing plaintext transport store.
        if std::fs::read_dir(path)?.next().is_some() {
            return Err(failed());
        }
        if unsafe { EncryptFileW(text.as_ptr()) } == 0 {
            return Err(failed());
        }
    }
    if unsafe { FileEncryptionStatusW(text.as_ptr(), &mut status) } == 0 || status != 1 {
        return Err(failed());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
pub fn verify_directory_encryption(path: &std::path::Path) -> io::Result<()> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?;
    #[repr(C)]
    struct Policy {
        size: u64,
        policy: [u8; 24],
    }
    let mut policy = Policy {
        size: 24,
        policy: [0; 24],
    };
    // Linux UAPI FS_IOC_GET_ENCRYPTION_POLICY_EX, argument size encoded as 9.
    if unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            // glibc takes an unsigned long; musl takes an int with the same low bits.
            0xc0096616u32 as _,
            &mut policy,
        )
    } != 0
        || !matches!(policy.size, 12 | 24)
    {
        return Err(failed());
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn verify_directory_encryption(_path: &std::path::Path) -> io::Result<()> {
    Err(failed())
}

#[cfg(unix)]
pub fn current_user_id() -> io::Result<String> {
    Ok(unsafe { libc::geteuid() }.to_string())
}
#[cfg(target_os = "linux")]
pub fn process_image(pid: u32) -> io::Result<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}
#[cfg(target_os = "macos")]
pub fn local_peer_process(socket: std::os::fd::BorrowedFd<'_>) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    let mut pid: libc::pid_t = 0;
    let mut size = std::mem::size_of_val(&pid) as libc::socklen_t;
    // Darwin's xucred does not carry a PID. Query the connected socket itself;
    // a missing, malformed or nonpositive kernel result never authenticates.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of_val(&pid)
        || pid <= 0
    {
        return Err(failed());
    }
    u32::try_from(pid).map_err(|_| failed())
}
#[cfg(target_os = "macos")]
pub fn process_image(pid: u32) -> io::Result<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let pid = i32::try_from(pid).map_err(|_| failed())?;
    let mut buf = vec![0u8; 4096];
    let length = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if length <= 0 {
        return Err(failed());
    }
    buf.truncate(length as usize);
    if let Some(n) = buf.iter().position(|b| *b == 0) {
        buf.truncate(n);
    }
    Ok(std::ffi::OsString::from_vec(buf).into())
}
#[cfg(unix)]
pub fn page_size() -> io::Result<usize> {
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n <= 0 {
        return Err(failed());
    }
    Ok(n as usize)
}
#[cfg(unix)]
pub fn lock_page(page: usize, size: usize) -> io::Result<()> {
    if unsafe { libc::mlock(page as *const _, size) } != 0 {
        return Err(failed());
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::madvise(page as *mut _, size, libc::MADV_DONTDUMP) } != 0 {
        unsafe { libc::munlock(page as *const _, size) };
        return Err(failed());
    }
    Ok(())
}
#[cfg(unix)]
pub fn unlock_page(page: usize, size: usize) {
    unsafe { libc::munlock(page as *const _, size) };
}
#[cfg(unix)]
pub fn harden_process() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(failed());
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(failed());
    }
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, BorrowedHandle, FromRawHandle},
        },
        path::Path,
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Security::{Authorization::*, *},
        System::{
            Diagnostics::Debug::*, ErrorReporting::*, Memory::*, SystemInformation::*, Threading::*,
        },
    };
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    struct Local(*mut core::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }
    fn sid_string(sid: PSID) -> io::Result<String> {
        let mut text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(failed());
        }
        let _memory = Local(text.cast());
        let mut length = 0;
        while length < 256 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err(failed());
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| failed())
    }
    pub fn current_user_id() -> io::Result<String> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(failed());
        }
        let token = Handle(token);
        let mut length = 0;
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut length) };
        if length == 0 || length > 1024 * 1024 {
            return Err(failed());
        }
        let mut aligned = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                aligned.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(failed());
        }
        let user = unsafe { &*aligned.as_ptr().cast::<TOKEN_USER>() };
        sid_string(user.User.Sid)
    }
    fn token_info(
        token: HANDLE,
        kind: TOKEN_INFORMATION_CLASS,
    ) -> io::Result<zeroize::Zeroizing<Vec<usize>>> {
        let mut length = 0;
        unsafe { GetTokenInformation(token, kind, ptr::null_mut(), 0, &mut length) };
        if length < std::mem::size_of::<TOKEN_USER>() as u32 || length > 1024 * 1024 {
            return Err(failed());
        }
        let mut bytes = zeroize::Zeroizing::new(vec![
            0usize;
            (length as usize)
                .div_ceil(std::mem::size_of::<usize>())
        ]);
        if unsafe {
            GetTokenInformation(token, kind, bytes.as_mut_ptr().cast(), length, &mut length)
        } == 0
        {
            return Err(failed());
        }
        Ok(bytes)
    }
    /// Select an existing SID in this process token for ownership of new objects.
    /// No privilege/group/capability or existing object's security is changed.
    pub(super) fn user_owned_objects() -> io::Result<()> {
        let mut token = ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                &mut token,
            )
        } == 0
        {
            return Err(failed());
        }
        let token = Handle(token);
        let user = token_info(token.0, TokenUser)?;
        let user = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() };
        let owner = TOKEN_OWNER {
            Owner: user.User.Sid,
        };
        if unsafe {
            SetTokenInformation(
                token.0,
                TokenOwner,
                (&owner as *const TOKEN_OWNER).cast(),
                std::mem::size_of::<TOKEN_OWNER>() as u32,
            )
        } == 0
        {
            return Err(failed());
        }
        let verified = token_info(token.0, TokenOwner)?;
        let verified = unsafe { &*verified.as_ptr().cast::<TOKEN_OWNER>() };
        if unsafe { EqualSid(verified.Owner, user.User.Sid) } == 0 {
            return Err(io::Error::other("private_object_owner_mismatch"));
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn default_owner_id() -> io::Result<String> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(failed());
        }
        let token = Handle(token);
        let owner = token_info(token.0, TokenOwner)?;
        sid_string(unsafe { (*owner.as_ptr().cast::<TOKEN_OWNER>()).Owner })
    }
    pub fn process_image(pid: u32) -> io::Result<std::path::PathBuf> {
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            return Err(failed());
        }
        let handle = Handle(raw);
        let mut buffer = vec![0u16; 32768];
        let mut length = buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut length) } == 0
        {
            return Err(failed());
        }
        let value = String::from_utf16(&buffer[..length as usize]).map_err(|_| failed())?;
        Ok(value.into())
    }
    pub fn kernel_object_owner(handle: BorrowedHandle<'_>) -> io::Result<String> {
        let mut owner = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        } != ERROR_SUCCESS
        {
            return Err(failed());
        }
        let _memory = Local(descriptor);
        sid_string(owner)
    }
    pub fn create_private_directory(path: &Path) -> io::Result<()> {
        use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
        let sid = current_user_id()?;
        let text: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
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
        let _memory = Local(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // The descriptor applies at creation, including an explicit owner even
        // when an administrator token's default owner is Administrators.
        if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn private_directory(path: &Path) -> io::Result<()> {
        let sid = current_user_id()?;
        let descriptor_text: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_text.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(failed());
        }
        let _memory = Local(descriptor);
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl = ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            == 0
            || present == 0
            || dacl.is_null()
        {
            return Err(failed());
        }
        let mut name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut owner = ptr::null_mut();
        let mut original = ptr::null_mut();
        let result = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut original,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let _original_memory = Local(original);
        if sid_string(owner)? != sid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "foreign_directory_owner",
            ));
        }
        // The owner may update the DACL without having WRITE_OWNER. Reassigning the
        // already correct owner needlessly fails in directories granting Modify.
        let result = unsafe {
            SetNamedSecurityInfoW(
                name.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        Ok(())
    }
    pub fn page_size() -> io::Result<usize> {
        let mut info = std::mem::MaybeUninit::<SYSTEM_INFO>::zeroed();
        unsafe { GetSystemInfo(info.as_mut_ptr()) };
        let n = unsafe { info.assume_init() }.dwPageSize;
        if n == 0 {
            return Err(failed());
        }
        Ok(n as usize)
    }
    pub fn lock_page(page: usize, size: usize) -> io::Result<()> {
        if unsafe { VirtualLock(page as *const _, size) } == 0 {
            static BUDGET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
            let adjusted = *BUDGET.get_or_init(|| {
                let (mut minimum, mut maximum) = (0usize, 0usize);
                if unsafe {
                    GetProcessWorkingSetSize(GetCurrentProcess(), &mut minimum, &mut maximum)
                } == 0
                {
                    return false;
                }
                // SQLCipher also locks allocations. The default Windows minimum
                // (50 pages) cannot accommodate six domain stores plus their vaults.
                (unsafe {
                    SetProcessWorkingSetSize(
                        GetCurrentProcess(),
                        minimum.max(16 * 1024 * 1024),
                        maximum.max(64 * 1024 * 1024),
                    )
                }) != 0
            });
            if !adjusted || unsafe { VirtualLock(page as *const _, size) } == 0 {
                return Err(failed());
            }
        }
        if unsafe { WerRegisterExcludedMemoryBlock(page as *const _, size as u32) } < 0 {
            unsafe { VirtualUnlock(page as *const _, size) };
            return Err(failed());
        }
        Ok(())
    }
    pub fn unlock_page(page: usize, size: usize) {
        unsafe {
            WerUnregisterExcludedMemoryBlock(page as *const _);
            VirtualUnlock(page as *const _, size)
        };
    }
    pub fn inherited_stdin_pipe() -> io::Result<std::fs::File> {
        use windows_sys::Win32::{
            Storage::FileSystem::{FILE_GENERIC_READ, FILE_TYPE_PIPE, GetFileType},
            System::Console::{GetStdHandle, STD_INPUT_HANDLE},
        };
        let source = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if source.is_null() || source == INVALID_HANDLE_VALUE {
            return Err(failed());
        }
        let mut copy = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &mut copy,
                FILE_GENERIC_READ,
                0,
                0,
            )
        } == 0
        {
            return Err(failed());
        }
        let copy = Handle(copy);
        if unsafe { GetFileType(copy.0) } != FILE_TYPE_PIPE {
            return Err(failed());
        }
        // SAFETY: this non-inheritable read handle was just allocated. Transfer
        // its sole ownership to File without closing the original std handle.
        let file = unsafe { std::fs::File::from_raw_handle(copy.0) };
        std::mem::forget(copy);
        Ok(file)
    }
    pub fn harden_process() -> io::Result<()> {
        unsafe { SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS) };
        if unsafe {
            WerSetFlags(
                WER_FAULT_REPORTING_FLAG_NOHEAP
                    | WER_FAULT_REPORTING_FLAG_NO_HEAP_ON_QUEUE
                    | WER_FAULT_REPORTING_DISABLE_SNAPSHOT_CRASH
                    | WER_FAULT_REPORTING_DISABLE_SNAPSHOT_HANG
                    | WER_FAULT_REPORTING_NO_UI,
            )
        } < 0
        {
            return Err(failed());
        }
        Ok(())
    }
}
#[cfg(windows)]
pub use windows::*;
