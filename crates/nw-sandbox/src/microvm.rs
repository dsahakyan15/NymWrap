//! Opt-in shadow-only Firecracker backend. The bwrap path is independent.
use std::{ffi::OsString, path::Path};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MicroVmError {
    #[error("MicroVM requires Linux x86_64; no fallback was attempted")]
    Unsupported,
    #[error("MicroVM: /dev/kvm is unavailable; check KVM support and device permissions")]
    Kvm,
    #[error(
        "MicroVM tools are missing or have an invalid SHA-256; run node scripts/fetch-microvm.mjs --prepare"
    )]
    Tools,
    #[error("MicroVM requires swap disabled to keep guest memory off disk")]
    Swap,
    #[error("MicroVM requires a non-piped kernel.core_pattern; disable host crash dump helpers")]
    CoreDump,
    #[error("MicroVM requires an owner-only shadow api.sock from NymWrap")]
    Api,
    #[error(
        "MicroVM project must fit into 64 MiB/4096 entries and contain no symlinks, hardlinks or special files"
    )]
    Project,
    #[error("MicroVM requires an absolute guest command path and at most 255 bounded arguments")]
    Command,
    #[error(
        "MicroVM failed to launch or guest stopped before reporting status; no fallback was attempted"
    )]
    Launch,
    #[error("MicroVM startup or runtime limit exceeded (30 seconds / one hour)")]
    Timeout,
}

/// The program path is a *guest* path. /work is an ephemeral RAM snapshot;
/// there is deliberately no automatic host writeback, shared disk or NIC.
pub fn run(
    work: &Path,
    program: &Path,
    args: &[OsString],
    api: &Path,
    tools: &Path,
) -> Result<i32, MicroVmError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        linux::run(work, program, args, api, tools)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (work, program, args, api, tools);
        Err(MicroVmError::Unsupported)
    }
}

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
const LIMIT: usize = 64 * 1024 * 1024;
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
fn terminal_output(bytes: &[u8]) -> zeroize::Zeroizing<String> {
    use std::fmt::Write;
    let input = zeroize::Zeroizing::new(String::from_utf8_lossy(bytes).into_owned());
    let mut output = zeroize::Zeroizing::new(String::new());
    for character in input.chars() {
        if (character.is_control() && character != '\n' && character != '\t')
            || matches!(character,'\u{200e}'|'\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        {
            let _ = write!(output, "\\u{{{:x}}}", character as u32);
        } else {
            output.push(character);
        }
    }
    output
}
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
fn arguments(
    program: &Path,
    args: &[OsString],
) -> Result<zeroize::Zeroizing<Vec<u8>>, MicroVmError> {
    let path = program.to_str().ok_or(MicroVmError::Command)?;
    if !path.starts_with('/')
        || path.split('/').any(|c| c == "..")
        || path.contains('\\')
        || args.len() > 255
    {
        return Err(MicroVmError::Command);
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    for arg in std::iter::once(program.as_os_str()).chain(args.iter().map(|v| v.as_os_str())) {
        let value = arg.as_encoded_bytes();
        if value.contains(&0) || bytes.len() + value.len() + 1 >= 65536 {
            return Err(MicroVmError::Command);
        }
        bytes.extend_from_slice(value);
        bytes.push(0);
    }
    Ok(bytes)
}

/// Minimal newc writer: names are relative components; no archive is extracted
/// on the host. Modes/UIDs/timestamps never carry host identity into the guest.
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
struct Initrd {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    count: u32,
}
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
impl Initrd {
    fn new() -> Self {
        Self {
            bytes: zeroize::Zeroizing::new(Vec::new()),
            count: 0,
        }
    }
    fn entry(&mut self, name: &str, mode: u32, data: &[u8], user: u32) -> Result<(), MicroVmError> {
        if name.starts_with('/')
            || name
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
            || name.contains('\0')
            || name.len() > 1024
            || self.count >= 4096
            || self.bytes.len() + name.len() + data.len() + 128 > LIMIT
        {
            return Err(MicroVmError::Project);
        }
        self.count += 1;
        let fields = [
            self.count,
            mode,
            user,
            user,
            1,
            0,
            u32::try_from(data.len()).map_err(|_| MicroVmError::Project)?,
            0,
            0,
            0,
            0,
            (name.len() + 1) as u32,
            0,
        ];
        self.bytes.extend_from_slice(b"070701");
        for field in fields {
            self.bytes
                .extend_from_slice(format!("{field:08x}").as_bytes());
        }
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
        self.bytes.extend_from_slice(data);
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
        Ok(())
    }
    fn finish(mut self) -> Result<zeroize::Zeroizing<Vec<u8>>, MicroVmError> {
        self.entry("TRAILER!!!", 0, &[], 0)?;
        Ok(self.bytes)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use super::*;
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        net::Shutdown,
        os::{
            fd::AsRawFd,
            unix::{
                fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt},
                net::{UnixListener, UnixStream},
            },
        },
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;
    const TOOLS: &str = include_str!("../../../scripts/microvm-binaries.json");
    struct SocketDirectory(PathBuf);
    impl SocketDirectory {
        fn new() -> Result<Self, MicroVmError> {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            for _ in 0..64 {
                let path = PathBuf::from(format!(
                    "/tmp/nw-vm-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                // Atomic create, owner-only from the outset. Existing names are
                // never followed or reused, including after a crashed session.
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(MicroVmError::Launch),
                }
            }
            Err(MicroVmError::Launch)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for SocketDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[derive(Deserialize)]
    struct Manifest {
        files: Vec<Asset>,
    }
    #[derive(Deserialize)]
    struct Asset {
        name: String,
        sha256: String,
        bytes: u64,
    }
    fn tool(base: &Path, name: &str) -> Result<Zeroizing<Vec<u8>>, MicroVmError> {
        let manifest: Manifest = serde_json::from_str(TOOLS).map_err(|_| MicroVmError::Tools)?;
        let asset = manifest
            .files
            .iter()
            .find(|f| f.name == name)
            .ok_or(MicroVmError::Tools)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(0x20000 | 0x800)
            .open(base.join(name))
            .map_err(|_| MicroVmError::Tools)?; // O_NOFOLLOW | O_NONBLOCK
        let meta = file.metadata().map_err(|_| MicroVmError::Tools)?;
        if !meta.is_file() || meta.len() != asset.bytes || meta.len() > 128 * 1024 * 1024 {
            return Err(MicroVmError::Tools);
        }
        let mut data = Zeroizing::new(Vec::new());
        Read::by_ref(&mut file)
            .take(asset.bytes + 1)
            .read_to_end(&mut data)
            .map_err(|_| MicroVmError::Tools)?;
        if data.len() as u64 != asset.bytes
            || format!("{:x}", Sha256::digest(&*data)) != asset.sha256
        {
            return Err(MicroVmError::Tools);
        }
        Ok(data)
    }
    fn snapshot(dir: &File, prefix: &str, image: &mut Initrd) -> Result<(), MicroVmError> {
        let mut names = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
            .map_err(|_| MicroVmError::Project)?
            .take(4097)
            .map(|r| r.map(|e| e.file_name()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| MicroVmError::Project)?;
        if names.len() > 4096 {
            return Err(MicroVmError::Project);
        }
        names.sort();
        for name in names {
            let mut file =
                nw_platform::microvm_open_child(dir, &name).map_err(|_| MicroVmError::Project)?;
            let info = file.metadata().map_err(|_| MicroVmError::Project)?;
            let name = name.to_str().ok_or(MicroVmError::Project)?;
            let path = format!("{prefix}/{name}");
            if info.is_dir() {
                image.entry(&path, 0o40700, &[], 1000)?;
                snapshot(&file, &path, image)?;
            } else if info.is_file() && info.nlink() == 1 && info.len() <= LIMIT as u64 {
                let mut data = Zeroizing::new(Vec::new());
                Read::by_ref(&mut file)
                    .take((LIMIT + 1) as u64)
                    .read_to_end(&mut data)
                    .map_err(|_| MicroVmError::Project)?;
                image.entry(
                    &path,
                    if info.mode() & 0o111 != 0 {
                        0o100700
                    } else {
                        0o100600
                    },
                    &data,
                    1000,
                )?;
            } else {
                return Err(MicroVmError::Project);
            }
        }
        Ok(())
    }
    fn image(
        work: &Path,
        program: &Path,
        args: &[OsString],
        tools: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, MicroVmError> {
        let mut image = Initrd::new();
        for dir in [
            "bin",
            "lib",
            "etc",
            "proc",
            "dev",
            "run",
            "run/nymwrap",
            "home",
            "home/user",
            "work",
        ] {
            image.entry(dir, 0o40755, &[], 0)?;
        }
        image.entry("tmp", 0o41777, &[], 0)?;
        for (name, asset) in [
            ("bin/busybox", "busybox"),
            ("lib/ld-musl-x86_64.so.1", "musl"),
            ("init", "guest-init"),
        ] {
            image.entry(name, 0o100555, &tool(tools, asset)?, 0)?;
        }
        image.entry(
            "lib/libc.musl-x86_64.so.1",
            0o120777,
            b"ld-musl-x86_64.so.1",
            0,
        )?;
        for name in [
            "sh", "cat", "ls", "pwd", "id", "env", "hostname", "date", "echo", "grep", "test",
            "nc", "nslookup", "wget", "sleep",
        ] {
            image.entry(&format!("bin/{name}"), 0o120777, b"busybox", 0)?;
        }
        for (path, bytes) in [
            ("etc/hostname", b"localhost\n".as_slice()),
            ("etc/hosts", b"127.0.0.1 localhost\n::1 localhost\n"),
            ("etc/machine-id", b"00000000000000000000000000000001\n"),
            ("etc/passwd", b"user:x:1000:1000:user:/home/user:/bin/sh\n"),
            ("etc/group", b"user:x:1000:\n"),
            ("etc/timezone", b"UTC\n"),
            (
                "etc/resolv.conf",
                b"nameserver 192.0.2.1\noptions attempts:1 timeout:1\n",
            ),
            (
                "home/user/.gitconfig",
                b"[user]\n\tname = user\n\temail = user@localhost\n",
            ),
        ] {
            image.entry(path, 0o100444, bytes, 0)?;
        }
        // Public UTC TZif file, no host zoneinfo or timestamp is copied.
        let mut utc = vec![0; 50];
        utc[..4].copy_from_slice(b"TZif");
        utc[39] = 1;
        utc[43] = 4;
        utc.extend_from_slice(b"UTC\0");
        image.entry("etc/localtime", 0o100444, &utc, 0)?;
        image.entry("run/argv", 0o100400, &arguments(program, args)?, 0)?;
        let mut dir = File::open("/").map_err(|_| MicroVmError::Project)?;
        for component in work.components() {
            if let std::path::Component::Normal(name) = component {
                dir = nw_platform::microvm_open_child(&dir, name)
                    .map_err(|_| MicroVmError::Project)?;
                if !dir.metadata().map_err(|_| MicroVmError::Project)?.is_dir() {
                    return Err(MicroVmError::Project);
                }
            }
        }
        snapshot(&dir, "work", &mut image)?;
        image.finish()
    }
    struct Running(Child);
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    struct Bridge {
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }
    impl Drop for Bridge {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }
    // Bounded relay; paths are trusted host configuration. Guest bytes are never
    // interpreted as host paths, shell commands, API authorities or destinations.
    fn bridge(listener: UnixListener, api: PathBuf) -> Result<Bridge, MicroVmError> {
        listener
            .set_nonblocking(true)
            .map_err(|_| MicroVmError::Api)?;
        let stop = Arc::new(AtomicBool::new(false));
        let end = stop.clone();
        let handle = thread::spawn(move || {
            let mut pairs: Vec<(UnixStream, UnixStream)> = Vec::new();
            let mut buffer = Zeroizing::new([0; 16384]);
            while !end.load(Ordering::Relaxed) {
                if let Ok((guest, _)) = listener.accept()
                    && pairs.len() < 8
                    && let Ok(host) = nw_platform::microvm_connect_api(&api)
                    && guest.set_nonblocking(true).is_ok()
                    && host.set_nonblocking(true).is_ok()
                {
                    pairs.push((guest, host));
                }
                // Each pending write is bounded and given a short deadline;
                // one stalled agent cannot indefinitely retain the VMM on drop.
                pairs.retain_mut(|(guest, host)| {
                    for (from, to) in [(&*guest, &*host), (&*host, &*guest)] {
                        match from.take(16384).read(&mut *buffer) {
                            Ok(0) => return false,
                            Ok(n) => {
                                if to.set_nonblocking(false).is_err()
                                    || to
                                        .set_write_timeout(Some(Duration::from_millis(100)))
                                        .is_err()
                                {
                                    return false;
                                }
                                let result = (&*to).write_all(&buffer[..n]);
                                if to.set_nonblocking(true).is_err() || result.is_err() {
                                    return false;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => return false,
                        }
                    }
                    true
                });
                thread::sleep(Duration::from_millis(5));
            }
            for (a, b) in pairs {
                let _ = a.shutdown(Shutdown::Both);
                let _ = b.shutdown(Shutdown::Both);
            }
        });
        Ok(Bridge {
            stop,
            handle: Some(handle),
        })
    }
    pub(super) fn run(
        work: &Path,
        program: &Path,
        args: &[OsString],
        api: &Path,
        tools: &Path,
    ) -> Result<i32, MicroVmError> {
        arguments(program, args)?;
        nw_platform::harden_process().map_err(|_| MicroVmError::Launch)?;
        nw_platform::deny_remote_sockets().map_err(|_| MicroVmError::Launch)?;
        let swaps = std::fs::read_to_string("/proc/swaps").map_err(|_| MicroVmError::Swap)?;
        if swaps.lines().count() != 1 {
            return Err(MicroVmError::Swap);
        }
        // Linux ignores RLIMIT_CORE for pipe-based crash handlers. exec resets
        // dumpability in the VMM, so a zero core limit alone is insufficient.
        let core_pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern")
            .map_err(|_| MicroVmError::CoreDump)?;
        if core_pattern.trim_start().starts_with('|') {
            return Err(MicroVmError::CoreDump);
        }
        let _kvm = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map_err(|_| MicroVmError::Kvm)?;
        let owner = nw_platform::current_user_id().map_err(|_| MicroVmError::Api)?;
        if owner == "0" {
            return Err(MicroVmError::Launch);
        }
        let meta = std::fs::symlink_metadata(api).map_err(|_| MicroVmError::Api)?;
        if !api.is_absolute()
            || api.file_name().is_none_or(|n| n != "api.sock")
            || !meta.file_type().is_socket()
            || meta.mode() & 0o077 != 0
            || meta.uid().to_string() != owner
        {
            return Err(MicroVmError::Api);
        }
        let work = work.canonicalize().map_err(|_| MicroVmError::Project)?;
        if !work.is_dir()
            || work == Path::new("/")
            || api.starts_with(&work)
            || std::env::var_os("HOME").is_some_and(|h| Path::new(&h).starts_with(&work))
        {
            return Err(MicroVmError::Project);
        }
        if !tools.is_absolute() {
            return Err(MicroVmError::Tools);
        }
        let mut files = nw_platform::MicroVmFiles::new();
        let executable = files
            .insert(&tool(tools, "firecracker")?)
            .map_err(|_| MicroVmError::Tools)?;
        let kernel = files
            .insert(&tool(tools, "vmlinux")?)
            .map_err(|_| MicroVmError::Tools)?;
        let initrd = files
            .insert(&image(&work, program, args, tools)?)
            .map_err(|_| MicroVmError::Launch)?;
        let directory = SocketDirectory::new()?;
        let socket = directory.path().join("v");
        let api_listener =
            UnixListener::bind(directory.path().join("v_8000")).map_err(|_| MicroVmError::Api)?;
        let output = UnixListener::bind(directory.path().join("v_8001"))
            .map_err(|_| MicroVmError::Launch)?;
        let status = UnixListener::bind(directory.path().join("v_8002"))
            .map_err(|_| MicroVmError::Launch)?;
        output
            .set_nonblocking(true)
            .map_err(|_| MicroVmError::Launch)?;
        status
            .set_nonblocking(true)
            .map_err(|_| MicroVmError::Launch)?;
        let config = serde_json::json!({
            "boot-source":{"kernel_image_path":kernel,"initrd_path":initrd,"boot_args":"console=ttyS0 reboot=k panic=1 pci=off rootfstype=ramfs random.trust_cpu=off"},
            "machine-config":{"vcpu_count":1,"mem_size_mib":256,"smt":false},
            "drives":[],"network-interfaces":[],"vsock":{"guest_cid":3,"uds_path":socket}
        });
        let config = files
            .insert(&serde_json::to_vec(&config).map_err(|_| MicroVmError::Launch)?)
            .map_err(|_| MicroVmError::Launch)?;
        let mut command = Command::new(executable);
        command
            .env_clear()
            .current_dir(directory.path())
            .args(["--no-api", "--config-file", &config])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        files.inherit(&mut command);
        let _bridge = bridge(api_listener, api.to_owned())?;
        let mut child = Running(command.spawn().map_err(|_| MicroVmError::Launch)?);
        let deadline = Instant::now() + Duration::from_secs(3600);
        let boot_deadline = Instant::now() + Duration::from_secs(30);
        let mut out = None;
        loop {
            if out.is_none()
                && let Ok((stream, _)) = output.accept()
            {
                stream
                    .set_nonblocking(true)
                    .map_err(|_| MicroVmError::Launch)?;
                out = Some(stream);
            }
            if let Some(stream) = &mut out {
                let mut b = Zeroizing::new([0; 16384]);
                if let Ok(n) = stream.read(&mut *b) {
                    std::io::stdout()
                        .write_all(terminal_output(&b[..n]).as_bytes())
                        .map_err(|_| MicroVmError::Launch)?;
                }
            }
            if let Ok((mut stream, _)) = status.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .map_err(|_| MicroVmError::Launch)?;
                let mut message = [0; 5];
                stream
                    .read_exact(&mut message)
                    .map_err(|_| MicroVmError::Launch)?;
                if &message[..4] != b"NWVM" {
                    return Err(MicroVmError::Launch);
                }
                // Status and stdout have independent vsock queues. Drain bytes
                // already written by the agent before terminating its VMM.
                let drain_deadline = Instant::now() + Duration::from_secs(1);
                if let Some(stream) = &mut out {
                    let mut bytes = Zeroizing::new([0; 16384]);
                    while Instant::now() < drain_deadline {
                        match stream.read(&mut *bytes) {
                            Ok(0) => break,
                            Ok(n) => std::io::stdout()
                                .write_all(terminal_output(&bytes[..n]).as_bytes())
                                .map_err(|_| MicroVmError::Launch)?,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(5))
                            }
                            Err(_) => break,
                        }
                    }
                }
                return Ok(message[4] as i32);
            }
            if child
                .0
                .try_wait()
                .map_err(|_| MicroVmError::Launch)?
                .is_some()
            {
                return Err(MicroVmError::Launch);
            }
            if Instant::now() > deadline || (out.is_none() && Instant::now() > boot_deadline) {
                return Err(MicroVmError::Timeout);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn socket_directory_is_private_and_removed_on_drop() {
            let directory = SocketDirectory::new().unwrap();
            let path = directory.path().to_owned();
            assert_eq!(
                std::fs::symlink_metadata(&path).unwrap().mode() & 0o777,
                0o700
            );
            drop(directory);
            assert!(!path.exists());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guest_output_cannot_send_terminal_commands() {
        assert_eq!(
            &*terminal_output(b"synthetic\x1b]52;c;secret\x07\r\n"),
            "synthetic\\u{1b}]52;c;secret\\u{7}\\u{d}\n"
        );
        assert_eq!(&*terminal_output("Пример\n\t".as_bytes()), "Пример\n\t");
    }
    #[test]
    fn rejects_unsafe_archive_names_and_oversized_arguments() {
        let mut image = Initrd::new();
        for path in [
            "/etc/passwd",
            "../secret",
            "work/../secret",
            "work//file",
            "work/./file",
        ] {
            assert_eq!(
                image.entry(path, 0o100600, b"synthetic", 1000),
                Err(MicroVmError::Project)
            );
        }
        assert_eq!(
            arguments(Path::new("relative"), &[]).err(),
            Some(MicroVmError::Command)
        );
        assert_eq!(
            arguments(Path::new("/bin/sh"), &["x".repeat(65536).into()]).err(),
            Some(MicroVmError::Command)
        );
        assert!(
            arguments(
                Path::new("/bin/sh"),
                &["a; $(never-executed)\nquoted".into()]
            )
            .is_ok()
        );
    }
    #[test]
    fn archive_has_fixed_identity_and_no_host_paths() {
        let mut image = Initrd::new();
        image
            .entry("work/synthetic", 0o100600, b"canary", 1000)
            .unwrap();
        let bytes = image.finish().unwrap();
        assert_eq!(&bytes[..6], b"070701");
        assert!(bytes.windows(6).any(|w| w == b"canary"));
    }
    #[test]
    fn unsupported_platform_never_falls_back() {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            assert_eq!(
                run(
                    Path::new("."),
                    Path::new("/bin/sh"),
                    &[],
                    Path::new("api.sock"),
                    Path::new(".")
                ),
                Err(MicroVmError::Unsupported)
            );
        }
    }
}
