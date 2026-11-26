//! Linux leaf setup: inherited, sealed BPF and an owned pidfd for bwrap's payload.
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::process::CommandExt,
};

pub struct SandboxIdentity {
    pid: u32,
    descriptor: OwnedFd,
}
impl SandboxIdentity {
    pub fn pin(pid: u32, parent: u32) -> io::Result<Self> {
        if pid < 2 || pid > i32::MAX as u32 {
            return Err(super::failed());
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = Self {
            pid,
            descriptor: unsafe { OwnedFd::from_raw_fd(fd as i32) },
        };
        // Pin first, then verify ancestry while the pidfd is still live. A PID
        // from bwrap's status stream alone must not authorize a reused PID.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let actual_parent = stat
            .rsplit_once(')')
            .and_then(|(_, tail)| tail.split_whitespace().nth(1))
            .and_then(|p| p.parse::<u32>().ok());
        if parent == 0 || actual_parent != Some(parent) {
            return Err(super::failed());
        }
        if !result.alive()? {
            return Err(super::failed());
        }
        Ok(result)
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn alive(&self) -> io::Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: self.descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result == 0)
    }
}
pub fn sandbox_status_stream(
    command: &mut std::process::Command,
) -> io::Result<std::os::unix::net::UnixStream> {
    let (read, write) = std::os::unix::net::UnixStream::pair()?;
    read.set_nonblocking(true)?;
    command.args(["--json-status-fd", &write.as_raw_fd().to_string()]);
    // Only the selected command inherits this descriptor, never another spawn.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(write.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(read)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn filter(seal_exec: bool) -> Vec<libc::sock_filter> {
    let stmt = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let eq = |k, jt, jf| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    #[cfg(target_arch = "x86_64")]
    let arch = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    let arch = 0xc00000b7;
    let deny = 0x00050000 | libc::EPERM as u32;
    let allow = 0x7fff0000;
    let mut rules = vec![
        stmt(0x20, 4),
        eq(arch, 1, 0),
        stmt(0x06, 0x80000000),
        stmt(0x20, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    rules.extend([
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        },
        stmt(0x06, 0x80000000),
    ]);
    for number in [libc::SYS_socket, libc::SYS_socketpair] {
        rules.extend([
            eq(number as u32, 0, 4),
            stmt(0x20, 16),
            eq(libc::AF_UNIX as u32, 1, 0),
            stmt(0x06, deny),
            stmt(0x06, allow),
        ]);
    }
    // Listeners use bind(2), not writable regular files. Even their writable
    // socket directory must not become a plaintext prompt/model-output store.
    let write_flags = (libc::O_ACCMODE | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u32;
    #[cfg(target_arch = "x86_64")]
    let open_calls = [(libc::SYS_openat, 32), (libc::SYS_open, 24)];
    #[cfg(target_arch = "aarch64")]
    let open_calls = [(libc::SYS_openat, 32)];
    for (number, offset) in open_calls {
        rules.extend([
            eq(number as u32, 0, 4),
            stmt(0x20, offset),
            libc::sock_filter {
                code: 0x45,
                jt: 0,
                jf: 1,
                k: write_flags,
            },
            stmt(0x06, deny),
            stmt(0x20, 0),
        ]);
    }
    rules.extend([
        eq(libc::SYS_openat2 as u32, 0, 1),
        stmt(0x06, 0x00050000 | libc::ENOSYS as u32),
    ]);
    #[cfg(target_arch = "x86_64")]
    rules.extend([eq(libc::SYS_creat as u32, 0, 1), stmt(0x06, deny)]);
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
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_execveat,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
    ] {
        rules.extend([eq(number as u32, 0, 1), stmt(0x06, deny)]);
    }
    #[cfg(target_arch = "x86_64")]
    for number in [libc::SYS_fork, libc::SYS_vfork] {
        rules.extend([eq(number as u32, 0, 1), stmt(0x06, deny)]);
    }
    // libc falls back to clone for threads; process clone and namespace clone fail.
    rules.extend([
        eq(libc::SYS_clone3 as u32, 0, 1),
        stmt(0x06, 0x00050000 | libc::ENOSYS as u32),
    ]);
    rules.extend([
        eq(libc::SYS_clone as u32, 0, 7),
        stmt(0x20, 16),
        libc::sock_filter {
            code: 0x45,
            jt: 1,
            jf: 0,
            k: libc::CLONE_THREAD as u32,
        },
        stmt(0x06, deny),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: (libc::CLONE_NEWUSER
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWCGROUP) as u32,
        },
        stmt(0x06, deny),
        stmt(0x06, allow),
        stmt(0x20, 0),
    ]);
    if seal_exec {
        rules.extend([eq(libc::SYS_execve as u32, 0, 1), stmt(0x06, deny)]);
        // pthread signalling remains limited to this process.
        rules.extend([
            eq(libc::SYS_tgkill as u32, 0, 4),
            stmt(0x20, 16),
            eq(unsafe { libc::getpid() } as u32, 1, 0),
            stmt(0x06, deny),
            stmt(0x06, allow),
        ]);
    }
    rules.push(stmt(0x06, allow));
    rules
}
pub fn sandbox_leaf_filter(command: &mut std::process::Command) -> io::Result<()> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = command;
        Err(super::failed())
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        use std::{
            fs::File,
            io::{Seek, Write},
        };
        let fd = unsafe {
            libc::memfd_create(
                c"nw-leaf-seccomp".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        for rule in filter(false) {
            file.write_all(&rule.code.to_ne_bytes())?;
            file.write_all(&[rule.jt, rule.jf])?;
            file.write_all(&rule.k.to_ne_bytes())?;
        }
        file.rewind()?;
        if unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        command.args(["--seccomp", &fd.to_string()]);
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}
pub fn confine_leaf_daemon() -> io::Result<()> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(super::failed())
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let mut rules = filter(true);
        let program = libc::sock_fprog {
            len: rules.len() as u16,
            filter: rules.as_mut_ptr(),
        };
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
            || unsafe { libc::syscall(libc::SYS_seccomp, 1, 1, &program) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    #[test]
    fn leaf_filter_covers_existing_threads_and_denies_exec_namespace_and_pidfd() {
        const CHILD: &str = "NYMWRAP_LEAF_FILTER_TEST";
        if std::env::var_os(CHILD).is_none() {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","sys::linux_leaf::tests::leaf_filter_covers_existing_threads_and_denies_exec_namespace_and_pidfd"])
                .env(CHILD,"1").status().unwrap().success());
            return;
        }
        std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let denied = || {
            assert_eq!(
                std::net::TcpListener::bind("127.0.0.1:0")
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(
                std::net::UdpSocket::bind("[::1]:0")
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            std::os::unix::net::UnixStream::pair().unwrap();
            assert_eq!(
                std::process::Command::new("/bin/true")
                    .spawn()
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWUSER) }, -1);
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) },
                -1
            );
            let argv = [c"/bin/true".as_ptr(), std::ptr::null()];
            assert_eq!(
                unsafe {
                    libc::execve(
                        c"/bin/true".as_ptr(),
                        argv.as_ptr(),
                        [std::ptr::null()].as_ptr(),
                    )
                },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        };
        let (send, receive) = std::sync::mpsc::channel();
        let existing = std::thread::spawn(move || {
            receive.recv().unwrap();
            denied();
        });
        super::confine_leaf_daemon().unwrap();
        send.send(()).unwrap();
        existing.join().unwrap();
        std::thread::spawn(denied).join().unwrap();
        denied();
    }
}
