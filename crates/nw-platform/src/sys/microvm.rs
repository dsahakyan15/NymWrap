//! Small Linux fd/lifetime boundary, separate from the bwrap launcher.
use std::{
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::Command,
};
/// Pin directory entries by descriptor; concurrent symlink/rename changes cannot
/// turn a project snapshot into reads from a host directory outside the project.
pub fn microvm_open_child(parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::other("invalid_project_entry"));
    }
    let name = std::ffi::CString::new(bytes)?;
    // SAFETY: live directory fd and NUL-terminated component. O_NONBLOCK avoids
    // blocking on an untrusted FIFO; the caller accepts only regular files/dirs.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// AF_UNIX connect is nonblocking from socket creation, including a full server
/// backlog. A stalled local API cannot prevent the VMM owner from stopping it.
pub fn microvm_connect_api(path: &std::path::Path) -> io::Result<std::os::unix::net::UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    let name = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is an all-zero-valid C structure.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if !path.is_absolute() || name.len() >= address.sun_path.len() || name.contains(&0) {
        return Err(io::Error::other("invalid_private_socket"));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (to, from) in address.sun_path.iter_mut().zip(name) {
        *to = *from as libc::c_char;
    }
    // SAFETY: scalar socket arguments; exactly one owner takes a successful fd.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    // SAFETY: a live descriptor and initialized sockaddr with an in-bounds NUL.
    if unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(stream)
}

/// Anonymous immutable files; never stage guest contents or arguments on disk.
pub struct MicroVmFiles(Vec<File>);
impl Default for MicroVmFiles {
    fn default() -> Self {
        Self::new()
    }
}
impl MicroVmFiles {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn insert(&mut self, bytes: &[u8]) -> io::Result<String> {
        use std::io::{Seek, Write};
        // SAFETY: constant name; a successful fd is transferred to exactly one owner.
        let fd = unsafe {
            libc::memfd_create(
                c"nw-shadow-microvm".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        file.rewind()?;
        // SAFETY: owned descriptor, scalar flags, no borrowed pointers.
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
        self.0.push(file);
        Ok(format!("/proc/self/fd/{fd}"))
    }
    pub fn inherit(self, command: &mut Command) {
        let parent = std::process::id() as libc::pid_t;
        // SAFETY: only async-signal-safe syscalls after fork; captures keep fds
        // alive until Command drop. Parent descriptors stay CLOEXEC.
        unsafe {
            command.pre_exec(move || {
                if libc::getppid() != parent
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() != parent
                {
                    return Err(io::Error::other("microvm_parent_unavailable"));
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                for file in &self.0 {
                    if libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::fs::symlink};
    #[test]
    fn project_directory_descriptor_rejects_symlink_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"synthetic-host-canary").unwrap();
        symlink(outside.path(), root.path().join("escape")).unwrap();
        let dir = File::open(root.path()).unwrap();
        assert!(microvm_open_child(&dir, std::ffi::OsStr::new("escape")).is_err());
        assert!(microvm_open_child(&dir, std::ffi::OsStr::new("../secret")).is_err());
    }
    #[test]
    fn inherited_guest_file_cannot_be_modified() {
        let mut files = MicroVmFiles::new();
        let path = files.insert(b"synthetic-private-snapshot").unwrap();
        let mut writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(writer.write_all(b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic-private-snapshot");
        let mut command = Command::new("/bin/cat");
        command.arg(path);
        files.inherit(&mut command);
        let output = command.output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"synthetic-private-snapshot");
    }
    #[test]
    fn api_connect_remains_nonblocking() {
        use std::io::Read;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("api.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut stream = microvm_connect_api(&path).unwrap();
        assert_eq!(
            stream.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
