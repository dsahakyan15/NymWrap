//! Trusted one-shot inventory worker. A missing/denied Seatbelt API is fatal.
use std::{
    io, mem,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    path::Path,
    process::Command,
    ptr,
    sync::Arc,
};
#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init_with_parameters(
        profile: *const libc::c_char,
        flags: u64,
        parameters: *const *const libc::c_char,
        error: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sandbox_free_error(error: *mut libc::c_char);
}
fn socket_address(
    family: libc::c_int,
    loopback: bool,
) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    if family == libc::AF_INET {
        let address = unsafe {
            &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
        };
        address.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
        address.sin_family = libc::AF_INET as libc::sa_family_t;
        address.sin_port = if loopback { 9u16.to_be() } else { 0 };
        address.sin_addr.s_addr = if loopback {
            u32::from_ne_bytes([127, 0, 0, 1])
        } else {
            0
        };
        return (
            storage,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
    }
    let address =
        unsafe { &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
    address.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
    address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    address.sin6_port = if loopback { 9u16.to_be() } else { 0 };
    if loopback {
        address.sin6_addr.s6_addr[15] = 1;
    }
    (
        storage,
        mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
    )
}
fn denied_network_call(result: libc::c_int) -> bool {
    result == -1 && io::Error::last_os_error().kind() == io::ErrorKind::PermissionDenied
}
fn verify_network_denied(family: libc::c_int, kind: libc::c_int) -> bool {
    let fd = unsafe { libc::socket(family, kind, 0) };
    if fd < 0 {
        return io::Error::last_os_error().kind() == io::ErrorKind::PermissionDenied;
    }
    let (bind_address, bind_length) = socket_address(family, false);
    let bind_denied = denied_network_call(unsafe {
        libc::bind(
            fd,
            (&bind_address as *const libc::sockaddr_storage).cast(),
            bind_length,
        )
    });
    if !bind_denied {
        unsafe { libc::close(fd) };
        return false;
    }
    let (peer_address, peer_length) = socket_address(family, true);
    let connect_denied = denied_network_call(unsafe {
        libc::connect(
            fd,
            (&peer_address as *const libc::sockaddr_storage).cast(),
            peer_length,
        )
    });
    unsafe { libc::close(fd) };
    connect_denied
}
pub fn confine_device_probe(git: Option<&std::fs::File>) -> io::Result<()> {
    let profile = c"(version 1)(deny default)(allow file-read-metadata)(allow sysctl-read)(allow iokit-get-properties)(allow mach-lookup (global-name \"com.apple.SystemConfiguration.configd\")(global-name \"com.apple.coreservices.launchservicesd\")(global-name \"com.apple.system.DirectoryService.libinfo_v1\"))(allow file-read-data (subpath \"/System\")(subpath \"/usr\")(subpath \"/private/etc\")(subpath \"/Library/Preferences/SystemConfiguration\")(subpath \"/dev\")(literal (param \"GLOBAL_GIT\"))(literal \"/Applications/Firefox.app/Contents/Resources/distribution/policies.json\"))";
    let mut error = ptr::null_mut();
    let mut path = zeroize::Zeroizing::new([0u8; 1024]);
    if let Some(git) = git {
        if unsafe { libc::fcntl(git.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } == -1 {
            return Err(io::Error::other("probe_git_unavailable"));
        }
    } else {
        path[..10].copy_from_slice(b"/dev/null\0");
    }
    let parameters = [c"GLOBAL_GIT".as_ptr(), path.as_ptr().cast(), ptr::null()];
    let result = unsafe {
        sandbox_init_with_parameters(profile.as_ptr(), 0, parameters.as_ptr(), &mut error)
    };
    if !error.is_null() {
        unsafe { sandbox_free_error(error) };
    }
    if result != 0 {
        return Err(io::Error::other("probe_sandbox_unavailable"));
    }
    // Darwin may allow creating an empty socket descriptor and enforce Seatbelt
    // only when it is bound or connected. Verify both actual operations before
    // accepting any request or identifiers; only a policy denial is evidence.
    for family in [libc::AF_INET, libc::AF_INET6] {
        for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
            if !verify_network_denied(family, kind) {
                return Err(io::Error::other("probe_network_policy_failed"));
            }
        }
    }
    Ok(())
}
pub fn macos_probe_command(program: &Path, git: Option<&std::fs::File>) -> io::Result<Command> {
    let mut command = Command::new(program.canonicalize()?);
    command
        .arg("--stdio")
        .env_clear()
        .env("TZ", "UTC")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8");
    if let Some(git) = git {
        let copy = Arc::new(git.try_clone()?);
        let fd = copy.as_raw_fd();
        command.arg("--git-fd").arg(fd.to_string());
        // Only fcntl is executed between fork and exec. Keep the owned file alive
        // in Command until spawn; all unrelated descriptors remain close-on-exec.
        unsafe {
            command.pre_exec(move || {
                let _keep = &copy;
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    Ok(command)
}
pub fn inherited_probe_file(fd: i32) -> io::Result<std::fs::File> {
    if fd < 3 || unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(io::Error::other("invalid_probe_file"));
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(io::Error::other("invalid_probe_file"));
    }
    Ok(file)
}
