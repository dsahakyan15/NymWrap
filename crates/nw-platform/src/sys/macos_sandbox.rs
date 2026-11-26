//! Direct policy checks avoid granting the sysctl utility's OID enumeration.
use std::{io, mem, ptr};

/// Call after confinement, before accepting worker input. No identifiers escape
/// even if an accidentally permissive policy lets the negative query succeed.
pub fn verify_runtime_sysctl_policy() -> io::Result<()> {
    let mut cpu = 0u32;
    let mut length = mem::size_of_val(&cpu);
    // SAFETY: the OS receives live, correctly sized writable allocations and a
    // constant NUL-terminated name. A null newp/zero newlen makes both calls read-only.
    let result = unsafe {
        libc::sysctlbyname(
            c"hw.ncpu".as_ptr(),
            (&mut cpu as *mut u32).cast(),
            &mut length,
            ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if cpu == 0 || length != mem::size_of_val(&cpu) {
        return Err(io::Error::other("runtime_sysctl_cpu_unavailable"));
    }
    let mut host = zeroize::Zeroizing::new([0u8; 1024]);
    let mut length = host.len();
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.hostname".as_ptr(),
            host.as_mut_ptr().cast(),
            &mut length,
            ptr::null_mut(),
            0,
        )
    };
    if result == -1 && io::Error::last_os_error().kind() == io::ErrorKind::PermissionDenied {
        Ok(())
    } else {
        Err(io::Error::other("runtime_sysctl_identifier_not_denied"))
    }
}
