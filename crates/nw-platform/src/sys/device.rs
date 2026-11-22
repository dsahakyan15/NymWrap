//! Read-only OS identity APIs; callers must first install their offline policy.
use std::io;
#[cfg(unix)]
use zeroize::Zeroizing;
fn unavailable() -> io::Error {
    io::Error::other("device_source_unavailable")
}
pub fn open_device_config(path: &std::path::Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(unavailable());
        }
    }
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(unavailable());
    }
    Ok(file)
}
#[cfg(unix)]
fn bounded_file(
    path: impl AsRef<std::path::Path>,
    maximum: usize,
) -> io::Result<Zeroizing<String>> {
    use std::io::Read;
    let mut value = Zeroizing::new(String::new());
    std::fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_string(&mut value)?;
    if value.len() > maximum {
        return Err(unavailable());
    }
    Ok(value)
}
#[cfg(unix)]
pub fn device_user_names() -> io::Result<Vec<String>> {
    use std::ffi::CStr;
    let mut buffer = Zeroizing::new(vec![0u8; 65536]);
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: libc writes only into live passwd/buffer; returned fields point
    // into that buffer and are copied before the buffer is zeroized and dropped.
    if unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    } != 0
        || found.is_null()
    {
        return Err(unavailable());
    }
    let mut names = vec![];
    for pointer in [entry.pw_name, entry.pw_gecos] {
        if !pointer.is_null() {
            let value = unsafe { CStr::from_ptr(pointer) }.to_string_lossy();
            let name = value.split(',').next().unwrap_or("").trim();
            if !name.is_empty() {
                names.push(name.to_owned());
            }
        }
    }
    Ok(names)
}
#[cfg(unix)]
pub fn device_host_names() -> io::Result<Vec<String>> {
    let mut buffer = Zeroizing::new(vec![0u8; 256]);
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return Err(unavailable());
    }
    let end = buffer
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(unavailable)?;
    Ok(vec![
        std::str::from_utf8(&buffer[..end])
            .map_err(|_| unavailable())?
            .into(),
    ])
}
#[cfg(target_os = "linux")]
pub fn device_machine_ids() -> io::Result<Vec<String>> {
    Ok(vec![
        bounded_file("/etc/machine-id", 1024)?.trim().to_owned(),
    ])
}
#[cfg(target_os = "macos")]
pub fn device_machine_ids() -> io::Result<Vec<String>> {
    Err(unavailable())
}
#[cfg(unix)]
pub fn device_timezones() -> io::Result<Vec<String>> {
    let mut names = vec![];
    if let Ok(zone) = bounded_file("/etc/timezone", 1024) {
        names.push(zone.trim().to_owned());
    }
    if let Ok(path) = std::fs::read_link("/etc/localtime")
        && let Some((_, zone)) = path.to_string_lossy().split_once("zoneinfo/")
    {
        names.push(zone.into());
    }
    let at = unsafe { libc::time(std::ptr::null_mut()) };
    let mut local: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&at, &mut local) }.is_null() {
        return Err(unavailable());
    }
    names.extend(offset_variants(local.tm_gmtoff / 60));
    Ok(names)
}
fn offset_variants(minutes: i64) -> Vec<String> {
    let sign = if minutes < 0 { '-' } else { '+' };
    let minutes = minutes.unsigned_abs();
    let (h, m) = (minutes / 60, minutes % 60);
    vec![
        format!("{sign}{h:02}:{m:02}"),
        format!("{sign}{h:02}{m:02}"),
        format!(
            "UTC{sign}{h}{}",
            if m == 0 {
                String::new()
            } else {
                format!(":{m:02}")
            }
        ),
        format!(
            "GMT{sign}{h}{}",
            if m == 0 {
                String::new()
            } else {
                format!(":{m:02}")
            }
        ),
    ]
}
#[cfg(target_os = "linux")]
pub fn device_mac_addresses() -> io::Result<Vec<String>> {
    let mut result = Zeroizing::new(vec![]);
    for (i, entry) in std::fs::read_dir("/sys/class/net")?.enumerate() {
        if i >= 1024 {
            return Err(unavailable());
        }
        let text = bounded_file(entry?.path().join("address"), 128)?;
        let bytes = text.trim();
        if bytes.split(':').count() == 6
            && bytes
                .chars()
                .any(|ch| matches!(ch,'1'..='9'|'a'..='f'|'A'..='F'))
        {
            result.push(bytes.into());
        }
    }
    Ok(std::mem::take(&mut *result))
}
#[cfg(target_os = "macos")]
pub fn device_mac_addresses() -> io::Result<Vec<String>> {
    Err(unavailable())
}
#[cfg(unix)]
pub fn device_ip_addresses() -> io::Result<Vec<String>> {
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut first = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(unavailable());
    }
    let _guard = Addresses(first);
    let mut values = Zeroizing::new(vec![]);
    let mut next = first;
    let mut count = 0;
    while !next.is_null() {
        count += 1;
        if count > 4096 {
            return Err(unavailable());
        }
        // SAFETY: the list and sockaddr allocations are owned by getifaddrs
        // until the guard runs; family determines the sockaddr layout.
        let item = unsafe { &*next };
        if !item.ifa_addr.is_null() {
            let address = unsafe { &*item.ifa_addr };
            let ip = match i32::from(address.sa_family) {
                libc::AF_INET => {
                    let addr = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in>() };
                    Some(std::net::IpAddr::from(addr.sin_addr.s_addr.to_ne_bytes()))
                }
                libc::AF_INET6 => {
                    let addr = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in6>() };
                    Some(std::net::IpAddr::from(addr.sin6_addr.s6_addr))
                }
                _ => None,
            };
            if let Some(ip) = ip
                && !ip.is_loopback()
                && !ip.is_unspecified()
            {
                values.push(ip.to_string());
            }
        }
        next = item.ifa_next;
    }
    values.sort();
    values.dedup();
    Ok(std::mem::take(&mut *values))
}
#[cfg(target_os = "linux")]
pub fn device_wifi_inventory() -> io::Result<(Vec<String>, Option<bool>)> {
    let mut values = Zeroizing::new(vec![]);
    let mut randomized = vec![];
    for (i, item) in std::fs::read_dir("/etc/NetworkManager/system-connections")?.enumerate() {
        if i >= 1024 {
            return Err(unavailable());
        }
        let item = item?;
        if !item.file_type()?.is_file() {
            return Err(unavailable());
        }
        let config = bounded_file(item.path(), 65536)?;
        let mut wifi = false;
        let mut profile_ssid = None;
        let mut profile_random = None;
        for line in config.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                wifi = matches!(line, "[wifi]" | "[802-11-wireless]");
            } else if wifi && let Some((key, value)) = line.split_once('=') {
                match key.trim() {
                    "ssid" => {
                        if profile_ssid.replace(value.to_owned()).is_some() {
                            return Err(unavailable());
                        }
                    }
                    "cloned-mac-address" => {
                        profile_random = match value.trim() {
                            "random" => Some(true),
                            "permanent" => Some(false),
                            _ => None,
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(ssid) = profile_ssid {
            values.push(ssid);
            randomized.push(profile_random);
        }
    }
    Ok((
        std::mem::take(&mut *values),
        crate::all_observed_true(&randomized),
    ))
}
#[cfg(target_os = "macos")]
pub fn device_wifi_inventory() -> io::Result<(Vec<String>, Option<bool>)> {
    Err(unavailable())
}
pub fn device_wifi_ssids() -> io::Result<Vec<String>> {
    device_wifi_inventory().map(|(ssids, _)| ssids)
}
#[cfg(not(windows))]
pub fn device_policy_hints() -> crate::HygienePolicyHints {
    crate::HygienePolicyHints::default()
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
