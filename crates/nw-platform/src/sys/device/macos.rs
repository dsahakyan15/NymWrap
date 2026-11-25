//! Read-only CoreFoundation/SystemConfiguration/IOKit. No location or scan API.
use super::{offset_variants, unavailable};
use std::{
    ffi::{c_char, c_void},
    io, ptr,
};
use zeroize::Zeroizing;
type Cf = *const c_void;
const UTF8: u32 = 0x08000100;
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: Cf);
    fn CFGetTypeID(value: Cf) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFStringGetLength(value: Cf) -> isize;
    fn CFStringCreateWithCString(allocator: Cf, text: *const c_char, encoding: u32) -> Cf;
    fn CFStringGetCString(value: Cf, output: *mut c_char, capacity: isize, encoding: u32) -> u8;
    fn CFTimeZoneCopySystem() -> Cf;
    fn CFTimeZoneGetName(zone: Cf) -> Cf;
    fn CFTimeZoneGetSecondsFromGMT(zone: Cf, at: f64) -> f64;
    fn CFAbsoluteTimeGetCurrent() -> f64;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFDictionaryGetCount(value: Cf) -> isize;
    fn CFDictionaryGetValue(value: Cf, key: Cf) -> Cf;
    fn CFDictionaryGetKeysAndValues(value: Cf, keys: *mut Cf, values: *mut Cf);
    fn CFURLCreateWithString(allocator: Cf, text: Cf, base: Cf) -> Cf;
    fn CFURLCopyFileSystemPath(url: Cf, style: isize) -> Cf;
}
#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCDynamicStoreCopyComputerName(store: Cf, encoding: *mut u32) -> Cf;
    fn SCPreferencesCreate(allocator: Cf, name: Cf, identifier: Cf) -> Cf;
    fn SCPreferencesGetValue(preferences: Cf, key: Cf) -> Cf;
}
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceMatching(name: *const c_char) -> Cf;
    fn IOServiceGetMatchingService(port: u32, matching: Cf) -> u32;
    fn IORegistryEntryCreateCFProperty(entry: u32, key: Cf, allocator: Cf, options: u32) -> Cf;
    fn IOObjectRelease(entry: u32) -> i32;
}
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn LSCopyDefaultHandlerForURLScheme(scheme: Cf) -> Cf;
    fn LSCopyDefaultApplicationURLForURL(url: Cf, roles: u32, error: *mut Cf) -> Cf;
}
pub fn device_browser_policy() -> io::Result<std::fs::File> {
    let https = Owned::string(c"https")?;
    let browser = Owned::new(unsafe { LSCopyDefaultHandlerForURLScheme(https.0) })?;
    if text(browser.0)? != "org.mozilla.firefox" {
        return Err(unavailable());
    }
    // Resolves a binding only; this never opens the URL or starts a browser.
    let scheme = Owned::string(c"https://example.test")?;
    let url = Owned::new(unsafe { CFURLCreateWithString(ptr::null(), scheme.0, ptr::null()) })?;
    let application =
        Owned::new(unsafe { LSCopyDefaultApplicationURLForURL(url.0, u32::MAX, ptr::null_mut()) })?;
    let path = Owned::new(unsafe { CFURLCopyFileSystemPath(application.0, 0) })?;
    if text(path.0)? != "/Applications/Firefox.app" {
        return Err(unavailable());
    }
    super::open_device_config(std::path::Path::new(
        "/Applications/Firefox.app/Contents/Resources/distribution/policies.json",
    ))
}
struct Owned(Cf);
impl Owned {
    fn new(value: Cf) -> io::Result<Self> {
        if value.is_null() {
            Err(unavailable())
        } else {
            Ok(Self(value))
        }
    }
    fn string(value: &std::ffi::CStr) -> io::Result<Self> {
        Self::new(unsafe { CFStringCreateWithCString(ptr::null(), value.as_ptr(), UTF8) })
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}
fn text(value: Cf) -> io::Result<String> {
    if value.is_null() || unsafe { CFGetTypeID(value) != CFStringGetTypeID() } {
        return Err(unavailable());
    }
    let mut bytes = Zeroizing::new(vec![0u8; 4097]);
    if unsafe { CFStringGetCString(value, bytes.as_mut_ptr().cast(), bytes.len() as isize, UTF8) }
        == 0
    {
        return Err(unavailable());
    }
    let end = bytes.iter().position(|b| *b == 0).ok_or_else(unavailable)?;
    let value_text = std::str::from_utf8(&bytes[..end]).map_err(|_| unavailable())?;
    if value_text.encode_utf16().count() as isize != unsafe { CFStringGetLength(value) } {
        return Err(unavailable());
    }
    Ok(value_text.to_owned())
}
pub fn device_host_names() -> io::Result<Vec<String>> {
    let mut bytes = Zeroizing::new([0u8; 256]);
    if unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(unavailable());
    }
    let end = bytes.iter().position(|b| *b == 0).ok_or_else(unavailable)?;
    let host = std::str::from_utf8(&bytes[..end])
        .map_err(|_| unavailable())?
        .to_owned();
    let computer =
        Owned::new(unsafe { SCDynamicStoreCopyComputerName(ptr::null(), ptr::null_mut()) })?;
    Ok(vec![host, text(computer.0)?])
}
pub fn device_machine_ids() -> io::Result<Vec<String>> {
    // IOServiceGetMatchingService consumes the matching dictionary on all paths.
    let matching = unsafe { IOServiceMatching(c"IOPlatformExpertDevice".as_ptr()) };
    if matching.is_null() {
        return Err(unavailable());
    }
    let service = unsafe { IOServiceGetMatchingService(0, matching) };
    if service == 0 {
        return Err(unavailable());
    }
    struct Service(u32);
    impl Drop for Service {
        fn drop(&mut self) {
            unsafe { IOObjectRelease(self.0) };
        }
    }
    let service = Service(service);
    let key = Owned::string(c"IOPlatformUUID")?;
    let value =
        Owned::new(unsafe { IORegistryEntryCreateCFProperty(service.0, key.0, ptr::null(), 0) })?;
    Ok(vec![text(value.0)?])
}
pub fn device_timezones() -> io::Result<Vec<String>> {
    // System zone, independent of the worker's normalized TZ=UTC environment.
    let zone = Owned::new(unsafe { CFTimeZoneCopySystem() })?;
    let mut result = vec![text(unsafe { CFTimeZoneGetName(zone.0) })?];
    let seconds = unsafe { CFTimeZoneGetSecondsFromGMT(zone.0, CFAbsoluteTimeGetCurrent()) };
    if !seconds.is_finite() || seconds.abs() > 86400.0 {
        return Err(unavailable());
    }
    result.extend(offset_variants(seconds as i64 / 60));
    Ok(result)
}
pub fn device_mac_addresses() -> io::Result<Vec<String>> {
    let mut first = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(unavailable());
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _addresses = Addresses(first);
    let mut values = Zeroizing::new(vec![]);
    let mut next = first;
    for _ in 0..4096 {
        if next.is_null() {
            values.sort();
            values.dedup();
            return Ok(std::mem::take(&mut *values));
        }
        let item = unsafe { &*next };
        if !item.ifa_addr.is_null() && unsafe { (*item.ifa_addr).sa_family as i32 } == libc::AF_LINK
        {
            let address = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_dl>() };
            let start = usize::from(address.sdl_nlen);
            let length = usize::from(address.sdl_alen);
            if length != 0 {
                let offset = std::mem::offset_of!(libc::sockaddr_dl, sdl_data);
                if length != 6 || offset + start + length > usize::from(address.sdl_len) {
                    return Err(unavailable());
                }
                let data = unsafe {
                    std::slice::from_raw_parts(
                        item.ifa_addr.cast::<u8>().add(offset + start),
                        length,
                    )
                };
                let bytes = data;
                if bytes.iter().any(|byte| *byte != 0) {
                    values.push(
                        bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<Vec<_>>()
                            .join(":"),
                    );
                }
            }
        }
        next = item.ifa_next;
    }
    Err(unavailable())
}
pub fn device_wifi_inventory() -> io::Result<(Vec<String>, Option<bool>)> {
    // Read saved configuration only. Modern macOS may deny/redact it; that is
    // unknown, never a successful empty list. Do not request location permission.
    let name = Owned::string(c"NymWrap read-only device probe")?;
    let path = Owned::string(
        c"/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
    )?;
    let preferences = Owned::new(unsafe { SCPreferencesCreate(ptr::null(), name.0, path.0) })?;
    let key = Owned::string(c"KnownNetworks")?;
    let networks = unsafe { SCPreferencesGetValue(preferences.0, key.0) };
    if networks.is_null() || unsafe { CFGetTypeID(networks) != CFDictionaryGetTypeID() } {
        return Err(unavailable());
    }
    let count = unsafe { CFDictionaryGetCount(networks) };
    if !(1..=1024).contains(&count) {
        return Err(unavailable());
    }
    let mut entries = vec![ptr::null(); count as usize];
    unsafe { CFDictionaryGetKeysAndValues(networks, ptr::null_mut(), entries.as_mut_ptr()) };
    let ssid = Owned::string(c"SSID_STR")?;
    let mut names = Zeroizing::new(vec![]);
    for entry in entries {
        if entry.is_null() || unsafe { CFGetTypeID(entry) != CFDictionaryGetTypeID() } {
            return Err(unavailable());
        }
        names.push(text(unsafe { CFDictionaryGetValue(entry, ssid.0) })?);
    }
    Ok((std::mem::take(&mut *names), None))
}
