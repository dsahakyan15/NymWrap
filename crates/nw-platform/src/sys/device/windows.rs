use super::{offset_variants, unavailable};
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::{IpHelper::*, NetManagement::*, WiFi::*},
    Networking::WinSock::*,
    System::{Registry::*, SystemInformation::*, Time::*, WindowsProgramming::GetUserNameW},
};
use zeroize::{Zeroize, Zeroizing};
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn string(units: &[u16]) -> String {
    String::from_utf16_lossy(&units[..units.iter().position(|c| *c == 0).unwrap_or(units.len())])
}
fn registry_string(root: HKEY, path: &str, name: &str) -> io::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(vec![0u16; 4096]);
    let mut length = (bytes.len() * 2) as u32;
    if unsafe {
        RegGetValueW(
            root,
            wide(path).as_ptr(),
            wide(name).as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            ptr::null_mut(),
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    } != ERROR_SUCCESS
    {
        return Err(unavailable());
    }
    Ok(Zeroizing::new(string(&bytes)))
}
pub fn device_browser_policy() -> io::Result<std::fs::File> {
    let default = registry_string(
        HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice",
        "ProgId",
    )?;
    if !default.starts_with("FirefoxURL") {
        return Err(unavailable());
    }
    // Registry enterprise policies can override distribution/policies.json.
    // Only a proven absence allows that file to certify the browser settings.
    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let mut key = ptr::null_mut();
        match unsafe {
            RegOpenKeyExW(
                root,
                wide(r"SOFTWARE\Policies\Mozilla\Firefox").as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut key,
            )
        } {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => {}
            ERROR_SUCCESS => {
                unsafe { RegCloseKey(key) };
                return Err(unavailable());
            }
            _ => return Err(unavailable()),
        }
    }
    let program_files = registry_string(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        "ProgramFilesDir",
    )?;
    let root = std::path::Path::new(program_files.as_str()).join("Mozilla Firefox");
    // A second/custom Firefox installation must not inherit the verdict from
    // this installation's policies. Resolve only the literal default command;
    // never execute it or expand environment variables from the registry.
    let command = registry_string(
        HKEY_CLASSES_ROOT,
        &format!(r"{}\shell\open\command", default.as_str()),
        "",
    )?;
    let executable = command
        .strip_prefix('"')
        .and_then(|rest| rest.split_once('"'))
        .map(|(path, _)| std::path::Path::new(path))
        .ok_or_else(unavailable)?;
    if executable.canonicalize()? != root.join("firefox.exe").canonicalize()? {
        return Err(unavailable());
    }
    let x86 = registry_string(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        "ProgramFilesDir (x86)",
    )
    .ok();
    if x86.as_ref().is_some_and(|base| {
        std::path::Path::new(base.as_str())
            .join("Mozilla Firefox/firefox.exe")
            .exists()
    }) {
        return Err(unavailable());
    }
    super::open_device_config(&root.join("distribution/policies.json"))
}
pub fn device_policy_hints() -> crate::HygienePolicyHints {
    fn dword(path: &str, name: &str) -> Option<u32> {
        let mut value = 0u32;
        let mut size = 4u32;
        if unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                wide(path).as_ptr(),
                wide(name).as_ptr(),
                RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
                ptr::null_mut(),
                (&mut value as *mut u32).cast(),
                &mut size,
            )
        } == ERROR_SUCCESS
            && size == 4
        {
            Some(value)
        } else {
            None
        }
    }
    crate::HygienePolicyHints {
        // A missing force-off policy does not tell us the user's effective consent.
        location_disabled: dword(
            r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors",
            "DisableLocation",
        )
        .and_then(|v| (v == 1).then_some(true)),
        llmnr_disabled: dword(
            r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "EnableMulticast",
        )
        .and_then(|v| match v {
            0 => Some(true),
            1 => Some(false),
            _ => None,
        }),
        netbios_disabled: netbios_policy(),
        // Neither absence of Bonjour nor an undocumented Dnscache switch
        // proves that every mDNS responder is disabled. Keep this unknown.
        mdns_disabled: None,
        // No trustworthy phase-error measurement is exposed by a configuration
        // flag. Do not turn enabled Windows Time service into a clock pass.
        clock_within_bounds: None,
    }
}
fn netbios_policy() -> Option<bool> {
    let mut key = ptr::null_mut();
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces").as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    } != ERROR_SUCCESS
    {
        return None;
    }
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }
    let key = Key(key);
    let mut values = vec![];
    for index in 0..1024 {
        let mut name = [0u16; 256];
        let mut length = name.len() as u32;
        let result = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut length,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if result == ERROR_NO_MORE_ITEMS {
            return crate::all_observed_true(&values);
        }
        if result != ERROR_SUCCESS {
            return None;
        }
        let name = string(&name);
        let mut option = 0u32;
        let mut size = 4;
        let result = unsafe {
            RegGetValueW(
                key.0,
                wide(&name).as_ptr(),
                wide("NetbiosOptions").as_ptr(),
                RRF_RT_REG_DWORD,
                ptr::null_mut(),
                (&mut option as *mut u32).cast(),
                &mut size,
            )
        };
        values.push(if result == ERROR_SUCCESS && size == 4 {
            match option {
                2 => Some(true),
                1 => Some(false),
                _ => None,
            }
        } else {
            None
        });
    }
    None
}
unsafe fn os_string(pointer: *const u16, limit: usize) -> io::Result<String> {
    if pointer.is_null() {
        return Err(unavailable());
    }
    let mut len = 0;
    // SAFETY: only Windows-owned, documented NUL-terminated output strings enter
    // here. They remain owned by the caller's guard until this copy finishes.
    while len < limit && unsafe { *pointer.add(len) } != 0 {
        len += 1;
    }
    if len == limit {
        return Err(unavailable());
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(pointer, len)
    }))
}
pub fn device_host_names() -> io::Result<Vec<String>> {
    let mut values = Zeroizing::new(vec![]);
    for kind in [
        ComputerNamePhysicalNetBIOS,
        ComputerNamePhysicalDnsHostname,
        ComputerNamePhysicalDnsDomain,
    ] {
        let mut data = Zeroizing::new(vec![0u16; 256]);
        let mut size = data.len() as u32;
        if unsafe { GetComputerNameExW(kind, data.as_mut_ptr(), &mut size) } == 0 {
            return Err(unavailable());
        }
        let value = string(&data);
        if !value.is_empty() {
            values.push(value);
        }
    }
    Ok(std::mem::take(&mut *values))
}
pub fn device_user_names() -> io::Result<Vec<String>> {
    let mut name = Zeroizing::new(vec![0u16; 257]);
    let mut size = name.len() as u32;
    if unsafe { GetUserNameW(name.as_mut_ptr(), &mut size) } == 0 {
        return Err(unavailable());
    }
    let mut raw = ptr::null_mut();
    let mut values = Zeroizing::new(vec![string(&name)]);
    if unsafe { NetUserGetInfo(ptr::null(), name.as_ptr(), 10, &mut raw) } != 0 {
        // A domain lookup is not an offline fallback. Retain an explicit
        // unknown result when the local account database cannot supply a name.
        return Err(unavailable());
    }
    struct Buffer(*mut u8);
    impl Drop for Buffer {
        fn drop(&mut self) {
            unsafe {
                NetApiBufferFree(self.0.cast());
            }
        }
    }
    let _buffer = Buffer(raw);
    if raw.is_null() {
        return Err(unavailable());
    }
    let user = unsafe { &*raw.cast::<USER_INFO_10>() };
    let full = unsafe { os_string(user.usri10_full_name, 1024) }?;
    if !full.is_empty() {
        values.push(full);
    }
    Ok(std::mem::take(&mut *values))
}
pub fn device_home_paths() -> io::Result<Vec<String>> {
    use windows_sys::Win32::{
        Security::TOKEN_QUERY,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::Shell::GetUserProfileDirectoryW,
    };
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(unavailable());
    }
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let token = Token(token);
    let mut bytes = Zeroizing::new(vec![0u16; 4096]);
    let mut length = bytes.len() as u32;
    if unsafe { GetUserProfileDirectoryW(token.0, bytes.as_mut_ptr(), &mut length) } == 0 {
        return Err(unavailable());
    }
    Ok(vec![string(&bytes)])
}
pub fn device_machine_ids() -> io::Result<Vec<String>> {
    let mut value = Zeroizing::new(vec![0u16; 128]);
    let mut bytes = (value.len() * 2) as u32;
    if unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide("SOFTWARE\\Microsoft\\Cryptography").as_ptr(),
            wide("MachineGuid").as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    } != ERROR_SUCCESS
    {
        return Err(unavailable());
    }
    Ok(vec![string(&value)])
}
pub fn device_timezones() -> io::Result<Vec<String>> {
    let mut zone: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let kind = unsafe { GetDynamicTimeZoneInformation(&mut zone) };
    if kind == TIME_ZONE_ID_INVALID {
        return Err(unavailable());
    }
    // GetDynamicTimeZoneInformation: 0=unknown, 1=standard, 2=daylight.
    let bias = zone.Bias
        + if kind == 2 {
            zone.DaylightBias
        } else {
            zone.StandardBias
        };
    let mut result = vec![
        string(&zone.TimeZoneKeyName),
        string(&zone.StandardName),
        string(&zone.DaylightName),
    ];
    result.retain(|s| !s.is_empty());
    result.extend(offset_variants(-i64::from(bias)));
    zone.TimeZoneKeyName.zeroize();
    zone.StandardName.zeroize();
    zone.DaylightName.zeroize();
    Ok(result)
}
fn adapters() -> io::Result<(Vec<String>, Vec<String>)> {
    let mut size = 15360u32;
    for _ in 0..3 {
        if size as usize > 1024 * 1024 {
            return Err(unavailable());
        }
        let mut memory = Zeroizing::new(vec![
            0usize;
            (size as usize).div_ceil(std::mem::size_of::<usize>())
        ]);
        let first = memory.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                ptr::null(),
                first,
                &mut size,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(unavailable());
        }
        let valid = |pointer: usize, len: usize, alignment: usize| {
            pointer >= first as usize
                && pointer.checked_add(len).is_some_and(|end| {
                    end <= first as usize + memory.len() * std::mem::size_of::<usize>()
                })
                && pointer.is_multiple_of(alignment)
        };
        let mut mac = Zeroizing::new(vec![]);
        let mut ips = Zeroizing::new(vec![]);
        let mut next = first;
        let mut count = 0;
        while !next.is_null() {
            count += 1;
            if count > 1024
                || !valid(
                    next as usize,
                    std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>(),
                    std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
                )
            {
                return Err(unavailable());
            }
            let item = unsafe { &*next };
            if item.PhysicalAddressLength == 6 && item.PhysicalAddress[..6].iter().any(|b| *b != 0)
            {
                mac.push(
                    item.PhysicalAddress[..6]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                );
            }
            let mut addr = item.FirstUnicastAddress;
            let mut addr_count = 0;
            while !addr.is_null() {
                addr_count += 1;
                if addr_count > 1024
                    || !valid(
                        addr as usize,
                        std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>(),
                        std::mem::align_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>(),
                    )
                {
                    return Err(unavailable());
                }
                let unicast = unsafe { &*addr };
                let socket = unicast.Address.lpSockaddr;
                if !socket.is_null()
                    && valid(
                        socket as usize,
                        std::mem::size_of::<SOCKADDR>(),
                        std::mem::align_of::<SOCKADDR>(),
                    )
                {
                    let family = unsafe { (*socket).sa_family };
                    let ip = if family == AF_INET
                        && valid(
                            socket as usize,
                            std::mem::size_of::<SOCKADDR_IN>(),
                            std::mem::align_of::<SOCKADDR_IN>(),
                        ) {
                        let address = unsafe { &*socket.cast::<SOCKADDR_IN>() };
                        Some(std::net::IpAddr::from(
                            unsafe { address.sin_addr.S_un.S_addr }.to_ne_bytes(),
                        ))
                    } else if family == AF_INET6
                        && valid(
                            socket as usize,
                            std::mem::size_of::<SOCKADDR_IN6>(),
                            std::mem::align_of::<SOCKADDR_IN6>(),
                        )
                    {
                        let address = unsafe { &*socket.cast::<SOCKADDR_IN6>() };
                        Some(std::net::IpAddr::from(unsafe { address.sin6_addr.u.Byte }))
                    } else {
                        None
                    };
                    if let Some(ip) = ip
                        && !ip.is_loopback()
                        && !ip.is_unspecified()
                    {
                        ips.push(ip.to_string());
                    }
                }
                addr = unicast.Next;
            }
            next = item.Next;
        }
        return Ok((std::mem::take(&mut *mac), std::mem::take(&mut *ips)));
    }
    Err(unavailable())
}
pub fn device_mac_addresses() -> io::Result<Vec<String>> {
    let (mac, ips) = adapters()?;
    let _ips = Zeroizing::new(ips);
    Ok(mac)
}
pub fn device_ip_addresses() -> io::Result<Vec<String>> {
    let (mac, ips) = adapters()?;
    let _mac = Zeroizing::new(mac);
    Ok(ips)
}
struct Wifi(windows_sys::Win32::Foundation::HANDLE);
impl Drop for Wifi {
    fn drop(&mut self) {
        unsafe {
            WlanCloseHandle(self.0, ptr::null());
        }
    }
}
struct WifiBuffer<T>(*mut T);
impl<T> Drop for WifiBuffer<T> {
    fn drop(&mut self) {
        unsafe {
            WlanFreeMemory(self.0.cast());
        }
    }
}
pub fn device_wifi_inventory() -> io::Result<(Vec<String>, Option<bool>)> {
    let mut handle = ptr::null_mut();
    let mut version = 0;
    if unsafe { WlanOpenHandle(2, ptr::null(), &mut version, &mut handle) } != ERROR_SUCCESS {
        return Err(unavailable());
    }
    let wifi = Wifi(handle);
    let mut interfaces = ptr::null_mut();
    if unsafe { WlanEnumInterfaces(wifi.0, ptr::null(), &mut interfaces) } != ERROR_SUCCESS {
        return Err(unavailable());
    }
    let interfaces = WifiBuffer(interfaces);
    if interfaces.0.is_null() {
        return Err(unavailable());
    }
    let count = unsafe { (*interfaces.0).dwNumberOfItems } as usize;
    if count > 256 {
        return Err(unavailable());
    }
    let mut values = Zeroizing::new(vec![]);
    let mut randomized = vec![];
    // SAFETY: the API allocates dwNumberOfItems variable-length interface entries;
    // both lists and XML remain Windows-owned until their guards free them.
    for i in 0..count {
        let interface = unsafe { &*(*interfaces.0).InterfaceInfo.as_ptr().add(i) };
        let mut profiles = ptr::null_mut();
        if unsafe {
            WlanGetProfileList(wifi.0, &interface.InterfaceGuid, ptr::null(), &mut profiles)
        } != ERROR_SUCCESS
        {
            return Err(unavailable());
        }
        let profiles = WifiBuffer(profiles);
        if profiles.0.is_null() {
            return Err(unavailable());
        }
        let count = unsafe { (*profiles.0).dwNumberOfItems } as usize;
        if count > 256 {
            return Err(unavailable());
        }
        for j in 0..count {
            let profile = unsafe { &*(*profiles.0).ProfileInfo.as_ptr().add(j) };
            let mut xml = ptr::null_mut();
            let (mut flags, mut access) = (0, 0);
            // flags=0 never requests WLAN_PROFILE_GET_PLAINTEXT_KEY.
            if unsafe {
                WlanGetProfile(
                    wifi.0,
                    &interface.InterfaceGuid,
                    profile.strProfileName.as_ptr(),
                    ptr::null(),
                    &mut xml,
                    &mut flags,
                    &mut access,
                )
            } != ERROR_SUCCESS
            {
                return Err(unavailable());
            }
            let xml = WifiBuffer(xml);
            let text = Zeroizing::new(unsafe { os_string(xml.0, 65536) }?);
            let result = crate::wlan::parse(&text);
            // The copy may contain encrypted key material. Wipe both copies.
            let units = text.encode_utf16().count();
            unsafe { std::slice::from_raw_parts_mut(xml.0, units) }.zeroize();
            let mut profile = result?;
            randomized.push(profile.randomized);
            values.push(std::mem::take(&mut profile.ssid));
            if values.len() > 256 {
                return Err(unavailable());
            }
        }
    }
    Ok((
        std::mem::take(&mut *values),
        crate::all_observed_true(&randomized),
    ))
}
