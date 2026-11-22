//! Read-only device inventory. Values travel only over bounded shadow stdio IPC.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::Read};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_FRAME: usize = 128 * 1024;
pub mod hygiene;
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    User,
    Host,
    Home,
    Mac,
    Wifi,
    Ip,
    Machine,
    Timezone,
    Git,
}
impl Source {
    pub const ALL: [Self; 9] = [
        Self::User,
        Self::Host,
        Self::Home,
        Self::Mac,
        Self::Wifi,
        Self::Ip,
        Self::Machine,
        Self::Timezone,
        Self::Git,
    ];
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DeviceValue {
    #[zeroize(skip)]
    pub source: Source,
    pub value: String,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub version: u16,
    #[zeroize(skip)]
    pub lane: nw_proto::Lane,
    pub values: Vec<DeviceValue>,
    /// Unavailable/partial sources are never presented as successful checks.
    #[zeroize(skip)]
    pub unavailable: Vec<Source>,
    #[serde(default)]
    #[zeroize(skip)]
    pub hygiene: hygiene::Report,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Hints {
    pub version: u16,
    #[zeroize(skip)]
    pub lane: nw_proto::Lane,
    pub user: Vec<String>,
    pub host: Vec<String>,
    pub home: Option<String>,
}
impl Default for Hints {
    fn default() -> Self {
        Self {
            version: 1,
            lane: nw_proto::Lane::Shadow,
            user: vec![],
            host: vec![],
            home: None,
        }
    }
}
impl Hints {
    /// The broker supplies only values hidden by the worker's environment clearing.
    pub fn from_environment() -> Self {
        let read = |names: &[&str]| {
            names
                .iter()
                .filter_map(|name| std::env::var(name).ok())
                .collect()
        };
        Self {
            version: 1,
            lane: nw_proto::Lane::Shadow,
            user: read(&["USERNAME", "USER", "LOGNAME"]),
            host: read(&["COMPUTERNAME", "USERDOMAIN", "HOSTNAME"]),
            home: std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).ok(),
        }
    }
    pub fn valid(&self) -> bool {
        self.version == 1
            && self.lane == nw_proto::Lane::Shadow
            && self.user.len() <= 3
            && self.host.len() <= 3
            && self
                .user
                .iter()
                .chain(&self.host)
                .chain(self.home.iter())
                .all(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
    }
}
impl Report {
    pub fn valid(&self) -> bool {
        let mut seen = BTreeSet::new();
        self.version == 1
            && self.lane == nw_proto::Lane::Shadow
            && self.values.len() <= 256
            && self.values.iter().all(|v| {
                (3..=1024).contains(&v.value.chars().count())
                    && v.value.len() <= 1024
                    && !v.value.contains("⟨NW_")
                    && !v.value.chars().any(char::is_control)
                    && seen.insert((v.source, &v.value))
            })
            && self.unavailable.len() <= Source::ALL.len()
            && self.unavailable.iter().collect::<BTreeSet<_>>().len() == self.unavailable.len()
            && self.hygiene.valid()
    }
}
pub fn home_variants(home: &str) -> Vec<String> {
    let mut values = BTreeSet::from([home.to_owned()]);
    if home.as_bytes().get(1) == Some(&b':') && home.as_bytes()[0].is_ascii_alphabetic() {
        let slash = home.replace('\\', "/");
        values.insert(slash.clone());
        values.insert(home.replace('\\', "\\\\"));
        let drive = (home.as_bytes()[0] as char).to_ascii_lowercase();
        values.insert(format!("/{drive}{}", &slash[2..]));
        values.insert(format!("/mnt/{drive}{}", &slash[2..]));
    }
    values.into_iter().collect()
}
fn push(values: &mut Vec<DeviceValue>, source: Source, text: String) {
    let mut text = Zeroizing::new(text);
    if (3..=1024).contains(&text.chars().count())
        && text.len() <= 1024
        && !text.chars().any(char::is_control)
        && !text.contains("⟨NW_")
        && !values
            .iter()
            .any(|item| item.source == source && item.value == *text)
    {
        values.push(DeviceValue {
            source,
            value: std::mem::take(&mut *text),
        });
    }
}
/// Parse literal user identity only. Includes, aliases and hooks are never followed.
pub fn git_identity(mut file: impl Read) -> Result<Vec<String>, &'static str> {
    let mut bytes = Zeroizing::new(vec![]);
    file.by_ref()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "probe_git_unavailable")?;
    if bytes.len() > 65536 {
        return Err("probe_git_too_large");
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "probe_git_invalid")?;
    let mut user = false;
    let mut result = Zeroizing::new(vec![]);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with(['#', ';']) || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err("probe_git_invalid");
            }
            let section = &line[1..line.len() - 1];
            if section.to_ascii_lowercase().starts_with("include") {
                return Err("probe_git_include_unavailable");
            }
            user = section.eq_ignore_ascii_case("user");
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            if user {
                return Err("probe_git_invalid");
            }
            continue;
        };
        if user && matches!(key.trim().to_ascii_lowercase().as_str(), "name" | "email") {
            let mut output = Zeroizing::new(String::new());
            let (mut quoted, mut escaped) = (false, false);
            for ch in value.trim().chars() {
                if escaped {
                    match ch {
                        '\\' | '"' => output.push(ch),
                        'n' => output.push('\n'),
                        't' => output.push('\t'),
                        'b' => output.push('\u{8}'),
                        _ => return Err("probe_git_invalid"),
                    };
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    quoted = !quoted;
                } else if !quoted && matches!(ch, '#' | ';') {
                    break;
                } else {
                    output.push(ch);
                }
            }
            if quoted || escaped {
                return Err("probe_git_invalid");
            }
            let value = output.trim();
            if !value.is_empty() {
                result.push(value.to_owned());
            }
        }
    }
    Ok(std::mem::take(&mut *result))
}

pub fn collect(hints: &Hints, git: Option<impl Read>) -> Result<Report, &'static str> {
    if !hints.valid() {
        return Err("invalid_probe_request");
    }
    let mut values = Vec::new();
    let mut unavailable = BTreeSet::new();
    for text in &hints.user {
        push(&mut values, Source::User, text.clone());
    }
    for text in &hints.host {
        push(&mut values, Source::Host, text.clone());
    }
    if let Some(home) = &hints.home {
        for text in home_variants(home) {
            push(&mut values, Source::Home, text);
        }
    }
    for (source, result) in [
        (Source::User, nw_platform::device_user_names()),
        (Source::Host, nw_platform::device_host_names()),
        (Source::Machine, nw_platform::device_machine_ids()),
        (Source::Timezone, nw_platform::device_timezones()),
        (Source::Mac, nw_platform::device_mac_addresses()),
        (Source::Ip, nw_platform::device_ip_addresses()),
    ] {
        match result {
            Ok(items) => {
                for text in items {
                    push(&mut values, source, text);
                }
            }
            Err(_) => {
                unavailable.insert(source);
            }
        }
    }
    let wifi = match nw_platform::device_wifi_inventory() {
        Ok((ssids, randomized)) => {
            for ssid in ssids {
                push(&mut values, Source::Wifi, ssid);
            }
            randomized
        }
        Err(_) => {
            unavailable.insert(Source::Wifi);
            None
        }
    };
    match git.map(git_identity).transpose() {
        Ok(Some(items)) => {
            for text in items {
                push(&mut values, Source::Git, text);
            }
        }
        _ => {
            unavailable.insert(Source::Git);
        }
    }
    // Empty, successfully queried sources (no Wi-Fi profiles, no git identity)
    // differ from access failures; the latter remain explicit in unavailable.
    for source in [
        Source::User,
        Source::Host,
        Source::Home,
        Source::Machine,
        Source::Timezone,
    ] {
        if !values.iter().any(|v| v.source == source) {
            unavailable.insert(source);
        }
    }
    values.sort_by(|a, b| (a.source, &a.value).cmp(&(b.source, &b.value)));
    let hygiene = hygiene::collect(
        &values,
        &unavailable,
        wifi,
        nw_platform::device_policy_hints(),
    );
    let report = Report {
        version: 1,
        lane: nw_proto::Lane::Shadow,
        values,
        unavailable: unavailable.into_iter().collect(),
        hygiene,
    };
    if !report.valid() {
        return Err("probe_capacity_exceeded");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_forms_and_git_literals_are_data_and_includes_are_never_executed() {
        let paths = home_variants(r"C:\Users\synthetic-device");
        for path in [
            r"C:\Users\synthetic-device",
            r"C:\\Users\\synthetic-device",
            "C:/Users/synthetic-device",
            "/c/Users/synthetic-device",
            "/mnt/c/Users/synthetic-device",
        ] {
            assert!(paths.iter().any(|s| s == path));
        }
        let parsed=git_identity(b"[user]\nname = \"Synthetic User\" # comment\nemail = user@example.test\n[alias]\nrun = !echo NEVER_EXECUTE\n".as_slice()).unwrap();
        assert_eq!(parsed, vec!["Synthetic User", "user@example.test"]);
        assert!(git_identity(b"[include]\npath = /private/NEVER_READ\n".as_slice()).is_err());
        assert!(git_identity(&b"x".repeat(65537)[..]).is_err());
    }
}
