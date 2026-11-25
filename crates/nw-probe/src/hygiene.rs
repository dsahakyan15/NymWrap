//! Observations are three-state. A manual instruction never confirms a measurement.
use crate::{DeviceValue, Source};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    WifiMac,
    Hostname,
    Multicast,
    Location,
    Clock,
    Browser,
}
impl CheckKind {
    pub const ALL: [Self; 6] = [
        Self::WifiMac,
        Self::Hostname,
        Self::Multicast,
        Self::Location,
        Self::Clock,
        Self::Browser,
    ];
}
#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    #[default]
    Unknown,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub kind: CheckKind,
    pub verdict: Verdict,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub checks: [Observation; 6],
    pub llmnr_disabled: Option<bool>,
    pub netbios_disabled: Option<bool>,
    pub mdns_disabled: Option<bool>,
}
impl Default for Report {
    fn default() -> Self {
        Self {
            checks: CheckKind::ALL.map(|kind| Observation {
                kind,
                verdict: Verdict::Unknown,
            }),
            llmnr_disabled: None,
            netbios_disabled: None,
            mdns_disabled: None,
        }
    }
}
impl Report {
    pub fn valid(&self) -> bool {
        self.checks
            .iter()
            .zip(CheckKind::ALL)
            .all(|(entry, kind)| entry.kind == kind)
            && (self.checks[2].verdict != Verdict::Pass
                || [
                    self.llmnr_disabled,
                    self.netbios_disabled,
                    self.mdns_disabled,
                ] == [Some(true); 3])
    }
    pub fn known(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.verdict != Verdict::Unknown)
            .count()
    }
    pub fn passed(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.verdict == Verdict::Pass)
            .count()
    }
    pub fn score(&self) -> Option<f64> {
        (self.known() != 0).then(|| self.passed() as f64 / 6.0)
    }
    pub(crate) fn set(&mut self, kind: CheckKind, verdict: Verdict) {
        if let Some(check) = self.checks.iter_mut().find(|c| c.kind == kind) {
            check.verdict = verdict;
        }
    }
}
fn observed(value: Option<bool>) -> Verdict {
    match value {
        Some(true) => Verdict::Pass,
        Some(false) => Verdict::Fail,
        None => Verdict::Unknown,
    }
}
/// A managed Firefox policy is evidence only when both preferences are locked.
/// Never execute preferences.js/user.js, follow includes, or infer all browsers.
pub fn browser_policy(mut file: impl std::io::Read) -> Verdict {
    use std::io::Read;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    if file.by_ref().take(65537).read_to_end(&mut bytes).is_err() || bytes.len() > 65536 {
        return Verdict::Unknown;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Verdict::Unknown;
    };
    let Some(preferences) = value.get("policies").and_then(|v| v.get("Preferences")) else {
        return Verdict::Unknown;
    };
    let mut result = Verdict::Pass;
    for name in ["geo.enabled", "media.peerconnection.enabled"] {
        let entry = &preferences[name];
        if entry.get("Value").and_then(|v| v.as_bool()) == Some(true) {
            return Verdict::Fail;
        }
        if entry.get("Value").and_then(|v| v.as_bool()) != Some(false)
            || entry.get("Status").and_then(|v| v.as_str()) != Some("locked")
        {
            result = Verdict::Unknown;
        }
    }
    result
}
fn normalize(value: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(
        value
            .nfkc()
            .flat_map(char::to_lowercase)
            .filter(|ch| ch.is_alphanumeric())
            .collect(),
    )
}
pub fn collect(
    values: &[DeviceValue],
    unavailable: &std::collections::BTreeSet<Source>,
    wifi: Option<bool>,
    policy: nw_platform::HygienePolicyHints,
) -> Report {
    let mut report = Report::default();
    report.set(CheckKind::WifiMac, observed(wifi));
    report.set(CheckKind::Location, observed(policy.location_disabled));
    report.llmnr_disabled = policy.llmnr_disabled;
    report.netbios_disabled = policy.netbios_disabled;
    report.mdns_disabled = policy.mdns_disabled;
    report.set(CheckKind::Clock, observed(policy.clock_within_bounds));
    // All three protocols must be observed off; one observed enabled protocol
    // already needs attention. Unobserved NetBIOS/mDNS cannot produce a pass.
    let protocols = [
        report.llmnr_disabled,
        report.netbios_disabled,
        report.mdns_disabled,
    ];
    report.set(
        CheckKind::Multicast,
        observed(if protocols.contains(&Some(false)) {
            Some(false)
        } else if protocols.iter().all(|v| *v == Some(true)) {
            Some(true)
        } else {
            None
        }),
    );
    if !unavailable.contains(&Source::User) && !unavailable.contains(&Source::Host) {
        let users: Vec<_> = values
            .iter()
            .filter(|v| v.source == Source::User)
            .flat_map(|v| v.value.split(|c: char| !c.is_alphanumeric()))
            .map(normalize)
            .filter(|s| s.chars().count() >= 3)
            .collect();
        let hosts: Vec<_> = values
            .iter()
            .filter(|v| v.source == Source::Host)
            .map(|v| normalize(&v.value))
            .collect();
        if !users.is_empty() && !hosts.is_empty() {
            let leaks = hosts
                .iter()
                .any(|h| users.iter().any(|u| h.contains(u.as_str())));
            let neutral = hosts.iter().all(|h| {
                h.as_str() == "localhost"
                    || ["desktop", "laptop"].iter().any(|prefix| {
                        h.strip_prefix(*prefix).is_some_and(|suffix| {
                            !suffix.is_empty()
                                && suffix.len() <= 16
                                && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
                        })
                    })
            });
            report.set(
                CheckKind::Hostname,
                if leaks {
                    Verdict::Fail
                } else if neutral {
                    Verdict::Pass
                } else {
                    Verdict::Unknown
                },
            );
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_requires_locked_false_preferences_and_never_executes_text() {
        let policy = |geo: &str, rtc: &str| {
            format!(
                r#"{{"policies":{{"Preferences":{{"geo.enabled":{geo},"media.peerconnection.enabled":{rtc}}}}}}}"#
            )
        };
        let off = r#"{"Value":false,"Status":"locked"}"#;
        assert!(browser_policy(policy(off, off).as_bytes()) == Verdict::Pass);
        for input in [
            policy("false", off),
            policy(r#"{"Value":false,"Status":"default"}"#, off),
            "NEVER_EXECUTE('SYNTHETIC_HYGIENE_CANARY')".into(),
            "{}".into(),
        ] {
            assert!(browser_policy(input.as_bytes()) == Verdict::Unknown);
        }
        assert!(
            browser_policy(policy(r#"{"Value":true,"Status":"locked"}"#, off).as_bytes())
                == Verdict::Fail
        );
        assert!(browser_policy(&vec![b'x'; 65537][..]) == Verdict::Unknown);
    }
    #[test]
    fn multicast_requires_every_protocol_off_and_clock_needs_an_actual_estimate() {
        let mut hints = nw_platform::HygienePolicyHints {
            llmnr_disabled: Some(true),
            netbios_disabled: Some(true),
            mdns_disabled: Some(true),
            clock_within_bounds: Some(true),
            ..Default::default()
        };
        let report = collect(&[], &Default::default(), None, hints);
        assert!(report.checks[2].verdict == Verdict::Pass);
        assert!(report.checks[4].verdict == Verdict::Pass);
        hints = nw_platform::HygienePolicyHints {
            llmnr_disabled: Some(true),
            netbios_disabled: None,
            mdns_disabled: Some(true),
            ..Default::default()
        };
        let report = collect(&[], &Default::default(), None, hints);
        assert!(report.checks[2].verdict == Verdict::Unknown);
        assert!(report.checks[4].verdict == Verdict::Unknown);
    }
    fn value(source: Source, text: &str) -> DeviceValue {
        DeviceValue {
            source,
            value: text.into(),
        }
    }
    #[test]
    fn unavailable_sources_and_partial_network_policies_never_become_success() {
        let values = [
            value(Source::User, "SyntheticPerson"),
            value(Source::Host, "DESKTOP-01"),
        ];
        let mut unavailable = std::collections::BTreeSet::new();
        let report = collect(
            &values,
            &unavailable,
            Some(true),
            nw_platform::HygienePolicyHints {
                location_disabled: Some(true),
                llmnr_disabled: Some(true),
                ..Default::default()
            },
        );
        assert!(report.valid());
        assert_eq!(report.known(), 3);
        assert_eq!(report.passed(), 3);
        assert_eq!(report.score(), Some(0.5));
        assert!(report.checks[2].verdict == Verdict::Unknown);
        unavailable.insert(Source::User);
        let report = collect(
            &values,
            &unavailable,
            None,
            nw_platform::HygienePolicyHints::default(),
        );
        assert_eq!(report.score(), None);
        let report = collect(
            &[
                value(Source::User, "Ｓｙｎｔｈｅｔｉｃ"),
                value(Source::Host, "synthetic-PC"),
            ],
            &Default::default(),
            None,
            nw_platform::HygienePolicyHints::default(),
        );
        assert!(report.checks[1].verdict == Verdict::Fail);
    }
}
