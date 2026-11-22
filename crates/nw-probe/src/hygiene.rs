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
    fn set(&mut self, kind: CheckKind, verdict: Verdict) {
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
