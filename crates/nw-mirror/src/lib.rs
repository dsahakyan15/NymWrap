use nw_drift::math::{Axis, Vector};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[derive(Debug, Error, Eq, PartialEq)]
#[error("invalid_snapshot")]
pub struct MirrorError;
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    YoutubeFeed,
    AdTopics,
    SearchSuggestions,
    AiMemory,
    Takeout,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub kind: SnapshotKind,
    pub captured_at: u64,
    pub items: Vec<String>,
}
impl Snapshot {
    pub fn validate(&self) -> Result<(), MirrorError> {
        if self.items.is_empty()
            || self.items.len() > 30
            || self.items.iter().any(|s| s.is_empty() || s.len() > 4096)
        {
            return Err(MirrorError);
        }
        Ok(())
    }
    pub fn position(&self, axis: &Axis, embeddings: &[Vector]) -> Result<f64, MirrorError> {
        self.validate()?;
        if embeddings.len() != self.items.len() {
            return Err(MirrorError);
        }
        axis.position(embeddings).map_err(|_| MirrorError)
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    pub shadow_requests: u64,
    pub account_requests: u64,
    pub leak_blocks: u64,
    pub decoys: u64,
    pub challenges: u64,
    pub cover_actions: u64,
    // Separate observation windows avoid treating unwired legacy counters as measured zero.
    #[serde(default)]
    observed_remote: u64,
    #[serde(default)]
    observed_decoys: u64,
    #[serde(default)]
    observed_actions: u64,
    #[serde(default)]
    observed_stops: u64,
    #[serde(default)]
    recent_stops: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    pub shadow_share: Option<f64>,
    pub cover_ratio: Option<f64>,
    pub challenge_rate: Option<f64>,
    pub leak_blocks: u64,
}
impl Counters {
    pub fn record_delivery(&mut self, decoy: bool) {
        if decoy {
            self.decoys = self.decoys.saturating_add(1);
            self.observed_decoys = self.observed_decoys.saturating_add(1);
        } else {
            self.observed_remote = self.observed_remote.saturating_add(1);
        }
    }
    pub fn record_action(&mut self) {
        self.cover_actions = self.cover_actions.saturating_add(1);
        self.observed_actions = self.observed_actions.saturating_add(1);
    }
    pub fn record_stop(&mut self, event_id: &str) -> Result<(), MirrorError> {
        if event_id.len() != 32
            || !event_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(MirrorError);
        }
        if !self.recent_stops.iter().any(|id| id == event_id) {
            self.challenges = self.challenges.saturating_add(1);
            self.observed_stops = self.observed_stops.saturating_add(1);
            if self.recent_stops.len() == 64 {
                self.recent_stops.remove(0);
            }
            self.recent_stops.push(event_id.into());
        }
        Ok(())
    }
    pub fn metrics(&self) -> Metrics {
        let ratio = |a: u64, b: u64| {
            if b == 0 {
                None
            } else {
                Some(a as f64 / b as f64)
            }
        };
        let share = |a: u64, b: u64| {
            if a == 0 && b == 0 {
                None
            } else {
                Some(a as f64 / (a as f64 + b as f64))
            }
        };
        Metrics {
            shadow_share: share(self.shadow_requests, self.account_requests),
            cover_ratio: ratio(self.observed_decoys, self.observed_remote),
            challenge_rate: share(self.observed_stops, self.observed_actions),
            leak_blocks: self.leak_blocks,
        }
    }
}
/// Hold an intended next stage until the observation reaches its expected position.
pub fn should_hold(observed: Option<f64>, expected: f64) -> Result<bool, MirrorError> {
    if !expected.is_finite() || observed.is_some_and(|v| !v.is_finite()) {
        return Err(MirrorError);
    }
    Ok(observed.is_none_or(|p| p + 0.05 < expected))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_metrics_are_not_zero_and_lag_holds() {
        assert!(Counters::default().metrics().shadow_share.is_none());
        assert_eq!(
            Counters {
                shadow_requests: 3,
                account_requests: 1,
                ..Default::default()
            }
            .metrics()
            .shadow_share,
            Some(0.75)
        );
        assert!(should_hold(None, 0.5).unwrap());
        assert!(should_hold(Some(0.2), 0.5).unwrap());
        assert!(!should_hold(Some(0.6), 0.5).unwrap());
        assert!(should_hold(Some(f64::NAN), 0.5).is_err());
    }
    #[test]
    fn only_observed_deliveries_and_cover_attempts_define_rates() {
        let mut c = Counters {
            shadow_requests: 100,
            cover_actions: 100,
            decoys: 20,
            challenges: 5,
            ..Default::default()
        };
        assert!(c.metrics().cover_ratio.is_none());
        assert!(c.metrics().challenge_rate.is_none());
        c.record_delivery(true);
        assert!(c.metrics().cover_ratio.is_none());
        c.record_delivery(false);
        c.record_delivery(false);
        assert_eq!(c.metrics().cover_ratio, Some(0.5));
        c.record_action();
        assert_eq!(c.metrics().challenge_rate, Some(0.0));
        c.record_stop(&"a".repeat(32)).unwrap();
        c.record_stop(&"a".repeat(32)).unwrap();
        assert_eq!(c.metrics().challenge_rate, Some(0.5));
        assert!(c.record_stop("untrusted text").is_err());
        c.shadow_requests = u64::MAX;
        c.account_requests = u64::MAX;
        assert_eq!(c.metrics().shadow_share, Some(0.5));
    }
}
