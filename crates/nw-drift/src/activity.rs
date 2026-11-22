//! A gradual, hash-bound UTC schedule. No browser timezone or fingerprint changes.
use crate::DriftError;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub start_hour_utc: u8,
    pub target_hour_utc: u8,
    pub width_hours: u8,
}
impl Default for Transition {
    fn default() -> Self {
        Self {
            start_hour_utc: 12,
            target_hour_utc: 12,
            width_hours: 6,
        }
    }
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub start_hour_utc: u8,
    pub width_hours: u8,
}
impl Window {
    fn valid(self) -> bool {
        self.start_hour_utc < 24 && (1..=12).contains(&self.width_hours)
    }
    pub fn contains(self, at: u64) -> bool {
        self.valid()
            && ((at % 86400) / 3600 + 24 - u64::from(self.start_hour_utc)) % 24
                < u64::from(self.width_hours)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub windows: Vec<Window>,
}
fn distance(a: u8, b: u8) -> i16 {
    (i16::from(b) - i16::from(a) + 12).rem_euclid(24) - 12
}
impl Transition {
    pub fn schedule(self, stages: usize) -> Result<Schedule, DriftError> {
        if !(3..=30).contains(&stages)
            || self.target_hour_utc >= 24
            || !(Window {
                start_hour_utc: self.start_hour_utc,
                width_hours: self.width_hours,
            })
            .valid()
        {
            return Err(DriftError::Plan);
        }
        let delta = distance(self.start_hour_utc, self.target_hour_utc);
        let schedule = Schedule {
            windows: (0..stages)
                .map(|i| Window {
                    start_hour_utc: (i16::from(self.start_hour_utc)
                        + delta * i as i16 / (stages - 1) as i16)
                        .rem_euclid(24) as u8,
                    width_hours: self.width_hours,
                })
                .collect(),
        };
        schedule.validate(stages)?;
        Ok(schedule)
    }
}
impl Schedule {
    pub fn validate(&self, stages: usize) -> Result<(), DriftError> {
        if !(3..=30).contains(&stages)
            || self.windows.len() != stages
            || self.windows.iter().any(|w| !w.valid())
            || self.windows.windows(2).any(|w| {
                w[0].width_hours != w[1].width_hours
                    || distance(w[0].start_hour_utc, w[1].start_hour_utc).abs() > 2
            })
        {
            return Err(DriftError::Plan);
        }
        Ok(())
    }
    pub fn allows(&self, stage: usize, at: u64) -> bool {
        self.windows.get(stage).is_some_and(|w| w.contains(at))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_clock_pairs_reach_the_target_with_steps_at_most_two_hours() {
        for start in 0..24 {
            for target in 0..24 {
                let schedule = Transition {
                    start_hour_utc: start,
                    target_hour_utc: target,
                    width_hours: 4,
                }
                .schedule(10)
                .unwrap();
                assert_eq!(schedule.windows.first().unwrap().start_hour_utc, start);
                assert_eq!(schedule.windows.last().unwrap().start_hour_utc, target);
                schedule.validate(10).unwrap();
            }
        }
        assert!(
            Transition {
                start_hour_utc: 0,
                target_hour_utc: 12,
                width_hours: 6
            }
            .schedule(3)
            .is_err()
        );
        assert!(
            Transition {
                start_hour_utc: 24,
                target_hour_utc: 0,
                width_hours: 6
            }
            .schedule(10)
            .is_err()
        );
    }
    #[test]
    fn utc_windows_wrap_midnight_without_extending_an_active_day() {
        let window = Window {
            start_hour_utc: 22,
            width_hours: 4,
        };
        for at in [22 * 3600, 86399, 0, 2 * 3600 - 1] {
            assert!(window.contains(at));
        }
        for at in [2 * 3600, 21 * 3600, 22 * 3600 - 1] {
            assert!(!window.contains(at));
        }
    }
}
