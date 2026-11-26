//! Scheduling policy with integer budgets. No network, clocks or user data here.
pub mod budget;
pub mod defer;
pub mod session;
use nw_proto::Profile;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Poisson,
    Constant,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub mean_interval_s: u64,
    pub max_requests_per_day: u32,
    pub max_spend_microusd: u64,
}
impl Config {
    pub fn for_profile(profile: Profile) -> Self {
        Self {
            mode: if profile == Profile::Paranoid {
                Mode::Constant
            } else {
                Mode::Poisson
            },
            mean_interval_s: 600,
            max_requests_per_day: 60,
            max_spend_microusd: 500_000,
        }
    }
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CoverError {
    #[error("invalid_cover_configuration")]
    Configuration,
    #[error("slot_not_ready")]
    NotReady,
    #[error("cover_budget_exhausted")]
    Budget,
    #[error("clock_moved_backwards")]
    Clock,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Slot {
    Real,
    Decoy,
    Queued,
}
pub struct Scheduler {
    config: Config,
    next_slot: u64,
    day: u64,
    last_now: u64,
    count: u32,
    spend: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    version: u16,
    next_slot: u64,
    day: u64,
    last_now: u64,
    count: u32,
    spend: u64,
}
impl Scheduler {
    pub fn delayed<R: Rng>(config: Config, now: u64, rng: &mut R) -> Result<Self, CoverError> {
        let mut scheduler = Self::new(config, now)?;
        scheduler.next_slot = now.saturating_add(scheduler.interval(rng));
        Ok(scheduler)
    }
    fn interval<R: Rng>(&self, rng: &mut R) -> u64 {
        match self.config.mode {
            Mode::Poisson => (-rng.gen_range(f64::MIN_POSITIVE..1.0).ln()
                * self.config.mean_interval_s as f64)
                .ceil()
                .max(1.0) as u64,
            Mode::Constant => self.config.mean_interval_s,
        }
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: 1,
            next_slot: self.next_slot,
            day: self.day,
            last_now: self.last_now,
            count: self.count,
            spend: self.spend,
        }
    }
    pub fn restore(config: Config, snapshot: Snapshot, now: u64) -> Result<Self, CoverError> {
        let mut scheduler = Self::new(config, now)?;
        if snapshot.version != 1 || snapshot.day != snapshot.last_now / 86400 {
            return Err(CoverError::Configuration);
        }
        if snapshot.last_now > now {
            return Err(CoverError::Clock);
        }
        scheduler.next_slot = snapshot.next_slot;
        scheduler.day = snapshot.day;
        scheduler.last_now = snapshot.last_now;
        scheduler.count = snapshot.count;
        scheduler.spend = snapshot.spend;
        Ok(scheduler)
    }
    pub fn new(config: Config, now: u64) -> Result<Self, CoverError> {
        if config.mean_interval_s == 0
            || config.mean_interval_s > 86400
            || config.max_requests_per_day == 0
            || config.max_spend_microusd == 0
        {
            return Err(CoverError::Configuration);
        }
        Ok(Self {
            config,
            next_slot: now,
            day: now / 86400,
            last_now: now,
            count: 0,
            spend: 0,
        })
    }
    pub fn usage(&self) -> (u32, u64) {
        (self.count, self.spend)
    }
    pub fn next_slot(&self) -> u64 {
        self.next_slot
    }
    /// Constant-rate admission: a missed slot is skipped, never released on arrival.
    /// Persist the snapshot even on NotReady, so restart cannot revive that slot.
    pub fn tick_constant<R: Rng>(
        &mut self,
        now: u64,
        has_real: bool,
        cost_upper_bound: u64,
        rng: &mut R,
    ) -> Result<Slot, CoverError> {
        if !matches!(self.config.mode, Mode::Constant) {
            return Err(CoverError::Configuration);
        }
        if now < self.last_now {
            return Err(CoverError::Clock);
        }
        if now > self.next_slot {
            let interval = self.config.mean_interval_s;
            let remainder = (now - self.next_slot) % interval;
            self.next_slot = now
                .checked_add(if remainder == 0 {
                    0
                } else {
                    interval - remainder
                })
                .ok_or(CoverError::Clock)?;
        }
        now.checked_add(self.config.mean_interval_s)
            .ok_or(CoverError::Clock)?;
        self.tick(now, has_real, cost_upper_bound, rng)
    }
    /// Reserve an upper cost bound before sending; failed attempts are charged conservatively.
    pub fn tick<R: Rng>(
        &mut self,
        now: u64,
        has_real: bool,
        cost_upper_bound: u64,
        rng: &mut R,
    ) -> Result<Slot, CoverError> {
        if now < self.last_now {
            return Err(CoverError::Clock);
        }
        self.last_now = now;
        if now / 86400 > self.day {
            self.day = now / 86400;
            self.count = 0;
            self.spend = 0;
        }
        if now < self.next_slot {
            return Err(CoverError::NotReady);
        }
        if self.count >= self.config.max_requests_per_day
            || cost_upper_bound == 0
            || self
                .spend
                .checked_add(cost_upper_bound)
                .is_none_or(|n| n > self.config.max_spend_microusd)
        {
            return Ok(Slot::Queued);
        }
        self.count += 1;
        self.spend += cost_upper_bound;
        let interval = self.interval(rng);
        self.next_slot = now.saturating_add(interval);
        Ok(if has_real { Slot::Real } else { Slot::Decoy })
    }
}

/// Independent synthetic prompts; never sampled from persona, cover, imports or vault.
pub fn decoy<R: Rng>(rng: &mut R) -> &'static str {
    const PROMPTS: &[&str] = &[
        "Explain how clouds form.",
        "Describe the history of pottery.",
        "Give a simple bread recipe.",
        "Explain why leaves change color.",
        "Describe how a sundial works.",
        "List common garden flowers.",
    ];
    PROMPTS[rng.gen_range(0..PROMPTS.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    #[test]
    fn paranoid_constant_slots_keep_phase_across_misses_budget_and_restore() {
        let mut rng = StdRng::seed_from_u64(6);
        let config = Config {
            mode: Mode::Constant,
            mean_interval_s: 10,
            max_requests_per_day: 1,
            max_spend_microusd: 1,
        };
        let mut scheduler = Scheduler::delayed(config.clone(), 0, &mut rng).unwrap();
        assert_eq!(
            scheduler.tick_constant(9, true, 1, &mut rng),
            Err(CoverError::NotReady)
        );
        assert_eq!(
            scheduler.tick_constant(11, true, 1, &mut rng),
            Err(CoverError::NotReady)
        );
        assert_eq!(scheduler.next_slot(), 20);
        scheduler = Scheduler::restore(config.clone(), scheduler.snapshot(), 11).unwrap();
        assert_eq!(
            scheduler.tick_constant(20, true, 1, &mut rng),
            Ok(Slot::Real)
        );
        assert_eq!(
            scheduler.tick_constant(20, true, 1, &mut rng),
            Err(CoverError::NotReady)
        );
        assert_eq!(
            scheduler.tick_constant(30, true, 1, &mut rng),
            Ok(Slot::Queued)
        );
        assert_eq!(
            scheduler.tick_constant(86401, true, 1, &mut rng),
            Err(CoverError::NotReady)
        );
        assert_eq!(scheduler.next_slot(), 86410);
        assert_eq!(
            scheduler.tick_constant(86410, false, 1, &mut rng),
            Ok(Slot::Decoy)
        );
        assert!(Scheduler::restore(config, scheduler.snapshot(), 86409).is_err());
        assert_eq!(
            scheduler.tick_constant(u64::MAX, true, 1, &mut rng),
            Err(CoverError::Clock)
        );
    }
    #[test]
    fn seven_days_never_exceed_budget_and_paranoid_queues() {
        for mode in [Mode::Constant, Mode::Poisson] {
            let mut rng = StdRng::seed_from_u64(73);
            let mut scheduler = Scheduler::new(
                Config {
                    mode,
                    mean_interval_s: 10,
                    max_requests_per_day: 60,
                    max_spend_microusd: 100,
                },
                0,
            )
            .unwrap();
            for now in (0..7 * 86400).step_by(10) {
                let _ = scheduler.tick(now, true, 3, &mut rng);
                let (count, spend) = scheduler.usage();
                assert!(count <= 60 && spend <= 100);
            }
            assert_eq!(
                scheduler.tick(7 * 86400 - 1, true, 1000, &mut rng),
                Ok(Slot::Queued)
            );
        }
    }
    #[test]
    fn no_catch_up_burst_or_clock_rollback_reset() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut scheduler = Scheduler::new(Config::for_profile(Profile::Paranoid), 100).unwrap();
        assert_eq!(scheduler.tick(100, true, 1, &mut rng), Ok(Slot::Real));
        assert_eq!(
            scheduler.tick(101, true, 1, &mut rng),
            Err(CoverError::NotReady)
        );
        assert_eq!(
            scheduler.tick(99, true, 1, &mut rng),
            Err(CoverError::Clock)
        );
        assert_eq!(scheduler.tick(10000, false, 1, &mut rng), Ok(Slot::Decoy));
        assert_eq!(
            scheduler.tick(10000, true, 1, &mut rng),
            Err(CoverError::NotReady)
        );
    }
    #[test]
    fn reopening_does_not_reset_budget_or_create_catchup_bursts() {
        let mut rng = StdRng::seed_from_u64(42);
        let config = Config {
            mode: Mode::Constant,
            mean_interval_s: 10,
            max_requests_per_day: 3,
            max_spend_microusd: 9,
        };
        let mut scheduler = Scheduler::new(config.clone(), 100).unwrap();
        for now in [100, 110, 120] {
            assert_eq!(scheduler.tick(now, true, 3, &mut rng), Ok(Slot::Real));
            scheduler = Scheduler::restore(config.clone(), scheduler.snapshot(), now).unwrap();
        }
        assert_eq!(scheduler.usage(), (3, 9));
        assert_eq!(scheduler.tick(130, true, 3, &mut rng), Ok(Slot::Queued));
        assert_eq!(scheduler.tick(86400, false, 3, &mut rng), Ok(Slot::Decoy));
        assert_eq!(
            scheduler.tick(86400, true, 3, &mut rng),
            Err(CoverError::NotReady)
        );
        assert!(Scheduler::restore(config, scheduler.snapshot(), 100).is_err());
    }
}
