//! Charge before sending. Persist this state before releasing any egress bytes.
use crate::CoverError;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DailyBudget {
    day: u64,
    last_now: u64,
    requests: u32,
    spent_microusd: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub day: u64,
    pub requests: u32,
    pub reserved_microusd: u64,
}
impl DailyBudget {
    pub fn new(now: u64) -> Self {
        Self {
            day: now / 86400,
            last_now: now,
            requests: 0,
            spent_microusd: 0,
        }
    }
    pub fn validate(&self) -> Result<(), CoverError> {
        if self.day != self.last_now / 86400 || (self.requests == 0) != (self.spent_microusd == 0) {
            return Err(CoverError::Configuration);
        }
        Ok(())
    }
    pub fn usage(&self) -> Usage {
        Usage {
            day: self.day,
            requests: self.requests,
            reserved_microusd: self.spent_microusd,
        }
    }
    pub fn reserve(
        &mut self,
        now: u64,
        max_requests: u32,
        max_microusd: u64,
        cost_upper_bound: u64,
    ) -> Result<Usage, CoverError> {
        self.validate()?;
        if now < self.last_now {
            return Err(CoverError::Clock);
        }
        if max_requests == 0 || max_microusd == 0 || cost_upper_bound == 0 {
            return Err(CoverError::Configuration);
        }
        if now / 86400 > self.day {
            *self = Self::new(now);
        }
        let count = self
            .requests
            .checked_add(1)
            .filter(|count| *count <= max_requests)
            .ok_or(CoverError::Budget)?;
        let spent = self
            .spent_microusd
            .checked_add(cost_upper_bound)
            .filter(|spent| *spent <= max_microusd)
            .ok_or(CoverError::Budget)?;
        self.last_now = now;
        self.requests = count;
        self.spent_microusd = spent;
        Ok(self.usage())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seven_days_restart_reservations_never_exceed_limit() {
        let mut budget = DailyBudget::new(0);
        for now in (0..7 * 86400).step_by(73) {
            let result = budget.reserve(now, 60, 500_000, 11_111);
            let usage = budget.usage();
            assert!(usage.requests <= 60 && usage.reserved_microusd <= 500_000);
            if result.is_err() {
                assert!(budget.reserve(now, 60, 500_000, 11_111).is_err());
            }
            budget.validate().unwrap();
            budget = serde_json::from_slice(&serde_json::to_vec(&budget).unwrap()).unwrap();
        }
        assert!(budget.reserve(1, 60, 500_000, 1).is_err());
    }
    #[test]
    fn lower_limits_and_overflow_do_not_reset_accounting() {
        let mut b = DailyBudget::new(100);
        b.reserve(100, 60, 500_000, 100).unwrap();
        assert!(b.reserve(101, 1, 99, 1).is_err());
        assert_eq!(b.usage().reserved_microusd, 100);
        assert!(b.reserve(101, 60, u64::MAX, u64::MAX).is_err());
        assert_eq!(b.usage().reserved_microusd, 100);
    }
}
