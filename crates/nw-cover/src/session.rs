//! Session boundaries use a monotonic clock. No identity, wall time or network.
use rand::Rng;
use std::time::{Duration, Instant};

pub const FIRST_SECONDS: std::ops::RangeInclusive<u64> = 300..=1800;
pub const TAIL_SECONDS: std::ops::RangeInclusive<u64> = 600..=3600;

#[derive(Clone, Copy)]
pub struct Clock {
    first: Instant,
    tail: Option<Instant>,
}
impl Clock {
    pub fn new(now: Instant, rng: &mut impl Rng) -> Self {
        Self {
            first: now + Duration::from_secs(rng.gen_range(FIRST_SECONDS)),
            tail: None,
        }
    }
    pub fn first_remaining(&self, now: Instant) -> Duration {
        self.first.saturating_duration_since(now)
    }
    pub fn tail_deadline(&self) -> Option<Instant> {
        self.tail
    }
    pub fn allowed(&self, now: Instant) -> bool {
        self.first <= now && self.tail.is_none_or(|end| now < end)
    }
    /// Repeated closes cannot extend the already chosen end of the session.
    pub fn close(&mut self, now: Instant, rng: &mut impl Rng) -> Instant {
        *self
            .tail
            .get_or_insert_with(|| now + Duration::from_secs(rng.gen_range(TAIL_SECONDS)))
    }
}

pub fn remaining_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn boundaries_are_bounded_monotonic_and_never_extended() {
        let start = Instant::now();
        let mut rng = StdRng::seed_from_u64(934_517);
        let mut first_samples = std::collections::BTreeSet::new();
        let mut tail_samples = std::collections::BTreeSet::new();
        for _ in 0..4096 {
            let mut clock = Clock::new(start, &mut rng);
            let wait = clock.first_remaining(start);
            assert!(FIRST_SECONDS.contains(&wait.as_secs()));
            first_samples.insert(wait.as_secs());
            assert!(!clock.allowed(start));
            assert!(!clock.allowed(start + wait - Duration::from_nanos(1)));
            assert!(clock.allowed(start + wait));
            let closed = start + Duration::from_secs(3600);
            let end = clock.close(closed, &mut rng);
            assert!(TAIL_SECONDS.contains(&(end - closed).as_secs()));
            tail_samples.insert((end - closed).as_secs());
            assert!(clock.allowed(end - Duration::from_nanos(1)));
            assert!(!clock.allowed(end));
            assert_eq!(clock.close(end + Duration::from_secs(9999), &mut rng), end);
            assert!(!clock.allowed(end + Duration::from_secs(9999)));
        }
        assert!(first_samples.len() > 1000 && tail_samples.len() > 1000);
        assert_eq!(remaining_seconds(Duration::from_millis(1001)), 2);
        assert_eq!(remaining_seconds(Duration::ZERO), 0);
    }
}
