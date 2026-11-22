//! Uniform asynchronous release windows, independent of prompt contents.
use crate::CoverError;
use rand::Rng;
pub const MAX_HOURS: u16 = 168;
pub fn not_before(now: u64, hours: u16, rng: &mut impl Rng) -> Result<u64, CoverError> {
    if hours > MAX_HOURS {
        return Err(CoverError::Configuration);
    }
    now.checked_add(rng.gen_range(0..=u64::from(hours) * 3600))
        .ok_or(CoverError::Clock)
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    #[test]
    fn sampled_slots_are_bounded_zero_is_immediate_and_overflow_fails_closed() {
        let mut rng = StdRng::seed_from_u64(8351);
        assert_eq!(not_before(100, 0, &mut rng), Ok(100));
        assert_eq!(
            not_before(100, MAX_HOURS + 1, &mut rng),
            Err(CoverError::Configuration)
        );
        let values: std::collections::BTreeSet<_> = (0..1000)
            .map(|_| not_before(100, 2, &mut rng).unwrap())
            .collect();
        assert!(values.len() > 800);
        assert!(values.iter().all(|at| (100..=7300).contains(at)));
        assert!(not_before(u64::MAX, 1, &mut rng).is_err());
    }
}
