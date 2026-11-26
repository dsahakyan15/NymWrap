//! Final dispatch gates shared by queued requests and the transport adapter.
use super::*;
use nw_proto::Profile;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// One dispatch window; its deadline starts before scheduler I/O. The dispatcher
/// attaches it to a request only after saving the encrypted slot reservation.
/// It cannot be cloned, extended by a wall-clock change, or reused after a send.
pub(super) struct Slot {
    deadline: Instant,
    wall_start: SystemTime,
    wall_deadline: SystemTime,
    used: AtomicBool,
}
impl Slot {
    pub(super) fn new() -> Self {
        let wall_start = SystemTime::now();
        let window = Duration::from_secs(1);
        Self {
            deadline: Instant::now() + window,
            wall_start,
            wall_deadline: wall_start.checked_add(window).unwrap_or(wall_start),
            used: AtomicBool::new(false),
        }
    }
    pub(super) fn check(&self, now: Instant) -> Result<(), CoreError> {
        self.check_at(now, SystemTime::now())
    }
    fn check_at(&self, now: Instant, wall: SystemTime) -> Result<(), CoreError> {
        if now >= self.deadline
            || wall < self.wall_start
            || wall >= self.wall_deadline
            || self.used.load(Ordering::SeqCst)
        {
            return Err(CoreError::Queue);
        }
        Ok(())
    }
    pub(super) fn consume(&self, now: Instant) -> Result<(), CoreError> {
        self.check(now)?;
        if self.used.swap(true, Ordering::SeqCst) {
            return Err(CoreError::Queue);
        }
        Ok(())
    }
}

/// The adapter supplies its actual trust; configuring Nym never proves L1.
pub(super) fn check_route(
    config: &Config,
    required: TrustLevel,
    actual: TrustLevel,
) -> Result<(), CoreError> {
    if actual == TrustLevel::L0
        || actual
            > required
                .min(config.shield.min_trust)
                .min(config.profile.min_trust())
    {
        return Err(CoreError::Trust);
    }
    Ok(())
}

pub(super) fn needs_slot(config: &Config) -> bool {
    config.profile == Profile::Paranoid
        || config.cover.enabled && config.cover.mode == crate::config::CoverMode::Constant
}

impl Route {
    pub(super) fn check_dispatch(&self, now: Instant) -> Result<(), CoreError> {
        check_dispatch(
            &self.config,
            self.required,
            self.trust(),
            self.job.is_some(),
            self.slot.as_ref(),
            now,
        )?;
        // The sole production adapter is Tor + pooled keys (L3). No fallback.
        if self.config.net.transport != crate::config::Transport::Tor {
            return Err(CoreError::Transport);
        }
        Ok(())
    }
}

fn check_dispatch(
    config: &Config,
    required: TrustLevel,
    actual: TrustLevel,
    approved: bool,
    slot: Option<&Slot>,
    now: Instant,
) -> Result<(), CoreError> {
    check_route(config, required, actual)?;
    if config.profile.requires_approval() && !approved {
        return Err(CoreError::Approval);
    }
    if needs_slot(config) && slot.is_none() {
        return Err(CoreError::Queue);
    }
    if config.profile == Profile::Paranoid {
        slot.ok_or(CoreError::Queue)?.check(now)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("../../../../../../tests/leak/src/paranoid_queue.rs");
}
