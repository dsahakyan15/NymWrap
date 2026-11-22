use super::*;
use nw_cover::session::remaining_seconds;
use std::time::Instant;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTiming {
    pub phase: Phase,
    pub first_send_in_s: u64,
    pub tail_remaining_s: Option<u64>,
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Locked,
    Starting,
    Foreground,
    Tail,
}
fn snapshot(s: &Session, now: Instant) -> SessionTiming {
    let Some(clock) = s.timing.filter(|_| s.workspace.is_some()) else {
        return SessionTiming {
            phase: Phase::Locked,
            first_send_in_s: 0,
            tail_remaining_s: None,
        };
    };
    let first_send_in_s = remaining_seconds(clock.first_remaining(now));
    let tail_remaining_s = clock.tail_deadline().map(|end| {
        remaining_seconds(end.saturating_duration_since(now)).min(
            s.tail_wall_deadline
                .unwrap_or(0)
                .saturating_sub(workspace::now()),
        )
    });
    SessionTiming {
        phase: if tail_remaining_s.is_some() {
            Phase::Tail
        } else if first_send_in_s != 0 {
            Phase::Starting
        } else {
            Phase::Foreground
        },
        first_send_in_s,
        tail_remaining_s,
    }
}
pub(in crate::service) fn session_timing(state: &State) -> Result<SessionTiming, String> {
    let s = state.session.lock().map_err(|_| "session_unavailable")?;
    Ok(snapshot(&s, Instant::now()))
}
pub(in crate::service) struct Closed {
    pub value: SessionTiming,
    pub timer: Option<(u64, Instant)>,
}
pub(in crate::service) fn close_session(state: &State) -> Result<Closed, String> {
    close_at(state, state.egress.is_some(), Instant::now())
}
fn close_at(state: &State, has_egress: bool, now: Instant) -> Result<Closed, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.in_tail() {
        return Ok(Closed {
            value: snapshot(&s, now),
            timer: None,
        });
    }
    let eligible = has_egress
        && s.timing.is_some()
        && s.workspace.as_mut().is_some_and(|w| {
            w.config.hard.background_tail
                && w.config.cover.enabled
                && w.device_probe_ready().unwrap_or(false)
        });
    // Cancel real jobs durably before advancing the epoch. Sending is uncertain,
    // never retried. Errors still lock; a corrupt index cannot authorize a tail.
    let cancelled = if let Some(w) = &mut s.workspace {
        w.remote_jobs()
            .and_then(|jobs| {
                for job in jobs {
                    if matches!(
                        job.state,
                        workspace::RemoteJobState::Queued | workspace::RemoteJobState::Sending
                    ) {
                        w.cancel_remote_job(&job.id)?;
                    }
                }
                Ok(())
            })
            .is_ok()
    } else {
        true
    };
    if eligible && cancelled {
        let end = s
            .timing
            .as_mut()
            .ok_or("session_changed")?
            .close(now, &mut rand::rngs::OsRng);
        // This second deadline can only shorten a tail. It covers suspend on
        // platforms whose monotonic clock stops while the machine is asleep.
        s.tail_wall_deadline = Some(workspace::now().saturating_add((end - now).as_secs()));
        state.invalidate_with_decoy(&mut s, true);
        s.engine = None;
        return Ok(Closed {
            value: snapshot(&s, now),
            timer: Some((s.epoch, end)),
        });
    }
    state.invalidate(&mut s);
    let epoch = s.epoch;
    *s = Session {
        epoch,
        ..Default::default()
    };
    Ok(Closed {
        value: snapshot(&s, now),
        timer: None,
    })
}
pub(in crate::service) fn expire_tail(state: &State, epoch: u64, deadline: Instant) -> bool {
    let Ok(mut s) = state.session.lock() else {
        return false;
    };
    if s.epoch != epoch
        || !s
            .timing
            .is_some_and(|c| c.tail_deadline() == Some(deadline))
        || !s.tail_expired(Instant::now())
    {
        return false;
    }
    state.invalidate(&mut s);
    let epoch = s.epoch;
    *s = Session {
        epoch,
        ..Default::default()
    };
    true
}
pub(in crate::service) fn tail_wait(
    state: &State,
    epoch: u64,
    deadline: Instant,
) -> Option<std::time::Duration> {
    let s = state.session.lock().ok()?;
    if s.epoch != epoch || s.timing.and_then(|c| c.tail_deadline()) != Some(deadline) {
        return None;
    }
    if s.tail_expired(Instant::now()) {
        return Some(std::time::Duration::ZERO);
    }
    Some(
        deadline
            .saturating_duration_since(Instant::now())
            .min(std::time::Duration::from_secs(1)),
    )
}

pub(super) async fn wait_first(state: &State, epoch: u64) -> Result<(), crate::CoreError> {
    let mut changes = state.changes.subscribe();
    loop {
        let delay = {
            let s = state
                .session
                .lock()
                .map_err(|_| crate::CoreError::Session)?;
            if s.epoch != epoch || s.workspace.is_none() {
                return Err(crate::CoreError::Session);
            }
            let clock = s.timing.ok_or(crate::CoreError::Session)?;
            let now = Instant::now();
            if s.tail_expired(now) {
                return Err(crate::CoreError::Session);
            }
            if clock.allowed(now) {
                return Ok(());
            }
            clock.first_remaining(now).min(
                clock
                    .tail_deadline()
                    .map_or(std::time::Duration::MAX, |end| {
                        end.saturating_duration_since(now)
                    }),
            )
        };
        tokio::select! {biased;
            _=changes.wait_for(|e| *e!=epoch)=>return Err(crate::CoreError::Session),
            _=tokio::time::sleep(delay)=>{},
        }
    }
}

#[cfg(test)]
#[path = "../../../../../tests/leak/src/core_session.rs"]
mod tests;
