//! Shadow cover traffic, never cover-lane legend activity.
use super::*;
use nw_cover::{Scheduler, Slot, Snapshot};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficJob {
    #[serde(default)]
    pub purpose: TrafficPurpose,
    pub id: String,
    pub created_at: u64,
    pub state: JobState,
    pub code: Option<String>,
}
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficPurpose {
    Real,
    #[default]
    Decoy,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Preparing,
    Succeeded,
    Uncertain,
    Blocked,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficStatus {
    pub enabled: bool,
    pub next_slot: Option<u64>,
    pub jobs: Vec<TrafficJob>,
}
impl Workspace {
    pub(super) fn recover_traffic_jobs(&mut self) -> Result<(), WorkspaceError> {
        let mut jobs = self.traffic_jobs()?;
        let mut changed = false;
        for job in &mut jobs {
            if job.state == JobState::Preparing {
                job.state = JobState::Uncertain;
                job.code = Some("previous_session_ended".into());
                changed = true;
            }
        }
        if changed {
            self.store
                .put_json(Domain::Vault, "traffic-jobs", &jobs, now())?;
        }
        Ok(())
    }
    fn traffic_jobs(&mut self) -> Result<Vec<TrafficJob>, WorkspaceError> {
        let jobs: Vec<TrafficJob> = self
            .store
            .get_json(Domain::Vault, "traffic-jobs")?
            .unwrap_or_default();
        if jobs.len() > 64
            || jobs.iter().any(|j| {
                j.id.len() != 64
                    || !j.id.bytes().all(|b| b.is_ascii_hexdigit())
                    || j.code.as_ref().is_some_and(|c| {
                        c.is_empty()
                            || c.len() > 64
                            || !c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                    })
            })
        {
            return Err(WorkspaceError::Invalid);
        }
        Ok(jobs)
    }
    pub fn traffic_status(&mut self) -> Result<TrafficStatus, WorkspaceError> {
        let snapshot: Option<Snapshot> = self.store.get_json(Domain::Vault, "traffic-scheduler")?;
        let next_slot = if let Some(snapshot) = snapshot {
            Some(
                Scheduler::restore(self.traffic_config(), snapshot, now())
                    .map_err(|_| WorkspaceError::Policy)?
                    .next_slot(),
            )
        } else {
            None
        };
        Ok(TrafficStatus {
            enabled: self.config.cover.enabled,
            next_slot,
            jobs: self.traffic_jobs()?,
        })
    }
    fn traffic_config(&self) -> nw_cover::Config {
        nw_cover::Config {
            mode: match self.config.cover.mode {
                crate::config::CoverMode::Poisson => nw_cover::Mode::Poisson,
                crate::config::CoverMode::Constant => nw_cover::Mode::Constant,
            },
            mean_interval_s: self.config.cover.mean_interval_s,
            max_requests_per_day: self.config.cover.max_requests_per_day,
            max_spend_microusd: (self.config.cover.max_spend_per_day_usd * 1_000_000.0).floor()
                as u64,
        }
    }
    /// A persisted slot is consumed before starting any model or remote operation.
    pub fn take_traffic_job(&mut self, at: u64) -> Result<Option<TrafficJob>, WorkspaceError> {
        self.take_traffic_slot(at, false)
    }
    /// Consume a persisted slot for a ready real request, or an independent decoy.
    /// The caller must reserve the shared network budget before dispatching bytes.
    pub fn take_traffic_slot(
        &mut self,
        at: u64,
        has_real: bool,
    ) -> Result<Option<TrafficJob>, WorkspaceError> {
        if !self.config.cover.enabled {
            return Ok(None);
        }
        self.config.validate().map_err(|_| WorkspaceError::Policy)?;
        let mut jobs = self.traffic_jobs()?;
        // A previous process may have died at any point. Never replay its operation.
        let mut recovered = false;
        for job in &mut jobs {
            if job.state == JobState::Preparing {
                job.state = JobState::Uncertain;
                job.code = Some("previous_session_ended".into());
                recovered = true;
            }
        }
        if recovered {
            self.store
                .put_json(Domain::Vault, "traffic-jobs", &jobs, at)?;
        }
        let config = self.traffic_config();
        let snapshot: Option<Snapshot> = self.store.get_json(Domain::Vault, "traffic-scheduler")?;
        let mut scheduler = match snapshot {
            Some(snapshot) => {
                Scheduler::restore(config, snapshot, at).map_err(|_| WorkspaceError::Policy)?
            }
            None => {
                // Enabling or reopening never emits an immediate startup burst.
                let scheduler = Scheduler::delayed(config, at, &mut rand::rngs::OsRng)
                    .map_err(|_| WorkspaceError::Policy)?;
                self.store.put_json(
                    Domain::Vault,
                    "traffic-scheduler",
                    &scheduler.snapshot(),
                    at,
                )?;
                return Ok(None);
            }
        };
        if at < scheduler.next_slot() {
            return Ok(None);
        }
        let cost = self
            .config
            .net
            .max_request_cost_microusd
            .ok_or(WorkspaceError::Policy)?;
        match self.check_network_cost(cost, at) {
            Ok(()) => {}
            Err(WorkspaceError::Budget) => return Ok(None),
            Err(error) => return Err(error),
        }
        match scheduler.tick(at, has_real, cost, &mut rand::rngs::OsRng) {
            Ok(Slot::Decoy | Slot::Real) => {}
            Ok(Slot::Queued) | Err(nw_cover::CoverError::NotReady) => return Ok(None),
            _ => return Err(WorkspaceError::Policy),
        }
        self.store.put_json(
            Domain::Vault,
            "traffic-scheduler",
            &scheduler.snapshot(),
            at,
        )?;
        let job = TrafficJob {
            purpose: if has_real {
                TrafficPurpose::Real
            } else {
                TrafficPurpose::Decoy
            },
            id: nw_cred::os::random_id(),
            created_at: at - at % 60,
            state: JobState::Preparing,
            code: None,
        };
        if jobs.len() == 64 {
            jobs.remove(0);
        }
        jobs.push(job.clone());
        self.store
            .put_json(Domain::Vault, "traffic-jobs", &jobs, at)?;
        Ok(Some(job))
    }
    pub fn finish_traffic_job(
        &mut self,
        id: &str,
        result: Result<(), &str>,
    ) -> Result<(), WorkspaceError> {
        let mut jobs = self.traffic_jobs()?;
        let job = jobs
            .iter_mut()
            .find(|j| j.id == id && j.state == JobState::Preparing)
            .ok_or(WorkspaceError::Invalid)?;
        match result {
            Ok(()) => job.state = JobState::Succeeded,
            Err(code) => {
                job.state = if matches!(code, "remote_transport_unavailable" | "session_changed") {
                    JobState::Uncertain
                } else {
                    JobState::Blocked
                };
                job.code = Some(code.into());
            }
        }
        self.store
            .put_json(Domain::Vault, "traffic-jobs", &jobs, now())?;
        Ok(())
    }
}
