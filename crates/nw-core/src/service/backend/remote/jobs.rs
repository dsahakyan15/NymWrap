use super::*;
use sha2::Digest;
use workspace::submissions::{Reservation, SubmissionOutcome, valid_key};
use workspace::{RemoteJobInfo, RemoteJobReply, RemoteJobState, RemoteJobView};
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteSubmission {
    Chat { reply: ChatResponse },
    Job { job: RemoteJobView },
}
pub(in crate::service) async fn submit_remote_job(
    conversation: String,
    messages: Vec<Message>,
    max_tokens: Option<u32>,
    min_trust: Option<TrustLevel>,
    idempotency_key: Option<String>,
    defer_hours: Option<u16>,
    state: &State,
) -> Result<RemoteSubmission, String> {
    if defer_hours.is_some_and(|n| n > nw_cover::defer::MAX_HOURS) {
        return Err("invalid_defer_window".into());
    }
    // Reserve before calling any model. Never persist or forward the caller's key.
    let receipt = if let Some(key) = idempotency_key.map(Zeroizing::new) {
        if !valid_key(&key) {
            return Err("invalid_idempotency_key".into());
        }
        let key_hash = format!("{:x}", sha2::Sha256::digest(key.as_bytes()));
        let base = (
            "submit-remote-job-v1",
            &conversation,
            &messages,
            max_tokens.unwrap_or(2048),
            min_trust,
        );
        // Preserve existing receipts when the caller did not add a release window.
        let bytes = Zeroizing::new(
            if let Some(hours) = defer_hours {
                serde_json::to_vec(&("submit-remote-job-defer-v2", &base, hours))
            } else {
                serde_json::to_vec(&base)
            }
            .map_err(|_| "invalid_request")?,
        );
        let fingerprint = format!("{:x}", sha2::Sha256::digest(&*bytes));
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        let w = require(&mut s)?;
        match w
            .reserve_submission(&key_hash, &fingerprint)
            .map_err(code)?
        {
            Reservation::New => Some((key_hash, epoch)),
            Reservation::Existing(outcome) => {
                return match outcome {
                    SubmissionOutcome::Pending => Err("idempotency_uncertain".into()),
                    SubmissionOutcome::Failed { code } => Err(code),
                    SubmissionOutcome::Local => w
                        .submission_reply(&key_hash)
                        .map(|reply| RemoteSubmission::Chat { reply })
                        .map_err(code),
                    SubmissionOutcome::Job { id } => {
                        // A pruned job is a tombstone, never permission to submit again.
                        if !w.remote_jobs().map_err(code)?.iter().any(|j| j.id == id) {
                            return Err("idempotency_expired".into());
                        }
                        drop(s);
                        let job = load_remote_job(id, state)?;
                        if job.info.state == RemoteJobState::Expired {
                            Err("idempotency_expired".into())
                        } else {
                            Ok(RemoteSubmission::Job { job })
                        }
                    }
                };
            }
        }
    } else {
        None
    };
    let result = submit_reserved_job(
        conversation,
        messages,
        max_tokens,
        min_trust,
        receipt.as_ref(),
        defer_hours,
        state,
    )
    .await;
    if let (Some((key, epoch)), Err(error)) = (&receipt, &result) {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        if s.epoch == *epoch {
            require(&mut s)?
                .finish_submission(
                    key,
                    SubmissionOutcome::Failed {
                        code: error.clone(),
                    },
                )
                .map_err(code)?;
        }
    }
    result
}
async fn submit_reserved_job(
    conversation: String,
    messages: Vec<Message>,
    max_tokens: Option<u32>,
    min_trust: Option<TrustLevel>,
    receipt: Option<&(String, u64)>,
    defer_hours: Option<u16>,
    state: &State,
) -> Result<RemoteSubmission, String> {
    let (epoch, required) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        if receipt.is_some_and(|(_, reserved_epoch)| *reserved_epoch != epoch) {
            return Err("session_changed".into());
        }
        let config = &require(&mut s)?.config;
        if config.shield.show_diff_before_send {
            return Err("approval_required".into());
        }
        (
            epoch,
            config
                .shield
                .min_trust
                .min(min_trust.unwrap_or(TrustLevel::L3)),
        )
    };
    let result = remote_action(
        conversation,
        messages,
        max_tokens,
        min_trust,
        Action::Review {
            expected_epoch: Some(epoch),
        },
        state,
    )
    .await?;
    match result {
        RemoteReviewResponse::Chat { reply } => {
            if let Some((key, reserved_epoch)) = receipt {
                let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
                if s.epoch != *reserved_epoch {
                    return Err("session_changed".into());
                }
                require(&mut s)?
                    .save_submission_reply(key, &reply)
                    .map_err(code)?;
            }
            Ok(RemoteSubmission::Chat { reply })
        }
        RemoteReviewResponse::Review { review, .. } => {
            let policy = {
                let s = state.session.lock().map_err(|_| "session_unavailable")?;
                if s.epoch != epoch {
                    Err("session_changed")
                } else if review.trust > required {
                    Err("trust_policy_violation")
                } else {
                    Ok(())
                }
            };
            if let Err(error) = policy {
                cancel_remote(review.approval_id.clone(), state).await?;
                return Err(error.into());
            }
            // Any concurrent config change replaces Engine and invalidates this capability.
            let job = start_job(
                review.approval_id.clone(),
                review.hash.clone(),
                receipt,
                defer_hours,
                state,
            )
            .await?;
            Ok(RemoteSubmission::Job { job })
        }
    }
}
pub(in crate::service) async fn start_remote_job(
    approval_id: String,
    hash: String,
    state: &State,
) -> Result<RemoteJobView, String> {
    start_job(approval_id, hash, None, None, state).await
}
async fn start_job(
    approval_id: String,
    hash: String,
    receipt: Option<&(String, u64)>,
    defer_hours: Option<u16>,
    state: &State,
) -> Result<RemoteJobView, String> {
    let (epoch, engine, config, context) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        if receipt.is_some_and(|(_, reserved_epoch)| *reserved_epoch != epoch) {
            return Err("session_changed".into());
        }
        let engine = s.engine.clone().ok_or("workspace_locked")?;
        let w = require(&mut s)?;
        (
            epoch,
            engine,
            w.config.clone(),
            w.routing_context().map_err(code)?,
        )
    };
    let mut route = Route {
        slot: None,
        job: None,
        state: state.clone(),
        epoch,
        required: config.shield.min_trust,
        context,
        config,
    };
    let approved = engine
        .take_remote_approval(&approval_id, &hash, &route)
        .await
        .map_err(code)?;
    let not_before = nw_cover::defer::not_before(
        workspace::now(),
        defer_hours.unwrap_or(route.config.hard.defer_max_hours),
        &mut rand::rngs::OsRng,
    )
    .map_err(|_| "invalid_defer_window")?;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    let first_floor = s.timing.map_or(0, |clock| {
        workspace::now().saturating_add(nw_cover::session::remaining_seconds(
            clock.first_remaining(std::time::Instant::now()),
        ))
    });
    let not_before = not_before.max(first_floor);
    let info = require(&mut s)?
        .create_remote_job(&approved, not_before)
        .map_err(code)?;
    // Link durably before spawning: a lost reply or crash can only observe this job.
    if let Some((key, _)) = receipt {
        require(&mut s)?
            .finish_submission(
                key,
                SubmissionOutcome::Job {
                    id: info.id.clone(),
                },
            )
            .map_err(code)?;
    }
    route.job = Some(info.id.clone());
    let job_id = info.id.clone();
    let worker_state = state.clone();
    let mut running = state.jobs.lock().map_err(|_| "session_unavailable")?;
    let worker = tokio::spawn(async move {
        // A clock rollback must never advance a deferred send. Cancellation aborts
        // this worker; restart preserves metadata but never replays the approval.
        while workspace::now() < not_before {
            tokio::time::sleep(std::time::Duration::from_secs(
                not_before.saturating_sub(workspace::now()),
            ))
            .await;
        }
        let reply = engine.complete_approved(approved, &route).await;
        if let Ok(mut session) = worker_state.session.lock()
            && session.epoch == epoch
            && let Some(w) = session.workspace.as_mut()
        {
            let result = match reply {
                Ok(reply) => {
                    match w
                        .save_chat_reply(&reply)
                        .and_then(|()| w.count_shadow(false))
                    {
                        Ok(()) => Ok(RemoteJobReply {
                            local_reason: reply.local_reason,
                            conversation: reply.conversation,
                            text: reply.text.expose_secret().into(),
                            trust: reply.trust,
                        }),
                        Err(_) => Err("remote_result_storage_failed"),
                    }
                }
                Err(error) => {
                    if error == CoreError::Blocked {
                        let _ = w.count_shadow(true);
                    }
                    Err(match error {
                        CoreError::Blocked => "shield_blocked",
                        CoreError::Budget => "network_budget_exhausted",
                        CoreError::Credential => "credential_pool_unavailable",
                        CoreError::Transport => "remote_transport_unavailable",
                        CoreError::Session => "session_changed",
                        CoreError::Trust => "trust_policy_violation",
                        CoreError::Approval => "approval_required",
                        CoreError::DeviceProbe => "device_probe_required",
                        _ => "remote_job_failed",
                    })
                }
            };
            let _ = w.finish_remote_job(&job_id, result);
        }
        if let Ok(mut jobs) = worker_state.jobs.lock() {
            jobs.remove(&job_id);
        }
    });
    running.insert(info.id.clone(), worker.abort_handle());
    Ok(RemoteJobView { info, reply: None })
}
pub(in crate::service) fn load_remote_jobs(state: &State) -> Result<Vec<RemoteJobInfo>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.remote_jobs().map_err(code)
}
pub(in crate::service) fn load_remote_job(
    id: String,
    state: &State,
) -> Result<RemoteJobView, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    let w = require(&mut s)?;
    let mut view = w.remote_job(&id).map_err(code)?;
    if matches!(
        view.info.state,
        RemoteJobState::Queued | RemoteJobState::Sending
    ) && !state
        .jobs
        .lock()
        .map_err(|_| "session_unavailable")?
        .contains_key(&id)
    {
        w.finish_remote_job(&id, Err("session_changed"))
            .map_err(code)?;
        view = w.remote_job(&id).map_err(code)?;
    }
    Ok(view)
}
pub(in crate::service) fn cancel_remote_job(id: String, state: &State) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.cancel_remote_job(&id).map_err(code)?;
    if let Some(worker) = state
        .jobs
        .lock()
        .map_err(|_| "session_unavailable")?
        .remove(&id)
    {
        worker.abort();
    }
    Ok(())
}
pub(in crate::service) fn load_remote_job_input(
    id: String,
    state: &State,
) -> Result<Vec<Message>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.remote_job_messages(&id).map_err(code)
}
