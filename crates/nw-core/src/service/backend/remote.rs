use super::*;
use crate::{CoreError, RemoteCompletion};
use nw_proto::TrustLevel;
mod decoys;
mod jobs;
pub(in crate::service) use decoys::{Decoys, prefetch_decoy};
pub use jobs::RemoteSubmission;
pub(in crate::service) use jobs::{
    cancel_remote_job, load_remote_job, load_remote_job_input, load_remote_jobs, start_remote_job,
    submit_remote_job,
};
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteReviewResponse {
    Review {
        review: crate::RemoteReview,
        provider_host: String,
        provider_path: String,
        provider_model: String,
        cost_microusd: u64,
    },
    Chat {
        reply: ChatResponse,
    },
}
enum Action {
    Chat,
    Review { expected_epoch: Option<u64> },
    Approve { approval_id: String, hash: String },
}
pub(in crate::service) fn traffic_status(
    state: &State,
) -> Result<workspace::TrafficStatus, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.traffic_status().map_err(code)
}
pub(in crate::service) async fn traffic_tick(state: &State) -> Result<(), String> {
    prefetch_decoy(state)?;
    traffic_tick_at(state, workspace::now()).await
}
async fn traffic_tick_at(state: &State, at: u64) -> Result<(), String> {
    let ready = {
        let mut pending = state
            .pending_sends
            .lock()
            .map_err(|_| "session_unavailable")?;
        pending.retain(|item| !item.response.is_closed());
        !pending.is_empty()
    };
    let (job, epoch, config, context) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        if s.tail_expired(std::time::Instant::now()) {
            return Ok(());
        }
        if s.timing
            .is_some_and(|clock| !clock.allowed(std::time::Instant::now()))
        {
            return Ok(());
        }
        if s.timing.is_none() && state.egress.is_some() {
            return Err("session_changed".into());
        }
        let tail = s.in_tail();
        let Some(w) = s.workspace.as_mut() else {
            return Ok(());
        };
        let real = !tail && ready && w.config.cover.mode == crate::config::CoverMode::Constant;
        let Some(job) = w.take_traffic_slot(at, real).map_err(code)? else {
            return Ok(());
        };
        (
            job,
            epoch,
            w.config.clone(),
            w.routing_context().map_err(code)?,
        )
    };
    let operation=async {
        if matches!(job.purpose,workspace::TrafficPurpose::Real) {
            let item=state.pending_sends.lock().map_err(|_|CoreError::Session)?.pop_front().ok_or(CoreError::Session)?;
            let QueuedSend {epoch:queued_epoch,conversation,body,config,context,required,job:remote_job,mut response}=item;
            if queued_epoch!=epoch{return Err(CoreError::Session);}
            let route=Route {state:state.clone(),epoch,config,context,required,job:Some(remote_job),scheduled:true};
            let result=tokio::select!{biased;_=response.closed()=>Err(CoreError::Session),result=route.send_now(&conversation,&body)=>result};
            let status=result.as_ref().map(|_|()).map_err(|e|match e {CoreError::Budget=>CoreError::Budget,CoreError::Credential=>CoreError::Credential,CoreError::Session=>CoreError::Session,_=>CoreError::Transport});
            let _=response.send(result);return status;
        }
        let ready=state.decoys.lock().map_err(|_|CoreError::Session)?.take(epoch).ok_or(CoreError::Model)?;
        // The replacement is prepared independently while this slot uses immutable checked bytes.
        prefetch_decoy(state).map_err(|_|CoreError::Session)?;
        let route=Route {state:state.clone(),epoch,context,required:config.shield.min_trust,config,job:None,scheduled:true};
        route.send_now(&ready.conversation,&ready.body).await?;
        Ok(())
    }.await;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    let result = operation.as_ref().map(|_| ()).map_err(|e| match e {
        CoreError::Transport => "remote_transport_unavailable",
        CoreError::Session => "session_changed",
        CoreError::Budget => "network_budget_exhausted",
        CoreError::Credential => "credential_pool_unavailable",
        CoreError::Model => "local_model_unavailable",
        _ => "shield_blocked",
    });
    require_background(&mut s)?
        .finish_traffic_job(&job.id, result)
        .map_err(code)?;
    operation.map_err(code)
}
struct Route {
    scheduled: bool,
    job: Option<String>,
    state: State,
    epoch: u64,
    config: Config,
    context: String,
    required: TrustLevel,
}
pub(super) struct QueuedSend {
    epoch: u64,
    conversation: String,
    body: nw_net::ShapedRequest,
    config: Config,
    context: String,
    required: TrustLevel,
    job: String,
    response: tokio::sync::oneshot::Sender<Result<SecretString, CoreError>>,
}
impl RemoteCompletion for Route {
    fn trust(&self) -> TrustLevel {
        TrustLevel::L3
    }
    fn context(&self) -> &str {
        &self.context
    }
    fn metadata(&self) -> Option<crate::RemoteMetadata<'_>> {
        Some(crate::RemoteMetadata {
            host: self.config.net.provider_host.as_deref()?,
            path: self.config.net.provider_path.as_deref()?,
            model: self.config.net.provider_model.as_deref()?,
        })
    }
    async fn complete(
        &self,
        conversation: &str,
        prepared: &nw_shield::Prepared,
        max_tokens: u32,
    ) -> Result<SecretString, CoreError> {
        if self.required < TrustLevel::L3 {
            return Err(CoreError::Trust);
        }
        if self.config.net.transport != crate::config::Transport::Tor {
            return Err(CoreError::Transport);
        }
        if self.job.is_none() && !self.scheduled {
            let session = self.state.session.lock().map_err(|_| CoreError::Session)?;
            if session.in_tail() || session.epoch != self.epoch {
                return Err(CoreError::Session);
            }
            if session
                .timing
                .is_some_and(|clock| !clock.allowed(std::time::Instant::now()))
            {
                return Err(CoreError::Queue);
            }
        }
        let shaped = nw_net::ShapedRequest::history(
            prepared,
            self.config
                .net
                .provider_model
                .as_deref()
                .ok_or(CoreError::Request)?,
            max_tokens,
        )
        .map_err(|_| CoreError::Blocked)?;
        if self.config.cover.enabled
            && self.config.cover.mode == crate::config::CoverMode::Constant
            && !self.scheduled
        {
            let job = self.job.clone().ok_or(CoreError::Queue)?;
            let (response, received) = tokio::sync::oneshot::channel();
            {
                let mut pending = self
                    .state
                    .pending_sends
                    .lock()
                    .map_err(|_| CoreError::Session)?;
                if pending.len() >= 64 {
                    return Err(CoreError::Limit);
                }
                pending.push_back(QueuedSend {
                    epoch: self.epoch,
                    conversation: conversation.into(),
                    body: shaped,
                    config: self.config.clone(),
                    context: self.context.clone(),
                    required: self.required,
                    job,
                    response,
                });
            }
            let mut changes = self.state.changes.subscribe();
            return tokio::select! {biased;_=changes.wait_for(|e|*e!=self.epoch)=>Err(CoreError::Session),result=received=>result.map_err(|_|CoreError::Session)?};
        }
        self.send_now(conversation, &shaped).await
    }
}
impl Route {
    fn workspace<'a>(&self, session: &'a mut Session) -> Result<&'a mut Workspace, CoreError> {
        if session.epoch != self.epoch
            || session.in_tail() && !(self.scheduled && self.job.is_none())
            || session.tail_expired(std::time::Instant::now())
        {
            return Err(CoreError::Session);
        }
        require_background(session).map_err(|_| CoreError::Session)
    }
    async fn send_now(
        &self,
        conversation: &str,
        shaped: &nw_net::ShapedRequest,
    ) -> Result<SecretString, CoreError> {
        let mut changes = self.state.changes.subscribe();
        let deadline = {
            let mut s = self.state.session.lock().map_err(|_| CoreError::Session)?;
            self.workspace(&mut s)?;
            s.timing.and_then(|clock| clock.tail_deadline())
        };
        let operation = async {
            timing::wait_first(&self.state, self.epoch).await?;
            let network = self.state.egress.as_ref().ok_or(CoreError::Transport)?;
            let _init = self.state.net_start.lock().await;
            let (initialize, bridges) = {
                let mut s = self.state.session.lock().map_err(|_| CoreError::Session)?;
                if s.epoch != self.epoch || s.workspace.is_none() {
                    return Err(CoreError::Session);
                }
                let w = self.workspace(&mut s)?;
                if !w.device_probe_ready().map_err(|_| CoreError::Session)? {
                    return Err(CoreError::DeviceProbe);
                }
                if !w
                    .has_provider_key(conversation, &nw_cred::os::OsProviderSecrets)
                    .map_err(|_| CoreError::Credential)?
                {
                    return Err(CoreError::Credential);
                }
                w.check_network_cost(
                    self.config
                        .net
                        .max_request_cost_microusd
                        .ok_or(CoreError::Budget)?,
                    workspace::now(),
                )
                .map_err(|_| CoreError::Budget)?;
                let bridges = w.bridges().map_err(|_| CoreError::Session)?;
                if s.network_context
                    .as_ref()
                    .is_some_and(|c| c != &self.context)
                {
                    return Err(CoreError::Session);
                }
                (s.network_context.is_none(), bridges)
            };
            if initialize {
                let path = Paths::discover()
                    .map_err(|_| CoreError::Transport)?
                    .data
                    .join("network/tor");
                network
                    .initialize_with_bridges(
                        &path,
                        self.config
                            .net
                            .provider_host
                            .as_deref()
                            .ok_or(CoreError::Request)?,
                        self.config
                            .net
                            .provider_path
                            .as_deref()
                            .ok_or(CoreError::Request)?,
                        bridges,
                    )
                    .await
                    .map_err(|_| CoreError::Transport)?;
                let mut s = self.state.session.lock().map_err(|_| CoreError::Session)?;
                if s.epoch != self.epoch {
                    return Err(CoreError::Session);
                }
                s.network_context = Some(self.context.clone());
            }
            drop(_init);
            // The pause does not expose user text and is cancellable before charging.
            use rand::Rng;
            let seconds = rand::rngs::OsRng.gen_range(2..=8);
            tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
            let key = {
                let mut s = self.state.session.lock().map_err(|_| CoreError::Session)?;
                if s.epoch != self.epoch {
                    return Err(CoreError::Session);
                }
                let now = std::time::Instant::now();
                if !s.timing.is_some_and(|clock| clock.allowed(now)) {
                    return Err(CoreError::Session);
                }
                let w = self.workspace(&mut s)?;
                if !w.device_probe_ready().map_err(|_| CoreError::Session)? {
                    return Err(CoreError::DeviceProbe);
                }
                let key = if self.scheduled && self.job.is_none() {
                    w.consume_provider_key(conversation, &nw_cred::os::OsProviderSecrets)
                } else {
                    w.acquire_provider_key(conversation, &nw_cred::os::OsProviderSecrets)
                }
                .map_err(|_| CoreError::Credential)?;
                w.reserve_network_cost(
                    self.config
                        .net
                        .max_request_cost_microusd
                        .ok_or(CoreError::Budget)?,
                    workspace::now(),
                )
                .map_err(|_| CoreError::Budget)?;
                if let Some(id) = &self.job {
                    w.remote_job_sending(id).map_err(|_| CoreError::Session)?;
                }
                key
            };
            let result = if self.scheduled && self.job.is_none() {
                network
                    .send_once(conversation, shaped, key.expose_secret())
                    .await
            } else {
                network
                    .send(conversation, shaped, key.expose_secret())
                    .await
            };
            let text = SecretString::from(result.map_err(|_| CoreError::Transport)?);
            {
                let mut session = self.state.session.lock().map_err(|_| CoreError::Session)?;
                if session.epoch != self.epoch {
                    return Err(CoreError::Session);
                }
                self.workspace(&mut session)?
                    .count_delivery(self.scheduled && self.job.is_none())
                    .map_err(|_| CoreError::Session)?;
            }
            Ok(text)
        };
        tokio::select! {biased;
            _=changes.wait_for(|epoch|*epoch!=self.epoch)=>Err(CoreError::Session),
            _=async { if let Some(end) = deadline { tokio::time::sleep_until(end.into()).await; } else { std::future::pending::<()>().await; } }=>Err(CoreError::Session),
            result=operation=>result,
        }
    }
}

pub(in crate::service) async fn remote_chat(
    conversation: String,
    messages: Vec<Message>,
    max_tokens: Option<u32>,
    min_trust: Option<TrustLevel>,
    state: &State,
) -> Result<ChatResponse, String> {
    match remote_action(
        conversation,
        messages,
        max_tokens,
        min_trust,
        Action::Chat,
        state,
    )
    .await?
    {
        RemoteReviewResponse::Chat { reply } => Ok(reply),
        RemoteReviewResponse::Review { .. } => Err("approval_required".into()),
    }
}
pub(in crate::service) async fn review_remote(
    conversation: String,
    messages: Vec<Message>,
    max_tokens: Option<u32>,
    state: &State,
) -> Result<RemoteReviewResponse, String> {
    remote_action(
        conversation,
        messages,
        max_tokens,
        None,
        Action::Review {
            expected_epoch: None,
        },
        state,
    )
    .await
}
pub(in crate::service) async fn approve_remote(
    approval_id: String,
    hash: String,
    state: &State,
) -> Result<ChatResponse, String> {
    match remote_action(
        "new".into(),
        vec![],
        None,
        None,
        Action::Approve { approval_id, hash },
        state,
    )
    .await?
    {
        RemoteReviewResponse::Chat { reply } => Ok(reply),
        RemoteReviewResponse::Review { .. } => Err("approval_required".into()),
    }
}
pub(in crate::service) async fn cancel_remote(
    approval_id: String,
    state: &State,
) -> Result<(), String> {
    let engine = state
        .session
        .lock()
        .map_err(|_| "session_unavailable")?
        .engine
        .clone()
        .ok_or("workspace_locked")?;
    engine.cancel_remote(&approval_id).await;
    Ok(())
}
async fn remote_action(
    conversation: String,
    messages: Vec<Message>,
    max_tokens: Option<u32>,
    min_trust: Option<TrustLevel>,
    action: Action,
    state: &State,
) -> Result<RemoteReviewResponse, String> {
    let (epoch, engine, snapshot, config, context) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        if let Action::Review {
            expected_epoch: Some(expected),
        } = &action
            && epoch != *expected
        {
            return Err("session_changed".into());
        }
        let engine = s.engine.clone().ok_or("workspace_locked")?;
        let w = require(&mut s)?;
        let snapshot = if conversation == "new" {
            None
        } else {
            Some(
                w.conversation_snapshot(&conversation)
                    .map_err(code)?
                    .ok_or("invalid_conversation")?,
            )
        };
        (
            epoch,
            engine,
            snapshot,
            w.config.clone(),
            w.routing_context().map_err(code)?,
        )
    };
    if let Some(snapshot) = snapshot {
        engine
            .restore_if_missing(&conversation, snapshot)
            .await
            .map_err(code)?;
    }
    let required = config
        .shield
        .min_trust
        .min(min_trust.unwrap_or(TrustLevel::L3));
    let route = Route {
        scheduled: false,
        job: None,
        state: state.clone(),
        epoch,
        config,
        context,
        required,
    };
    let reply = match action {
        Action::Chat => engine
            .chat_remote(
                &conversation,
                &messages,
                max_tokens.unwrap_or(2048),
                &route,
                None,
            )
            .await
            .map(crate::RemoteStep::Chat),
        Action::Review { .. } => {
            engine
                .review_remote(&conversation, &messages, max_tokens.unwrap_or(2048), &route)
                .await
        }
        Action::Approve { approval_id, hash } => engine
            .approve_remote(&approval_id, &hash, &route)
            .await
            .map(crate::RemoteStep::Chat),
    };
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    let w = require(&mut s)?;
    match reply {
        Ok(crate::RemoteStep::Review(review)) => Ok(RemoteReviewResponse::Review {
            review,
            provider_host: route
                .config
                .net
                .provider_host
                .clone()
                .ok_or("invalid_request")?,
            provider_path: route
                .config
                .net
                .provider_path
                .clone()
                .ok_or("invalid_request")?,
            provider_model: route
                .config
                .net
                .provider_model
                .clone()
                .ok_or("invalid_request")?,
            cost_microusd: route
                .config
                .net
                .max_request_cost_microusd
                .ok_or("invalid_request")?,
        }),
        Ok(crate::RemoteStep::Chat(reply)) => {
            w.save_chat_reply(&reply).map_err(code)?;
            w.count_shadow(false).map_err(code)?;
            Ok(RemoteReviewResponse::Chat {
                reply: ChatResponse {
                    conversation: reply.conversation,
                    text: reply.text.expose_secret().into(),
                    trust: reply.trust,
                    local_reason: reply.local_reason,
                },
            })
        }
        Err(error) => {
            if error == CoreError::Blocked {
                w.count_shadow(true).map_err(code)?;
            }
            Err(code(error))
        }
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;
    use nw_platform::LockedKey;
    use nw_vault::{VaultError, os_secret::SecretStore};
    #[derive(Default)]
    struct Keys(Mutex<std::collections::BTreeMap<String, LockedKey>>);
    impl SecretStore for Keys {
        fn put(&self, id: &str, key: &LockedKey) -> Result<(), VaultError> {
            self.0
                .lock()
                .unwrap()
                .insert(id.into(), key.copy().map_err(|_| VaultError::MemoryLock)?);
            Ok(())
        }
        fn get(&self, id: &str) -> Result<LockedKey, VaultError> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .ok_or(VaultError::OsSecret)?
                .copy()
                .map_err(|_| VaultError::MemoryLock)
        }
        fn remove(&self, id: &str) -> Result<(), VaultError> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }
    }
    struct Model;
    impl LocalModel for Model {
        async fn embed_identified(
            &self,
            texts: &[String],
        ) -> Result<nw_llm::EmbeddingBatch, nw_llm::ModelError> {
            Ok(crate::link_fixture::identified(texts))
        }
        async fn identify_entities(&self, _: &str) -> Result<SecretString, nw_llm::ModelError> {
            Ok(SecretString::from(r#"{"local_only":false,"entities":[]}"#))
        }
        async fn canonicalize(&self, t: &str) -> Result<SecretString, nw_llm::ModelError> {
            Ok(SecretString::from(t.to_owned()))
        }
        async fn complete(&self, _: &[Message]) -> Result<SecretString, nw_llm::ModelError> {
            Err(nw_llm::ModelError::Unavailable)
        }
        async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, nw_llm::ModelError> {
            Err(nw_llm::ModelError::Unavailable)
        }
    }
    #[tokio::test]
    async fn submission_receipts_survive_restart_and_never_reexecute_or_disclose_keys() {
        use sha2::Digest;
        use workspace::submissions::{Reservation, SubmissionOutcome};
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("receipts");
        let keys = Arc::new(Keys::default());
        let mut w = Workspace::create_with(
            &root,
            SecretString::from(""),
            nw_proto::Profile::Standard,
            keys.clone(),
        )
        .unwrap();
        let key = "SYNTHETIC_IDEMPOTENCY_CANARY_77013";
        let digest = format!("{:x}", sha2::Sha256::digest(key));
        let input = || {
            vec![Message {
                role: nw_llm::Role::User,
                content: "Explain synthetic pottery".into(),
            }]
        };
        let bytes = serde_json::to_vec(&(
            "submit-remote-job-v1",
            "new",
            input(),
            32u32,
            None::<TrustLevel>,
        ))
        .unwrap();
        let fingerprint = format!("{:x}", sha2::Sha256::digest(bytes));
        assert!(matches!(
            w.reserve_submission(&digest, &fingerprint).unwrap(),
            Reservation::New
        ));
        drop(w);
        let w = Workspace::open_with(&root, SecretString::from(""), keys).unwrap();
        let state = State::default();
        state.session.lock().unwrap().workspace = Some(w);
        // No model is configured in State: every replay path must return before inference.
        let result = submit_remote_job(
            "new".into(),
            input(),
            Some(32),
            None,
            Some(key.into()),
            None,
            &state,
        )
        .await;
        assert!(matches!(result,Err(e) if e=="idempotency_uncertain"));
        let result = submit_remote_job(
            "new".into(),
            input(),
            Some(33),
            None,
            Some(key.into()),
            None,
            &state,
        )
        .await;
        assert!(matches!(result,Err(e) if e=="idempotency_conflict"));
        let result = submit_remote_job(
            "new".into(),
            input(),
            Some(32),
            Some(TrustLevel::L0),
            Some(key.into()),
            None,
            &state,
        )
        .await;
        assert!(matches!(result,Err(e) if e=="idempotency_conflict"));
        {
            let mut session = state.session.lock().unwrap();
            let w = require(&mut session).unwrap();
            w.save_submission_reply(
                &digest,
                &ChatResponse {
                    local_reason: None,
                    conversation: "a".repeat(32),
                    text: "synthetic saved answer".into(),
                    trust: TrustLevel::L0,
                },
            )
            .unwrap();
        }
        let RemoteSubmission::Chat { reply } = submit_remote_job(
            "new".into(),
            input(),
            Some(32),
            None,
            Some(key.into()),
            None,
            &state,
        )
        .await
        .unwrap() else {
            panic!("local result expected")
        };
        assert_eq!(reply.text, "synthetic saved answer");
        {
            let mut session = state.session.lock().unwrap();
            let w = require(&mut session).unwrap();
            w.shred(nw_vault::Domain::ShadowHistory).unwrap();
            let expired = w.submission_reply(&digest);
            assert!(matches!(
                expired,
                Err(workspace::WorkspaceError::IdempotencyExpired)
            ));
            // A pruned remote job retains its receipt, rather than authorizing another send.
            let key = format!("{:x}", sha2::Sha256::digest("SYNTHETIC_REMOTE_RECEIPT_KEY"));
            w.reserve_submission(&key, &fingerprint).unwrap();
            w.finish_submission(&key, SubmissionOutcome::Job { id: "b".repeat(64) })
                .unwrap();
        }
        let result = submit_remote_job(
            "new".into(),
            input(),
            Some(32),
            None,
            Some("SYNTHETIC_REMOTE_RECEIPT_KEY".into()),
            None,
            &state,
        )
        .await;
        assert!(matches!(result,Err(e) if e=="idempotency_expired"));
        drop(state);
        for file in std::fs::read_dir(&root).unwrap() {
            let path = file.unwrap().path();
            if path.is_file() {
                let bytes = std::fs::read(path).unwrap();
                for marker in [key, "synthetic saved answer", "Explain synthetic pottery"] {
                    assert!(!bytes.windows(marker.len()).any(|s| s == marker.as_bytes()));
                }
            }
        }
    }
    #[tokio::test]
    async fn constant_real_request_waits_for_slot_and_budget_without_leaking_canary() {
        let directory = tempfile::tempdir().unwrap();
        let mut w = Workspace::create_with(
            &directory.path().join("queue"),
            SecretString::from(""),
            nw_proto::Profile::Standard,
            Arc::new(Keys::default()),
        )
        .unwrap();
        let mut config = w.config.clone();
        config.cover.enabled = true;
        config.cover.mode = crate::config::CoverMode::Constant;
        config.cover.mean_interval_s = 10;
        config.cover.max_requests_per_day = 1;
        config.net = crate::config::NetConfig {
            transport: crate::config::Transport::Tor,
            provider_host: Some("example.test".into()),
            provider_path: Some("/v1/chat/completions".into()),
            credential_ref: Some("keyring:pool".into()),
            provider_model: Some("synthetic".into()),
            max_request_cost_microusd: Some(1),
        };
        w.save_config(config.clone()).unwrap();
        w.set_secrets(vec![SecretRecord {
            kind: nw_shield::SecretKind::Secret,
            value: "CONST_QUEUE_CANARY_59013".into(),
            local_only: false,
        }])
        .unwrap();
        let engine =
            Arc::new(crate::link_fixture::configured(Model, w.shield().unwrap(), &config).unwrap());
        let at = 1_000_000;
        assert!(w.take_traffic_slot(at, false).unwrap().is_none());
        let state = State::default();
        state.session.lock().unwrap().workspace = Some(w);
        let mut route = Route {
            scheduled: false,
            job: None,
            state: state.clone(),
            epoch: 0,
            config,
            context: "a".repeat(64),
            required: TrustLevel::L3,
        };
        let input = [Message {
            role: nw_llm::Role::User,
            content: "Explain pottery for CONST_QUEUE_CANARY_59013".into(),
        }];
        // Even an overdue slot cannot spend budget or leave during the first delay.
        state.session.lock().unwrap().timing = Some(nw_cover::session::Clock::new(
            std::time::Instant::now(),
            &mut rand::rngs::OsRng,
        ));
        traffic_tick_at(&state, at + 86400).await.unwrap();
        assert!(
            require(&mut state.session.lock().unwrap())
                .unwrap()
                .traffic_status()
                .unwrap()
                .jobs
                .is_empty()
        );
        state.session.lock().unwrap().timing = Some(nw_cover::session::Clock::new(
            std::time::Instant::now() - std::time::Duration::from_secs(3600),
            &mut rand::rngs::OsRng,
        ));
        let crate::RemoteStep::Review(review) = engine
            .review_remote("new", &input, 32, &route)
            .await
            .unwrap()
        else {
            panic!("review expected")
        };
        let approved = engine
            .take_remote_approval(&review.approval_id, &review.hash, &route)
            .await
            .unwrap();
        let info = require(&mut state.session.lock().unwrap())
            .unwrap()
            .create_remote_job(&approved, 0)
            .unwrap();
        route.job = Some(info.id.clone());
        let sending = tokio::spawn(async move { engine.complete_approved(approved, &route).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if !state.pending_sends.lock().unwrap().is_empty() {
                    break;
                }
                assert!(!sending.is_finished());
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            !std::str::from_utf8(state.pending_sends.lock().unwrap()[0].body.bytes())
                .unwrap()
                .contains("CONST_QUEUE_CANARY_59013")
        );
        traffic_tick_at(&state, at + 9).await.unwrap();
        assert!(!sending.is_finished());
        require(&mut state.session.lock().unwrap())
            .unwrap()
            .reserve_network_cost(1, at)
            .unwrap();
        traffic_tick_at(&state, at + 10).await.unwrap();
        assert!(!sending.is_finished());
        assert_eq!(state.pending_sends.lock().unwrap().len(), 1);
        // A later UTC day releases a slot. No transport is installed, so it fails closed.
        assert_eq!(
            traffic_tick_at(&state, at + 86400).await.unwrap_err(),
            "remote_transport_unavailable"
        );
        assert!(matches!(sending.await.unwrap(), Err(CoreError::Transport)));
        assert!(state.pending_sends.lock().unwrap().is_empty());
    }
}
