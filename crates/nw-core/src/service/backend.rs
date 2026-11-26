use crate::{
    Engine,
    config::{Config, Paths},
    workspace::{self, Overview, Persona, Review, SecretRecord, Workspace},
};
use nw_llm::{LocalModel, Message, UnixModel};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;
mod device;
mod remote;
mod timing;
pub(super) use device::{device_probe_status, maybe_device_probe, run_device_probe};
pub use remote::{RemoteReviewResponse, RemoteSubmission};
pub(super) use remote::{
    approve_remote, cancel_remote, remote_chat, review_remote, traffic_status, traffic_tick,
};
pub(super) use remote::{
    cancel_remote_job, load_remote_job, load_remote_job_input, load_remote_jobs, start_remote_job,
    submit_remote_job,
};
pub use timing::{Phase as SessionPhase, SessionTiming};
pub(super) use timing::{close_session, expire_tail, session_timing, tail_wait};

#[derive(Default)]
pub(super) struct Session {
    pub(super) epoch: u64,
    workspace: Option<Workspace>,
    engine: Option<Arc<Engine<UnixModel>>>,
    model: Option<OwnedModel>,
    network_context: Option<String>,
    timing: Option<nw_cover::session::Clock>,
    tail_wall_deadline: Option<u64>,
}
impl Session {
    pub(super) fn in_tail(&self) -> bool {
        self.timing
            .is_some_and(|clock| clock.tail_deadline().is_some())
    }
    fn tail_expired(&self, now: std::time::Instant) -> bool {
        self.timing
            .and_then(|c| c.tail_deadline())
            .is_some_and(|end| {
                now >= end
                    || self
                        .tail_wall_deadline
                        .is_none_or(|wall| workspace::now() >= wall)
            })
    }
}
struct OwnedModel {
    #[cfg(not(windows))]
    child: Arc<Mutex<nw_sandbox::daemon::Child>>,
    #[cfg(not(windows))]
    _lifetime: nw_sandbox::daemon::Input,
    #[cfg(windows)]
    worker: Arc<nw_llm::windows_worker::WindowsModel>,
}
#[cfg(windows)]
impl Drop for OwnedModel {
    fn drop(&mut self) {
        self.worker.stop();
    }
}
#[derive(Clone)]
pub(super) struct State {
    pub(super) session: Arc<Mutex<Session>>,
    egress: Option<Arc<nw_net::client::Client>>,
    model_start: Arc<tokio::sync::Mutex<()>>,
    probe_start: Arc<tokio::sync::Mutex<()>>,
    changes: tokio::sync::watch::Sender<u64>,
    net_start: Arc<tokio::sync::Mutex<()>>,
    jobs: Arc<Mutex<std::collections::BTreeMap<String, tokio::task::AbortHandle>>>,
    pending_sends: Arc<Mutex<std::collections::VecDeque<remote::QueuedSend>>>,
    decoys: Arc<Mutex<remote::Decoys>>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            session: Arc::default(),
            egress: None,
            model_start: Arc::default(),
            probe_start: Arc::default(),
            changes: tokio::sync::watch::channel(0).0,
            net_start: Arc::default(),
            jobs: Arc::default(),
            pending_sends: Arc::default(),
            decoys: Arc::default(),
        }
    }
}
impl State {
    pub(super) fn runtime(egress: Option<Arc<nw_net::client::Client>>) -> Self {
        Self {
            egress,
            ..Default::default()
        }
    }
    fn invalidate(&self, session: &mut Session) {
        self.invalidate_with_decoy(session, false);
    }
    fn invalidate_with_decoy(&self, session: &mut Session, preserve: bool) {
        if let Ok(mut decoys) = self.decoys.lock() {
            if preserve {
                decoys.carry(session.epoch, session.epoch.wrapping_add(1));
            } else {
                decoys.clear();
            }
        }
        if let Ok(mut pending) = self.pending_sends.lock() {
            pending.clear();
        }
        if let Ok(mut jobs) = self.jobs.lock() {
            for (_, job) in std::mem::take(&mut *jobs) {
                job.abort();
            }
        }
        session.epoch = session.epoch.wrapping_add(1);
        self.changes.send_replace(session.epoch);
    }
}
pub(super) fn path() -> Result<PathBuf, String> {
    Ok(Paths::discover().map_err(code)?.data.join("store"))
}
pub(super) fn code(e: impl std::fmt::Display) -> String {
    e.to_string()
}
pub(super) fn require(session: &mut Session) -> Result<&mut Workspace, String> {
    if session.in_tail() {
        return Err("workspace_locked".into());
    }
    require_background(session)
}
fn require_background(session: &mut Session) -> Result<&mut Workspace, String> {
    session
        .workspace
        .as_mut()
        .ok_or_else(|| "workspace_locked".into())
}
pub(super) fn refresh_engine(session: &mut Session) -> Result<(), String> {
    let model = local_model(session)?;
    let w = require(session)?;
    let references = w.linkcheck_references().map_err(code)?;
    let engine = Engine::configured(model, w.shield().map_err(code)?, &w.config)
        .map_err(code)?
        .with_linkcheck(references);
    session.engine = Some(Arc::new(engine));
    Ok(())
}
fn local_model(session: &mut Session) -> Result<UnixModel, String> {
    let model = require_background(session)?.model().map_err(code)?;
    Ok(match &session.model {
        Some(owned) => {
            #[cfg(windows)]
            {
                model.expect_windows_worker(&owned.worker)
            }
            #[cfg(not(windows))]
            {
                model.expect_sandboxed_peer(&owned.child)
            }
        }
        None => model,
    })
}
#[derive(Serialize, Deserialize)]
pub struct StorageStatus {
    egress_available: bool,
    model_managed: bool,
    exists: bool,
    unlocked: bool,
    path: String,
    overview: Option<Overview>,
}
pub(super) fn storage_status(
    session: &mut Session,
    egress_available: bool,
) -> Result<StorageStatus, String> {
    let path = path()?;
    Ok(StorageStatus {
        egress_available,
        model_managed: !session.in_tail() && session.model.is_some(),
        exists: path.join("root.nwenc").exists(),
        unlocked: !session.in_tail() && session.workspace.is_some(),
        path: path.to_string_lossy().into_owned(),
        overview: if session.in_tail() {
            None
        } else {
            session
                .workspace
                .as_mut()
                .map(Workspace::overview)
                .transpose()
                .map_err(code)?
        },
    })
}
pub(super) fn status() -> crate::Status {
    crate::status()
}
pub(super) fn workspace_status(state: &State) -> Result<StorageStatus, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    storage_status(&mut s, state.egress.is_some())
}
pub(super) async fn open_workspace(
    password: String,
    create: bool,
    profile: nw_proto::Profile,
    state: &State,
) -> Result<StorageStatus, String> {
    let password = SecretString::from(password);
    let epoch = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        if s.in_tail() {
            state.invalidate(&mut s);
            let epoch = s.epoch;
            *s = Session {
                epoch,
                ..Default::default()
            };
        }
        if s.workspace.is_some() {
            return Err("workspace_already_open".into());
        }
        state.invalidate(&mut s);
        s.epoch
    };
    let root = path()?;
    let workspace = tokio::task::spawn_blocking(move || {
        if create {
            Workspace::create(&root, password, profile)
        } else {
            Workspace::open(&root, password)
        }
    })
    .await
    .map_err(|_| "workspace_unavailable")?
    .map_err(code)?;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    s.workspace = Some(workspace);
    s.timing = Some(nw_cover::session::Clock::new(
        std::time::Instant::now(),
        &mut rand::rngs::OsRng,
    ));
    refresh_engine(&mut s)?;
    storage_status(&mut s, state.egress.is_some())
}
pub(super) fn clear_session(state: &State) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    state.invalidate(&mut s);
    let epoch = s.epoch;
    *s = Session {
        epoch,
        ..Default::default()
    };
    Ok(())
}
pub(super) fn preview_shield(input: crate::PreviewInput) -> Result<crate::Preview, String> {
    crate::preview(input).map_err(code)
}
pub(super) fn load_secrets(state: &State) -> Result<Vec<SecretRecord>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.secrets().map_err(code)
}
pub(super) fn provider_keys(state: &State) -> Result<Vec<workspace::CredentialInfo>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?
        .provider_keys(&nw_cred::os::OsProviderSecrets)
        .map_err(code)
}
pub(super) fn add_provider_key(
    key: String,
    state: &State,
) -> Result<Vec<workspace::CredentialInfo>, String> {
    let key = SecretString::from(key);
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?
        .add_provider_key(key, &nw_cred::os::OsProviderSecrets)
        .map_err(code)?;
    require(&mut s)?
        .provider_keys(&nw_cred::os::OsProviderSecrets)
        .map_err(code)
}
pub(super) fn retire_provider_key(
    id: String,
    state: &State,
) -> Result<Vec<workspace::CredentialInfo>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    state.invalidate(&mut s);
    require(&mut s)?
        .retire_provider_key(&id, &nw_cred::os::OsProviderSecrets)
        .map_err(code)?;
    require(&mut s)?
        .provider_keys(&nw_cred::os::OsProviderSecrets)
        .map_err(code)
}
pub(super) fn save_secrets(secrets: Vec<SecretRecord>, state: &State) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.set_secrets(secrets).map_err(code)?;
    state.invalidate(&mut s);
    refresh_engine(&mut s)
}
pub(super) fn load_config(state: &State) -> Result<Config, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    Ok(require(&mut s)?.config.clone())
}
pub(super) fn load_bridge_status(state: &State) -> Result<nw_net::bridges::BridgeStatus, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.bridge_status().map_err(code)
}
pub(super) fn save_bridges(
    config: Option<nw_net::bridges::BridgeConfig>,
    state: &State,
) -> Result<nw_net::bridges::BridgeStatus, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    let status = require(&mut s)?.set_bridges(config).map_err(code)?;
    state.invalidate(&mut s);
    refresh_engine(&mut s)?;
    Ok(status)
}
pub(super) fn network_usage(state: &State) -> Result<nw_cover::budget::Usage, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.network_usage().map_err(code)
}
pub(super) fn save_config(config: Config, state: &State) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    let changed = require(&mut s)?.config.llm != config.llm;
    require(&mut s)?.save_config(config).map_err(code)?;
    if changed {
        s.model = None;
    }
    state.invalidate(&mut s);
    refresh_engine(&mut s)
}
pub(super) async fn start_model(state: &State) -> Result<StorageStatus, String> {
    let _gate = state.model_start.lock().await;
    let (epoch, config) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        if let Some(model) = s.model.as_mut() {
            #[cfg(windows)]
            {
                let _ = model;
                return Err("model_already_running".into());
            }
            #[cfg(not(windows))]
            {
                if model
                    .child
                    .lock()
                    .map_err(|_| "model_start_failed")?
                    .try_wait()
                    .map_err(|_| "model_start_failed")?
                    .is_none()
                {
                    return Err("model_already_running".into());
                }
                s.model = None;
            }
        }
        (s.epoch, require(&mut s)?.config.llm.clone())
    };
    let model = config.model_path.as_deref().ok_or("model_files_required")?;
    let hash = config
        .model_sha256
        .as_deref()
        .ok_or("model_files_required")?;
    let embed = config.embed_path.as_deref().ok_or("model_files_required")?;
    let embed_hash = config
        .embed_sha256
        .as_deref()
        .ok_or("model_files_required")?;
    if config.model != "default" || config.embed_model != "nomic-embed-text" {
        return Err("invalid_model_aliases".into());
    }
    #[cfg(not(windows))]
    let endpoint =
        nw_ipc::Endpoint::new(config.endpoint.clone(), nw_proto::Lane::Shadow).map_err(code)?;
    #[cfg(not(windows))]
    if endpoint.connect().await.is_ok() {
        return Err("model_already_running".into());
    }
    let binary = std::env::current_exe()
        .map_err(|_| "model_component_missing")?
        .parent()
        .ok_or("model_component_missing")?
        .join(format!("nw-llmd{}", std::env::consts::EXE_SUFFIX));
    #[cfg(windows)]
    let owned = OwnedModel {
        worker: Arc::new(
            nw_llm::windows_worker::WindowsModel::load(
                &binary,
                std::path::Path::new(model),
                hash,
                std::path::Path::new(embed),
                embed_hash,
            )
            .await
            .map_err(|_| "model_sandbox_unavailable")?,
        ),
    };
    #[cfg(not(windows))]
    let owned = {
        let mut command = tokio::process::Command::new(&binary);
        command
            .args([
                "--parent-stdio",
                "--socket",
                &config.endpoint,
                "--model",
                model,
                "--sha256",
                hash,
                "--embed-model",
                embed,
                "--embed-sha256",
                embed_hash,
            ])
            .env_clear()
            .current_dir(binary.parent().ok_or("model_component_missing")?)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        for name in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        #[cfg(target_os = "linux")]
        let mut child = {
            let mut arguments: Vec<std::ffi::OsString> = vec![
                "--parent-stdio".into(),
                "--socket".into(),
                config.endpoint.clone().into(),
                "--sha256".into(),
                hash.into(),
                "--embed-sha256".into(),
                embed_hash.into(),
            ];
            #[cfg(target_os = "linux")]
            arguments.extend([
                "--model".into(),
                "@file:chat".into(),
                "--embed-model".into(),
                "@file:embedding".into(),
            ]);
            nw_sandbox::daemon::Launch {
                profile: nw_sandbox::daemon::Profile::Model,
                binary: binary.clone(),
                arguments,
                listener: Some(config.endpoint.clone().into()),
                upstream: vec![],
                files: vec![
                    ("chat".into(), model.into()),
                    ("embedding".into(), embed.into()),
                ],
                environment: vec![],
            }
            .spawn()
            .await
            .map_err(|_| "model_sandbox_unavailable")?
        };
        #[cfg(not(any(windows, target_os = "linux")))]
        let mut child = nw_sandbox::daemon::Child::coordinator(
            command.spawn().map_err(|_| "model_start_failed")?,
        );
        let lifetime = child.stdin.take().ok_or("model_start_failed")?;
        let operation = async {
            loop {
                if child
                    .try_wait()
                    .map_err(|_| "model_start_failed")?
                    .is_some()
                {
                    return Err("model_start_failed");
                }
                if let Ok(stream) = endpoint.connect().await {
                    if nw_ipc::peer_process(&stream).map_err(|_| "ipc_wrong_peer")?
                        != child.id().ok_or("model_start_failed")?
                    {
                        return Err("ipc_wrong_peer");
                    }
                    return Ok(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(120), operation)
            .await
            .map_err(|_| "model_start_timeout")??;
        OwnedModel {
            child: Arc::new(Mutex::new(child)),
            _lifetime: lifetime,
        }
    };
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch || s.workspace.is_none() {
        return Err("session_changed".into());
    }
    s.model = Some(owned);
    state.invalidate(&mut s);
    refresh_engine(&mut s)?;
    storage_status(&mut s, state.egress.is_some())
}
pub(super) async fn audit_import(
    content: String,
    format: nw_audit::Format,
    encoding: Option<String>,
    state: &State,
) -> Result<nw_audit::Summary, String> {
    let epoch = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        require(&mut s)?;
        s.epoch
    };
    let content = Zeroizing::new(content);
    let bytes = tokio::task::spawn_blocking(move || -> Result<Zeroizing<Vec<u8>>, String> {
        if encoding.as_deref() == Some("base64") {
            use base64::Engine;
            if content.len() > nw_audit::MAX_IMPORT_BYTES.div_ceil(3) * 4 {
                return Err("import_too_large".into());
            }
            let bytes = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(content.as_bytes())
                    .map_err(|_| "invalid_import")?,
            );
            Ok(bytes)
        } else if encoding.as_deref().is_none_or(|e| e == "utf8") {
            if content.len() > nw_audit::MAX_IMPORT_BYTES {
                return Err("import_too_large".into());
            }
            Ok(Zeroizing::new(content.as_bytes().to_vec()))
        } else {
            Err("invalid_import".into())
        }
    })
    .await
    .map_err(|_| "import_worker_failed")??;
    let summary = crate::import_worker::import(&bytes, format)
        .await
        .map_err(String::from)?;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    let summary = require(&mut s)?.save_import(summary).map_err(code)?;
    state.invalidate(&mut s);
    refresh_engine(&mut s)?;
    Ok(summary)
}
pub(super) fn load_summary(state: &State) -> Result<Option<nw_audit::Summary>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.summary().map_err(code)
}
pub(super) fn load_persona(state: &State) -> Result<Persona, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    Ok(require(&mut s)?.persona().clone())
}
pub(super) async fn research_persona(state: &State) -> Result<Persona, String> {
    let (epoch, model, summary) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        let model = local_model(&mut s)?;
        let w = require(&mut s)?;
        (
            epoch,
            model,
            w.summary().map_err(code)?.ok_or("import_required")?,
        )
    };
    let persona = workspace::research(&model, &summary).await.map_err(code)?;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    require(&mut s)?
        .save_persona(persona.clone())
        .map_err(code)?;
    state.invalidate(&mut s);
    refresh_engine(&mut s)?;
    Ok(persona)
}
pub(super) fn confirm_traits(
    choices: Vec<(String, bool)>,
    state: &State,
) -> Result<Persona, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    let persona = require(&mut s)?.confirm_traits(&choices).map_err(code)?;
    state.invalidate(&mut s);
    refresh_engine(&mut s)?;
    Ok(persona)
}
pub(super) async fn generate_plan(
    input: crate::planning::PlanInput,
    socket: String,
    secrets: Vec<SecretRecord>,
    state: &State,
) -> Result<Review, String> {
    let (epoch, model, shield, input) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        state.invalidate(&mut s);
        let epoch = s.epoch;
        let w = require(&mut s)?;
        let changed_endpoint = !socket.trim().is_empty() && w.config.llm.endpoint != socket;
        if !socket.trim().is_empty() {
            let mut c = w.config.clone();
            c.llm.endpoint = socket;
            w.save_config(c).map_err(code)?;
        }
        if !input.confirmed_interests.is_empty() {
            w.set_manual_interests(input.confirmed_interests)
                .map_err(code)?;
        }
        w.set_secrets(secrets).map_err(code)?;
        let mut plan_input = w
            .plan_input(input.cover, input.sensitive_consent)
            .map_err(code)?;
        plan_input.activity = input.activity;
        let shield = w.shield().map_err(code)?;
        if changed_endpoint {
            s.model = None;
        }
        let prepared = (epoch, local_model(&mut s)?, shield, plan_input);
        refresh_engine(&mut s)?;
        prepared
    };
    let checked = crate::planning::generate(&model, &shield, &input)
        .await
        .map_err(code)?;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    require(&mut s)?.save_plan(checked).map_err(code)
}
pub(super) fn load_plan(state: &State) -> Result<Option<Review>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.review().map_err(code)
}
pub(super) fn approve_plan(hash: String, state: &State) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.approve(&hash).map_err(code)
}
pub(super) fn daily_tasks(state: &State) -> Result<Vec<nw_proto::DriftTask>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.daily_tasks(workspace::now()).map_err(code)
}
pub(super) fn load_day(state: &State) -> Result<Option<workspace::DayReview>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.day_review().map_err(code)
}
pub(super) async fn generate_day(state: &State) -> Result<workspace::DayReview, String> {
    let (epoch, model, shield, template) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        let model = local_model(&mut s)?;
        let w = require(&mut s)?;
        (
            epoch,
            model,
            w.shield().map_err(code)?,
            w.day_template().map_err(code)?,
        )
    };
    let (day, vectors) = workspace::rewrite_day(&model, &shield, template)
        .await
        .map_err(code)?;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    require(&mut s)?.save_day(day, vectors).map_err(code)
}
pub(super) fn approve_day(hash: String, state: &State) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.approve_day(&hash).map_err(code)
}
pub(super) fn complete_task(task: nw_proto::DriftTask, state: &State) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?
        .complete_bound_task(&task, workspace::now())
        .map_err(code)
}
pub(super) fn pause(paused: bool, state: &State) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.pause(paused).map_err(code)
}
#[derive(Serialize, Deserialize)]
pub struct ChatResponse {
    pub conversation: String,
    pub text: String,
    pub trust: nw_proto::TrustLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_reason: Option<crate::linkcheck::LocalReason>,
}
impl Drop for ChatResponse {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.text.zeroize();
    }
}
pub(super) async fn embeddings(texts: Vec<String>, state: &State) -> Result<Vec<Vec<f64>>, String> {
    let (epoch, model) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        require(&mut s)?;
        (epoch, local_model(&mut s)?)
    };
    let vectors = model.embed(&texts).await.map_err(code)?;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    require(&mut s)?.count_shadow(false).map_err(code)?;
    Ok(vectors)
}
pub(super) async fn chat(
    conversation: String,
    messages: Vec<Message>,
    max_tokens: Option<u32>,
    state: &State,
) -> Result<ChatResponse, String> {
    let (epoch, engine, snapshot) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        let engine = s.engine.clone().ok_or("workspace_locked")?;
        let snapshot = if conversation == "new" {
            None
        } else {
            Some(
                require(&mut s)?
                    .conversation_snapshot(&conversation)
                    .map_err(code)?
                    .ok_or("invalid_conversation")?,
            )
        };
        (epoch, engine, snapshot)
    };
    if let Some(snapshot) = snapshot {
        engine
            .restore_if_missing(&conversation, snapshot)
            .await
            .map_err(code)?;
    }
    let reply = engine
        .chat_with_limit(&conversation, &messages, max_tokens.unwrap_or(2048))
        .await;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    let w = require(&mut s)?;
    match reply {
        Ok(reply) => {
            w.save_chat_reply(&reply).map_err(code)?;
            w.count_shadow(false).map_err(code)?;
            Ok(ChatResponse {
                conversation: reply.conversation,
                text: reply.text.expose_secret().into(),
                trust: reply.trust,
                local_reason: reply.local_reason,
            })
        }
        Err(e) => {
            if e == crate::CoreError::Blocked {
                w.count_shadow(true).map_err(code)?;
            }
            Err(code(e))
        }
    }
}
pub(super) fn list_conversations(
    state: &State,
) -> Result<Vec<workspace::ConversationInfo>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.conversations().map_err(code)
}
pub(super) fn load_history(conversation: String, state: &State) -> Result<Vec<Message>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.history(&conversation).map_err(code)
}
pub(super) async fn save_snapshot(
    kind: nw_mirror::SnapshotKind,
    items: Vec<String>,
    state: &State,
) -> Result<workspace::Observation, String> {
    let snapshot = nw_mirror::Snapshot {
        kind,
        items,
        captured_at: workspace::now(),
    };
    snapshot.validate().map_err(code)?;
    let (epoch, model) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        require(&mut s)?;
        (epoch, local_model(&mut s)?)
    };
    let vectors = model.embed(&snapshot.items).await.map_err(code)?;
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    require(&mut s)?.snapshot(snapshot, &vectors).map_err(code)
}
pub(super) async fn purge_candidates(
    state: &State,
) -> Result<Vec<workspace::PurgeCandidate>, String> {
    let (epoch, model, titles) = {
        let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
        let epoch = s.epoch;
        let model = local_model(&mut s)?;
        let w = require(&mut s)?;
        let summary = w.summary().map_err(code)?.ok_or("import_required")?;
        let titles = summary
            .titles
            .into_iter()
            .chain(summary.searches)
            .take(300)
            .collect::<Vec<_>>();
        (epoch, model, titles)
    };
    let mut vectors = vec![];
    for chunk in titles.chunks(16) {
        vectors.extend(model.embed(chunk).await.map_err(code)?);
    }
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    if s.epoch != epoch {
        return Err("session_changed".into());
    }
    require(&mut s)?
        .purge_candidates(&titles, &vectors)
        .map_err(code)
}
pub(super) fn purge_hash(batch: nw_purge::Batch) -> Result<String, String> {
    batch.hash().map_err(code)
}
pub(super) fn approve_purge(
    batch: nw_purge::Batch,
    hash: String,
    state: &State,
) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.approve_purge(batch, &hash).map_err(code)
}
pub(super) fn purge_template() -> String {
    nw_purge::deletion_template().into()
}
pub(super) fn load_purge_batches(state: &State) -> Result<Vec<workspace::PurgeBatchView>, String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.purge_batches().map_err(code)
}
pub(super) fn record_purge_result(
    hash: String,
    outcome: nw_purge::guides::ObservedOutcome,
    completed_steps: Vec<String>,
    state: &State,
) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?
        .record_purge_result(&hash, outcome, completed_steps)
        .map_err(code)
}
pub(super) fn account_activity(count: u64, state: &State) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?.count_account_activity(count).map_err(code)
}
pub(super) fn shred_domain(
    domain: nw_vault::Domain,
    confirmation: String,
    state: &State,
) -> Result<(), String> {
    if confirmation != "СТЕРЕТЬ" {
        return Err("confirmation_required".into());
    }
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?;
    state.invalidate(&mut s);
    require(&mut s)?.shred(domain).map_err(code)?;
    refresh_engine(&mut s)
}
pub(super) fn destroy_data(confirmation: String, state: &State) -> Result<(), String> {
    if confirmation != "СТЕРЕТЬ ВСЁ" {
        return Err("confirmation_required".into());
    }
    let mut s = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut s)?;
    state.invalidate(&mut s);
    s.engine = None;
    let workspace = s.workspace.take().ok_or("workspace_locked")?;
    workspace.destroy().map_err(code)
}
