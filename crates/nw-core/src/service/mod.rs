//! Typed shadow RPC. The daemon is the sole owner of the unlocked workspace.
mod backend;
mod cover;
use crate::{
    config::Config,
    planning::PlanInput,
    workspace::{self, ConversationInfo, DayReview, Persona, PurgeCandidate, Review, SecretRecord},
};
pub use backend::{ChatResponse, RemoteSubmission, SessionPhase, SessionTiming, StorageStatus};
use nw_ipc::{Endpoint, Listener, Packet};
use nw_llm::Message;
pub use nw_net::bridges::BridgeConfig;
use nw_proto::{DriftTask, Lane, Profile};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::{io::AsyncReadExt, sync::Semaphore};
const FRAME_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Sensitive(String);
impl Sensitive {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    fn take(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    SubmitRemoteJob {
        conversation: String,
        messages: Vec<Message>,
        max_tokens: Option<u32>,
        min_trust: Option<nw_proto::TrustLevel>,
        idempotency_key: Option<Sensitive>,
        defer_hours: Option<u16>,
    },
    StartRemoteJob {
        approval_id: String,
        hash: String,
    },
    LoadRemoteJob {
        id: String,
    },
    LoadRemoteJobs {},
    CancelRemoteJob {
        id: String,
    },
    LoadRemoteJobInput {
        id: String,
    },
    TrafficStatus {},
    SessionTiming {},
    CloseSession {},
    ReviewRemote {
        conversation: String,
        messages: Vec<Message>,
        max_tokens: Option<u32>,
    },
    ApproveRemote {
        approval_id: String,
        hash: String,
    },
    CancelRemote {
        approval_id: String,
    },
    LoadNetworkUsage {},
    StartModel {},
    LoadProviderKeys {},
    AddProviderKey {
        key: Sensitive,
    },
    RetireProviderKey {
        id: String,
    },
    Status {},
    WorkspaceStatus {},
    OpenWorkspace {
        password: Sensitive,
        create: bool,
        profile: Profile,
    },
    Lock {},
    PreviewShield {
        input: crate::PreviewInput,
    },
    LoadSecrets {},
    LoadDeviceProbe {},
    RunDeviceProbe {},
    SaveSecrets {
        secrets: Vec<SecretRecord>,
    },
    LoadConfig {},
    LoadBridgeStatus {},
    SaveBridges {
        config: Option<nw_net::bridges::BridgeConfig>,
    },
    SaveConfig {
        config: Box<Config>,
    },
    AuditImport {
        content: Sensitive,
        format: nw_audit::Format,
        encoding: Option<String>,
    },
    LoadSummary {},
    LoadPersona {},
    ResearchPersona {},
    ConfirmTraits {
        choices: Vec<(String, bool)>,
    },
    GeneratePlan {
        input: PlanInput,
        socket: String,
        secrets: Vec<SecretRecord>,
    },
    LoadPlan {},
    ApprovePlan {
        hash: String,
    },
    LoadDay {},
    GenerateDay {},
    ApproveDay {
        hash: String,
    },
    DailyTasks {},
    CompleteTask {
        task: DriftTask,
    },
    Pause {
        paused: bool,
    },
    Chat {
        conversation: String,
        messages: Vec<Message>,
        max_tokens: Option<u32>,
    },
    RemoteChat {
        conversation: String,
        messages: Vec<Message>,
        max_tokens: Option<u32>,
        min_trust: Option<nw_proto::TrustLevel>,
    },
    ListConversations {},
    LoadHistory {
        conversation: String,
    },
    Embeddings {
        texts: Vec<String>,
    },
    SaveSnapshot {
        kind: nw_mirror::SnapshotKind,
        items: Vec<String>,
    },
    PurgeCandidates {},
    PurgeHash {
        batch: nw_purge::Batch,
    },
    ApprovePurge {
        batch: nw_purge::Batch,
        hash: String,
    },
    PurgeTemplate {},
    PurgeGuide {
        service: nw_proto::Service,
    },
    LoadPurgeBatches {},
    RecordPurgeResult {
        hash: String,
        outcome: nw_purge::guides::ObservedOutcome,
        completed_steps: Vec<String>,
    },
    AccountActivity {
        count: u64,
    },
    ShredDomain {
        domain: nw_vault::Domain,
        confirmation: String,
    },
    DestroyData {
        confirmation: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    RemoteSubmission {
        value: RemoteSubmission,
    },
    RemoteJob {
        value: workspace::RemoteJobView,
    },
    RemoteJobs {
        value: Vec<workspace::RemoteJobInfo>,
    },
    Traffic {
        value: workspace::TrafficStatus,
    },
    SessionTiming {
        value: SessionTiming,
    },
    RemoteReview {
        value: backend::RemoteReviewResponse,
    },
    NetworkUsage {
        value: nw_cover::budget::Usage,
    },
    Credentials {
        value: Vec<workspace::CredentialInfo>,
    },
    Error {
        code: String,
    },
    Ack {},
    Status {
        value: crate::Status,
    },
    Storage {
        value: StorageStatus,
    },
    Preview {
        value: crate::Preview,
    },
    Secrets {
        value: Vec<SecretRecord>,
    },
    DeviceProbe {
        value: workspace::DeviceProbeStatus,
    },
    Config {
        value: Box<Config>,
    },
    Bridges {
        value: nw_net::bridges::BridgeStatus,
    },
    Summary {
        value: Option<nw_audit::Summary>,
    },
    Persona {
        value: Persona,
    },
    Plan {
        value: Option<Review>,
    },
    Day {
        value: Option<DayReview>,
    },
    Tasks {
        value: Vec<DriftTask>,
    },
    Chat {
        value: ChatResponse,
    },
    Conversations {
        value: Vec<ConversationInfo>,
    },
    History {
        value: Vec<Message>,
    },
    Embeddings {
        value: Vec<Vec<f64>>,
    },
    Observation {
        value: workspace::Observation,
    },
    PurgeCandidates {
        value: Vec<PurgeCandidate>,
    },
    PurgeGuide {
        value: nw_purge::guides::Guide,
    },
    PurgeBatches {
        value: Vec<workspace::PurgeBatchView>,
    },
    Hash {
        value: String,
    },
    Template {
        value: String,
    },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bridges,
    SessionTiming,
    DeviceProbe,
    RemoteSubmission,
    RemoteJob,
    RemoteJobs,
    Traffic,
    RemoteReview,
    NetworkUsage,
    Credentials,
    Ack,
    Status,
    Storage,
    Preview,
    Secrets,
    Config,
    Summary,
    Persona,
    Plan,
    Day,
    Tasks,
    Chat,
    Conversations,
    History,
    Embeddings,
    Observation,
    PurgeCandidates,
    PurgeGuide,
    PurgeBatches,
    Hash,
    Template,
}
impl Command {
    fn expected(&self) -> Kind {
        match self {
            Self::SubmitRemoteJob { .. } => Kind::RemoteSubmission,
            Self::StartRemoteJob { .. } | Self::LoadRemoteJob { .. } => Kind::RemoteJob,
            Self::LoadRemoteJobs {} => Kind::RemoteJobs,
            Self::LoadRemoteJobInput { .. } => Kind::History,
            Self::TrafficStatus { .. } => Kind::Traffic,
            Self::SessionTiming {} | Self::CloseSession {} => Kind::SessionTiming,
            Self::ReviewRemote { .. } => Kind::RemoteReview,
            Self::ApproveRemote { .. } => Kind::Chat,
            Self::LoadNetworkUsage { .. } => Kind::NetworkUsage,
            Self::LoadProviderKeys { .. }
            | Self::AddProviderKey { .. }
            | Self::RetireProviderKey { .. } => Kind::Credentials,
            Self::Status { .. } => Kind::Status,
            Self::WorkspaceStatus { .. } | Self::OpenWorkspace { .. } => Kind::Storage,
            Self::StartModel { .. } => Kind::Storage,
            Self::PreviewShield { .. } => Kind::Preview,
            Self::LoadSecrets { .. } => Kind::Secrets,
            Self::LoadDeviceProbe {} | Self::RunDeviceProbe {} => Kind::DeviceProbe,
            Self::LoadConfig { .. } => Kind::Config,
            Self::LoadBridgeStatus {} | Self::SaveBridges { .. } => Kind::Bridges,
            Self::AuditImport { .. } | Self::LoadSummary { .. } => Kind::Summary,
            Self::LoadPersona { .. }
            | Self::ResearchPersona { .. }
            | Self::ConfirmTraits { .. } => Kind::Persona,
            Self::GeneratePlan { .. } | Self::LoadPlan { .. } => Kind::Plan,
            Self::LoadDay { .. } | Self::GenerateDay { .. } => Kind::Day,
            Self::DailyTasks { .. } => Kind::Tasks,
            Self::Chat { .. } | Self::RemoteChat { .. } => Kind::Chat,
            Self::ListConversations { .. } => Kind::Conversations,
            Self::LoadHistory { .. } => Kind::History,
            Self::Embeddings { .. } => Kind::Embeddings,
            Self::SaveSnapshot { .. } => Kind::Observation,
            Self::PurgeCandidates { .. } => Kind::PurgeCandidates,
            Self::PurgeGuide { .. } => Kind::PurgeGuide,
            Self::LoadPurgeBatches { .. } => Kind::PurgeBatches,
            Self::PurgeHash { .. } => Kind::Hash,
            Self::PurgeTemplate { .. } => Kind::Template,
            _ => Kind::Ack,
        }
    }
}
impl Reply {
    fn kind(&self) -> Option<Kind> {
        Some(match self {
            Self::RemoteSubmission { .. } => Kind::RemoteSubmission,
            Self::RemoteJob { .. } => Kind::RemoteJob,
            Self::RemoteJobs { .. } => Kind::RemoteJobs,
            Self::Traffic { .. } => Kind::Traffic,
            Self::SessionTiming { .. } => Kind::SessionTiming,
            Self::RemoteReview { .. } => Kind::RemoteReview,
            Self::NetworkUsage { .. } => Kind::NetworkUsage,
            Self::Credentials { .. } => Kind::Credentials,
            Self::Error { .. } => return None,
            Self::Ack { .. } => Kind::Ack,
            Self::Status { .. } => Kind::Status,
            Self::Storage { .. } => Kind::Storage,
            Self::Preview { .. } => Kind::Preview,
            Self::Secrets { .. } => Kind::Secrets,
            Self::DeviceProbe { .. } => Kind::DeviceProbe,
            Self::Config { .. } => Kind::Config,
            Self::Bridges { .. } => Kind::Bridges,
            Self::Summary { .. } => Kind::Summary,
            Self::Persona { .. } => Kind::Persona,
            Self::Plan { .. } => Kind::Plan,
            Self::Day { .. } => Kind::Day,
            Self::Tasks { .. } => Kind::Tasks,
            Self::Chat { .. } => Kind::Chat,
            Self::Conversations { .. } => Kind::Conversations,
            Self::History { .. } => Kind::History,
            Self::Embeddings { .. } => Kind::Embeddings,
            Self::Observation { .. } => Kind::Observation,
            Self::PurgeCandidates { .. } => Kind::PurgeCandidates,
            Self::PurgeGuide { .. } => Kind::PurgeGuide,
            Self::PurgeBatches { .. } => Kind::PurgeBatches,
            Self::Hash { .. } => Kind::Hash,
            Self::Template { .. } => Kind::Template,
        })
    }
    pub fn into_json(self) -> Result<serde_json::Value, String> {
        fn json<T: Serialize>(value: T) -> Result<serde_json::Value, String> {
            serde_json::to_value(value).map_err(|_| "invalid_core_reply".into())
        }
        match self {
            Self::RemoteSubmission { value } => json(value),
            Self::RemoteJob { value } => json(value),
            Self::RemoteJobs { value } => json(value),
            Self::Traffic { value } => json(value),
            Self::SessionTiming { value } => json(value),
            Self::RemoteReview { value } => json(value),
            Self::NetworkUsage { value } => json(value),
            Self::Credentials { value } => json(value),
            Self::Error { code } => Err(code),
            Self::Ack {} => Ok(serde_json::Value::Null),
            Self::Status { value } => json(value),
            Self::Storage { value } => json(value),
            Self::Preview { value } => json(value),
            Self::Secrets { value } => json(value),
            Self::DeviceProbe { value } => json(value),
            Self::Config { value } => json(value),
            Self::Bridges { value } => json(value),
            Self::Summary { value } => json(value),
            Self::Persona { value } => json(value),
            Self::Plan { value } => json(value),
            Self::Day { value } => json(value),
            Self::Tasks { value } => json(value),
            Self::Chat { value } => json(value),
            Self::Conversations { value } => json(value),
            Self::History { value } => json(value),
            Self::Embeddings { value } => json(value),
            Self::Observation { value } => json(value),
            Self::PurgeCandidates { value } => json(value),
            Self::PurgeGuide { value } => json(value),
            Self::PurgeBatches { value } => json(value),
            Self::Hash { value } | Self::Template { value } => json(value),
        }
    }
}
fn error(code: String) -> Reply {
    Reply::Error {
        code: if !code.is_empty()
            && code.len() <= 64
            && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        {
            code
        } else {
            "core_operation_failed".into()
        },
    }
}

#[derive(Clone, Default)]
pub struct Service {
    state: backend::State,
    shutdown: Arc<tokio::sync::Notify>,
    exit_on_lock: bool,
}
impl Service {
    pub async fn run_traffic(&self) {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            backend::maybe_device_probe(&self.state);
            let _ = backend::traffic_tick(&self.state).await;
        }
    }
    pub fn new() -> Self {
        Self::default()
    }
    pub fn runtime(egress: Option<Arc<nw_net::client::Client>>) -> Self {
        Self {
            state: backend::State::runtime(egress),
            shutdown: Arc::default(),
            exit_on_lock: true,
        }
    }
    pub async fn stopped(&self) {
        self.shutdown.notified().await;
    }
    pub async fn handle(&self, command: Command) -> Reply {
        let state = &self.state;
        let tail = match state.session.lock() {
            Ok(s) => s.in_tail(),
            Err(_) => return error("session_unavailable".into()),
        };
        if tail
            && !matches!(
                &command,
                Command::Status {}
                    | Command::WorkspaceStatus {}
                    | Command::SessionTiming {}
                    | Command::CloseSession {}
                    | Command::Lock {}
                    | Command::OpenWorkspace { .. }
            )
        {
            return error("workspace_locked".into());
        }
        let result: Result<Reply, String> = match command {
            Command::SessionTiming {} => {
                backend::session_timing(state).map(|value| Reply::SessionTiming { value })
            }
            Command::CloseSession {} => backend::close_session(state).map(|closed| {
                if let Some((epoch, deadline)) = closed.timer {
                    let state = state.clone();
                    let shutdown = self.shutdown.clone();
                    let exit = self.exit_on_lock;
                    // Independent of the traffic loop: a slow network request must
                    // not keep keys or packets alive past the chosen tail deadline.
                    tokio::spawn(async move {
                        while let Some(delay) = backend::tail_wait(&state, epoch, deadline) {
                            tokio::time::sleep(delay).await;
                            if backend::expire_tail(&state, epoch, deadline) {
                                if exit {
                                    shutdown.notify_one();
                                }
                                break;
                            }
                        }
                    });
                }
                Reply::SessionTiming {
                    value: closed.value,
                }
            }),
            Command::SubmitRemoteJob {
                conversation,
                messages,
                max_tokens,
                min_trust,
                idempotency_key,
                defer_hours,
            } => backend::submit_remote_job(
                conversation,
                messages,
                max_tokens,
                min_trust,
                idempotency_key.map(Sensitive::take),
                defer_hours,
                state,
            )
            .await
            .map(|value| Reply::RemoteSubmission { value }),
            Command::StartRemoteJob { approval_id, hash } => {
                backend::start_remote_job(approval_id, hash, state)
                    .await
                    .map(|value| Reply::RemoteJob { value })
            }
            Command::LoadRemoteJob { id } => {
                backend::load_remote_job(id, state).map(|value| Reply::RemoteJob { value })
            }
            Command::LoadRemoteJobs {} => {
                backend::load_remote_jobs(state).map(|value| Reply::RemoteJobs { value })
            }
            Command::CancelRemoteJob { id } => {
                backend::cancel_remote_job(id, state).map(|()| Reply::Ack {})
            }
            Command::LoadRemoteJobInput { id } => {
                backend::load_remote_job_input(id, state).map(|value| Reply::History { value })
            }
            Command::TrafficStatus {} => {
                backend::traffic_status(state).map(|value| Reply::Traffic { value })
            }
            Command::LoadNetworkUsage {} => {
                backend::network_usage(state).map(|value| Reply::NetworkUsage { value })
            }
            Command::StartModel {} => backend::start_model(state)
                .await
                .map(|value| Reply::Storage { value }),
            Command::LoadProviderKeys {} => {
                backend::provider_keys(state).map(|value| Reply::Credentials { value })
            }
            Command::AddProviderKey { key } => backend::add_provider_key(key.take(), state)
                .map(|value| Reply::Credentials { value }),
            Command::RetireProviderKey { id } => {
                backend::retire_provider_key(id, state).map(|value| Reply::Credentials { value })
            }
            Command::Status {} => Ok(Reply::Status {
                value: backend::status(),
            }),
            Command::WorkspaceStatus {} => {
                backend::workspace_status(state).map(|value| Reply::Storage { value })
            }
            Command::OpenWorkspace {
                password,
                create,
                profile,
            } => backend::open_workspace(password.take(), create, profile, state)
                .await
                .map(|value| Reply::Storage { value }),
            Command::Lock {} => backend::clear_session(state).map(|()| Reply::Ack {}),
            Command::PreviewShield { input } => {
                backend::preview_shield(input).map(|value| Reply::Preview { value })
            }
            Command::LoadSecrets {} => {
                backend::load_secrets(state).map(|value| Reply::Secrets { value })
            }
            Command::LoadDeviceProbe {} => {
                backend::device_probe_status(state).map(|value| Reply::DeviceProbe { value })
            }
            Command::RunDeviceProbe {} => backend::run_device_probe(state)
                .await
                .map(|value| Reply::DeviceProbe { value }),
            Command::SaveSecrets { secrets } => {
                backend::save_secrets(secrets, state).map(|()| Reply::Ack {})
            }
            Command::LoadConfig {} => backend::load_config(state).map(|value| Reply::Config {
                value: Box::new(value),
            }),
            Command::LoadBridgeStatus {} => {
                backend::load_bridge_status(state).map(|value| Reply::Bridges { value })
            }
            Command::SaveBridges { config } => {
                backend::save_bridges(config, state).map(|value| Reply::Bridges { value })
            }
            Command::SaveConfig { config } => {
                backend::save_config(*config, state).map(|()| Reply::Ack {})
            }
            Command::AuditImport {
                content,
                format,
                encoding,
            } => backend::audit_import(content.take(), format, encoding, state)
                .await
                .map(|value| Reply::Summary { value: Some(value) }),
            Command::LoadSummary {} => {
                backend::load_summary(state).map(|value| Reply::Summary { value })
            }
            Command::LoadPersona {} => {
                backend::load_persona(state).map(|value| Reply::Persona { value })
            }
            Command::ResearchPersona {} => backend::research_persona(state)
                .await
                .map(|value| Reply::Persona { value }),
            Command::ConfirmTraits { choices } => {
                backend::confirm_traits(choices, state).map(|value| Reply::Persona { value })
            }
            Command::GeneratePlan {
                input,
                socket,
                secrets,
            } => backend::generate_plan(input, socket, secrets, state)
                .await
                .map(|value| Reply::Plan { value: Some(value) }),
            Command::LoadPlan {} => backend::load_plan(state).map(|value| Reply::Plan { value }),
            Command::ApprovePlan { hash } => {
                backend::approve_plan(hash, state).map(|()| Reply::Ack {})
            }
            Command::LoadDay {} => backend::load_day(state).map(|value| Reply::Day { value }),
            Command::GenerateDay {} => backend::generate_day(state)
                .await
                .map(|value| Reply::Day { value: Some(value) }),
            Command::ApproveDay { hash } => {
                backend::approve_day(hash, state).map(|()| Reply::Ack {})
            }
            Command::DailyTasks {} => {
                backend::daily_tasks(state).map(|value| Reply::Tasks { value })
            }
            Command::CompleteTask { task } => {
                backend::complete_task(task, state).map(|()| Reply::Ack {})
            }
            Command::Pause { paused } => backend::pause(paused, state).map(|()| Reply::Ack {}),
            Command::Chat {
                conversation,
                messages,
                max_tokens,
            } => backend::chat(conversation, messages, max_tokens, state)
                .await
                .map(|value| Reply::Chat { value }),
            Command::ReviewRemote {
                conversation,
                messages,
                max_tokens,
            } => backend::review_remote(conversation, messages, max_tokens, state)
                .await
                .map(|value| Reply::RemoteReview { value }),
            Command::ApproveRemote { approval_id, hash } => {
                backend::approve_remote(approval_id, hash, state)
                    .await
                    .map(|value| Reply::Chat { value })
            }
            Command::CancelRemote { approval_id } => backend::cancel_remote(approval_id, state)
                .await
                .map(|()| Reply::Ack {}),
            Command::RemoteChat {
                conversation,
                messages,
                max_tokens,
                min_trust,
            } => backend::remote_chat(conversation, messages, max_tokens, min_trust, state)
                .await
                .map(|value| Reply::Chat { value }),
            Command::ListConversations {} => {
                backend::list_conversations(state).map(|value| Reply::Conversations { value })
            }
            Command::LoadHistory { conversation } => {
                backend::load_history(conversation, state).map(|value| Reply::History { value })
            }
            Command::Embeddings { texts } => backend::embeddings(texts, state)
                .await
                .map(|value| Reply::Embeddings { value }),
            Command::SaveSnapshot { kind, items } => backend::save_snapshot(kind, items, state)
                .await
                .map(|value| Reply::Observation { value }),
            Command::PurgeCandidates {} => backend::purge_candidates(state)
                .await
                .map(|value| Reply::PurgeCandidates { value }),
            Command::PurgeHash { batch } => {
                backend::purge_hash(batch).map(|value| Reply::Hash { value })
            }
            Command::ApprovePurge { batch, hash } => {
                backend::approve_purge(batch, hash, state).map(|()| Reply::Ack {})
            }
            Command::PurgeTemplate {} => Ok(Reply::Template {
                value: backend::purge_template(),
            }),
            Command::PurgeGuide { service } => Ok(Reply::PurgeGuide {
                value: nw_purge::guides::guide(service),
            }),
            Command::LoadPurgeBatches {} => {
                backend::load_purge_batches(state).map(|value| Reply::PurgeBatches { value })
            }
            Command::RecordPurgeResult {
                hash,
                outcome,
                completed_steps,
            } => backend::record_purge_result(hash, outcome, completed_steps, state)
                .map(|()| Reply::Ack {}),
            Command::AccountActivity { count } => {
                backend::account_activity(count, state).map(|()| Reply::Ack {})
            }
            Command::ShredDomain {
                domain,
                confirmation,
            } => backend::shred_domain(domain, confirmation, state).map(|()| Reply::Ack {}),
            Command::DestroyData { confirmation } => {
                backend::destroy_data(confirmation, state).map(|()| Reply::Ack {})
            }
        };
        result.unwrap_or_else(error)
    }
    pub async fn serve_shadow(&self, listener: Listener) -> std::io::Result<()> {
        if listener.lane() != Lane::Shadow {
            return Err(std::io::Error::other("ipc_wrong_lane"));
        }
        let permits = Arc::new(Semaphore::new(8));
        loop {
            let mut stream = listener.accept().await.map_err(std::io::Error::other)?;
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let service = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(bytes) = nw_ipc::read_frame(&mut stream, FRAME_LIMIT).await else {
                    return;
                };
                let Ok(packet) = serde_json::from_slice::<Packet<Command>>(&bytes) else {
                    return;
                };
                if packet.lane != Lane::Shadow
                    || packet.version != nw_proto::SCHEMA_VERSION
                    || packet.request_id == 0
                {
                    return;
                }
                let exit = service.exit_on_lock
                    && matches!(
                        &packet.body,
                        Command::Lock {} | Command::CloseSession {} | Command::DestroyData { .. }
                    );
                let reply = tokio::select! {reply=service.handle(packet.body)=>Some(reply),_closed=stream.read_u8()=>None};
                if let Some(reply) = reply {
                    let stop = exit
                        && matches!(
                            &reply,
                            Reply::Ack {}
                                | Reply::SessionTiming {
                                    value: SessionTiming {
                                        phase: SessionPhase::Locked,
                                        ..
                                    }
                                }
                        );
                    let packet = Packet::new(Lane::Shadow, packet.request_id, reply);
                    if let Ok(bytes) = serde_json::to_vec(&packet) {
                        let bytes = zeroize::Zeroizing::new(bytes);
                        let _ = nw_ipc::write_frame(&mut stream, &bytes, FRAME_LIMIT).await;
                    }
                    if stop {
                        service.shutdown.notify_one();
                    }
                }
            });
        }
    }
    pub async fn serve_cover(&self, listener: Listener) -> std::io::Result<()> {
        nw_bridge::serve(listener, cover::DesktopCover(self.state.clone())).await
    }
}

#[derive(Clone)]
pub struct Client {
    endpoint: Endpoint,
    #[cfg(not(target_os = "linux"))]
    expected_images: Vec<std::path::PathBuf>,
}
impl Client {
    pub fn with_endpoint(
        endpoint: Endpoint,
        expected_image: std::path::PathBuf,
    ) -> Result<Self, String> {
        if endpoint.lane() != Lane::Shadow {
            return Err("ipc_wrong_lane".into());
        }
        if !expected_image.is_absolute() {
            return Err("invalid_core_binary".into());
        }
        Ok(Self {
            endpoint,
            #[cfg(not(target_os = "linux"))]
            expected_images: vec![expected_image],
        })
    }
    pub fn current_user() -> Result<Self, String> {
        let paths = crate::config::Paths::discover().map_err(|e| e.to_string())?;
        let binary = std::env::current_exe()
            .map_err(|_| "invalid_core_binary")?
            .parent()
            .ok_or("invalid_core_binary")?
            .join(format!("nymwrapd{}", std::env::consts::EXE_SUFFIX));
        let client = Self::with_endpoint(
            Endpoint::new(paths.core_shadow, Lane::Shadow).map_err(|e| e.to_string())?,
            binary,
        )?;
        #[cfg(not(target_os = "linux"))]
        {
            let mut client = client;
            if cfg!(debug_assertions) {
                client.expected_images.push(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../../target/debug")
                        .join(format!("nymwrapd{}", std::env::consts::EXE_SUFFIX)),
                );
            }
            Ok(client)
        }
        #[cfg(target_os = "linux")]
        Ok(client)
    }
    pub async fn request(&self, command: Command) -> Result<Reply, String> {
        use rand::RngCore;
        let mut id = rand::rngs::OsRng.next_u64();
        if id == 0 {
            id = 1;
        }
        let expected = command.expected();
        let mut stream = self.endpoint.connect().await.map_err(|e| e.to_string())?;
        #[cfg(not(target_os = "linux"))]
        {
            let pid = nw_ipc::peer_process(&stream).map_err(|_| "ipc_wrong_peer")?;
            let image = nw_platform::process_image(pid)
                .and_then(|p| p.canonicalize())
                .map_err(|_| "ipc_wrong_peer")?;
            if !self
                .expected_images
                .iter()
                .any(|p| p.canonicalize().is_ok_and(|expected| expected == image))
            {
                return Err("ipc_wrong_peer".into());
            }
        }
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(&Packet::new(Lane::Shadow, id, command))
                .map_err(|_| "invalid_core_request")?,
        );
        nw_ipc::write_frame(&mut stream, &bytes, FRAME_LIMIT)
            .await
            .map_err(|e| e.to_string())?;
        let response = nw_ipc::read_frame_timeout(
            &mut stream,
            FRAME_LIMIT,
            std::time::Duration::from_secs(900),
        )
        .await
        .map_err(|e| e.to_string())?;
        let packet: Packet<Reply> =
            serde_json::from_slice(&response).map_err(|_| "invalid_core_reply")?;
        if packet.version != nw_proto::SCHEMA_VERSION
            || packet.lane != Lane::Shadow
            || packet.request_id != id
            || packet.body.kind().is_some_and(|kind| kind != expected)
        {
            return Err("invalid_core_reply".into());
        }
        if let Reply::Error { code } = &packet.body
            && (!code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') || code.len() > 64)
        {
            return Err("invalid_core_reply".into());
        }
        Ok(packet.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imported_summary_roundtrips_through_tagged_rpc() {
        let mut summary = nw_audit::Summary {
            records: 1,
            ..Default::default()
        };
        summary.activity_hours.insert(12, 1);
        let reply = Reply::Summary {
            value: Some(summary),
        };
        let bytes = serde_json::to_vec(&Packet::new(Lane::Shadow, 17, reply)).unwrap();
        let packet: Packet<Reply> = serde_json::from_slice(&bytes).unwrap();
        assert!(
            matches!(packet.body,Reply::Summary{value:Some(summary)}if summary.activity_hours.get(&12)==Some(&1))
        );
    }
    #[tokio::test]
    async fn daemon_protocol_is_private_and_rejects_foreign_fields() {
        for value in [
            serde_json::json!({"op":"status","vault":[]}),
            serde_json::json!({"op":"execute","text":"synthetic"}),
        ] {
            assert!(serde_json::from_value::<Command>(value).is_err());
        }
        let dir = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let address = format!("nymwrap-core-test-{}", std::process::id());
        #[cfg(unix)]
        let address = dir
            .path()
            .join("private/core.sock")
            .to_string_lossy()
            .into_owned();
        let _keep = dir;
        let endpoint = Endpoint::new(address, Lane::Shadow).unwrap();
        let listener = Listener::bind(endpoint.clone()).unwrap();
        let service = Service::new();
        let server = tokio::spawn(async move {
            service.serve_shadow(listener).await.unwrap();
        });
        let client = Client::with_endpoint(endpoint, std::env::current_exe().unwrap()).unwrap();
        assert!(matches!(
            client.request(Command::Status {}).await.unwrap(),
            Reply::Status { .. }
        ));
        assert!(matches!(
            client.request(Command::LoadSecrets {}).await.unwrap(),
            Reply::Error { .. }
        ));
        server.abort();
        let _ = server.await;
    }
}
