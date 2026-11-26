//! Shadow core. Cover modules receive explicit, reviewed cover data only.
pub mod config;
mod flight;
mod import_worker;
pub mod linkcheck;
#[cfg(test)]
pub(crate) mod link_fixture {
    use crate as nw_core;
    include!("../../../tests/leak/src/link_fixture.rs");
}
mod probe_worker;
pub use import_worker::import as audit_offline;
pub mod planning;
mod remote_review;
pub(crate) use remote_review::ApprovedRemote;
pub use remote_review::{RemoteReview, RemoteStep};
pub mod service;
pub mod workspace;
use nw_llm::{LocalModel, Message, Role};
use nw_proto::{MAX_TEXT_BYTES, Profile, TrustLevel};
use nw_shield::{ConversationVault, Shield};
use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CoreError {
    #[error("device_probe_required")]
    DeviceProbe,
    #[error("async_remote_required")]
    Queue,
    #[error("request_in_progress")]
    Busy,
    #[error("network_budget_exhausted")]
    Budget,
    #[error("session_changed")]
    Session,
    #[error("credential_pool_unavailable")]
    Credential,
    #[error("remote_transport_unavailable")]
    Transport,
    #[error("trust_policy_violation")]
    Trust,
    #[error("approval_required")]
    Approval,
    #[error("shield_blocked")]
    Blocked,
    #[error("local_model_unavailable")]
    Model,
    #[error("invalid_conversation")]
    Conversation,
    #[error("conversation_limit")]
    Limit,
    #[error("unsupported_model")]
    Unsupported,
    #[error("invalid_request")]
    Request,
}
struct Conversation {
    force_local: bool,
    local_reason: Option<linkcheck::LocalReason>,
    remote_context: Option<String>,
    vault: ConversationVault,
    canonical: Vec<Message>,
    real: Vec<SecretString>,
    turns: usize,
}
#[derive(Default)]
struct ConversationState {
    records: BTreeMap<String, Conversation>,
    pending: BTreeMap<String, remote_review::Pending>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationRecord {
    #[serde(default = "legacy_local_only")]
    force_local: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_reason: Option<linkcheck::LocalReason>,
    #[serde(default)]
    remote_context: Option<String>,
    version: u16,
    canonical: Vec<Message>,
    real: Vec<String>,
    turns: usize,
}
fn legacy_local_only() -> bool {
    true
}
impl Drop for ConversationRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.real.zeroize();
    }
}
impl ConversationRecord {
    pub fn messages(&self) -> Vec<Message> {
        self.canonical
            .iter()
            .zip(&self.real)
            .map(|(c, r)| Message {
                role: c.role,
                content: r.clone(),
            })
            .collect()
    }
    pub fn title(&self) -> String {
        self.canonical
            .iter()
            .zip(&self.real)
            .find(|(c, _)| c.role == Role::User)
            .map(|(_, r)| r.chars().take(90).collect())
            .unwrap_or_else(|| "Разговор".into())
    }
}
pub struct ConversationSnapshot {
    record: ConversationRecord,
    vault: nw_shield::VaultSnapshot,
}
impl Conversation {
    fn fork(&self) -> Result<Self, CoreError> {
        Ok(Self {
            force_local: self.force_local,
            local_reason: self.local_reason,
            remote_context: self.remote_context.clone(),
            vault: ConversationVault::restore(self.vault.snapshot())
                .map_err(|_| CoreError::Blocked)?,
            canonical: self.canonical.clone(),
            real: self
                .real
                .iter()
                .map(|s| SecretString::from(s.expose_secret().to_owned()))
                .collect(),
            turns: self.turns,
        })
    }
    fn snapshot(&self) -> ConversationSnapshot {
        ConversationSnapshot {
            record: ConversationRecord {
                force_local: self.force_local,
                local_reason: self.local_reason,
                remote_context: self.remote_context.clone(),
                version: 2,
                canonical: self.canonical.clone(),
                real: self
                    .real
                    .iter()
                    .map(|s| s.expose_secret().to_owned())
                    .collect(),
                turns: self.turns,
            },
            vault: self.vault.snapshot(),
        }
    }
}
pub struct Engine<M: LocalModel> {
    model: M,
    shield: Shield,
    max_turns: usize,
    translate_to_english: bool,
    min_trust: TrustLevel,
    approval_required: bool,
    linkcheck: Option<linkcheck::References>,
    linkcheck_settings: linkcheck::Settings,
    conversations: Mutex<ConversationState>,
    flights: flight::Flights,
}
pub struct ChatReply {
    pub conversation: String,
    pub text: SecretString,
    pub trust: TrustLevel,
    pub local_reason: Option<linkcheck::LocalReason>,
    snapshot: ConversationSnapshot,
}
impl<M: LocalModel> Engine<M> {
    pub fn new(model: M, shield: Shield, profile: Profile) -> Self {
        Self {
            model,
            shield,
            max_turns: profile.max_turns(),
            translate_to_english: false,
            min_trust: profile.min_trust(),
            approval_required: profile.requires_approval(),
            linkcheck: None,
            linkcheck_settings: linkcheck::Settings::for_profile(profile),
            conversations: Mutex::new(ConversationState::default()),
            flights: flight::Flights::default(),
        }
    }
    pub async fn forget(&self, id: &str) {
        let mut state = self.conversations.lock().await;
        self.flights.cancel(id);
        state.records.remove(id);
        state.pending.retain(|_, p| p.conversation != id);
    }
    pub fn configured(
        model: M,
        shield: Shield,
        config: &config::Config,
    ) -> Result<Self, CoreError> {
        config.validate()?;
        let mut engine = Self::new(model, shield, config.profile);
        engine.max_turns = config.shield.max_turns_per_conversation;
        engine.translate_to_english = config.shield.translate_to_english;
        engine.min_trust = config.shield.min_trust;
        engine.approval_required = config.shield.show_diff_before_send;
        engine.linkcheck_settings = config.shield.linkcheck.clone();
        Ok(engine)
    }
    /// Missing dossier material permits local answers only.
    pub fn with_linkcheck(mut self, references: Option<linkcheck::References>) -> Self {
        self.linkcheck = references;
        self
    }
    pub async fn restore_if_missing(
        &self,
        id: &str,
        mut snapshot: ConversationSnapshot,
    ) -> Result<(), CoreError> {
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CoreError::Conversation);
        }
        let mut state = self.conversations.lock().await;
        state.expire();
        if self.flights.active(id)? {
            return Err(CoreError::Busy);
        }
        if state.pending.values().any(|p| p.conversation == id) {
            return Err(CoreError::Approval);
        }
        if state.records.contains_key(id) {
            return Ok(());
        }
        if state.records.len() + state.pending.len() + self.flights.len()? >= 128 {
            return Err(CoreError::Limit);
        }
        let conversations = &mut state.records;
        let record = &mut snapshot.record;
        if !matches!(record.version, 1 | 2)
            || record.local_reason.is_some() && !record.force_local
            || record
                .remote_context
                .as_ref()
                .is_some_and(|c| c.len() != 64 || !c.bytes().all(|b| b.is_ascii_hexdigit()))
            || record.turns == 0
            || record.turns > self.max_turns
            || record.real.len() != record.canonical.len()
            || record.real.len() > 64
            || record
                .canonical
                .last()
                .is_none_or(|m| m.role != Role::Assistant)
            || record.real.iter().map(String::len).sum::<usize>() > MAX_TEXT_BYTES * 2
            || record
                .canonical
                .iter()
                .map(|m| m.content.len())
                .sum::<usize>()
                > MAX_TEXT_BYTES * 2
        {
            return Err(CoreError::Conversation);
        }
        let vault = ConversationVault::restore(snapshot.vault).map_err(|_| CoreError::Blocked)?;
        for message in &record.canonical {
            vault
                .rehydrate(&message.content)
                .map_err(|_| CoreError::Blocked)?;
        }
        let real = record.real.drain(..).map(SecretString::from).collect();
        conversations.insert(
            id.into(),
            Conversation {
                // Version 1 did not reliably mark a remote -> local turn.
                // Its old local answers cannot be certified for remote reuse.
                force_local: record.force_local || record.version == 1,
                local_reason: record.local_reason,
                remote_context: record.remote_context.take(),
                vault,
                canonical: std::mem::take(&mut record.canonical),
                real,
                turns: record.turns,
            },
        );
        Ok(())
    }
    pub async fn chat(&self, id: &str, messages: &[Message]) -> Result<ChatReply, CoreError> {
        self.chat_with_limit(id, messages, 2048).await
    }
    pub async fn chat_with_limit(
        &self,
        id: &str,
        messages: &[Message],
        max_tokens: u32,
    ) -> Result<ChatReply, CoreError> {
        self.chat_using::<NoRemote>(id, messages, max_tokens, None, false)
            .await?
            .into_reply()
    }
    pub async fn chat_remote<R: RemoteCompletion>(
        &self,
        id: &str,
        messages: &[Message],
        max_tokens: u32,
        remote: &R,
        approval: Option<&str>,
    ) -> Result<ChatReply, CoreError> {
        // Approval is a single-use pending capability, never a caller-computed digest.
        if approval.is_some() {
            return Err(CoreError::Approval);
        }
        self.chat_using(id, messages, max_tokens, Some(remote), false)
            .await?
            .into_reply()
    }
    pub async fn review_remote<R: RemoteCompletion>(
        &self,
        id: &str,
        messages: &[Message],
        max_tokens: u32,
        remote: &R,
    ) -> Result<RemoteStep, CoreError> {
        self.chat_using(id, messages, max_tokens, Some(remote), true)
            .await
    }
    async fn chat_using<R: RemoteCompletion>(
        &self,
        id: &str,
        messages: &[Message],
        max_tokens: u32,
        remote: Option<&R>,
        review: bool,
    ) -> Result<RemoteStep, CoreError> {
        if max_tokens == 0 || max_tokens > 2048 {
            return Err(CoreError::Request);
        }
        if messages.is_empty()
            || messages.len() > 63
            || messages.iter().map(|m| m.content.len()).sum::<usize>() > MAX_TEXT_BYTES
            || messages.last().is_none_or(|m| m.role != Role::User)
        {
            return Err(CoreError::Request);
        }
        if messages
            .iter()
            .enumerate()
            .any(|(i, m)| m.role == Role::System && i != 0)
        {
            return Err(CoreError::Request);
        }
        let mut state = self.conversations.lock().await;
        state.expire();
        if self.flights.active(id)? {
            return Err(CoreError::Busy);
        }
        let new = id == "new";
        if state.pending.values().any(|p| p.conversation == id) {
            return Err(CoreError::Approval);
        }
        if new && state.records.len() + state.pending.len() + self.flights.len()? >= 128 {
            return Err(CoreError::Limit);
        }
        let key = if new {
            let mut bytes = [0u8; 16];
            OsRng.fill_bytes(&mut bytes);
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        } else {
            id.to_owned()
        };
        if !new && !state.records.contains_key(&key) {
            return Err(CoreError::Conversation);
        }
        let mut conversation = if new {
            Conversation {
                force_local: false,
                local_reason: None,
                remote_context: None,
                vault: ConversationVault::default(),
                canonical: vec![],
                real: vec![],
                turns: 0,
            }
        } else {
            state
                .records
                .get(&key)
                .ok_or(CoreError::Conversation)?
                .fork()?
        };
        // The committed history stays unchanged until a complete answer is accepted.
        if conversation.turns >= self.max_turns {
            return Err(CoreError::Limit);
        }
        if messages.len() <= conversation.real.len() {
            return Err(CoreError::Conversation);
        }
        for ((supplied, previous), canonical) in messages
            .iter()
            .zip(&conversation.real)
            .zip(&conversation.canonical)
        {
            if supplied.content != previous.expose_secret() || supplied.role != canonical.role {
                return Err(CoreError::Conversation);
            }
        }
        if messages.iter().filter(|m| m.role == Role::User).count() > self.max_turns {
            return Err(CoreError::Limit);
        }
        let new_start = conversation.canonical.len();
        for message in &messages[conversation.real.len()..] {
            let minimized = self
                .shield
                .minimize(&message.content, &mut conversation.vault)
                .map_err(|_| CoreError::Blocked)?;
            let minimized = if remote.is_some()
                && !conversation.force_local
                && self.shield.classify(&message.content) != nw_shield::Sensitivity::LocalOnly
            {
                let analysis = self
                    .model
                    .identify_entities(minimized.expose_secret())
                    .await;
                let result = match analysis {
                    Ok(analysis) => self.shield.minimize_entities(
                        minimized.expose_secret(),
                        analysis.expose_secret(),
                        &mut conversation.vault,
                    ),
                    Err(_) => Err(nw_shield::Block::InvalidModelOutput),
                };
                match result {
                    Ok(result) => {
                        conversation.force_local |= result.local_only;
                        result.text
                    }
                    Err(nw_shield::Block::InvalidModelOutput) => {
                        // Invalid spans are rejected before the vault is mutated.
                        // No privacy model can grant remote permission by failing;
                        // a local answer can still use the deterministic masks.
                        conversation.force_local = true;
                        conversation.local_reason =
                            Some(linkcheck::LocalReason::EntityVerificationUnavailable);
                        minimized
                    }
                    Err(_) => return Err(CoreError::Blocked),
                }
            } else {
                minimized
            };
            let canonical = self
                .model
                .canonicalize_with_translation(minimized.expose_secret(), self.translate_to_english)
                .await
                .map_err(|_| CoreError::Model)?;
            self.shield
                .leakcheck(canonical.expose_secret(), &conversation.vault)
                .map_err(|_| CoreError::Blocked)?;
            conversation.canonical.push(Message {
                role: message.role,
                content: canonical.expose_secret().to_owned(),
            });
            conversation
                .real
                .push(SecretString::from(message.content.clone()));
        }
        let mut local_only = conversation.force_local
            || messages
                .iter()
                .any(|m| self.shield.classify(&m.content) == nw_shield::Sensitivity::LocalOnly)
            || conversation.canonical.iter().any(|m| {
                self.shield.classify(&m.content) == nw_shield::Sensitivity::LocalOnly
                    || self.shield.has_unresolved_name(&m.content)
            });
        if remote.is_some()
            && !local_only
            && let Some(reason) = self.protect_linkage(&mut conversation, new_start).await
        {
            conversation.force_local = true;
            conversation.local_reason = Some(reason);
            local_only = true;
        }
        let remote_work = if let Some(remote) = remote.filter(|_| !local_only) {
            // Availability is independent of a candidate's policy floor. Never
            // offer approval at L1/L2 just because an experimental flag is set.
            remote.check_available()?;
            if conversation
                .remote_context
                .as_deref()
                .is_some_and(|context| context != remote.context())
                || conversation.turns > 0 && conversation.remote_context.is_none()
            {
                return Err(CoreError::Conversation);
            }
            let trust = remote.trust();
            if trust > self.min_trust {
                return Err(CoreError::Trust);
            }
            for message in &conversation.canonical {
                self.shield
                    .leakcheck(&message.content, &conversation.vault)
                    .map_err(|_| CoreError::Blocked)?;
            }
            self.check_route_metadata(&conversation.vault, remote)?;
            let transcript = zeroize::Zeroizing::new(
                serde_json::to_string(&conversation.canonical).map_err(|_| CoreError::Request)?,
            );
            let prepared = self
                .shield
                .checked_output(
                    &transcript,
                    &conversation.vault,
                    nw_shield::Sensitivity::RemoteOk,
                )
                .map_err(|_| CoreError::Blocked)?;
            if prepared.sensitivity == nw_shield::Sensitivity::LocalOnly {
                return Err(CoreError::Blocked);
            }
            if review {
                if state.pending.len() >= 16 {
                    return Err(CoreError::Limit);
                }
                let (pending, view) = remote_review::Pending::new(
                    key,
                    conversation,
                    prepared,
                    remote.context(),
                    trust,
                    max_tokens,
                );
                state.pending.insert(view.approval_id.clone(), pending);
                return Ok(RemoteStep::Review(view));
            }
            if self.approval_required {
                return Err(CoreError::Approval);
            }
            Some((prepared, trust, remote.context().to_owned()))
        } else {
            None
        };
        let flight = self.flights.begin(&key)?;
        drop(state);
        let work = async {
            if let Some((prepared, trust, context)) = remote_work {
                let answer = remote
                    .ok_or(CoreError::Transport)?
                    .complete(&key, &prepared, max_tokens)
                    .await?;
                conversation.remote_context = Some(context);
                Ok((answer, trust))
            } else {
                // A local answer may reproduce private facts from the original
                // task. Its history must never be upgraded to remote later.
                conversation.force_local = true;
                Ok((
                    self.model
                        // The checked original transcript is needed to solve the
                        // local task; rewrite stages still see only masked text.
                        .complete_with_limit(messages, max_tokens)
                        .await
                        .map_err(|_| CoreError::Model)?,
                    TrustLevel::L0,
                ))
            }
        };
        let (answer, trust) = tokio::select! {biased;_=flight.cancelled()=>Err(CoreError::Session),result=work=>result}?;
        let mut state = self.conversations.lock().await;
        if !flight.valid() {
            return Err(CoreError::Session);
        }
        Ok(RemoteStep::Chat(remote_review::finish(
            &mut state,
            key,
            conversation,
            answer,
            trust,
        )?))
    }
    pub async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f64>>, CoreError> {
        self.model.embed(texts).await.map_err(|_| CoreError::Model)
    }
}
pub struct RemoteMetadata<'a> {
    pub host: &'a str,
    pub path: &'a str,
    pub model: &'a str,
}
impl<M: LocalModel> Engine<M> {
    fn check_route_metadata(
        &self,
        vault: &ConversationVault,
        remote: &impl RemoteCompletion,
    ) -> Result<(), CoreError> {
        if let Some(metadata) = remote.metadata() {
            for value in [metadata.host, metadata.path, metadata.model] {
                self.shield
                    .check_known_secrets(value, vault)
                    .map_err(|_| CoreError::Blocked)?;
            }
        }
        Ok(())
    }
}
pub trait RemoteCompletion: Send + Sync {
    fn check_available(&self) -> Result<(), CoreError> {
        Ok(())
    }
    fn trust(&self) -> TrustLevel;
    fn context(&self) -> &str;
    fn metadata(&self) -> Option<RemoteMetadata<'_>> {
        None
    }
    fn complete(
        &self,
        conversation: &str,
        prepared: &nw_shield::Prepared,
        max_tokens: u32,
    ) -> impl std::future::Future<Output = Result<SecretString, CoreError>> + Send;
}
struct NoRemote;
impl RemoteCompletion for NoRemote {
    fn trust(&self) -> TrustLevel {
        TrustLevel::L3
    }
    fn context(&self) -> &str {
        "disabled"
    }
    async fn complete(
        &self,
        _: &str,
        _: &nw_shield::Prepared,
        _: u32,
    ) -> Result<SecretString, CoreError> {
        Err(CoreError::Transport)
    }
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PreviewSecret {
    #[zeroize(skip)]
    pub kind: nw_shield::SecretKind,
    pub value: String,
    #[serde(default)]
    pub local_only: bool,
}
#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PreviewInput {
    pub text: String,
    #[serde(default)]
    pub secrets: Vec<PreviewSecret>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    pub minimized: String,
    pub sensitivity: nw_shield::Sensitivity,
    pub replacements: usize,
    pub leakcheck: bool,
    pub rewrite_backend: String,
    pub remote_enabled: bool,
}
pub fn preview(mut input: PreviewInput) -> Result<Preview, CoreError> {
    let secrets = input
        .secrets
        .drain(..)
        .map(|mut s| nw_shield::Secret::new(s.kind, std::mem::take(&mut s.value), s.local_only))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreError::Request)?;
    let shield = Shield::new(secrets).map_err(|_| CoreError::Request)?;
    let mut vault = ConversationVault::default();
    let prepared = shield
        .prepare(&input.text, &mut vault, |text| {
            Ok(text.split_whitespace().collect::<Vec<_>>().join(" "))
        })
        .map_err(|_| CoreError::Blocked)?;
    Ok(Preview {
        minimized: prepared.text().to_owned(),
        sensitivity: prepared.sensitivity,
        replacements: vault.len(),
        leakcheck: true,
        rewrite_backend: "deterministic_preview".into(),
        remote_enabled: false,
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub version: String,
    pub release_status: String,
    pub remote_enabled: bool,
    pub default_lane: nw_proto::Lane,
    pub supported_route: TrustLevel,
    pub local_model_transport: String,
}
pub fn status() -> Status {
    Status {
        version: env!("CARGO_PKG_VERSION").into(),
        release_status: "development".into(),
        remote_enabled: false,
        default_lane: nw_proto::Lane::Shadow,
        supported_route: TrustLevel::L0,
        local_model_transport: (if cfg!(windows) {
            "named_pipe"
        } else {
            "unix_socket"
        })
        .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Model;
    impl LocalModel for Model {
        async fn complete(&self, messages: &[Message]) -> Result<SecretString, nw_llm::ModelError> {
            Ok(SecretString::from(messages.last().unwrap().content.clone()))
        }
        async fn canonicalize(&self, text: &str) -> Result<SecretString, nw_llm::ModelError> {
            Ok(SecretString::from(text.to_owned()))
        }
        async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, nw_llm::ModelError> {
            Err(nw_llm::ModelError::Unavailable)
        }
    }
    #[tokio::test]
    async fn conversations_are_separate_and_reject_injected_history() {
        let engine = Engine::new(
            Model,
            Shield::new(vec![
                nw_shield::Secret::new(
                    nw_shield::SecretKind::Person,
                    "Synthetic Person".into(),
                    false,
                )
                .unwrap(),
            ])
            .unwrap(),
            Profile::Standard,
        );
        let reply = engine
            .chat(
                "new",
                &[Message {
                    role: Role::User,
                    content: "Hello Synthetic Person".into(),
                }],
            )
            .await
            .unwrap();
        assert_eq!(reply.text.expose_secret(), "Hello Synthetic Person");
        let other = engine
            .chat(
                "new",
                &[Message {
                    role: Role::User,
                    content: "Other task".into(),
                }],
            )
            .await
            .unwrap();
        assert_ne!(other.conversation, reply.conversation);
        assert!(
            engine
                .chat(
                    &reply.conversation,
                    &[Message {
                        role: Role::User,
                        content: "Other task".into()
                    }]
                )
                .await
                .is_err()
        );
        assert!(
            engine
                .chat(
                    "unknown",
                    &[Message {
                        role: Role::User,
                        content: "test".into()
                    }]
                )
                .await
                .is_err()
        );
    }
}
