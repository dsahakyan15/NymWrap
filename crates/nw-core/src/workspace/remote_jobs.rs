//! Durable shadow job metadata; original text and results use ShadowHistory.
use super::*;
use nw_proto::TrustLevel;
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteJobState {
    Queued,
    Sending,
    Done,
    Uncertain,
    Blocked,
    Cancelled,
    Expired,
}
impl RemoteJobState {
    fn active(self) -> bool {
        matches!(self, Self::Queued | Self::Sending)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteJobInfo {
    pub id: String,
    pub conversation: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub state: RemoteJobState,
    pub code: Option<String>,
    pub trust: TrustLevel,
    #[serde(default)]
    pub not_before: u64,
}
#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct RemoteJobReply {
    pub conversation: String,
    pub text: String,
    #[zeroize(skip)]
    pub trust: TrustLevel,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_reason: Option<crate::linkcheck::LocalReason>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteJobView {
    pub info: RemoteJobInfo,
    pub reply: Option<RemoteJobReply>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    messages: Vec<Message>,
    reply: Option<RemoteJobReply>,
}
fn identifier(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn minute() -> u64 {
    let at = now();
    at - at % 60
}
impl Workspace {
    fn job_index(&mut self) -> Result<Vec<RemoteJobInfo>, WorkspaceError> {
        let jobs: Vec<RemoteJobInfo> = self
            .store
            .get_json(Domain::Vault, "remote-job-index")?
            .unwrap_or_default();
        if jobs.len() > 64
            || jobs.iter().any(|j| {
                !identifier(&j.id, 64)
                    || !identifier(&j.conversation, 32)
                    || j.trust == TrustLevel::L0
                    || j.updated_at < j.created_at
                    || j.code.as_ref().is_some_and(|c| {
                        c.is_empty()
                            || c.len() > 64
                            || !c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                    })
            })
        {
            return Err(WorkspaceError::Invalid);
        }
        let unique: std::collections::BTreeSet<_> = jobs.iter().map(|j| &j.id).collect();
        if unique.len() != jobs.len() {
            return Err(WorkspaceError::Invalid);
        }
        Ok(jobs)
    }
    pub fn remote_jobs(&mut self) -> Result<Vec<RemoteJobInfo>, WorkspaceError> {
        self.job_index()
    }
    pub(crate) fn create_remote_job(
        &mut self,
        approved: &crate::ApprovedRemote,
        not_before: u64,
    ) -> Result<RemoteJobInfo, WorkspaceError> {
        let mut jobs = self.job_index()?;
        if jobs.len() == 64 {
            let index = jobs
                .iter()
                .position(|j| !j.state.active())
                .ok_or(WorkspaceError::Policy)?;
            let old = jobs.remove(index);
            self.store
                .remove(Domain::ShadowHistory, &format!("remote-job-{}", old.id))?;
        }
        let created_at = minute();
        let info = RemoteJobInfo {
            id: nw_cred::os::random_id(),
            conversation: approved.conversation().into(),
            created_at,
            updated_at: created_at,
            state: RemoteJobState::Queued,
            code: None,
            trust: approved.trust(),
            not_before,
        };
        let payload = Payload {
            messages: approved.messages(),
            reply: None,
        };
        self.store.put_json(
            Domain::ShadowHistory,
            &format!("remote-job-{}", info.id),
            &payload,
            now(),
        )?;
        jobs.push(info.clone());
        self.store
            .put_json(Domain::Vault, "remote-job-index", &jobs, now())?;
        Ok(info)
    }
    pub fn remote_job(&mut self, id: &str) -> Result<RemoteJobView, WorkspaceError> {
        if !identifier(id, 64) {
            return Err(WorkspaceError::Invalid);
        }
        let mut jobs = self.job_index()?;
        let info = jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or(WorkspaceError::Invalid)?;
        let payload: Option<Payload> = self
            .store
            .get_json(Domain::ShadowHistory, &format!("remote-job-{id}"))?;
        if payload.is_none() {
            info.state = RemoteJobState::Expired;
            info.code = Some("history_expired".into());
        }
        let view = RemoteJobView {
            info: info.clone(),
            reply: payload.and_then(|p| p.reply),
        };
        if view.info.state == RemoteJobState::Expired {
            self.store
                .put_json(Domain::Vault, "remote-job-index", &jobs, now())?;
        }
        Ok(view)
    }
    pub fn remote_job_messages(&mut self, id: &str) -> Result<Vec<Message>, WorkspaceError> {
        if !identifier(id, 64) {
            return Err(WorkspaceError::Invalid);
        }
        let payload: Payload = self
            .store
            .get_json(Domain::ShadowHistory, &format!("remote-job-{id}"))?
            .ok_or(WorkspaceError::Invalid)?;
        Ok(payload.messages)
    }
    pub(crate) fn remote_job_sending(&mut self, id: &str) -> Result<(), WorkspaceError> {
        let mut jobs = self.job_index()?;
        let info = jobs
            .iter_mut()
            .find(|j| j.id == id && j.state == RemoteJobState::Queued)
            .ok_or(WorkspaceError::Policy)?;
        if now() < info.not_before {
            return Err(WorkspaceError::TooSoon);
        }
        info.state = RemoteJobState::Sending;
        info.updated_at = minute().max(info.updated_at);
        self.store
            .put_json(Domain::Vault, "remote-job-index", &jobs, now())?;
        Ok(())
    }
    pub(crate) fn finish_remote_job(
        &mut self,
        id: &str,
        result: Result<RemoteJobReply, &str>,
    ) -> Result<(), WorkspaceError> {
        let mut jobs = self.job_index()?;
        let info = jobs
            .iter_mut()
            .find(|j| j.id == id && j.state.active())
            .ok_or(WorkspaceError::Policy)?;
        match result {
            Ok(reply) => {
                if reply.conversation != info.conversation
                    || reply.trust != info.trust
                    || reply.local_reason.is_some() && reply.trust != TrustLevel::L0
                    || reply.text.len() > nw_proto::MAX_TEXT_BYTES
                {
                    return Err(WorkspaceError::Invalid);
                }
                let key = format!("remote-job-{id}");
                let mut payload: Payload = self
                    .store
                    .get_json(Domain::ShadowHistory, &key)?
                    .ok_or(WorkspaceError::Invalid)?;
                payload.reply = Some(reply);
                self.store
                    .put_json(Domain::ShadowHistory, &key, &payload, now())?;
                info.state = RemoteJobState::Done;
            }
            Err(code) => {
                if code.is_empty()
                    || code.len() > 64
                    || !code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                {
                    return Err(WorkspaceError::Invalid);
                }
                info.state = if info.state == RemoteJobState::Sending
                    || matches!(code, "remote_transport_unavailable" | "session_changed")
                {
                    RemoteJobState::Uncertain
                } else {
                    RemoteJobState::Blocked
                };
                info.code = Some(code.into());
            }
        }
        info.updated_at = minute().max(info.updated_at);
        self.store
            .put_json(Domain::Vault, "remote-job-index", &jobs, now())?;
        Ok(())
    }
    pub(crate) fn cancel_remote_job(&mut self, id: &str) -> Result<(), WorkspaceError> {
        let mut jobs = self.job_index()?;
        let info = jobs
            .iter_mut()
            .find(|j| j.id == id && j.state.active())
            .ok_or(WorkspaceError::Policy)?;
        info.state = if info.state == RemoteJobState::Sending {
            RemoteJobState::Uncertain
        } else {
            RemoteJobState::Cancelled
        };
        info.code = Some("cancelled_by_user".into());
        info.updated_at = minute().max(info.updated_at);
        self.store
            .put_json(Domain::Vault, "remote-job-index", &jobs, now())?;
        Ok(())
    }
    pub(super) fn recover_remote_jobs(&mut self) -> Result<(), WorkspaceError> {
        let mut jobs = self.job_index()?;
        let mut changed = false;
        for info in &mut jobs {
            if info.state.active() {
                info.state = RemoteJobState::Uncertain;
                info.code = Some("previous_session_ended".into());
                info.updated_at = minute().max(info.updated_at);
                changed = true;
            }
        }
        if changed {
            self.store
                .put_json(Domain::Vault, "remote-job-index", &jobs, now())?;
        }
        Ok(())
    }
}
