use super::*;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const REVIEW_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteReview {
    pub approval_id: String,
    pub hash: String,
    pub conversation: String,
    pub transcript: String,
    pub max_tokens: u32,
    pub trust: TrustLevel,
    pub expires_in_s: u64,
}
impl Drop for RemoteReview {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.transcript.zeroize();
    }
}
pub enum RemoteStep {
    Review(RemoteReview),
    Chat(ChatReply),
}
/// Accepted once, kept only in shadow memory. Dropping it cancels the reservation.
pub(crate) struct ApprovedRemote {
    pending: Pending,
    flight: crate::flight::Flight,
}
impl ApprovedRemote {
    pub fn conversation(&self) -> &str {
        &self.pending.conversation
    }
    pub fn messages(&self) -> Vec<Message> {
        self.pending
            .turn
            .canonical
            .iter()
            .zip(&self.pending.turn.real)
            .map(|(canonical, real)| Message {
                role: canonical.role,
                content: real.expose_secret().into(),
            })
            .collect()
    }
    pub fn trust(&self) -> TrustLevel {
        self.pending.trust
    }
    pub(crate) fn shape(&self, model: &str) -> Result<nw_net::ShapedRequest, CoreError> {
        nw_net::ShapedRequest::history(&self.pending.prepared, model, self.pending.max_tokens)
            .map_err(|_| CoreError::Blocked)
    }
}
impl RemoteStep {
    pub(super) fn into_reply(self) -> Result<ChatReply, CoreError> {
        match self {
            Self::Chat(reply) => Ok(reply),
            Self::Review(_) => Err(CoreError::Approval),
        }
    }
}
pub(super) struct Pending {
    pub conversation: String,
    turn: Conversation,
    prepared: nw_shield::Prepared,
    context: String,
    trust: TrustLevel,
    max_tokens: u32,
    hash: String,
    created: Instant,
}
impl Pending {
    pub fn new(
        conversation: String,
        turn: Conversation,
        prepared: nw_shield::Prepared,
        context: &str,
        trust: TrustLevel,
        max_tokens: u32,
    ) -> (Self, RemoteReview) {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let approval_id: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let mut digest = Sha256::new();
        digest.update(b"NW-REMOTE-REVIEW-v2");
        digest.update(nonce);
        digest.update(conversation.as_bytes());
        digest.update(context.as_bytes());
        digest.update(max_tokens.to_le_bytes());
        digest.update(prepared.text().as_bytes());
        let hash = format!("{:x}", digest.finalize());
        let view = RemoteReview {
            approval_id,
            hash: hash.clone(),
            conversation: conversation.clone(),
            transcript: prepared.text().into(),
            max_tokens,
            trust,
            expires_in_s: REVIEW_LIFETIME.as_secs(),
        };
        (
            Self {
                conversation,
                turn,
                prepared,
                context: context.into(),
                trust,
                max_tokens,
                hash,
                created: Instant::now(),
            },
            view,
        )
    }
}
impl ConversationState {
    pub fn expire(&mut self) {
        self.pending
            .retain(|_, pending| pending.created.elapsed() < REVIEW_LIFETIME);
    }
}
impl<M: LocalModel> Engine<M> {
    pub async fn cancel_remote(&self, approval_id: &str) {
        self.conversations.lock().await.pending.remove(approval_id);
    }
    pub async fn approve_remote<R: RemoteCompletion>(
        &self,
        approval_id: &str,
        hash: &str,
        remote: &R,
    ) -> Result<ChatReply, CoreError> {
        let approved = self.take_remote_approval(approval_id, hash, remote).await?;
        self.complete_approved(approved, remote).await
    }
    pub(crate) async fn take_remote_approval<R: RemoteCompletion>(
        &self,
        approval_id: &str,
        hash: &str,
        remote: &R,
    ) -> Result<ApprovedRemote, CoreError> {
        let mut state = self.conversations.lock().await;
        state.expire();
        // Consume before checking or sending: neither a wrong digest nor an uncertain send is replayable.
        let pending = state
            .pending
            .remove(approval_id)
            .ok_or(CoreError::Approval)?;
        if pending.hash != hash
            || pending.context != remote.context()
            || pending.trust != remote.trust()
            || pending.trust > self.min_trust
        {
            return Err(CoreError::Approval);
        }
        remote.check_available()?;
        self.shield
            .leakcheck(pending.prepared.text(), &pending.turn.vault)
            .map_err(|_| CoreError::Blocked)?;
        self.check_route_metadata(&pending.turn.vault, remote)?;
        let flight = self.flights.begin(&pending.conversation)?;
        drop(state);
        Ok(ApprovedRemote { pending, flight })
    }
    pub(crate) async fn complete_approved<R: RemoteCompletion>(
        &self,
        approved: ApprovedRemote,
        remote: &R,
    ) -> Result<ChatReply, CoreError> {
        let ApprovedRemote {
            mut pending,
            flight,
        } = approved;
        if !flight.belongs_to(&self.flights)
            || !flight.valid()
            || pending.context != remote.context()
            || pending.trust != remote.trust()
            || pending.trust > self.min_trust
        {
            return Err(CoreError::Approval);
        }
        remote.check_available()?;
        self.shield
            .leakcheck(pending.prepared.text(), &pending.turn.vault)
            .map_err(|_| CoreError::Blocked)?;
        self.check_route_metadata(&pending.turn.vault, remote)?;
        let answer = tokio::select! {biased;_=flight.cancelled()=>Err(CoreError::Session),result=remote.complete(&pending.conversation,&pending.prepared,pending.max_tokens)=>result}?;
        let mut state = self.conversations.lock().await;
        if !flight.valid() {
            return Err(CoreError::Session);
        }
        pending.turn.remote_context = Some(pending.context);
        finish(
            &mut state,
            pending.conversation,
            pending.turn,
            answer,
            pending.trust,
        )
    }
}
pub(super) fn finish(
    state: &mut ConversationState,
    key: String,
    mut conversation: Conversation,
    answer: SecretString,
    trust: TrustLevel,
) -> Result<ChatReply, CoreError> {
    if answer.expose_secret().len() > MAX_TEXT_BYTES {
        return Err(CoreError::Model);
    }
    let text = conversation
        .vault
        .rehydrate(answer.expose_secret())
        .map_err(|_| CoreError::Blocked)?;
    conversation.canonical.push(Message {
        role: Role::Assistant,
        content: answer.expose_secret().into(),
    });
    conversation
        .real
        .push(SecretString::from(text.expose_secret().to_owned()));
    conversation.turns += 1;
    let local_reason = conversation.local_reason;
    let snapshot = conversation.snapshot();
    state.records.insert(key.clone(), conversation);
    Ok(ChatReply {
        conversation: key,
        text,
        trust,
        local_reason,
        snapshot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_reviews_release_the_conversation_without_committing_a_turn() {
        let shield = Shield::new(vec![]).unwrap();
        let turn = Conversation {
            force_local: false,
            local_reason: None,
            remote_context: None,
            vault: ConversationVault::default(),
            canonical: vec![],
            real: vec![],
            turns: 0,
        };
        let prepared = shield
            .checked_output("[]", &turn.vault, nw_shield::Sensitivity::RemoteOk)
            .unwrap();
        let (mut pending, review) = Pending::new(
            "a".repeat(32),
            turn,
            prepared,
            &"b".repeat(64),
            TrustLevel::L3,
            32,
        );
        pending.created = Instant::now()
            .checked_sub(REVIEW_LIFETIME + Duration::from_secs(1))
            .unwrap();
        let mut state = ConversationState::default();
        state.pending.insert(review.approval_id.clone(), pending);
        state.expire();
        assert!(state.pending.is_empty());
        assert!(state.records.is_empty());
    }
}
