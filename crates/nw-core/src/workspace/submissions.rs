//! Durable at-most-once receipts. A pending or missing result never authorizes replay.
use super::*;
use std::collections::BTreeMap;

const LIMIT: usize = 8192;
const INDEX: &str = "submission-receipts-v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum SubmissionOutcome {
    Pending,
    Job { id: String },
    Local,
    Failed { code: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    fingerprint: String,
    outcome: SubmissionOutcome,
}

pub(crate) enum Reservation {
    New,
    Existing(SubmissionOutcome),
}

pub(crate) fn valid_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Workspace {
    fn receipts(&mut self) -> Result<BTreeMap<String, Receipt>, WorkspaceError> {
        let receipts: BTreeMap<String, Receipt> = self
            .store
            .get_json(Domain::Vault, INDEX)?
            .unwrap_or_default();
        if receipts.len() > LIMIT
            || receipts.iter().any(|(key, receipt)| {
                !hash(key)
                    || !hash(&receipt.fingerprint)
                    || match &receipt.outcome {
                        SubmissionOutcome::Job { id } => !hash(id),
                        SubmissionOutcome::Failed { code } => {
                            code.is_empty()
                                || code.len() > 64
                                || !code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                        }
                        _ => false,
                    }
            })
        {
            return Err(WorkspaceError::Invalid);
        }
        Ok(receipts)
    }
    pub(crate) fn reserve_submission(
        &mut self,
        key: &str,
        fingerprint: &str,
    ) -> Result<Reservation, WorkspaceError> {
        if !hash(key) || !hash(fingerprint) {
            return Err(WorkspaceError::Invalid);
        }
        let mut receipts = self.receipts()?;
        if let Some(receipt) = receipts.get(key) {
            if receipt.fingerprint != fingerprint {
                return Err(WorkspaceError::IdempotencyConflict);
            }
            return Ok(Reservation::Existing(receipt.outcome.clone()));
        }
        if receipts.len() == LIMIT {
            return Err(WorkspaceError::IdempotencyCapacity);
        }
        receipts.insert(
            key.into(),
            Receipt {
                fingerprint: fingerprint.into(),
                outcome: SubmissionOutcome::Pending,
            },
        );
        self.store
            .put_json(Domain::Vault, INDEX, &receipts, now())?;
        Ok(Reservation::New)
    }
    pub(crate) fn finish_submission(
        &mut self,
        key: &str,
        outcome: SubmissionOutcome,
    ) -> Result<(), WorkspaceError> {
        let mut receipts = self.receipts()?;
        let receipt = receipts.get_mut(key).ok_or(WorkspaceError::Invalid)?;
        if !matches!(receipt.outcome, SubmissionOutcome::Pending) {
            return Err(WorkspaceError::Policy);
        }
        receipt.outcome = outcome;
        self.store
            .put_json(Domain::Vault, INDEX, &receipts, now())?;
        Ok(())
    }
    pub(crate) fn save_submission_reply(
        &mut self,
        key: &str,
        reply: &crate::service::ChatResponse,
    ) -> Result<(), WorkspaceError> {
        if !hash(key) || reply.trust != nw_proto::TrustLevel::L0 {
            return Err(WorkspaceError::Invalid);
        }
        self.store.put_json(
            Domain::ShadowHistory,
            &format!("submission-{key}"),
            reply,
            now(),
        )?;
        self.finish_submission(key, SubmissionOutcome::Local)
    }
    pub(crate) fn submission_reply(
        &mut self,
        key: &str,
    ) -> Result<crate::service::ChatResponse, WorkspaceError> {
        if !hash(key) {
            return Err(WorkspaceError::Invalid);
        }
        self.store
            .get_json(Domain::ShadowHistory, &format!("submission-{key}"))?
            .ok_or(WorkspaceError::IdempotencyExpired)
    }
}
