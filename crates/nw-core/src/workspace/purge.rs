//! User-observed deletion results. No operation here contacts or changes a service.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeBatchView {
    pub hash: String,
    pub batch: nw_purge::Batch,
    pub review: Option<nw_purge::guides::Review>,
}
impl Workspace {
    fn approved_purge_batch(&mut self, hash: &str) -> Result<nw_purge::Batch, WorkspaceError> {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(WorkspaceError::Invalid);
        }
        let batch: nw_purge::Batch = self
            .store
            .get_json(Domain::Imports, &format!("purge-{hash}"))?
            .ok_or(WorkspaceError::Approval)?;
        batch.approve(hash).map_err(|_| WorkspaceError::Invalid)?;
        Ok(batch)
    }
    pub fn purge_batches(&mut self) -> Result<Vec<PurgeBatchView>, WorkspaceError> {
        let ids = self.store.recent_ids(Domain::Imports, "purge-", 100)?;
        let mut views = Vec::with_capacity(ids.len());
        for id in ids {
            let hash = id.strip_prefix("purge-").ok_or(WorkspaceError::Invalid)?;
            let batch = self.approved_purge_batch(hash)?;
            let review: Option<nw_purge::guides::Review> = self
                .store
                .get_json(Domain::Imports, &format!("purge_result-{hash}"))?;
            if let Some(review) = &review {
                review
                    .validate(batch.service)
                    .map_err(|_| WorkspaceError::Invalid)?;
            }
            views.push(PurgeBatchView {
                hash: hash.into(),
                batch,
                review,
            });
        }
        Ok(views)
    }
    pub fn record_purge_result(
        &mut self,
        hash: &str,
        outcome: nw_purge::guides::ObservedOutcome,
        completed_steps: Vec<String>,
    ) -> Result<(), WorkspaceError> {
        let batch = self.approved_purge_batch(hash)?;
        let at = now();
        let review = nw_purge::guides::Review {
            outcome,
            completed_steps,
            checked_at: at - at % 60,
        };
        review
            .validate(batch.service)
            .map_err(|_| WorkspaceError::Invalid)?;
        self.store.put_json(
            Domain::Imports,
            &format!("purge_result-{hash}"),
            &review,
            at,
        )?;
        Ok(())
    }
}
