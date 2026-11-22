//! A daily rewrite is data until checked against the approved stage and approved by a human.
use crate::{Action, ApprovedPlan, DriftError, EmbeddingEvidence, Safety, math, safety};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Day {
    pub plan_hash: String,
    /// Zero-based stage and day; UI tasks use one-based numbers.
    pub stage: usize,
    pub day: usize,
    pub actions: Vec<Action>,
}
pub struct CheckedDay {
    day: Day,
    hash: String,
}
pub struct ApprovedDay {
    day: Day,
    hash: String,
}
impl Day {
    pub fn evaluate(
        &self,
        plan: &ApprovedPlan,
        evidence: &EmbeddingEvidence,
        vectors: &[math::Vector],
    ) -> Result<CheckedDay, DriftError> {
        let stage = plan.plan().stages.get(self.stage).ok_or(DriftError::Plan)?;
        let base = evidence
            .stages
            .get(self.stage)
            .ok_or(DriftError::Embedding)?;
        if self.plan_hash != plan.hash()
            || self.day >= usize::from(plan.plan().days_per_stage)
            || self.actions.len() != stage.actions.len()
            || vectors.len() != self.actions.len()
            || base.len() != vectors.len()
        {
            return Err(DriftError::Plan);
        }
        let axis = math::Axis::new(&evidence.persona, &evidence.cover)?;
        for (((candidate, original), vector), reference) in self
            .actions
            .iter()
            .zip(&stage.actions)
            .zip(vectors)
            .zip(base)
        {
            if candidate.text.chars().any(char::is_control)
                || candidate.service != original.service
                || candidate.text.len() > 4096
                || safety(&candidate.text)? == Safety::Sensitive && !plan.plan().sensitive_consent
                || math::cos(vector, reference)? < 0.80
                || (axis.position(std::slice::from_ref(vector))?
                    - axis.position(std::slice::from_ref(reference))?)
                .abs()
                    > 0.08
            {
                return Err(DriftError::Plan);
            }
        }
        let hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).map_err(|_| DriftError::Plan)?)
        );
        Ok(CheckedDay {
            day: self.clone(),
            hash,
        })
    }
}
impl CheckedDay {
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn day(&self) -> &Day {
        &self.day
    }
    pub fn approve(self, hash: &str) -> Result<ApprovedDay, DriftError> {
        if self.hash != hash {
            return Err(DriftError::Approval);
        }
        Ok(ApprovedDay {
            day: self.day,
            hash: self.hash,
        })
    }
}
impl ApprovedDay {
    pub fn day(&self) -> &Day {
        &self.day
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
}
