pub mod activity;
pub mod math;
pub mod variants;
use nw_proto::{DriftTask, Service};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

pub const MIN_DAY_GAP_S: u64 = 12 * 60 * 60;
#[derive(Debug, Error, Eq, PartialEq)]
pub enum DriftError {
    #[error("outside_activity_window")]
    ActivityWindow,
    #[error("invalid_embedding")]
    Embedding,
    #[error("invalid_plan")]
    Plan,
    #[error("unsafe_cover")]
    UnsafeCover,
    #[error("sensitive_consent_required")]
    SensitiveConsent,
    #[error("plan_approval_required")]
    Approval,
    #[error("day_not_ready")]
    TooSoon,
    #[error("execution_paused")]
    Paused,
    #[error("invalid_progress")]
    Progress,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub service: Service,
    pub text: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub theme: String,
    pub bridge: String,
    pub actions: Vec<Action>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<activity::Schedule>,
    pub cover: String,
    pub days_per_stage: u16,
    pub stages: Vec<Stage>,
    pub sensitive_consent: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Safety {
    Allowed,
    Sensitive,
}

/// Conservative baseline filter. Custom free-form model plans also require local review.
pub fn safety(text: &str) -> Result<Safety, DriftError> {
    let t: String = text.nfkc().flat_map(char::to_lowercase).collect();
    const BLOCKED: &[&str] = &[
        "weapon",
        "firearm",
        "suicide",
        "self-harm",
        "self harm",
        "extremis",
        "terroris",
        "cocaine",
        "heroin",
        "gambl",
        "anorexi",
        "bulimi",
        "identity theft",
        "defraud",
        "оруж",
        "наркот",
        "экстрем",
        "суицид",
        "самоповреж",
        "азарт",
        "анорекс",
        "булими",
        "обман банк",
        "выдать себя за",
    ];
    const SENSITIVE: &[&str] = &[
        "health",
        "religio",
        "politi",
        "sexual",
        "financ",
        "credit",
        "здоров",
        "религ",
        "полит",
        "сексуал",
        "финанс",
        "кредит",
    ];
    if t.len() > 4096 || t.trim().is_empty() || BLOCKED.iter().any(|w| t.contains(w)) {
        return Err(DriftError::UnsafeCover);
    }
    Ok(if SENSITIVE.iter().any(|w| t.contains(w)) {
        Safety::Sensitive
    } else {
        Safety::Allowed
    })
}
impl Plan {
    pub fn validate(&self) -> Result<(), DriftError> {
        if let Some(activity) = &self.activity {
            activity.validate(self.stages.len())?;
        }
        if !(3..=30).contains(&self.stages.len()) || !(1..=30).contains(&self.days_per_stage) {
            return Err(DriftError::Plan);
        }
        let mut texts = vec![self.cover.as_str()];
        for stage in &self.stages {
            if stage.bridge.trim().is_empty() || !(1..=10).contains(&stage.actions.len()) {
                return Err(DriftError::Plan);
            }
            texts.extend([stage.theme.as_str(), stage.bridge.as_str()]);
            texts.extend(stage.actions.iter().map(|a| a.text.as_str()));
        }
        for text in texts {
            if text.chars().any(char::is_control) {
                return Err(DriftError::Plan);
            }
            if safety(text)? == Safety::Sensitive && !self.sensitive_consent {
                return Err(DriftError::SensitiveConsent);
            }
        }
        Ok(())
    }
    /// Includes timing, every action, service and sensitive-topic consent.
    pub fn hash(&self) -> Result<String, DriftError> {
        self.validate()?;
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).map_err(|_| DriftError::Plan)?)
        ))
    }
    pub fn services(&self) -> BTreeSet<Service> {
        self.stages
            .iter()
            .flat_map(|s| s.actions.iter().map(|a| a.service))
            .collect()
    }
    pub fn evaluate(
        &self,
        persona: &[math::Vector],
        cover: &[math::Vector],
        stages: &[Vec<math::Vector>],
    ) -> Result<CheckedPlan, DriftError> {
        let hash = self.hash()?;
        if stages.len() != self.stages.len()
            || stages
                .iter()
                .zip(&self.stages)
                .any(|(vectors, stage)| vectors.len() != stage.actions.len())
        {
            return Err(DriftError::Embedding);
        }
        let checks = math::score(persona, cover, stages, self.stages.len())?;
        if !checks.valid {
            return Err(DriftError::Plan);
        }
        Ok(CheckedPlan {
            plan: self.clone(),
            hash,
            checks,
            evidence: EmbeddingEvidence {
                persona: persona.to_vec(),
                cover: cover.to_vec(),
                stages: stages.to_vec(),
            },
        })
    }
}
pub struct CheckedPlan {
    plan: Plan,
    hash: String,
    checks: math::PlanChecks,
    evidence: EmbeddingEvidence,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingEvidence {
    pub persona: Vec<math::Vector>,
    pub cover: Vec<math::Vector>,
    pub stages: Vec<Vec<math::Vector>>,
}
impl CheckedPlan {
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn checks(&self) -> &math::PlanChecks {
        &self.checks
    }
    pub fn evidence(&self) -> &EmbeddingEvidence {
        &self.evidence
    }
    pub fn approve(self, displayed_hash: &str) -> Result<ApprovedPlan, DriftError> {
        if displayed_hash != self.hash {
            return Err(DriftError::Approval);
        }
        Ok(ApprovedPlan {
            plan: self.plan,
            hash: self.hash,
        })
    }
}
pub struct ApprovedPlan {
    plan: Plan,
    hash: String,
}
impl ApprovedPlan {
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    plan_hash: String,
    completed_days: usize,
    active_started: Option<u64>,
    last_started: Option<u64>,
    completed_actions: BTreeSet<usize>,
    paused: bool,
}
impl Progress {
    pub fn slot(&self, plan: &Plan) -> Option<(usize, usize)> {
        if self.completed_days >= plan.stages.len() * plan.days_per_stage as usize {
            None
        } else {
            Some((
                self.completed_days / plan.days_per_stage as usize,
                self.completed_days % plan.days_per_stage as usize,
            ))
        }
    }
    pub fn validate(&self, approved: &ApprovedPlan) -> Result<(), DriftError> {
        let total = approved.plan.stages.len() * approved.plan.days_per_stage as usize;
        if self.plan_hash != approved.hash && !self.plan_hash.is_empty()
            || self.completed_days > total
            || self.completed_days == total && self.active_started.is_some()
            || self.active_started.is_some() && self.last_started != self.active_started
        {
            return Err(DriftError::Progress);
        }
        if self.completed_days < total {
            let stage = self.completed_days / approved.plan.days_per_stage as usize;
            if self
                .completed_actions
                .iter()
                .any(|i| *i >= approved.plan.stages[stage].actions.len())
            {
                return Err(DriftError::Progress);
            }
        }
        Ok(())
    }
    pub fn paused(&self) -> bool {
        self.paused
    }
    pub fn last_started(&self) -> Option<u64> {
        self.last_started
    }
    pub fn pause(&mut self) {
        self.paused = true;
    }
    pub fn resume(&mut self) {
        self.paused = false;
    }
    pub fn completed_days(&self) -> usize {
        self.completed_days
    }
    pub fn tasks(
        &mut self,
        approved: &ApprovedPlan,
        now: u64,
    ) -> Result<Vec<DriftTask>, DriftError> {
        if self.paused {
            return Err(DriftError::Paused);
        }
        if self.plan_hash.is_empty() {
            self.plan_hash = approved.hash.clone();
        }
        if self.plan_hash != approved.hash {
            return Err(DriftError::Approval);
        }
        let plan = &approved.plan;
        if self.completed_days >= plan.stages.len() * plan.days_per_stage as usize {
            return Ok(vec![]);
        }
        let stage = self.completed_days / plan.days_per_stage as usize;
        if plan
            .activity
            .as_ref()
            .is_some_and(|schedule| !schedule.allows(stage, now))
        {
            return Err(DriftError::ActivityWindow);
        }
        if self.active_started.is_none() {
            if self
                .last_started
                .is_some_and(|last| now < last.saturating_add(MIN_DAY_GAP_S))
            {
                return Err(DriftError::TooSoon);
            }
            self.active_started = Some(now);
            self.last_started = Some(now);
            self.completed_actions.clear();
        }
        let day = self.completed_days % plan.days_per_stage as usize;
        // Daily variants require new validation/approval. Never silently invent actions.
        Ok(plan.stages[stage]
            .actions
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.completed_actions.contains(i))
            .map(|(i, action)| DriftTask {
                plan_hash: approved.hash.clone(),
                stage: stage as u16 + 1,
                day: day as u16 + 1,
                action_index: i as u16,
                service: action.service,
                text: action.text.clone(),
            })
            .collect())
    }
    pub fn complete(
        &mut self,
        approved: &ApprovedPlan,
        action_index: usize,
    ) -> Result<(), DriftError> {
        if self.paused {
            return Err(DriftError::Paused);
        }
        if self.plan_hash != approved.hash || self.active_started.is_none() {
            return Err(DriftError::Progress);
        }
        let stage = self.completed_days / approved.plan.days_per_stage as usize;
        let count = approved
            .plan
            .stages
            .get(stage)
            .ok_or(DriftError::Progress)?
            .actions
            .len();
        if action_index >= count || !self.completed_actions.insert(action_index) {
            return Err(DriftError::Progress);
        }
        if self.completed_actions.len() == count {
            self.completed_days += 1;
            self.active_started = None;
            self.completed_actions.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        Plan {
            activity: None,
            cover: "gardening".into(),
            days_per_stage: 1,
            sensitive_consent: false,
            stages: (0..4)
                .map(|i| Stage {
                    theme: format!("garden {i}"),
                    bridge: "nature".into(),
                    actions: vec![Action {
                        service: Service::Google,
                        text: "garden ideas".into(),
                    }],
                })
                .collect(),
        }
    }
    fn checked(p: &Plan) -> CheckedPlan {
        let angle = |a: f64| vec![a.cos(), a.sin()];
        p.evaluate(
            &[angle(0.0), angle(0.1)],
            &[angle(1.47), angle(1.57)],
            &[
                vec![angle(0.05)],
                vec![angle(0.5)],
                vec![angle(1.0)],
                vec![angle(1.5)],
            ],
        )
        .unwrap()
    }
    #[test]
    fn approval_is_bound_to_actions_services_and_timing() {
        let mut p = plan();
        let hash = p.hash().unwrap();
        p.stages[0].actions[0].service = Service::Chatgpt;
        assert_ne!(p.hash().unwrap(), hash);
        assert!(checked(&p).approve(&hash).is_err());
        p = plan();
        p.days_per_stage = 2;
        assert_ne!(p.hash().unwrap(), hash);
        p = plan();
        assert!(!serde_json::to_string(&p).unwrap().contains("activity"));
        p.activity = Some(activity::Transition::default().schedule(4).unwrap());
        assert_ne!(p.hash().unwrap(), hash);
        let timed = checked(&p);
        let old = timed.hash().to_owned();
        p.activity = Some(
            activity::Transition {
                start_hour_utc: 13,
                target_hour_utc: 13,
                width_hours: 6,
            }
            .schedule(4)
            .unwrap(),
        );
        assert!(checked(&p).approve(&old).is_err());
        assert!(safety("firearms").is_err());
        assert_eq!(safety("politics"), Ok(Safety::Sensitive));
    }
    #[test]
    fn execution_checks_utc_window_again_after_a_day_has_started() {
        let mut p = plan();
        p.activity = Some(
            activity::Transition {
                start_hour_utc: 22,
                target_hour_utc: 4,
                width_hours: 4,
            }
            .schedule(4)
            .unwrap(),
        );
        let checked = checked(&p);
        let hash = checked.hash().to_owned();
        let approved = checked.approve(&hash).unwrap();
        let mut progress = Progress::default();
        assert!(matches!(
            progress.tasks(&approved, 21 * 3600),
            Err(DriftError::ActivityWindow)
        ));
        assert!(progress.last_started().is_none());
        assert!(!progress.tasks(&approved, 23 * 3600).unwrap().is_empty());
        assert!(!progress.tasks(&approved, 86400 + 3600).unwrap().is_empty());
        assert!(matches!(
            progress.tasks(&approved, 86400 + 2 * 3600),
            Err(DriftError::ActivityWindow)
        ));
    }
    #[test]
    fn pause_day_gap_clock_rollback_and_completion_are_enforced() {
        let p = plan();
        let approved = checked(&p).approve(&p.hash().unwrap()).unwrap();
        let mut progress = Progress::default();
        assert_eq!(progress.tasks(&approved, 100).unwrap().len(), 1);
        progress.complete(&approved, 0).unwrap();
        assert!(progress.complete(&approved, 0).is_err());
        assert!(progress.tasks(&approved, 99).is_err());
        assert!(progress.tasks(&approved, 101).is_err());
        progress.pause();
        assert!(progress.tasks(&approved, 50000).is_err());
        progress.resume();
        assert_eq!(
            progress.tasks(&approved, 100 + MIN_DAY_GAP_S).unwrap()[0].stage,
            2
        );
    }
    #[test]
    fn daily_rewrite_is_checked_and_approval_bound() {
        let p = plan();
        let checked = checked(&p);
        let evidence = checked.evidence().clone();
        let approved = checked.approve(&p.hash().unwrap()).unwrap();
        let mut day = variants::Day {
            plan_hash: approved.hash().into(),
            stage: 0,
            day: 0,
            actions: p.stages[0].actions.clone(),
        };
        let checked = day
            .evaluate(&approved, &evidence, &evidence.stages[0])
            .unwrap();
        let hash = checked.hash().to_owned();
        assert!(checked.approve("wrong").is_err());
        day.actions[0].service = Service::Youtube;
        assert!(
            day.evaluate(&approved, &evidence, &evidence.stages[0])
                .is_err()
        );
        day.actions[0].service = Service::Google;
        day.actions[0].text = "a different garden wording".into();
        let checked = day
            .evaluate(&approved, &evidence, &evidence.stages[0])
            .unwrap();
        assert_ne!(checked.hash(), hash);
        assert!(
            day.evaluate(&approved, &evidence, &[vec![0.0, 1.0]])
                .is_err()
        );
    }
}
