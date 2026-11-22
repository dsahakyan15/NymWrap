//! One-shot cover search permits. Interrupted actions remain tombstones.
use super::*;
#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Attempt {
    session: String,
    token: String,
    started_at: u64,
    completed: bool,
}
fn task_id(task: &DriftTask) -> Result<String, WorkspaceError> {
    Ok(format!(
        "execution-{:x}",
        Sha256::digest(serde_json::to_vec(task).map_err(|_| WorkspaceError::Invalid)?)
    ))
}
fn same(a: &DriftTask, b: &DriftTask) -> bool {
    a.plan_hash == b.plan_hash
        && a.stage == b.stage
        && a.day == b.day
        && a.action_index == b.action_index
        && a.service == b.service
        && a.text == b.text
}
impl Workspace {
    fn search_execution_policy(&self, task: &DriftTask) -> Result<(), WorkspaceError> {
        if !matches!(self.config.drift.mode, crate::config::DriftMode::Extension)
            || !matches!(
                task.service,
                nw_proto::Service::Google | nw_proto::Service::Youtube
            )
            || task.text.chars().count() > 512
        {
            return Err(WorkspaceError::Policy);
        }
        Ok(())
    }
    pub fn begin_search_execution(
        &mut self,
        task: &DriftTask,
        at: u64,
    ) -> Result<String, WorkspaceError> {
        self.search_execution_policy(task)?;
        let tasks = self.daily_tasks(at)?;
        if !tasks.iter().any(|t| same(t, task)) {
            return Err(WorkspaceError::Invalid);
        }
        let id = task_id(task)?;
        if self.store.get(Domain::CoverLog, &id)?.is_some() {
            return Err(WorkspaceError::AlreadyAttempted);
        }
        if let Some(previous) = self
            .store
            .recent_ids(Domain::CoverLog, "execution-", 1)?
            .first()
        {
            let prior: Attempt = self
                .store
                .get_json(Domain::CoverLog, previous)?
                .ok_or(WorkspaceError::Invalid)?;
            let still_pending = tasks
                .iter()
                .map(task_id)
                .collect::<Result<Vec<_>, _>>()?
                .contains(previous);
            if !prior.completed && still_pending && at < prior.started_at.saturating_add(900) {
                return Err(WorkspaceError::ExecutionBusy);
            }
        }
        let token = nw_cred::os::random_id();
        self.store.put_json(
            Domain::CoverLog,
            &id,
            &Attempt {
                session: self.execution_session.to_string(),
                token: token.clone(),
                started_at: at,
                completed: false,
            },
            at,
        )?;
        Ok(token)
    }
    pub fn finish_search_execution(
        &mut self,
        task: &DriftTask,
        token: &str,
        at: u64,
    ) -> Result<(), WorkspaceError> {
        self.validate_search_execution(task, token, at)?;
        let id = task_id(task)?;
        let mut attempt: Attempt = self
            .store
            .get_json(Domain::CoverLog, &id)?
            .ok_or(WorkspaceError::Invalid)?;
        let minimum = 20 + task.text.chars().count() as u64 * 60 / 1000;
        if attempt.completed
            || attempt.token != token
            || at < attempt.started_at.saturating_add(minimum)
            || at > attempt.started_at.saturating_add(900)
        {
            return Err(WorkspaceError::Policy);
        }
        self.complete_bound_task(task, at)?;
        attempt.completed = true;
        self.store.put_json(Domain::CoverLog, &id, &attempt, at)?;
        Ok(())
    }
    pub fn validate_search_execution(
        &mut self,
        task: &DriftTask,
        token: &str,
        at: u64,
    ) -> Result<(), WorkspaceError> {
        self.search_execution_policy(task)?;
        let attempt: Attempt = self
            .store
            .get_json(Domain::CoverLog, &task_id(task)?)?
            .ok_or(WorkspaceError::Invalid)?;
        if attempt.completed
            || attempt.token != token
            || attempt.session != self.execution_session.as_str()
            || at < attempt.started_at
            || at > attempt.started_at.saturating_add(900)
        {
            return Err(WorkspaceError::Policy);
        }
        if !self.daily_tasks(at)?.iter().any(|t| same(t, task)) {
            return Err(WorkspaceError::Invalid);
        }
        Ok(())
    }
}
