use super::{Domain, Workspace, WorkspaceError, now};
use nw_cover::budget::{DailyBudget, Usage};
impl Workspace {
    pub fn check_network_cost(&mut self, cost: u64, at: u64) -> Result<(), WorkspaceError> {
        let mut budget: DailyBudget = self
            .store
            .get_json(Domain::Vault, "network-budget")?
            .unwrap_or_else(|| DailyBudget::new(at));
        budget
            .reserve(
                at,
                self.config.cover.max_requests_per_day,
                (self.config.cover.max_spend_per_day_usd * 1_000_000.0).floor() as u64,
                cost,
            )
            .map_err(|_| WorkspaceError::Budget)?;
        Ok(())
    }
    pub fn reserve_network_cost(&mut self, cost: u64, at: u64) -> Result<Usage, WorkspaceError> {
        let mut budget: DailyBudget = self
            .store
            .get_json(Domain::Vault, "network-budget")?
            .unwrap_or_else(|| DailyBudget::new(at));
        let usage = budget
            .reserve(
                at,
                self.config.cover.max_requests_per_day,
                (self.config.cover.max_spend_per_day_usd * 1_000_000.0).floor() as u64,
                cost,
            )
            .map_err(|_| WorkspaceError::Budget)?;
        // The shadow accounting state survives a Metrics-domain shred.
        self.store
            .put_json(Domain::Vault, "network-budget", &budget, now())?;
        Ok(usage)
    }
    pub fn network_usage(&mut self) -> Result<Usage, WorkspaceError> {
        let budget: DailyBudget = self
            .store
            .get_json(Domain::Vault, "network-budget")?
            .unwrap_or_else(|| DailyBudget::new(now()));
        budget.validate().map_err(|_| WorkspaceError::Invalid)?;
        Ok(budget.usage())
    }
}
