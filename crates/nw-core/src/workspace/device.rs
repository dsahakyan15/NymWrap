use super::*;
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProbeStatus {
    pub last_attempt: u64,
    pub last_success: u64,
    pub protected_values: usize,
    pub unavailable: Vec<nw_probe::Source>,
    pub code: Option<String>,
}
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
impl Workspace {
    pub fn device_probe_status(&mut self) -> Result<DeviceProbeStatus, WorkspaceError> {
        let mut status: DeviceProbeStatus = self
            .store
            .get_json(Domain::Vault, "device-probe-status")?
            .unwrap_or_default();
        status.protected_values = self
            .secrets()?
            .iter()
            .filter(|s| matches!(s.kind, SecretKind::Device))
            .count();
        Ok(status)
    }
    pub(crate) fn device_probe_due(&mut self) -> Result<bool, WorkspaceError> {
        let status = self.device_probe_status()?;
        let at = now();
        Ok(self.config.hard.device_secrets
            && (status.last_attempt == 0
                || at < status.last_attempt
                || at.saturating_sub(status.last_attempt) >= 86400))
    }
    pub(crate) fn device_probe_ready(&mut self) -> Result<bool, WorkspaceError> {
        if !self.config.hard.device_secrets {
            return Ok(true);
        }
        let status = self.device_probe_status()?;
        let at = now();
        Ok(status.last_success > 0
            && at >= status.last_success
            && at - status.last_success < 86400
            && status.code.is_none()
            && status.unavailable.is_empty())
    }
    pub(crate) fn remember_device_removals(
        &mut self,
        next: &[SecretRecord],
    ) -> Result<(), WorkspaceError> {
        let mut suppressed: std::collections::BTreeSet<String> = self
            .store
            .get_json(Domain::Vault, "device-probe-suppressed")?
            .unwrap_or_default();
        let previous = self.secrets()?;
        for item in previous
            .iter()
            .filter(|s| matches!(s.kind, SecretKind::Device))
        {
            if !next
                .iter()
                .any(|s| matches!(s.kind, SecretKind::Device) && s.value == item.value)
            {
                suppressed.insert(digest(&item.value));
            }
        }
        for item in next.iter().filter(|s| matches!(s.kind, SecretKind::Device)) {
            suppressed.remove(&digest(&item.value));
        }
        if suppressed.len() > 4096 {
            return Err(WorkspaceError::Invalid);
        }
        self.store
            .put_json(Domain::Vault, "device-probe-suppressed", &suppressed, now())?;
        Ok(())
    }
    pub(crate) fn begin_device_probe(&mut self) -> Result<(), WorkspaceError> {
        let mut status = self.device_probe_status()?;
        status.last_attempt = now();
        status.code = Some("probe_pending".into());
        self.store
            .put_json(Domain::Vault, "device-probe-status", &status, now())?;
        Ok(())
    }
    pub(crate) fn save_device_probe(
        &mut self,
        report: Result<nw_probe::Report, &str>,
    ) -> Result<bool, WorkspaceError> {
        let at = now();
        let mut status = self.device_probe_status()?;
        status.last_attempt = at;
        let mut changed = false;
        match report {
            Ok(report) => {
                if !report.valid() {
                    return Err(WorkspaceError::Invalid);
                }
                let suppressed: std::collections::BTreeSet<String> = self
                    .store
                    .get_json(Domain::Vault, "device-probe-suppressed")?
                    .unwrap_or_default();
                let mut secrets = self.secrets()?;
                let previous_len = secrets.len();
                for item in &report.values {
                    if !suppressed.contains(&digest(&item.value))
                        && !secrets.iter().any(|s| s.value == item.value)
                    {
                        secrets.push(SecretRecord {
                            kind: SecretKind::Device,
                            value: item.value.clone(),
                            local_only: false,
                        });
                    }
                }
                let validated = secrets
                    .iter()
                    .map(|s| Secret::new(s.kind, s.value.clone(), s.local_only))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| WorkspaceError::Invalid)?;
                Shield::new(validated).map_err(|_| WorkspaceError::Invalid)?;
                // Commit protection before marking the inventory successful.
                self.store
                    .put_json(Domain::Vault, "secrets", &secrets, at)?;
                changed = previous_len != secrets.len();
                status.last_success = at;
                status.code = None;
                status.unavailable = report.unavailable.clone();
                status.protected_values = secrets
                    .iter()
                    .filter(|s| matches!(s.kind, SecretKind::Device))
                    .count();
                self.execution_session = zeroize::Zeroizing::new(nw_cred::os::random_id());
            }
            Err(code) => {
                status.code = Some(
                    match code {
                        "probe_sandbox_unavailable" => "probe_sandbox_unavailable",
                        "probe_timeout" => "probe_timeout",
                        _ => "probe_failed",
                    }
                    .into(),
                );
            }
        }
        self.store
            .put_json(Domain::Vault, "device-probe-status", &status, at)?;
        Ok(changed)
    }
}
