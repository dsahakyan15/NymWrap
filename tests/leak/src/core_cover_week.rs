//! M3 synthetic clock driver: production Workspace slots/accounting, no network of its own.
use nw_core::{config::CoverMode, workspace::Workspace};
use nw_platform::LockedKey;
use nw_vault::{VaultError, os_secret::SecretStore};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    future::Future,
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Keys(Mutex<BTreeMap<String, LockedKey>>);
impl SecretStore for Keys {
    fn put(&self, id: &str, value: &LockedKey) -> Result<(), VaultError> {
        self.0
            .lock()
            .unwrap()
            .insert(id.into(), value.copy().map_err(|_| VaultError::MemoryLock)?);
        Ok(())
    }
    fn get(&self, id: &str) -> Result<LockedKey, VaultError> {
        let keys = self.0.lock().unwrap();
        let key = keys.get(id).ok_or(VaultError::OsSecret)?;
        key.copy().map_err(|_| VaultError::MemoryLock)
    }
    fn remove(&self, id: &str) -> Result<(), VaultError> {
        self.0.lock().unwrap().remove(id);
        Ok(())
    }
}

pub async fn exercise<F, S, O>(root: &Path, prepare: F, mut send: S) -> Value
where
    F: Fn(usize) -> nw_net::ShapedRequest,
    S: FnMut(String, nw_net::ShapedRequest, bool) -> O,
    O: Future<Output = ()>,
{
    let mut scenarios = Vec::new();
    let mut packet_index = 16usize;
    for (scenario, (mode, max_requests, max_spend)) in [
        (CoverMode::Poisson, 3, 14),
        (CoverMode::Poisson, 5, 10),
        (CoverMode::Constant, 3, 14),
        (CoverMode::Constant, 5, 10),
    ]
    .into_iter()
    .enumerate()
    {
        let path = root.join(scenario.to_string());
        let keys = Arc::new(Keys::default());
        let mut workspace = Workspace::create_with(
            &path,
            SecretString::from(""),
            nw_proto::Profile::Standard,
            keys.clone(),
        )
        .unwrap();
        let mut config = workspace.config.clone();
        config.cover.enabled = true;
        config.cover.mode = mode;
        config.cover.mean_interval_s = 60;
        config.cover.max_requests_per_day = max_requests;
        config.cover.max_spend_per_day_usd = f64::from(max_spend) / 1_000_000.0;
        config.net.transport = nw_core::config::Transport::Tor;
        config.net.provider_host = Some("api.example.test".into());
        config.net.provider_path = Some("/v1/chat/completions".into());
        config.net.provider_model = Some("synthetic".into());
        config.net.credential_ref = Some("keyring:pool".into());
        config.net.max_request_cost_microusd = Some(3);
        workspace.save_config(config).unwrap();
        assert!(workspace.take_traffic_slot(0, false).unwrap().is_none());
        let mut days = Vec::new();
        for day in 0..7u64 {
            let mut events = Vec::new();
            for slot in 0..3 {
                let at = workspace
                    .traffic_status()
                    .unwrap()
                    .next_slot
                    .unwrap()
                    .max(day * 86400);
                assert!(at < (day + 1) * 86400);
                let real = (slot + day as usize) % 2 == 0;
                assert!(workspace.take_traffic_slot(at - 1, real).unwrap().is_none());
                let job = workspace.take_traffic_slot(at, real).unwrap().unwrap();
                let usage = workspace.reserve_network_cost(3, at).unwrap();
                let body = prepare(packet_index);
                let hash = format!("{:x}", Sha256::digest(body.bytes()));
                let bytes = body.bytes().len();
                let conversation = format!("{packet_index:032x}");
                send(conversation.clone(), body, real).await;
                workspace.finish_traffic_job(&job.id, Ok(())).unwrap();
                // Reopening must preserve both reservations and cannot emit another slot.
                drop(workspace);
                workspace =
                    Workspace::open_with(&path, SecretString::from(""), keys.clone()).unwrap();
                assert_eq!(
                    serde_json::to_value(workspace.network_usage().unwrap()).unwrap(),
                    serde_json::to_value(&usage).unwrap()
                );
                assert!(workspace.take_traffic_slot(at, !real).unwrap().is_none());
                events.push(json!({"packet_index":packet_index,"conversation":conversation,"at":at,
                    "kind":if real {"real"} else {"decoy"},"bytes":bytes,"sha256":hash,"usage":usage,
                    "slot_id":job.id}));
                packet_index += 1;
            }
            let before = serde_json::to_value(workspace.network_usage().unwrap()).unwrap();
            for at in [(day + 1) * 86400 - 2, (day + 1) * 86400 - 1] {
                assert!(workspace.take_traffic_slot(at, true).unwrap().is_none());
                assert!(workspace.take_traffic_slot(at, false).unwrap().is_none());
                assert!(workspace.reserve_network_cost(3, at).is_err());
                assert_eq!(
                    serde_json::to_value(workspace.network_usage().unwrap()).unwrap(),
                    before
                );
                drop(workspace);
                workspace =
                    Workspace::open_with(&path, SecretString::from(""), keys.clone()).unwrap();
                assert_eq!(
                    serde_json::to_value(workspace.network_usage().unwrap()).unwrap(),
                    before
                );
            }
            assert!(workspace.reserve_network_cost(3, 0).is_err());
            days.push(json!({"day":day,"events":events,"usage":before,"blocked_probes":2}));
        }
        scenarios.push(
            json!({"mode":mode,"max_requests_per_day":max_requests,"max_spend_microusd":max_spend,
            "cost_upper_bound_microusd":3,"mean_interval_s":60,"days":days}),
        );
    }
    assert_eq!(packet_index, 100);
    json!({"version":1,"simulated_days":7,"production_workspace":true,"scenarios":scenarios})
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn seven_day_driver_uses_persisted_core_slots_and_both_budget_limits() {
        let root = tempfile::tempdir().unwrap();
        let shield = nw_shield::Shield::new(vec![]).unwrap();
        let mut sent = 0;
        let result = super::exercise(
            root.path(),
            |_| {
                let prepared = shield
                    .prepare("Explain pottery.", &mut Default::default(), |text| {
                        Ok(serde_json::json!([{"role":"user","content":text}]).to_string())
                    })
                    .unwrap();
                nw_net::ShapedRequest::history(&prepared, "synthetic", 16).unwrap()
            },
            |_, _, _| {
                sent += 1;
                std::future::ready(())
            },
        )
        .await;
        assert_eq!(sent, 84);
        assert_eq!(result["scenarios"].as_array().unwrap().len(), 4);
    }
}
