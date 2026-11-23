//! The evaluator owns its workers; kernel peer credentials stay bound to their
//! retained child handles. No /proc permission or caller-supplied PID is trusted.
use nw_llm::UnixModel;
use serde::Deserialize;
use std::{
    io::Read,
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Deserialize, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub model_path: String,
    pub model_sha256: String,
    pub embed_path: String,
    pub embed_sha256: String,
}
#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub defender: Plan,
    pub attacker: Plan,
    pub stop_after_invalid_attacker: bool,
}
impl Launch {
    pub fn read(reader: impl Read) -> Result<Self, Box<dyn std::error::Error>> {
        let mut bytes = Zeroizing::new(vec![]);
        reader.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err("worker_plan_too_large".into());
        }
        let launch: Self = serde_json::from_slice(&bytes)?;
        for plan in [&launch.defender, &launch.attacker] {
            if !Path::new(&plan.model_path).is_absolute()
                || !Path::new(&plan.embed_path).is_absolute()
                || !super::hex_hash(&plan.model_sha256)
                || plan.embed_sha256 != nw_core::linkcheck::MODEL_SHA256
            {
                return Err("invalid_worker_plan".into());
            }
        }
        Ok(launch)
    }
}
pub struct Worker {
    child: Arc<Mutex<tokio::process::Child>>,
    pub model: UnixModel,
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            drop(child.stdin.take());
            let _ = child.start_kill();
        }
    }
}
impl Worker {
    pub async fn start(
        binary: &Path,
        endpoint: &str,
        plan: &Plan,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if !binary.is_absolute() {
            return Err("invalid_worker_image".into());
        }
        let mut command = tokio::process::Command::new(binary);
        command
            .args([
                "--parent-stdio",
                "--socket",
                endpoint,
                "--model",
                &plan.model_path,
                "--sha256",
                &plan.model_sha256,
                "--embed-model",
                &plan.embed_path,
                "--embed-sha256",
                &plan.embed_sha256,
            ])
            .env_clear()
            .current_dir(binary.parent().ok_or("invalid_worker_image")?)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for key in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let child = Arc::new(Mutex::new(command.spawn()?));
        let model = UnixModel::new(endpoint.into(), "default".into(), "nomic-embed-text".into())?
            .expect_spawned_peer(&child);
        let result = Self { child, model };
        let address = nw_ipc::Endpoint::new(endpoint.into(), nw_proto::Lane::Shadow)?;
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if result
                .child
                .lock()
                .map_err(|_| "worker_state_unavailable")?
                .try_wait()?
                .is_some()
            {
                return Err("worker_exited_before_ready".into());
            }
            if let Ok(stream) = address.connect().await {
                let mut child = result
                    .child
                    .lock()
                    .map_err(|_| "worker_state_unavailable")?;
                if child.try_wait()?.is_some()
                    || nw_ipc::peer_process(&stream)?
                        != child.id().ok_or("worker_exited_before_ready")?
                {
                    return Err("worker_peer_unverified".into());
                }
                drop(child);
                return Ok(result);
            }
            if Instant::now() > deadline {
                return Err("worker_start_timeout".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
