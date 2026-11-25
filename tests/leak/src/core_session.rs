//! Compiled inside core so regressions exercise its actual session/dispatch gates.
use super::*;
use crate::{
    CoreError, RemoteCompletion, RemoteStep,
    service::{Command, Reply, Service},
};
use nw_platform::LockedKey;
use nw_proto::{Profile, TrustLevel};
use nw_vault::{VaultError, os_secret::SecretStore};
use std::time::Duration;
const CANARY: &str = "SESSION_PRIVATE_CANARY_68124";
#[test]
fn strict_and_paranoid_never_keep_an_unapproved_l3_tail_even_with_stale_consent() {
    for profile in [Profile::Strict, Profile::Paranoid] {
        let (_directory, state) = fixture(true);
        {
            let mut session = state.session.lock().unwrap();
            let workspace = session.workspace.as_mut().unwrap();
            workspace.config.profile = profile;
            assert!(workspace.config.shield.min_trust == TrustLevel::L3);
        }
        let closed = close_at(&state, true, Instant::now()).unwrap();
        assert!(closed.value.phase == Phase::Locked);
        assert!(closed.timer.is_none());
        assert!(state.session.lock().unwrap().workspace.is_none());
    }
}

#[tokio::test]
async fn unapproved_same_user_shadow_client_cannot_read_unlocked_secrets() {
    use nw_ipc::{Endpoint, Listener, Packet};
    use nw_proto::Lane;
    let (directory, source) = fixture(false);
    let service = Service::runtime(None);
    service.state.session.lock().unwrap().workspace =
        source.session.lock().unwrap().workspace.take();
    #[cfg(unix)]
    let address = directory
        .path()
        .join("private/attack.sock")
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let address = format!(
        "nymwrap-unapproved-{}-{}",
        std::process::id(),
        directory.path().file_name().unwrap().to_string_lossy()
    );
    let endpoint = Endpoint::new(address, Lane::Shadow).unwrap();
    let listener = Listener::bind(endpoint.clone()).unwrap();
    let worker = service.clone();
    let server = tokio::spawn(async move {
        worker.serve_shadow(listener).await.unwrap();
    });
    let mut stream = endpoint.connect().await.unwrap();
    let bytes = serde_json::to_vec(&Packet::new(Lane::Shadow, 1, Command::LoadSecrets {})).unwrap();
    // Early rejection can close the pipe before the first legacy frame is written.
    let _write = nw_ipc::write_frame(&mut stream, &bytes, 4096).await;
    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        nw_ipc::read_frame(&mut stream, 4096),
    )
    .await;
    server.abort();
    let _ = server.await;
    match reply {
        Ok(Err(_)) => {}
        Ok(Ok(bytes)) => {
            assert!(
                !bytes
                    .windows(CANARY.len())
                    .any(|part| part == CANARY.as_bytes()),
                "unapproved same-user IPC client received a vault canary"
            );
            let packet: Packet<Reply> = serde_json::from_slice(&bytes).unwrap();
            assert!(matches!(packet.body, Reply::Error { .. }));
        }
        Err(_) => panic!("unapproved client must be rejected within the bounded handshake"),
    }
}

#[tokio::test]
async fn authorized_control_reads_its_canary_but_api_cannot_read_or_approve() {
    use crate::service::{Client, RpcRole};
    use nw_ipc::{Endpoint, Listener};
    use nw_proto::Lane;
    for role in [RpcRole::Control, RpcRole::Api] {
        let (directory, source) = fixture(false);
        let mut service = Service::runtime(None);
        service.state.session.lock().unwrap().workspace =
            source.session.lock().unwrap().workspace.take();
        #[cfg(unix)]
        let address = directory
            .path()
            .join("private/authorized.sock")
            .to_string_lossy()
            .into_owned();
        #[cfg(windows)]
        let address = format!(
            "nymwrap-authorized-{}-{}",
            std::process::id(),
            directory.path().file_name().unwrap().to_string_lossy()
        );
        let endpoint = Endpoint::new(address, Lane::Shadow).unwrap();
        let listener = Listener::bind(endpoint.clone()).unwrap();
        let client: Client = service.authorize_test_client(endpoint, role);
        let server = tokio::spawn(async move {
            service.serve_shadow(listener).await.unwrap();
        });
        let secrets = client.request(Command::LoadSecrets {}).await;
        let approval = client
            .request(Command::ApproveRemote {
                approval_id: "a".repeat(32),
                hash: "b".repeat(64),
            })
            .await;
        let config = client.request(Command::LoadConfig {}).await;
        let history = client
            .request(Command::LoadHistory {
                conversation: "a".repeat(32),
            })
            .await;
        let lock = client.request(Command::Lock {}).await;
        server.abort();
        let _ = server.await;
        if role == RpcRole::Control {
            let value = serde_json::to_string(&secrets.unwrap()).unwrap();
            assert!(
                value.contains(CANARY),
                "positive control must read the unlocked synthetic vault"
            );
            assert!(matches!(config.unwrap(), Reply::Config { .. }));
            assert!(matches!(lock.unwrap(), Reply::Ack {}));
        } else {
            for outcome in [secrets, approval, config, history, lock] {
                assert!(
                    matches!(outcome.unwrap(), Reply::Error { code } if code == "ipc_forbidden")
                );
            }
        }
    }
}

#[test]
fn private_bridges_are_encrypted_reopened_bound_to_approvals_and_guarded_by_shield() {
    use nw_net::bridges::{BridgeConfig, BridgeTransport};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let keys = Arc::new(Keys::default());
    let mut w = Workspace::create_with(
        &root,
        SecretString::from(""),
        Profile::Standard,
        keys.clone(),
    )
    .unwrap();
    let before = w.routing_context().unwrap();
    let url = "https://bridge.example.test/PRIVATE_BRIDGE_CANARY_57214";
    let settings = BridgeConfig {
        transport: BridgeTransport::Webtunnel,
        lines: vec![format!(
            "webtunnel 192.0.2.55:443 {} url={url} ver=0.0.1",
            "A".repeat(40)
        )],
    };
    let status = w.set_bridges(Some(settings)).unwrap();
    assert!(
        !serde_json::to_string(&status)
            .unwrap()
            .contains("PRIVATE_BRIDGE_CANARY")
    );
    let after = w.routing_context().unwrap();
    assert_ne!(before, after);
    let shield = w.shield().unwrap();
    assert!(
        shield
            .leakcheck(url, &nw_shield::ConversationVault::default())
            .is_err()
    );
    drop(w);
    fn ciphertext(path: &std::path::Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                ciphertext(&path);
            } else {
                assert!(
                    !std::fs::read(path)
                        .unwrap()
                        .windows(b"PRIVATE_BRIDGE_CANARY".len())
                        .any(|w| w == b"PRIVATE_BRIDGE_CANARY")
                );
            }
        }
    }
    ciphertext(&root);
    let mut w = Workspace::open_with(&root, SecretString::from(""), keys).unwrap();
    assert_eq!(w.routing_context().unwrap(), after);
    assert_eq!(w.bridge_status().unwrap().lines, 1);
    w.set_bridges(None).unwrap();
    assert_eq!(w.routing_context().unwrap(), before);
}

#[tokio::test]
async fn rpc_replay_reflection_wrong_role_key_and_legacy_frames_cannot_read_vault() {
    use crate::service::{RpcRole, auth};
    use nw_ipc::{Endpoint, IpcError, Listener, Packet};
    use nw_proto::Lane;
    let (directory, source) = fixture(false);
    let mut service = Service::runtime(None);
    service.state.session.lock().unwrap().workspace =
        source.session.lock().unwrap().workspace.take();
    #[cfg(unix)]
    let address = directory
        .path()
        .join("private/replay.sock")
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let address = format!(
        "nymwrap-rpc-replay-{}-{}",
        std::process::id(),
        directory.path().file_name().unwrap().to_string_lossy()
    );
    let endpoint = Endpoint::new(address, Lane::Shadow).unwrap();
    let listener = Listener::bind(endpoint.clone()).unwrap();
    let client = service.authorize_test_client(endpoint.clone(), RpcRole::Control);
    let server = tokio::spawn(async move {
        service.serve_shadow(listener).await.unwrap();
    });
    let outcome: Result<bool, Box<dyn std::error::Error>> = async {
        let request = zeroize::Zeroizing::new(serde_json::to_vec(&Packet::new(
            Lane::Shadow,
            81,
            Command::LoadSecrets {},
        ))?);
        let key = &client.grant.key;
        let other_key = auth::Key::random()?;
        let mut stream = endpoint.connect().await?;
        let challenge = nw_ipc::read_frame(&mut stream, 32).await?;
        let challenge: [u8; 32] = challenge.as_slice().try_into()?;
        let recorded = key.seal(RpcRole::Control, &challenge, false, &request)?;
        nw_ipc::write_frame(&mut stream, &recorded, 4096).await?;
        let response = nw_ipc::read_frame(&mut stream, 4096).await?;
        let response = key.open(RpcRole::Control, &challenge, true, &response)?;
        let mut all_checked = response
            .windows(CANARY.len())
            .any(|part| part == CANARY.as_bytes());
        drop(stream);
        for mode in 0..5 {
            let mut stream = endpoint.connect().await?;
            let fresh = nw_ipc::read_frame(&mut stream, 32).await?;
            let fresh: [u8; 32] = fresh.as_slice().try_into()?;
            all_checked &= fresh != challenge;
            let invalid = match mode {
                0 => recorded.clone(),
                1 => key.seal(RpcRole::Control, &fresh, true, &request)?,
                2 => other_key.seal(RpcRole::Control, &fresh, false, &request)?,
                3 => key.seal(RpcRole::Api, &fresh, false, &request)?,
                _ => request.clone(),
            };
            nw_ipc::write_frame(&mut stream, &invalid, 4096).await?;
            let response =
                nw_ipc::read_frame_timeout(&mut stream, 4096, Duration::from_secs(2)).await;
            all_checked &= matches!(response, Err(IpcError::Io));
        }
        let valid = client.request(Command::LoadSecrets {}).await?;
        all_checked &= serde_json::to_string(&valid)?.contains(CANARY);
        Ok(all_checked)
    }
    .await;
    server.abort();
    let _ = server.await;
    assert!(
        outcome.unwrap(),
        "invalid authority must close its connection; the authorized positive control must remain available"
    );
}

#[derive(Default)]
struct Keys(Mutex<std::collections::BTreeMap<String, LockedKey>>);
impl SecretStore for Keys {
    fn put(&self, id: &str, key: &LockedKey) -> Result<(), VaultError> {
        self.0
            .lock()
            .unwrap()
            .insert(id.into(), key.copy().map_err(|_| VaultError::MemoryLock)?);
        Ok(())
    }
    fn get(&self, id: &str) -> Result<LockedKey, VaultError> {
        self.0
            .lock()
            .unwrap()
            .get(id)
            .ok_or(VaultError::OsSecret)?
            .copy()
            .map_err(|_| VaultError::MemoryLock)
    }
    fn remove(&self, id: &str) -> Result<(), VaultError> {
        self.0.lock().unwrap().remove(id);
        Ok(())
    }
}
fn fixture(consent: bool) -> (tempfile::TempDir, State) {
    let directory = tempfile::tempdir().unwrap();
    let mut w = Workspace::create_with(
        &directory.path().join("workspace"),
        SecretString::from(""),
        Profile::Standard,
        Arc::new(Keys::default()),
    )
    .unwrap();
    let mut config = w.config.clone();
    config.hard.device_secrets = false;
    config.hard.background_tail = consent;
    config.cover.enabled = consent;
    config.net = crate::config::NetConfig {
        transport: crate::config::Transport::Tor,
        provider_host: Some("example.test".into()),
        provider_path: Some("/v1/chat/completions".into()),
        provider_model: Some("synthetic".into()),
        credential_ref: Some("keyring:pool".into()),
        max_request_cost_microusd: Some(1),
    };
    w.save_config(config).unwrap();
    w.set_secrets(vec![SecretRecord {
        kind: nw_shield::SecretKind::Secret,
        value: CANARY.into(),
        local_only: false,
    }])
    .unwrap();
    let state = State::default();
    let mut s = state.session.lock().unwrap();
    s.workspace = Some(w);
    s.timing = Some(nw_cover::session::Clock::new(
        Instant::now() - Duration::from_secs(3600),
        &mut rand::rngs::OsRng,
    ));
    drop(s);
    (directory, state)
}
struct Model;
impl LocalModel for Model {
    async fn embed_identified(
        &self,
        texts: &[String],
    ) -> Result<nw_llm::EmbeddingBatch, nw_llm::ModelError> {
        Ok(crate::link_fixture::identified(texts))
    }
    async fn complete(&self, _: &[Message]) -> Result<SecretString, nw_llm::ModelError> {
        unreachable!("no answer generation in boundary tests")
    }
    async fn canonicalize(&self, text: &str) -> Result<SecretString, nw_llm::ModelError> {
        Ok(text.to_owned().into())
    }
    async fn identify_entities(&self, _: &str) -> Result<SecretString, nw_llm::ModelError> {
        Ok(r#"{"local_only":false,"entities":[]}"#.into())
    }
    async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, nw_llm::ModelError> {
        Err(nw_llm::ModelError::Unavailable)
    }
}
struct NoNetwork;
impl RemoteCompletion for NoNetwork {
    fn trust(&self) -> TrustLevel {
        TrustLevel::L3
    }
    fn context(&self) -> &str {
        "synthetic-boundaries"
    }
    async fn complete(
        &self,
        _: &str,
        _: &nw_shield::Prepared,
        _: u32,
    ) -> Result<SecretString, CoreError> {
        panic!("boundary test must not send")
    }
}
async fn job(w: &mut Workspace) -> workspace::RemoteJobInfo {
    let engine = crate::link_fixture::configured(Model, w.shield().unwrap(), &w.config).unwrap();
    let RemoteStep::Review(review) = engine
        .review_remote(
            "new",
            &[Message {
                role: nw_llm::Role::User,
                content: format!("Explain pottery for {CANARY}"),
            }],
            32,
            &NoNetwork,
        )
        .await
        .unwrap()
    else {
        panic!("review expected");
    };
    assert!(!review.transcript.contains(CANARY));
    let approved = engine
        .take_remote_approval(&review.approval_id, &review.hash, &NoNetwork)
        .await
        .unwrap();
    w.create_remote_job(&approved, 0).unwrap()
}

#[tokio::test]
async fn close_cancels_real_jobs_and_tail_cannot_expose_or_destroy_workspace() {
    let (_directory, state) = fixture(true);
    // Both durable states must be resolved before background operation starts.
    let mut w = state.session.lock().unwrap().workspace.take().unwrap();
    let queued = job(&mut w).await;
    let sending = job(&mut w).await;
    w.remote_job_sending(&sending.id).unwrap();
    state.session.lock().unwrap().workspace = Some(w);
    let worker = tokio::spawn(std::future::pending::<()>());
    state
        .jobs
        .lock()
        .unwrap()
        .insert(queued.id.clone(), worker.abort_handle());
    let closed = close_at(&state, true, Instant::now()).unwrap();
    assert!(closed.value.phase == Phase::Tail);
    assert!((600..=3600).contains(&closed.value.tail_remaining_s.unwrap()));
    assert!(worker.await.unwrap_err().is_cancelled());
    assert!(state.jobs.lock().unwrap().is_empty());
    let deadline = closed.timer.unwrap();
    assert_eq!(
        close_at(&state, true, Instant::now() + Duration::from_secs(500))
            .unwrap()
            .timer,
        None
    );
    assert_eq!(
        state
            .session
            .lock()
            .unwrap()
            .timing
            .unwrap()
            .tail_deadline(),
        Some(deadline.1)
    );
    {
        let mut s = state.session.lock().unwrap();
        assert_eq!(require(&mut s).err().unwrap(), "workspace_locked");
        let w = require_background(&mut s).unwrap();
        let jobs = w.remote_jobs().unwrap();
        assert!(
            jobs.iter()
                .any(|j| j.id == queued.id && j.state == workspace::RemoteJobState::Cancelled)
        );
        assert!(
            jobs.iter()
                .any(|j| j.id == sending.id && j.state == workspace::RemoteJobState::Uncertain)
        );
        assert!(!storage_status(&mut s, true).unwrap().unlocked);
        assert!(storage_status(&mut s, true).unwrap().overview.is_none());
    }
    let service = Service {
        state: state.clone(),
        ..Service::default()
    };
    for command in [
        Command::LoadSecrets {},
        Command::LoadConfig {},
        Command::LoadHistory {
            conversation: "a".repeat(32),
        },
        Command::DestroyData {
            confirmation: "СТЕРЕТЬ ВСЁ".into(),
        },
    ] {
        let reply = service.handle(command).await;
        assert!(!serde_json::to_string(&reply).unwrap().contains(CANARY));
        assert!(matches!(reply, Reply::Error {code} if code=="workspace_locked"));
    }
    assert!(matches!(
        nw_bridge::Handler::handle(
            &crate::service::cover::DesktopCover(state.clone()),
            nw_bridge::Command::Status {}
        )
        .await,
        nw_bridge::Result::Error {
            code: nw_bridge::ErrorCode::WorkspaceLocked
        }
    ));
    assert!(!expire_tail(&state, deadline.0, deadline.1));
    assert!(matches!(
        service.handle(Command::Lock {}).await,
        Reply::Ack {}
    ));
    assert!(state.session.lock().unwrap().workspace.is_none());
    assert!(!expire_tail(&state, deadline.0, deadline.1));
}

#[tokio::test]
async fn first_delay_is_cancellable_and_missing_clock_never_authorizes_a_send() {
    let (_directory, state) = fixture(false);
    state.session.lock().unwrap().timing = None;
    assert!(matches!(
        wait_first(&state, 0).await,
        Err(CoreError::Session)
    ));
    state.session.lock().unwrap().timing = Some(nw_cover::session::Clock::new(
        Instant::now(),
        &mut rand::rngs::OsRng,
    ));
    let pending = wait_first(&state, 0);
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut pending)
            .await
            .is_err()
    );
    clear_session(&state).unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), &mut pending)
            .await
            .unwrap(),
        Err(CoreError::Session)
    ));
}

#[test]
fn absent_consent_or_transport_locks_and_expired_tail_drops_keys() {
    for consent in [false, true] {
        let (_directory, state) = fixture(consent);
        let closed = close_at(&state, !consent, Instant::now()).unwrap();
        assert!(closed.value.phase == Phase::Locked);
        assert!(state.session.lock().unwrap().workspace.is_none());
    }
    let (_directory, state) = fixture(true);
    let closed = close_at(&state, true, Instant::now() - Duration::from_secs(7200)).unwrap();
    let (epoch, deadline) = closed.timer.unwrap();
    assert!(!expire_tail(&state, epoch + 1, deadline));
    assert!(expire_tail(&state, epoch, deadline));
    assert!(state.session.lock().unwrap().workspace.is_none());
}

#[tokio::test]
async fn wall_deadline_also_blocks_a_tail_when_monotonic_time_has_not_elapsed() {
    let (_directory, state) = fixture(true);
    let closed = close_at(&state, true, Instant::now()).unwrap();
    let (epoch, deadline) = closed.timer.unwrap();
    assert!(Instant::now() < deadline);
    state.session.lock().unwrap().tail_wall_deadline = Some(workspace::now().saturating_sub(1));
    assert!(matches!(
        wait_first(&state, epoch).await,
        Err(CoreError::Session)
    ));
    assert!(expire_tail(&state, epoch, deadline));
    assert!(state.session.lock().unwrap().workspace.is_none());
}
