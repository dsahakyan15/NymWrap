//! Exercise the exact daemon dispatcher, substituting only the remote transport.
use super::*;
use nw_ipc::{Endpoint, IpcError};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

const CANARY: &str = "SYNTHETIC_DISPATCHER_DEVICE_CANARY_75241";
const REPLY: &str = "SYNTHETIC_DISPATCHER_REPLY_CANARY_81492";
#[derive(Default)]
struct Captured {
    initialized: AtomicUsize,
    requests: Mutex<Vec<(bool, Vec<u8>)>>,
}
struct FixtureFactory(Arc<Captured>);
struct FixtureConnection(Arc<Captured>);
impl Factory for FixtureFactory {
    type Transport = FixtureConnection;
    async fn bootstrap(
        &self,
        _: &Path,
        _: Provider,
        _: Option<&BridgeConfig>,
    ) -> Result<FixtureConnection, &'static str> {
        self.0.initialized.fetch_add(1, Ordering::SeqCst);
        Ok(FixtureConnection(self.0.clone()))
    }
}
impl Connection for FixtureConnection {
    async fn transmit(&self, request: &Request, once: bool) -> Result<String, &'static str> {
        self.0
            .requests
            .lock()
            .unwrap()
            .push((once, request.body.clone()));
        Ok(REPLY.into())
    }
}
type Check<T> = std::result::Result<T, Box<dyn std::error::Error>>;
async fn exchange(
    endpoint: &Endpoint,
    key: &SessionKey,
    sequence: u64,
    command: &Command,
) -> Check<Response> {
    let envelope = key.seal(sequence, command)?;
    let bytes = serde_json::to_vec(&envelope)?;
    let mut stream = endpoint.connect().await?;
    nw_ipc::write_frame(&mut stream, &bytes, MAX_WIRE * 5).await?;
    let response =
        nw_ipc::read_frame_timeout(&mut stream, MAX_WIRE * 5, Duration::from_secs(2)).await?;
    if response
        .windows(REPLY.len())
        .any(|part| part == REPLY.as_bytes())
    {
        return Err("plaintext_reply_canary".into());
    }
    let envelope: Envelope = serde_json::from_slice(&response)?;
    Ok(key.open(&envelope, sequence)?)
}
async fn rejected(endpoint: &Endpoint, envelope: &Envelope) -> Check<bool> {
    let mut stream = endpoint.connect().await?;
    nw_ipc::write_frame(&mut stream, &serde_json::to_vec(envelope)?, MAX_WIRE * 5).await?;
    Ok(matches!(
        nw_ipc::read_frame_timeout(&mut stream, MAX_WIRE * 5, Duration::from_secs(2)).await,
        Err(IpcError::Io)
    ))
}
fn request(body: &[u8]) -> Request {
    Request {
        conversation: "a".repeat(32),
        body: body.to_vec(),
        authorization: "synthetic-provider-key".into(),
    }
}
#[tokio::test]
async fn daemon_dispatcher_authenticates_before_sending_and_never_replays_a_canary() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let address = format!("nymwrap-dispatcher-{}", std::process::id());
    #[cfg(unix)]
    let address = directory
        .path()
        .join("private/dispatch.sock")
        .to_string_lossy()
        .into_owned();
    let endpoint = Endpoint::new(address, Lane::Shadow).unwrap();
    let listener = Listener::bind(endpoint.clone()).unwrap();
    let captured = Arc::new(Captured::default());
    let factory = FixtureFactory(captured.clone());
    let key = SessionKey::new([41; 32]).unwrap();
    let server_key = SessionKey::new([41; 32]).unwrap();
    let other = SessionKey::new([42; 32]).unwrap();
    let shield = nw_shield::Shield::new(vec![
        nw_shield::Secret::new(nw_shield::SecretKind::Device, CANARY.into(), false).unwrap(),
    ])
    .unwrap();
    let prepared = shield
        .prepare(
            &format!("Explain pottery for {CANARY}."),
            &mut nw_shield::ConversationVault::default(),
            |text| Ok(serde_json::json!([{"role":"user","content":text}]).to_string()),
        )
        .unwrap();
    let shaped = nw_net::ShapedRequest::history(&prepared, "synthetic", 16).unwrap();
    let server = tokio::spawn(serve_with(listener, server_key, factory));
    let outcome: Check<bool> = async {
        let init = Command::Initialize { state: "synthetic-not-created".into(), host: "api.example.test".into(), path: "/v1/chat/completions".into(), bridges: None };
        let mut passed = rejected(&endpoint, &other.seal(1, &init)?).await?;
        passed &= captured.initialized.load(Ordering::SeqCst) == 0;
        passed &= matches!(exchange(&endpoint, &key, 1, &Command::Send { request: request(shaped.bytes()) }).await?, Response::Error { .. });
        passed &= captured.requests.lock().unwrap().is_empty();
        passed &= matches!(exchange(&endpoint, &key, 2, &init).await?, Response::Ready {});
        passed &= captured.initialized.load(Ordering::SeqCst) == 1;
        let command = Command::Send { request: request(shaped.bytes()) };
        passed &= matches!(&exchange(&endpoint, &key, 3, &command).await?, Response::Answer { text } if text == REPLY);
        passed &= rejected(&endpoint, &key.seal(3, &command)?).await?;
        passed &= matches!(&exchange(&endpoint, &key, 4, &Command::SendOnce { request: request(shaped.bytes()) }).await?, Response::Answer { text } if text == REPLY);
        passed &= matches!(exchange(&endpoint, &key, 5, &Command::Reset {}).await?, Response::Ready {});
        passed &= matches!(exchange(&endpoint, &key, 6, &command).await?, Response::Error { .. });
        Ok(passed)
    }.await;
    server.abort();
    let _ = server.await;
    directory.close().unwrap();
    assert!(outcome.unwrap());
    let requests = captured.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!([requests[0].0, requests[1].0], [false, true]);
    for (_, body) in requests.iter() {
        assert!(body == shaped.bytes());
        assert!(
            !body
                .windows(CANARY.len())
                .any(|part| part == CANARY.as_bytes())
        );
    }
}
