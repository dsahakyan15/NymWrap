//! Remote sockets exist only here. Provider names are resolved inside Arti.
use arti_client::TorClient;
use nw_net::wire::Request;
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path, sync::Arc};
use tokio::sync::Mutex;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_rtcompat::PreferredRuntime;
use zeroize::Zeroizing;
mod bridges;
pub mod server;

#[derive(Clone)]
pub struct Provider {
    host: String,
    path: String,
}
impl Provider {
    pub fn new(host: String, path: String) -> Result<Self, &'static str> {
        nw_net::validate_provider(&host, &path).map_err(|_| "invalid_provider")?;
        if host.len() > 253
            || host.parse::<std::net::IpAddr>().is_ok()
            || !host.contains('.')
            || host.split('.').any(|s| {
                s.is_empty()
                    || s.len() > 63
                    || s.starts_with('-')
                    || s.ends_with('-')
                    || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            || path.len() > 128
            || !path.starts_with('/')
            || path
                .bytes()
                .any(|b| !b.is_ascii_graphic() || b"?#\\".contains(&b))
        {
            return Err("invalid_provider");
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            path,
        })
    }
}
pub struct Tor {
    root: Arc<TorClient<PreferredRuntime>>,
    conversations: Mutex<BTreeMap<String, Arc<TorClient<PreferredRuntime>>>>,
    provider: Provider,
    _transport_binary: Option<bridges::VerifiedBinary>,
    #[cfg(test)]
    test_tls: Option<Arc<rustls::ClientConfig>>,
}
impl Tor {
    pub async fn bootstrap(directory: &Path, provider: Provider) -> Result<Self, &'static str> {
        Self::bootstrap_with_bridges(directory, provider, None).await
    }
    pub async fn bootstrap_with_bridges(
        directory: &Path,
        provider: Provider,
        bridges: Option<&nw_net::bridges::BridgeConfig>,
    ) -> Result<Self, &'static str> {
        // EFS/fscrypt must be verified before Arti creates even its first file.
        nw_platform::encrypted_directory(directory)
            .map_err(|_| "encrypted_transport_state_required")?;
        let mut builder = arti_client::config::TorClientConfigBuilder::from_directories(
            directory.join("state"),
            directory.join("cache"),
        );
        let binary = bridges
            .map(|settings| self::bridges::configure(&mut builder, settings))
            .transpose()?;
        let config = builder.build().map_err(|_| "invalid_tor_configuration")?;
        let root = tokio::time::timeout(
            std::time::Duration::from_secs(180),
            TorClient::create_bootstrapped(config),
        )
        .await
        .map_err(|_| "tor_bootstrap_timeout")?
        .map_err(|_| "tor_bootstrap_failed")?;
        Ok(Self {
            root,
            conversations: Mutex::new(BTreeMap::new()),
            provider,
            _transport_binary: binary,
            #[cfg(test)]
            test_tls: None,
        })
    }
    pub async fn send(&self, request: &Request) -> Result<String, &'static str> {
        validate(request)?;
        let client = {
            let mut conversations = self.conversations.lock().await;
            if !conversations.contains_key(&request.conversation) {
                if conversations.len() >= 128 {
                    return Err("conversation_limit");
                }
                conversations.insert(request.conversation.clone(), self.root.isolated_client());
            }
            conversations
                .get(&request.conversation)
                .ok_or("invalid_conversation")?
                .clone()
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            self.exchange(&client, request),
        )
        .await
        .map_err(|_| "transport_timeout")?
    }
    /// An independent decoy cannot retain a conversation entry after its single attempt.
    pub async fn send_once(&self, request: &Request) -> Result<String, &'static str> {
        validate(request)?;
        let client = self.root.isolated_client();
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            self.exchange(&client, request),
        )
        .await
        .map_err(|_| "transport_timeout")?
    }
    async fn exchange(
        &self,
        client: &TorClient<PreferredRuntime>,
        request: &Request,
    ) -> Result<String, &'static str> {
        // No std/Tokio TCP connector, system DNS, redirects, retry or proxy env.
        let stream = client
            .connect((self.provider.host.as_str(), 443))
            .await
            .map_err(|_| "tor_connect_failed")?;
        #[cfg(test)]
        local_tor_tests::record_circuit(request, &stream);
        let name = rustls::pki_types::ServerName::try_from(self.provider.host.clone())
            .map_err(|_| "invalid_provider")?;
        let tls = Arc::new(provider_tls()?);
        #[cfg(test)]
        let tls = self.test_tls.clone().unwrap_or(tls);
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(name, stream.compat())
            .await
            .map_err(|_| "provider_tls_failed")?;
        http_exchange(stream, &self.provider, request).await
    }
}
fn provider_tls() -> Result<rustls::ClientConfig, &'static str> {
    provider_tls_with_roots(rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
}
fn provider_tls_with_roots(
    roots: rustls::RootCertStore,
) -> Result<rustls::ClientConfig, &'static str> {
    use rustls::crypto::ring::{cipher_suite::*, kx_group};
    let mut crypto = rustls::crypto::ring::default_provider();
    crypto.cipher_suites = vec![
        TLS13_AES_256_GCM_SHA384,
        TLS13_AES_128_GCM_SHA256,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    crypto.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1];
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(crypto))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| "tls_configuration_failed")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.extension_order_seed = Some(0);
    tls.resumption = rustls::client::Resumption::disabled();
    tls.enable_early_data = false;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.cert_compressors.clear();
    tls.cert_decompressors.clear();
    Ok(tls)
}
// The sole production caller supplies an authenticated TLS stream over Arti.
// Keeping serialization at this seam lets canaries inspect Hyper's actual bytes.
async fn http_exchange<S>(
    stream: S,
    provider: &Provider,
    request: &Request,
) -> Result<String, &'static str>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| "provider_http_failed")?;
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    struct Abort(tokio::task::JoinHandle<()>);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _guard = Abort(task);
    let body = http_body_util::Full::new(hyper::body::Bytes::copy_from_slice(&request.body));
    let authorization = nw_platform::LockedString::new(secrecy::SecretString::from(format!(
        "Bearer {}",
        request.authorization
    )))
    .map_err(|_| "credential_memory_lock_failed")?;
    let mut authorization = hyper::header::HeaderValue::from_maybe_shared(
        hyper::body::Bytes::from_owner(authorization),
    )
    .map_err(|_| "invalid_request")?;
    authorization.set_sensitive(true);
    let outbound = hyper::Request::builder()
        .method("POST")
        .uri(&provider.path)
        .header("Host", &provider.host)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("Authorization", authorization)
        .body(body)
        .map_err(|_| "invalid_request")?;
    let response = sender
        .send_request(outbound)
        .await
        .map_err(|_| "provider_http_failed")?;
    if !response.status().is_success() {
        return Err("provider_rejected_request");
    }
    if response
        .headers()
        .get("content-encoding")
        .is_some_and(|h| h != "identity")
    {
        return Err("invalid_provider_response");
    }
    if response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .is_none_or(|h| h.split(';').next() != Some("application/json"))
    {
        return Err("invalid_provider_response");
    }
    use http_body_util::BodyExt;
    let bytes = Zeroizing::new(
        http_body_util::Limited::new(response.into_body(), 1024 * 1024)
            .collect()
            .await
            .map_err(|_| "invalid_provider_response")?
            .to_bytes()
            .to_vec(),
    );
    parse_answer(&bytes)
}
#[cfg(test)]
#[path = "../../../tests/leak/src/netd_http.rs"]
mod http_wire_canaries;
#[cfg(test)]
#[path = "../../../tests/leak/src/netd_local_tor.rs"]
mod local_tor_tests;
#[cfg(test)]
#[path = "../../../tests/leak/src/netd_golden_evidence.rs"]
mod protocol_evidence;
#[cfg(test)]
#[path = "../../../tests/leak/src/netd_tls.rs"]
mod tls_wire_golden;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Chat {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: u8,
    max_tokens: u32,
    stream: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatMessage {
    role: String,
    content: String,
}
pub fn validate(request: &Request) -> Result<(), &'static str> {
    if request.conversation.len() != 32
        || !request.conversation.bytes().all(|b| b.is_ascii_hexdigit())
        || request.authorization.len() < 8
        || request.authorization.len() > 4096
        || !request.authorization.bytes().all(|b| b.is_ascii_graphic())
        || !nw_net::BYTE_BUCKETS.contains(&request.body.len())
    {
        return Err("invalid_request");
    }
    let chat: Chat = serde_json::from_slice(&request.body).map_err(|_| "invalid_request")?;
    if chat.model.is_empty()
        || chat.model.len() > 128
        || chat.model.chars().any(char::is_control)
        || chat.messages.is_empty()
        || chat.messages.len() > 63
        || chat.messages.last().is_none_or(|m| m.role != "user")
        || chat.messages.iter().enumerate().any(|(i, m)| {
            !matches!(m.role.as_str(), "user" | "assistant" | "system")
                || m.role == "system" && i != 0
        })
        || chat.messages.iter().map(|m| m.content.len()).sum::<usize>() > nw_proto::MAX_TEXT_BYTES
        || chat.temperature != 0
        || chat.stream
        || !(1..=2048).contains(&chat.max_tokens)
    {
        return Err("invalid_request");
    }
    Ok(())
}
pub fn parse_answer(bytes: &[u8]) -> Result<String, &'static str> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "invalid_provider_response")?;
    let choices = value["choices"]
        .as_array()
        .filter(|v| v.len() == 1)
        .ok_or("invalid_provider_response")?;
    let message = &choices[0]["message"];
    if message["role"] != "assistant"
        || message.get("tool_calls").is_some()
        || message.get("function_call").is_some()
    {
        return Err("unsupported_provider_action");
    }
    let text = message["content"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= nw_proto::MAX_TEXT_BYTES)
        .ok_or("invalid_provider_response")?;
    Ok(text.into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "contacts the public Tor network; requires an EFS/fscrypt directory named by NYMWRAP_TOR_STATE"]
    async fn actual_tor_isolates_conversations() {
        use tor_proto::client::stream::ClientStreamCtrl;
        let directory = std::env::var_os("NYMWRAP_TOR_STATE").expect("NYMWRAP_TOR_STATE required");
        let tor = Tor::bootstrap(
            Path::new(&directory),
            Provider::new("example.com".into(), "/".into()).unwrap(),
        )
        .await
        .unwrap();
        let first = tor.root.isolated_client();
        let second = tor.root.isolated_client();
        let a = first.connect(("example.com", 443)).await.unwrap();
        let b = second.connect(("example.com", 443)).await.unwrap();
        let a = a.client_stream_ctrl().unwrap().tunnel().unwrap();
        let b = b.client_stream_ctrl().unwrap().tunnel().unwrap();
        assert_ne!(a.unique_id(), b.unique_id());
        let prepared = nw_shield::Shield::new(vec![])
            .unwrap()
            .prepare(
                "Explain pottery.",
                &mut nw_shield::ConversationVault::default(),
                |text| Ok(text.into()),
            )
            .unwrap();
        let shaped = nw_net::ShapedRequest::new(&prepared).unwrap();
        let request = Request {
            conversation: "c".repeat(32),
            body: shaped.bytes().to_vec(),
            authorization: "synthetic-one-shot-token".into(),
        };
        assert!(tor.send_once(&request).await.is_err()); // example.com is not an AI provider.
        assert!(tor.conversations.lock().await.is_empty());
    }
    #[test]
    fn provider_and_response_are_data_only() {
        for host in [
            "127.0.0.1",
            "localhost",
            "user@example.test",
            "example.test:443",
            "bad..test",
        ] {
            assert!(Provider::new(host.into(), "/v1/chat/completions".into()).is_err());
        }
        assert!(Provider::new("api.example.test".into(), "/v1/chat/completions".into()).is_ok());
        assert_eq!(parse_answer(br#"{"choices":[{"message":{"role":"assistant","content":"<script>data</script>"}}]}"#).unwrap(),"<script>data</script>");
        assert!(
            parse_answer(
                br#"{"choices":[{"message":{"role":"assistant","content":"x","tool_calls":[]}}]}"#
            )
            .is_err()
        );
    }
}
