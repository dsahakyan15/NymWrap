//! Real Tor/TLS/HTTP over CI-owned network namespaces, observed by tcpdump.
//! Private authorities, test CA and TLS key logging do not exist in a release.
use super::*;
use base64ct::Encoding;
use nw_shield::{ConversationVault, Secret, SecretKind, Shield};
use rustls::pki_types::pem::PemObject;
use std::time::Duration;
use tor_proto::client::stream::ClientStreamCtrl;

pub(super) fn record_circuit(request: &Request, stream: &arti_client::DataStream) {
    let Some(fixture) = std::env::var_os("NW_TEST_TOR_FIXTURE") else {
        return;
    };
    static CIRCUITS: std::sync::Mutex<BTreeMap<String, String>> =
        std::sync::Mutex::new(BTreeMap::new());
    let circuit = format!(
        "{:?}",
        stream
            .client_stream_ctrl()
            .unwrap()
            .tunnel()
            .unwrap()
            .unique_id()
    );
    let mut circuits = CIRCUITS.lock().unwrap();
    circuits.insert(request.conversation.clone(), circuit);
    std::fs::write(
        std::path::Path::new(&fixture).join("circuit-receipt.json"),
        serde_json::to_vec(&*circuits).unwrap(),
    )
    .unwrap();
}

struct LocalFactory;
impl crate::server::Factory for LocalFactory {
    type Transport = Tor;
    async fn bootstrap(
        &self,
        directory: &Path,
        provider: Provider,
        bridges: Option<&nw_net::bridges::BridgeConfig>,
    ) -> Result<Tor, &'static str> {
        assert!(bridges.is_none());
        let fixture = std::path::PathBuf::from(std::env::var_os("NW_TEST_TOR_FIXTURE").unwrap());
        assert_eq!(directory, fixture.join("mount/private"));
        nw_platform::encrypted_directory(directory).unwrap();
        let config = chutney_config(&std::fs::read(fixture.join("arti.json")).unwrap());
        let root = tokio::time::timeout(
            Duration::from_secs(180),
            TorClient::create_bootstrapped(config),
        )
        .await
        .unwrap()
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(
                rustls::pki_types::CertificateDer::from_pem_slice(
                    &std::fs::read(fixture.join("provider-ca.pem")).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let mut tls = provider_tls_with_roots(roots).unwrap();
        tls.key_log = Arc::new(rustls::KeyLogFile::new());
        Ok(Tor {
            root,
            conversations: Mutex::new(BTreeMap::new()),
            provider,
            _transport_binary: None,
            test_tls: Some(Arc::new(tls)),
        })
    }
}

#[tokio::test]
#[ignore = "test-only netd process, launched by the administrative CI coordinator"]
async fn netd_process_worker() {
    use std::io::Read;
    use zeroize::Zeroize;
    let fixture = std::path::PathBuf::from(std::env::var_os("NW_TEST_TOR_FIXTURE").unwrap());
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_ne!(nw_platform::current_user_id().unwrap(), "0");
    let namespace = std::fs::read_link("/proc/self/ns/net").unwrap();
    assert_eq!(
        namespace.to_str().unwrap(),
        std::env::var("NW_TEST_NETNS_COOKIE").unwrap()
    );
    nw_platform::harden_process().unwrap();
    let denied = matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect("192.0.2.2:443")
        )
        .await,
        Err(_) | Ok(Err(_))
    );
    assert!(denied);
    std::fs::write(fixture.join("worker-state.json"), serde_json::to_vec(&serde_json::json!({
        "namespace":namespace.to_str().unwrap(), "pid":std::process::id(), "direct_provider_connection_denied":denied
    })).unwrap()).unwrap();
    let mut parent = nw_platform::inherited_stdin_pipe().unwrap();
    let mut bytes = Zeroizing::new([0; 32]);
    parent.read_exact(&mut *bytes).unwrap();
    let key = nw_net::wire::SessionKey::new(*bytes).unwrap();
    bytes.zeroize();
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = parent.read(&mut [0]);
        let _ = tx.send(());
    });
    let endpoint = nw_ipc::Endpoint::new(
        std::env::var("NW_TEST_SOCKET").unwrap(),
        nw_proto::Lane::Shadow,
    )
    .unwrap();
    let listener = nw_ipc::Listener::bind(endpoint).unwrap();
    tokio::select! {
        result = crate::server::serve_with(listener, key, LocalFactory) => result.unwrap(),
        _ = &mut rx => {},
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Canaries {
    device: BTreeMap<String, String>,
    detectors: BTreeMap<String, String>,
}
fn canaries() -> Canaries {
    serde_json::from_str(include_str!("../fixtures/pcap-canaries.json")).unwrap()
}
fn shield() -> Shield {
    Shield::new(
        canaries()
            .device
            .values()
            .map(|value| Secret::new(SecretKind::Device, value.clone(), false).unwrap())
            .collect(),
    )
    .unwrap()
}
fn encodings(value: &str) -> [String; 6] {
    [
        value.to_owned(),
        value.to_lowercase(),
        base64ct::Base64::encode_string(value.as_bytes()),
        value.bytes().map(|b| format!("%{b:02X}")).collect(),
        value
            .chars()
            .map(|ch| format!("\\u{:04x}", ch as u32))
            .collect(),
        value
            .chars()
            .map(|ch| ch.to_string())
            .collect::<Vec<_>>()
            .join(" "),
    ]
}
fn shaped(fact: &str, length: usize, index: usize) -> Request {
    let prepared = shield()
        .prepare(
            &format!("Explain pottery for {fact}. {}", "x".repeat(length)),
            &mut ConversationVault::default(),
            |text| Ok(serde_json::json!([{"role":"user","content":text}]).to_string()),
        )
        .unwrap();
    let shaped = nw_net::ShapedRequest::history(&prepared, "synthetic", 16).unwrap();
    Request {
        conversation: format!("{index:032x}"),
        body: shaped.bytes().to_vec(),
        authorization: "synthetic-provider-token".into(),
    }
}
fn chutney_config(bytes: &[u8]) -> arti_client::TorClientConfig {
    // Pinned Chutney emits the pre-proposal-330 list. Arti 0.48 expects
    // AuthorityContacts; never retain its public authority contact defaults.
    let mut config: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let authorities = &mut config["tor_network"]["authorities"];
    let identities: Vec<_> = authorities
        .as_array()
        .unwrap()
        .iter()
        .map(|authority| authority["v3ident"].as_str().unwrap().to_owned())
        .collect();
    assert!(!identities.is_empty());
    *authorities = serde_json::json!({
        "v3idents": identities, "uploads": [], "downloads": [], "votes": []
    });
    let builder: arti_client::config::TorClientConfigBuilder =
        serde_json::from_value(config).unwrap();
    builder.build().unwrap()
}
#[test]
fn chutney_authorities_replace_all_public_directory_defaults() {
    let identity = "0101010101010101010101010101010101010101";
    let config = serde_json::json!({"tor_network": {
        "authorities": [{"name":"synthetic", "v3ident":identity}],
        "fallback_caches": [{"rsa_identity":identity,
            "ed_identity":base64ct::Base64Unpadded::encode_string(&[2; 32]),
            "orports":["192.0.2.2:5000"]}]
    }});
    let config = chutney_config(&serde_json::to_vec(&config).unwrap());
    let directory = config.dir_mgr_config().unwrap();
    let authorities = directory.authorities();
    assert_eq!(
        authorities.v3idents(),
        &vec![tor_llcrypto::pk::rsa::RsaIdentity::from_hex(identity).unwrap()]
    );
    assert!(authorities.uploads().is_empty());
    assert!(authorities.downloads().is_empty());
    assert!(authorities.votes().is_empty());
    assert_eq!(directory.fallbacks().len(), 1);
}
#[test]
fn every_pcap_canary_and_encoding_is_vetoed_after_a_model_reintroduction() {
    let data = canaries();
    assert_eq!(data.device.len(), 9);
    assert_eq!(data.detectors.len(), 7);
    for (kind, fact) in data.device.iter().chain(data.detectors.iter()) {
        assert!(fact.len() > 8);
        for (encoding, encoded) in encodings(fact).into_iter().enumerate() {
            assert!(
                shield()
                    .prepare(
                        &format!("Explain pottery for {fact}"),
                        &mut ConversationVault::default(),
                        |_| Ok(encoded)
                    )
                    .is_err(),
                "a synthetic pcap canary escaped the final model gate: {kind}/{encoding}"
            );
        }
    }
}
#[tokio::test]
#[ignore = "requires CI-owned Chutney namespaces, fscrypt, test PKI and OS pcap"]
async fn actual_local_tor_tls_packets_have_no_hard_canaries_or_direct_fallback() {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(
        std::fs::read_link("/proc/self/ns/net")
            .unwrap()
            .to_string_lossy(),
        std::env::var("NW_TEST_NETNS_COOKIE").unwrap()
    );
    assert_ne!(nw_platform::current_user_id().unwrap(), "0");
    nw_platform::harden_process().unwrap();
    let fixture = std::path::PathBuf::from(std::env::var_os("NW_TEST_TOR_FIXTURE").unwrap());
    nw_platform::encrypted_directory(&fixture.join("mount/private")).unwrap();
    let bytes = std::fs::read(fixture.join("arti.json")).unwrap();
    assert!(bytes.len() < 128 * 1024);
    let config = chutney_config(&bytes);
    let root = tokio::time::timeout(
        Duration::from_secs(180),
        TorClient::create_bootstrapped(config),
    )
    .await
    .unwrap()
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(
            rustls::pki_types::CertificateDer::from_pem_slice(
                &std::fs::read(fixture.join("provider-ca.pem")).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let mut tls = provider_tls_with_roots(roots).unwrap();
    tls.key_log = Arc::new(rustls::KeyLogFile::new());
    let tor = Tor {
        root,
        conversations: Mutex::new(BTreeMap::new()),
        provider: Provider::new("api.example.test".into(), "/v1/chat/completions".into()).unwrap(),
        _transport_binary: None,
        test_tls: Some(Arc::new(tls)),
    };
    // The provider stays available in the relay namespace. Netd's namespace
    // firewall permits only relay/directory ports, including after Tor stops.
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect("192.0.2.2:443")
        )
        .await,
        Err(_) | Ok(Err(_))
    ));
    let data = canaries();
    let mut lengths = std::collections::BTreeSet::new();
    for (index, fact) in data
        .device
        .values()
        .chain(data.detectors.values())
        .enumerate()
    {
        let request = shaped(fact, [32, 2200, 4400, 8500, 17000][index % 5], index);
        lengths.insert(request.body.len());
        assert_eq!(tor.send(&request).await.unwrap(), "synthetic safe answer");
    }
    assert_eq!(
        lengths.into_iter().collect::<Vec<_>>(),
        nw_net::BYTE_BUCKETS
    );
    let clients = tor
        .conversations
        .lock()
        .await
        .values()
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    let a = clients[0].connect(("api.example.test", 443)).await.unwrap();
    let b = clients[1].connect(("api.example.test", 443)).await.unwrap();
    assert_ne!(
        a.client_stream_ctrl()
            .unwrap()
            .tunnel()
            .unwrap()
            .unique_id(),
        b.client_stream_ctrl()
            .unwrap()
            .tunnel()
            .unwrap()
            .unique_id()
    );
    drop((a, b));
    std::fs::write(fixture.join("ready-to-stop"), b"ready").unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !fixture.join("transport-stopped").is_file() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(20),
            tor.send(&shaped("plain public task", 32, 100))
        )
        .await,
        Err(_) | Ok(Err(_))
    ));
    std::fs::write(fixture.join("rust-result.json"), serde_json::to_vec(&serde_json::json!({"complete":true,
        "requests":16,"buckets":nw_net::BYTE_BUCKETS,"different_circuits":true,"transport_stop_failed_closed":true,
        "direct_provider_connection_denied":true})).unwrap()).unwrap();
}
