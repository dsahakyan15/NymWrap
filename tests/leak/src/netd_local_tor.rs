//! Real Tor/TLS/HTTP over CI-owned network namespaces, observed by tcpdump.
//! Private authorities, test CA and TLS key logging do not exist in a release.
use super::*;
use base64ct::Encoding;
use nw_shield::{ConversationVault, Secret, SecretKind, Shield};
use rustls::pki_types::pem::PemObject;
use std::time::Duration;
use tor_proto::client::stream::ClientStreamCtrl;

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
    let builder: arti_client::config::TorClientConfigBuilder =
        serde_json::from_slice(&bytes).unwrap();
    let root = tokio::time::timeout(
        Duration::from_secs(180),
        TorClient::create_bootstrapped(builder.build().unwrap()),
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
