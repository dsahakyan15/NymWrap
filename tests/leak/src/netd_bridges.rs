use super::*;
use nw_net::bridges::BridgeTransport;
fn settings(transport: BridgeTransport) -> BridgeConfig {
    let extra=match transport{BridgeTransport::Obfs4=>format!("cert={} iat-mode=0","A".repeat(70)),BridgeTransport::Snowflake=>"url=https://broker.example.test/ front=front.example.test ice=stun:stun.example.test:3478".into(),BridgeTransport::Webtunnel=>"url=https://tunnel.example.test/SYNTHETIC_BRIDGE_CANARY_58214 ver=0.0.1".into()};
    BridgeConfig {
        transport,
        lines: vec![format!(
            "{} 192.0.2.55:443 {} {extra}",
            transport.name(),
            "A".repeat(40)
        )],
    }
}
#[test]
fn bridge_builders_require_a_managed_pinned_transport_without_fallback() {
    for transport in [
        BridgeTransport::Obfs4,
        BridgeTransport::Snowflake,
        BridgeTransport::Webtunnel,
    ] {
        let settings = settings(transport);
        let mut builder = TorClientConfigBuilder::default();
        configure_builder(&mut builder, &settings, Path::new("/synthetic/lyrebird")).unwrap();
        assert!(builder.build().is_ok());
        // Arti rejects bridges with no matching PT; no direct-Tor fallback.
        let mut missing = TorClientConfigBuilder::default();
        missing
            .bridges()
            .enabled(arti_client::config::BoolOrAuto::Explicit(true));
        missing
            .bridges()
            .bridges()
            .push(settings.lines[0].parse().unwrap());
        assert!(missing.build().is_err());
    }
}
#[test]
fn binary_size_hash_and_file_type_are_checked_before_execution() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lyrebird");
    let bytes = b"synthetic executable bytes";
    std::fs::write(&path, bytes).unwrap();
    let pin = Pin {
        platform: "synthetic".into(),
        bytes: bytes.len() as u64,
        binary_sha256: format!("{:x}", Sha256::digest(bytes)),
    };
    drop(verify(&path, &pin).unwrap());
    std::fs::write(&path, b"untrusted executable bytes").unwrap();
    assert!(verify(&path, &pin).is_err());
    assert!(verify(dir.path(), &pin).is_err());
    let manifest: Manifest =
        serde_json::from_str(include_str!("../../../scripts/transport-binaries.json")).unwrap();
    assert_eq!(manifest.artifacts.len(), 5);
    assert!(
        manifest
            .artifacts
            .iter()
            .all(|p| p.binary_sha256.len() == 64 && p.bytes < 32 * 1024 * 1024)
    );
}

#[tokio::test]
#[ignore = "requires installed pinned Lyrebird and encrypted PT state; CI runs it explicitly"]
async fn actual_installed_pt_listeners_stop_when_managed_handle_is_dropped() {
    use tor_ptmgr::ipc::{
        PluggableClientTransport, PluggableTransport, PtClientParametersBuilder,
        PtCommonParametersBuilder,
    };
    let path = PathBuf::from(
        std::env::var_os("NW_TEST_PT_BINARY").expect("NW_TEST_PT_BINARY is required"),
    );
    let manifest: Manifest =
        serde_json::from_str(include_str!("../../../scripts/transport-binaries.json")).unwrap();
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let pin = manifest
        .artifacts
        .iter()
        .find(|p| p.platform == platform)
        .unwrap();
    let binary = verify(&path, pin).unwrap();
    let directory = if let Some(base) = std::env::var_os("NW_TEST_PT_STATE") {
        tempfile::tempdir_in(base).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let private = directory.path().join("private");
    nw_platform::encrypted_directory(&private).unwrap();
    for protocol in ["obfs4", "snowflake", "webtunnel"] {
        let state = private.join(protocol);
        nw_platform::encrypted_directory(&state).unwrap();
        let common = PtCommonParametersBuilder::default()
            .state_location(state)
            .timeout(Some(std::time::Duration::from_secs(10)))
            .build()
            .unwrap();
        let client = PtClientParametersBuilder::default()
            .transports(vec![protocol.parse().unwrap()])
            .build()
            .unwrap();
        let mut pt = PluggableClientTransport::new(binary.path.clone(), vec![], common, client);
        pt.launch(tor_rtcompat::PreferredRuntime::current().unwrap())
            .await
            .unwrap();
        assert_eq!(pt.transport_methods().len(), 1);
        let endpoint = pt.transport_methods().values().next().unwrap().endpoint();
        assert!(endpoint.ip().is_loopback());
        let mut listener = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(endpoint),
        )
        .await
        .unwrap()
        .unwrap();
        drop(pt);
        use tokio::io::AsyncReadExt;
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), listener.read_u8()).await,
            Ok(Err(_))
        ));
    }
}
