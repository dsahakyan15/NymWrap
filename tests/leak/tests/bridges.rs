use nw_net::{
    bridges::{BridgeConfig, BridgeTransport},
    wire::{Command, SessionKey},
};
const CANARY: &str = "PRIVATE_BRIDGE_CANARY_57214";
fn config() -> BridgeConfig {
    BridgeConfig {
        transport: BridgeTransport::Webtunnel,
        lines: vec![format!(
            "webtunnel 192.0.2.55:443 {} url=https://bridge.example.test/{CANARY} ver=0.0.1",
            "A".repeat(40)
        )],
    }
}
#[test]
fn bridge_settings_are_bounded_control_data_and_do_not_escape_the_encrypted_ipc_frame() {
    let settings = config();
    settings.validate().unwrap();
    let key = SessionKey::new([27; 32]).unwrap();
    let frame = key
        .seal(
            1,
            &Command::Initialize {
                state: "/synthetic/state".into(),
                host: "provider.example.test".into(),
                path: "/v1/chat/completions".into(),
                bridges: Some(settings),
            },
        )
        .unwrap();
    assert!(
        !String::from_utf8(serde_json::to_vec(&frame).unwrap())
            .unwrap()
            .contains(CANARY)
    );
    let decoded: Command = key.open(&frame, 1).unwrap();
    assert!(
        matches!(&decoded,Command::Initialize{bridges:Some(config),..} if config.lines[0].contains(CANARY))
    );
    let mut malformed = config();
    malformed.lines.push(malformed.lines[0].clone());
    assert!(malformed.validate().is_err());
    for line in [
        "webtunnel evil.example.test:443 A url=https://bridge.example.test/",
        "webtunnel 127.0.0.1:443 A url=https://bridge.example.test/",
        "webtunnel 192.0.2.55:443 A\nexec malicious",
    ] {
        malformed.lines = vec![line.into()];
        assert!(malformed.validate().is_err());
    }
    let mut json = serde_json::to_value(config()).unwrap();
    json["binary_path"] = "/host/program".into();
    assert!(serde_json::from_value::<BridgeConfig>(json).is_err());
    let mut config = config();
    config.lines[0].push_str(" arguments=--host-command");
    assert!(config.validate().is_err());
}
