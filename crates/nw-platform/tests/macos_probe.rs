#![cfg(target_os = "macos")]
use std::process::Command;
#[test]
fn macos_probe_policy_is_offline_readonly_and_cannot_spawn() {
    if std::env::var_os("NW_MAC_PROBE_CHILD").is_some() {
        let git = nw_platform::open_device_config(std::path::Path::new(
            &std::env::var_os("NW_MAC_PROBE_GIT").unwrap(),
        ))
        .unwrap();
        let private = std::env::var_os("NW_MAC_PROBE_PRIVATE").unwrap();
        nw_platform::harden_process().unwrap();
        nw_platform::confine_device_probe(Some(&git)).unwrap();
        assert!(std::fs::read(&private).is_err());
        assert!(std::fs::write(private, b"forbidden").is_err());
        for address in ["0.0.0.0:0", "[::]:0"] {
            assert!(std::net::TcpListener::bind(address).is_err());
            assert!(std::net::UdpSocket::bind(address).is_err());
        }
        assert!(Command::new("/usr/bin/true").status().is_err());
        use std::io::Read;
        let mut bytes = String::new();
        (&git).read_to_string(&mut bytes).unwrap();
        assert_eq!(bytes, "synthetic git fixture");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let git = directory.path().join("gitconfig");
    let private = directory.path().join("private-canary");
    std::fs::write(&git, b"synthetic git fixture").unwrap();
    std::fs::write(&private, b"SYNTHETIC_MACOS_PROBE_CANARY_92174").unwrap();
    assert!(std::fs::read(&private).is_ok());
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "macos_probe_policy_is_offline_readonly_and_cannot_spawn",
        ])
        .env("NW_MAC_PROBE_CHILD", "1")
        .env("NW_MAC_PROBE_GIT", git)
        .env("NW_MAC_PROBE_PRIVATE", private)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native macOS probe confinement failed"
    );
}
