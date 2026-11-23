//! Opt-in canary through the real Windows LPAC model to the shaped egress boundary.
use super::*;
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Managed(Child);
impl Drop for Managed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[tokio::test]
#[ignore = "requires built nw-llmd, pinned GGUFs and actual Windows AppContainers"]
async fn actual_isolated_model_keeps_canary_out_of_shaped_egress() {
    use base64::Engine as _;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let models = root.join("target/test-models");
    let address = format!("nymwrap-isolated-canary-test-{}", std::process::id());
    let mut child = Managed(
        Command::new(root.join("target/debug/nw-llmd.exe"))
            .args(["--parent-stdio", "--socket", &address, "--model"])
            .arg(models.join("qwen2.5-0.5b-instruct-q4_k_m.gguf"))
            .args([
                "--sha256",
                "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
                "--embed-model",
            ])
            .arg(models.join("nomic-embed-text-v1.5.Q4_K_M.gguf"))
            .args([
                "--embed-sha256",
                "d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "isolated model exited before ready"
            );
            if tokio::net::windows::named_pipe::ClientOptions::new()
                .open(format!(r"\\.\pipe\{address}"))
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    const CANARY: &str = "SYNTHETIC_LPAC_CANARY_74dcbec1_SecretOnly";
    let model = nw_llm::UnixModel::new(address.into(), "default".into(), "nomic-embed-text".into())
        .unwrap();
    let engine = test_engine(
        model,
        Shield::new(vec![
            Secret::new(SecretKind::Secret, CANARY.into(), false).unwrap(),
        ])
        .unwrap(),
        Profile::Standard,
    );
    let remote = route();
    let reply = engine
        .chat_remote(
            "new",
            &user(format!("Explain pottery for {CANARY}.")),
            32,
            &remote,
            None,
        )
        .await
        .unwrap();
    assert_eq!(reply.trust, TrustLevel::L3);
    let bodies = remote.bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    let body = std::str::from_utf8(&bodies[0]).unwrap();
    assert!(!body.contains(CANARY));
    assert!(!body.contains(&base64::engine::general_purpose::STANDARD.encode(CANARY)));
    assert!([2048, 4096, 8192, 16384, 32768].contains(&bodies[0].len()));
}
