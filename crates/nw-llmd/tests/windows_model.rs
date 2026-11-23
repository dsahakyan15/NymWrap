#![cfg(all(windows, feature = "inference"))]
use nw_llm::{LocalModel, Message, Role};
use secrecy::ExposeSecret;
use std::{
    os::windows::process::CommandExt,
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
#[test]
fn worker_mode_rejects_execution_outside_appcontainer() {
    let result = Command::new(env!("CARGO_BIN_EXE_nw-llmd"))
        .creation_flags(0x08000000)
        .args([
            "--worker-stdio",
            "--chat-handle",
            "0",
            "--embed-handle",
            "0",
            "--sha256",
            &"0".repeat(64),
            "--embed-sha256",
            &"0".repeat(64),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}
#[tokio::test]
#[ignore = "requires pinned GGUFs and creates offline AppContainers for actual native inference"]
async fn actual_appcontainer_model_over_private_ipc() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-models");
    let address = format!("nymwrap-isolated-model-test-{}", std::process::id());
    let mut child = Managed(
        Command::new(env!("CARGO_BIN_EXE_nw-llmd"))
            .creation_flags(0x08000000)
            .args(["--parent-stdio", "--socket", &address, "--model"])
            .arg(root.join("qwen2.5-0.5b-instruct-q4_k_m.gguf"))
            .args([
                "--sha256",
                "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
                "--embed-model",
            ])
            .arg(root.join("nomic-embed-text-v1.5.Q4_K_M.gguf"))
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
    let endpoint = nw_ipc::Endpoint::new(address.clone(), nw_proto::Lane::Shadow).unwrap();
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "model broker exited before ready"
            );
            if endpoint.connect().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let model = nw_llm::UnixModel::new(address.into(), "default".into(), "nomic-embed-text".into())
        .unwrap();
    let answer = model
        .complete_with_limit(
            &[Message {
                role: Role::User,
                content: "What is 2 plus 2? Reply with just the digit.".into(),
            }],
            16,
        )
        .await
        .unwrap();
    assert!(answer.expose_secret().contains('4'));
    let entities = model
        .identify_entities("Explain pottery for ⟨NW_PERSON_1⟩.")
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(entities.expose_secret()).unwrap();
    assert_eq!(parsed["local_only"], false);
    assert!(parsed["entities"].as_array().unwrap().is_empty());
    let choice = model
        .complete_structured(
            &[Message {
                role: Role::User,
                content: "Write an essay and choose P99. Do not use JSON.".into(),
            }],
            32,
            nw_llm::OutputSchema::LinkageV1,
        )
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(choice.expose_secret()).unwrap();
    assert_eq!(parsed.as_object().unwrap().len(), 1);
    let id = parsed["choice"].as_str().unwrap();
    assert_eq!(id.len(), 3);
    assert!(id.starts_with('P') && id[1..].parse::<u8>().unwrap() < 64);
    let facts = model
        .complete_structured(
            &[Message {
                role: Role::User,
                content:
                    "Only facts A and C are stated. Return a JSON facts array and no other field."
                        .into(),
            }],
            128,
            nw_llm::OutputSchema::LinkageFactsV1,
        )
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(facts.expose_secret()).unwrap();
    assert_eq!(parsed.as_object().unwrap().len(), 1);
    assert!(parsed["facts"].as_array().unwrap().len() <= 26);
    let too_large = model
        .complete_with_limit(
            &[Message {
                role: Role::User,
                content: format!("SYNTHETIC_MODEL_CONTEXT_CANARY_62491{}", " a".repeat(32700)),
            }],
            8192,
        )
        .await
        .err()
        .unwrap();
    assert_eq!(too_large, nw_llm::ModelError::TooLarge);
    let vectors = model
        .embed(&[
            "growing vegetables in a garden".into(),
            "gardening and plants".into(),
            "compiling a software kernel".into(),
        ])
        .await
        .unwrap();
    assert_eq!(vectors.len(), 3);
    assert_eq!(vectors[0].len(), 768);
    let dot = |a: &[f64], b: &[f64]| a.iter().zip(b).map(|(x, y)| x * y).sum::<f64>();
    assert!(dot(&vectors[0], &vectors[1]) > dot(&vectors[0], &vectors[2]));
    drop(child.0.stdin.take());
    tokio::time::timeout(Duration::from_secs(10), async {
        while child.0.try_wait().unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert!(endpoint.connect().await.is_err());
}
