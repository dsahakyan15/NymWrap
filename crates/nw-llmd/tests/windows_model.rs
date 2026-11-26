#![cfg(all(windows, feature = "inference"))]
use nw_llm::{LocalModel, Message, Role};
use secrecy::ExposeSecret;
use std::{
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    sync::Arc,
};
#[path = "../../../tests/leak/src/multilingual_assertions.rs"]
mod multilingual_assertions;
struct Managed(Arc<nw_llm::windows_worker::WindowsModel>);
impl Drop for Managed {
    fn drop(&mut self) {
        self.0.stop();
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
#[test]
fn ordinary_http_broker_is_not_an_inference_fallback() {
    let result = Command::new(env!("CARGO_BIN_EXE_nw-llmd"))
        .creation_flags(0x08000000)
        .args([
            "--socket",
            "nymwrap-SYNTHETIC_MODEL_CANARY",
            "--model",
            "SYNTHETIC_MODEL_CANARY",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("SYNTHETIC_MODEL_CANARY"));
}
async fn start_model(
    embedding: &str,
    hash: &str,
    label: &str,
) -> (Managed, nw_llm::UnixModel, nw_ipc::Endpoint) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-models");
    let address = format!("nymwrap-isolated-model-{label}-test-{}", std::process::id());
    let worker = Arc::new(
        nw_llm::windows_worker::WindowsModel::load(
            std::path::Path::new(env!("CARGO_BIN_EXE_nw-llmd")),
            &root.join("qwen2.5-0.5b-instruct-q4_k_m.gguf"),
            "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
            &root.join(embedding),
            hash,
        )
        .await
        .unwrap(),
    );
    let endpoint = nw_ipc::Endpoint::new(address.clone(), nw_proto::Lane::Shadow).unwrap();
    let model = nw_llm::UnixModel::new(address.into(), "default".into(), "local-embedding".into())
        .unwrap()
        .expect_windows_worker(&worker);
    (Managed(worker), model, endpoint)
}
#[tokio::test]
#[ignore = "requires pinned GGUFs and creates offline AppContainers for actual native inference"]
async fn actual_appcontainer_model_over_private_ipc() {
    let (child, model, endpoint) = start_model(
        "nomic-embed-text-v1.5.Q4_K_M.gguf",
        nw_llm::embedding::NOMIC_SHA256,
        "nomic",
    )
    .await;
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
    stop_model(child, &endpoint, &model).await;
}
async fn stop_model(child: Managed, endpoint: &nw_ipc::Endpoint, model: &nw_llm::UnixModel) {
    child.0.stop();
    let result = model
        .complete(&[Message {
            role: Role::User,
            content: "SYNTHETIC_CLOSED_MODEL_CANARY".into(),
        }])
        .await;
    assert!(matches!(result, Err(nw_llm::ModelError::Unavailable)));
    assert!(endpoint.connect().await.is_err());
    drop(child);
    assert!(matches!(
        model
            .complete(&[Message {
                role: Role::User,
                content: "SYNTHETIC_REVOKED_MODEL_CANARY".into()
            }])
            .await,
        Err(nw_llm::ModelError::Peer)
    ));
}
#[tokio::test]
#[ignore = "requires pinned multilingual GGUF and creates offline AppContainers"]
async fn actual_multilingual_appcontainer_embeddings() {
    let (child, model, endpoint) = start_model(
        "Qwen3-Embedding-0.6B-Q8_0.gguf",
        nw_llm::embedding::QWEN3_SHA256,
        "multilingual",
    )
    .await;
    multilingual_assertions::verify(&model).await;
    stop_model(child, &endpoint, &model).await;
}
