//! Original task context belongs to final L0 reasoning, never to remote rewriting.
use super::*;
use crate::{CoreError, RemoteCompletion, RemoteStep};
use nw_llm::ModelError;
use nw_proto::TrustLevel;
use std::sync::Mutex;

const NUMBER: &str = "73926";
const LOCAL_REPLY: &str = "SYNTHETIC_LOCAL_REPLY_CANARY_82413";
const UNUSED_DEVICE: &str = "SYNTHETIC_UNMENTIONED_DEVICE_CANARY_51842";

struct Model {
    fail_ner: bool,
    numeric: bool,
    inputs: Arc<Mutex<Vec<Vec<Message>>>>,
}
fn assert_masked(text: &str, stage: &str) {
    for value in [NUMBER, LOCAL_REPLY, UNUSED_DEVICE] {
        assert!(!text.contains(value), "{stage} received a raw canary");
    }
}
impl LocalModel for Model {
    async fn identify_entities(&self, text: &str) -> Result<SecretString, ModelError> {
        assert_masked(text, "NER");
        if self.fail_ner {
            Err(ModelError::Unavailable)
        } else {
            Ok(r#"{"local_only":false,"entities":[]}"#.into())
        }
    }
    async fn canonicalize(&self, text: &str) -> Result<SecretString, ModelError> {
        assert_masked(text, "canonicalize");
        Ok(text.to_owned().into())
    }
    async fn complete(&self, messages: &[Message]) -> Result<SecretString, ModelError> {
        assert!(messages.iter().all(|m| !m.content.contains(UNUSED_DEVICE)));
        self.inputs.lock().unwrap().push(messages.to_vec());
        Ok(if self.numeric {
            if messages.iter().any(|m| m.content.contains(NUMBER)) {
                "73900"
            } else {
                "missing original task value"
            }
        } else {
            LOCAL_REPLY
        }
        .into())
    }
    async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, ModelError> {
        panic!("anonymous vectors cannot authorize egress")
    }
    async fn embed_identified(
        &self,
        texts: &[String],
    ) -> Result<nw_llm::EmbeddingBatch, ModelError> {
        Ok(crate::link_fixture::identified(texts))
    }
}
#[derive(Default)]
struct Capture(Mutex<Vec<SecretString>>);
impl RemoteCompletion for Capture {
    fn trust(&self) -> TrustLevel {
        TrustLevel::L3
    }
    fn context(&self) -> &str {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
    async fn complete(
        &self,
        _: &str,
        prepared: &nw_shield::Prepared,
        max_tokens: u32,
    ) -> Result<SecretString, CoreError> {
        let shaped = nw_net::ShapedRequest::history(prepared, "synthetic", max_tokens)
            .map_err(|_| CoreError::Blocked)?;
        assert!(nw_net::BYTE_BUCKETS.contains(&shaped.bytes().len()));
        assert_masked(&String::from_utf8_lossy(shaped.bytes()), "outgoing bytes");
        self.0
            .lock()
            .unwrap()
            .push(prepared.text().to_owned().into());
        Ok("A synthetic public pottery answer.".into())
    }
}
fn secrets() -> Vec<SecretRecord> {
    [
        (SecretKind::Secret, NUMBER),
        (SecretKind::Secret, LOCAL_REPLY),
        (SecretKind::Device, UNUSED_DEVICE),
    ]
    .into_iter()
    .map(|(kind, value)| SecretRecord {
        kind,
        value: value.into(),
        local_only: false,
    })
    .collect()
}
fn user(text: &str) -> Message {
    Message {
        role: Role::User,
        content: text.into(),
    }
}
fn append(history: &mut Vec<Message>, answer: &str, next: &str) {
    history.push(Message {
        role: Role::Assistant,
        content: answer.into(),
    });
    history.push(user(next));
}
#[tokio::test]
async fn l0_final_reasoning_retains_original_task_values_without_reading_unmentioned_secrets() {
    // Direct L0, missing dossier, and failed NER all need the original task.
    for route in 0..3 {
        let inputs = Arc::new(Mutex::new(vec![]));
        let shield = Shield::new(
            secrets()
                .into_iter()
                .map(|s| Secret::new(s.kind, s.value.clone(), s.local_only).unwrap())
                .collect(),
        )
        .unwrap();
        let engine = crate::Engine::new(
            Model {
                fail_ner: route == 2,
                numeric: true,
                inputs: inputs.clone(),
            },
            shield,
            Profile::Standard,
        );
        let history = vec![user(
            "Round 73926 to the nearest hundred. Return one integer.",
        )];
        let remote = Capture::default();
        let reply = if route == 0 {
            engine.chat("new", &history).await
        } else {
            engine.chat_remote("new", &history, 32, &remote, None).await
        }
        .unwrap();
        assert_eq!(reply.trust, TrustLevel::L0);
        assert_eq!(reply.text.expose_secret(), "73900");
        assert!(remote.0.lock().unwrap().is_empty());
        let observed = inputs.lock().unwrap();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0][0].content, history[0].content);
    }
}
#[tokio::test]
async fn remote_then_local_stays_local_with_original_roles_after_encrypted_reopen() {
    check_local_history(true, false).await;
}
#[tokio::test]
async fn unlisted_local_facts_cannot_reenter_the_remote_history_after_a_local_turn() {
    check_local_history(false, false).await;
}
#[tokio::test]
async fn legacy_snapshot_with_unmarked_local_answers_is_restored_only_locally() {
    check_local_history(false, true).await;
}
async fn check_local_history(known_reply: bool, legacy: bool) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("original-local-context");
    let keys = Arc::new(tests::MemoryKeys::default());
    let mut workspace = Workspace::create_with(
        &root,
        SecretString::from(""),
        Profile::Standard,
        keys.clone(),
    )
    .unwrap();
    let mut registered = secrets();
    if !known_reply {
        registered.retain(|secret| secret.value != LOCAL_REPLY);
    }
    workspace.set_secrets(registered).unwrap();
    let inputs = Arc::new(Mutex::new(vec![]));
    let model = || Model {
        fail_ner: false,
        numeric: false,
        inputs: inputs.clone(),
    };
    let engine =
        crate::link_fixture::engine(model(), workspace.shield().unwrap(), Profile::Standard);
    let remote = Capture::default();
    let mut history = vec![user("Explain a common pottery technique.")];
    let first = engine
        .chat_remote("new", &history, 128, &remote, None)
        .await
        .unwrap();
    assert_eq!(first.trust, TrustLevel::L3);
    let id = first.conversation.clone();
    append(&mut history, first.text.expose_secret(), "Now round 73926.");
    let local = engine.chat(&id, &history).await.unwrap();
    assert_eq!(local.trust, TrustLevel::L0);
    assert_eq!(local.text.expose_secret(), LOCAL_REPLY);
    {
        let observed = inputs.lock().unwrap();
        assert_eq!(observed[0].len(), history.len());
        for (actual, original) in observed[0].iter().zip(&history) {
            assert!(actual.role == original.role);
            assert_eq!(actual.content, original.content);
        }
    }
    append(
        &mut history,
        local.text.expose_secret(),
        "Repeat the answer.",
    );
    let mut retry = engine
        .chat_remote(&id, &history, 128, &remote, None)
        .await
        .expect("a local reply cannot be upgraded to a remote turn");
    assert_eq!(retry.trust, TrustLevel::L0);
    assert_eq!(remote.0.lock().unwrap().len(), 1);
    if legacy {
        // Version 1 persisted no reliable marker for remote -> local turns.
        retry.snapshot.record.version = 1;
        retry.snapshot.record.force_local = false;
    }
    workspace.save_chat_reply(&retry).unwrap();
    drop(engine);
    drop(workspace);
    fn ciphertext_only(path: &std::path::Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                ciphertext_only(&path);
            } else {
                let bytes = std::fs::read(path).unwrap();
                for secret in [NUMBER, LOCAL_REPLY, UNUSED_DEVICE] {
                    assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
                }
            }
        }
    }
    ciphertext_only(&root);
    let mut workspace = Workspace::open_with(&root, SecretString::from(""), keys).unwrap();
    let recovered =
        crate::link_fixture::engine(model(), workspace.shield().unwrap(), Profile::Standard);
    recovered
        .restore_if_missing(&id, workspace.conversation_snapshot(&id).unwrap().unwrap())
        .await
        .unwrap();
    let mut history = workspace.history(&id).unwrap();
    assert!(history.iter().any(|m| m.content == LOCAL_REPLY));
    history.push(user("Repeat again."));
    let RemoteStep::Chat(reply) = recovered
        .review_remote(&id, &history, 128, &remote)
        .await
        .unwrap()
    else {
        panic!("reopened local conversation cannot create a remote approval");
    };
    assert_eq!(reply.trust, TrustLevel::L0);
    assert_eq!(reply.text.expose_secret(), LOCAL_REPLY);
    assert_eq!(remote.0.lock().unwrap().len(), 1);
}
