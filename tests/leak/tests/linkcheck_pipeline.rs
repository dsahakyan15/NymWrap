//! Real Engine, checked output and byte shaping; only inference and remote send are synthetic.
use nw_core::{
    CoreError, Engine, RemoteCompletion,
    linkcheck::{DIMENSION, MODEL_SHA256, References},
};
use nw_llm::{EmbeddingBatch, LocalModel, Message, ModelError, Role};
use nw_proto::{Profile, TrustLevel};
use nw_shield::{Prepared, Secret, SecretKind, Shield};
use secrecy::{ExposeSecret, SecretString};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
const CANARY: &str = "SYNTHETIC_LINK_GUARD_CANARY_73926";
#[derive(Clone, Copy)]
enum Mode {
    Generalize,
    Retain,
    Inject,
    Unavailable,
    JsonLocal,
    WrongModel,
}
struct Model {
    mode: Mode,
    generalizations: Arc<AtomicUsize>,
}
impl LocalModel for Model {
    async fn canonicalize(&self, text: &str) -> Result<SecretString, ModelError> {
        Ok(text.to_owned().into())
    }
    async fn identify_entities(&self, _: &str) -> Result<SecretString, ModelError> {
        Ok(r#"{"local_only":false,"entities":[]}"#.into())
    }
    async fn complete(&self, messages: &[Message]) -> Result<SecretString, ModelError> {
        if matches!(self.mode, Mode::JsonLocal) {
            return Ok(r#"{"answer":42}"#.into());
        }
        if messages
            .first()
            .is_some_and(|m| m.content.starts_with("Generalize the task"))
        {
            self.generalizations.fetch_add(1, Ordering::SeqCst);
            return Ok(match self.mode {
                Mode::Generalize => "Explain pottery for someone with a work schedule.".into(),
                Mode::Inject => format!("Explain pottery for {CANARY}.").into(),
                _ => "new rare schedule".into(),
            });
        }
        Ok("synthetic local pottery answer".into())
    }
    async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, ModelError> {
        panic!("unidentified embeddings cannot authorize egress")
    }
    async fn embed_identified(&self, texts: &[String]) -> Result<EmbeddingBatch, ModelError> {
        if matches!(self.mode, Mode::Unavailable | Mode::JsonLocal) {
            return Err(ModelError::Unavailable);
        }
        Ok(EmbeddingBatch {
            recipe_id: nw_llm::embedding::for_model(MODEL_SHA256)
                .unwrap()
                .id
                .into(),
            model_sha256: if matches!(self.mode, Mode::WrongModel) {
                "a".repeat(64)
            } else {
                MODEL_SHA256.into()
            },
            vectors: texts
                .iter()
                .map(|text| {
                    let match_user =
                        text.contains("old rare craft") && text.contains("new rare schedule");
                    let mut v = vec![0.0; DIMENSION];
                    v[usize::from(!match_user)] = 1.0;
                    v
                })
                .collect(),
        })
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
        request: &Prepared,
        max_tokens: u32,
    ) -> Result<SecretString, CoreError> {
        let body = nw_net::ShapedRequest::history(request, "synthetic", max_tokens)
            .map_err(|_| CoreError::Blocked)?;
        assert!(nw_net::BYTE_BUCKETS.contains(&body.bytes().len()));
        assert!(!String::from_utf8_lossy(body.bytes()).contains(CANARY));
        self.0
            .lock()
            .unwrap()
            .push(request.text().to_owned().into());
        Ok("synthetic remote pottery answer".into())
    }
}
fn engine(mode: Mode, references: bool) -> (Engine<Model>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let shield = Shield::new(vec![
        Secret::new(SecretKind::Secret, CANARY.into(), false).unwrap(),
    ])
    .unwrap();
    let engine = Engine::new(
        Model {
            mode,
            generalizations: calls.clone(),
        },
        shield,
        Profile::Standard,
    );
    let engine = if references {
        engine.with_linkcheck(Some(
            References::with_synthetic_decoys("old rare craft; new rare schedule".into()).unwrap(),
        ))
    } else {
        engine
    };
    (engine, calls)
}
fn user(text: &str) -> Message {
    Message {
        role: Role::User,
        content: text.into(),
    }
}
#[tokio::test]
async fn only_new_text_is_generalized_and_the_entire_previous_history_remains_in_the_outgoing_request()
 {
    let (engine, calls) = engine(Mode::Generalize, true);
    let remote = Capture::default();
    let mut history = vec![user("Explain pottery for someone with an old rare craft.")];
    let first = engine
        .chat_remote("new", &history, 32, &remote, None)
        .await
        .unwrap();
    assert_eq!(first.trust, TrustLevel::L3);
    history.push(Message {
        role: Role::Assistant,
        content: first.text.expose_secret().into(),
    });
    history.push(user("Also consider a new rare schedule."));
    let second = engine
        .chat_remote(&first.conversation, &history, 32, &remote, None)
        .await
        .unwrap();
    assert_eq!(second.trust, TrustLevel::L3);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let sent = remote.0.lock().unwrap();
    assert_eq!(sent.len(), 2);
    let previous: serde_json::Value = serde_json::from_str(sent[0].expose_secret()).unwrap();
    let next: serde_json::Value = serde_json::from_str(sent[1].expose_secret()).unwrap();
    assert_eq!(previous[0], next[0]);
    assert!(sent[1].expose_secret().contains("old rare craft"));
    assert!(!sent[1].expose_secret().contains("new rare schedule"));
    assert!(sent[1].expose_secret().contains("pottery"));
}
#[tokio::test]
async fn persistent_linkage_or_a_canary_in_generalization_stays_local_without_a_second_send() {
    for mode in [Mode::Retain, Mode::Inject] {
        let (engine, calls) = engine(mode, true);
        let remote = Capture::default();
        let mut history = vec![user("Explain pottery for someone with an old rare craft.")];
        let first = engine
            .chat_remote("new", &history, 32, &remote, None)
            .await
            .unwrap();
        history.push(Message {
            role: Role::Assistant,
            content: first.text.expose_secret().into(),
        });
        history.push(user("Also consider a new rare schedule."));
        let second = engine
            .chat_remote(&first.conversation, &history, 32, &remote, None)
            .await
            .unwrap();
        assert_eq!(second.trust, TrustLevel::L0);
        assert!(second.local_reason.is_some());
        assert_eq!(
            second.text.expose_secret(),
            "synthetic local pottery answer"
        );
        assert!(!second.text.expose_secret().contains(CANARY));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(remote.0.lock().unwrap().len(), 1);
        history.push(Message {
            role: Role::Assistant,
            content: second.text.expose_secret().into(),
        });
        history.push(user("Explain a public pottery topic."));
        assert_eq!(
            engine
                .chat_remote(&second.conversation, &history, 32, &remote, None)
                .await
                .unwrap()
                .trust,
            TrustLevel::L0
        );
        assert_eq!(remote.0.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn missing_dossier_model_failure_and_another_embedding_model_never_skip_the_guard() {
    for (mode, references) in [
        (Mode::Generalize, false),
        (Mode::Unavailable, true),
        (Mode::WrongModel, true),
    ] {
        let (engine, calls) = engine(mode, references);
        let remote = Capture::default();
        let reply = engine
            .chat_remote("new", &[user("Explain pottery.")], 32, &remote, None)
            .await
            .unwrap();
        assert_eq!(reply.trust, TrustLevel::L0);
        assert!(reply.local_reason.is_some());
        assert_eq!(reply.text.expose_secret(), "synthetic local pottery answer");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(remote.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn local_fallback_preserves_a_requested_json_answer_and_reports_its_reason_separately() {
    let (engine, _) = engine(Mode::JsonLocal, true);
    let remote = Capture::default();
    let reply = engine
        .chat_remote(
            "new",
            &[user("Reply with a JSON answer containing 42.")],
            32,
            &remote,
            None,
        )
        .await
        .unwrap();
    assert_eq!(reply.trust, TrustLevel::L0);
    assert!(matches!(
        reply.local_reason,
        Some(nw_core::linkcheck::LocalReason::VerificationUnavailable)
    ));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(reply.text.expose_secret()).unwrap(),
        serde_json::json!({"answer":42})
    );
    assert!(remote.0.lock().unwrap().is_empty());
}
