//! The original twelve disclosed combinations remain executable regressions.
//! Geometry is controlled here; real model accuracy is measured separately.
use nw_core::{CoreError, Engine, RemoteCompletion, linkcheck};
use nw_llm::{EmbeddingBatch, LocalModel, Message, ModelError, Role};
use nw_proto::{Profile, TrustLevel};
use nw_shield::{Prepared, Shield};
use secrecy::{ExposeSecret, SecretString};
use std::sync::atomic::{AtomicUsize, Ordering};

struct ConjunctionModel(Vec<String>);
impl LocalModel for ConjunctionModel {
    async fn identify_entities(&self, _: &str) -> Result<SecretString, ModelError> {
        Ok(r#"{"local_only":false,"entities":[]}"#.into())
    }
    async fn canonicalize(&self, text: &str) -> Result<SecretString, ModelError> {
        Ok(text.to_owned().into())
    }
    async fn generalize(&self, text: &str) -> Result<SecretString, ModelError> {
        // An unsuccessful rewrite must not authorize disclosure of the combination.
        Ok(text.to_owned().into())
    }
    async fn complete(&self, _: &[Message]) -> Result<SecretString, ModelError> {
        Ok("generic local gardening answer".into())
    }
    async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, ModelError> {
        panic!("anonymous embeddings cannot authorize disclosure")
    }
    async fn embed_identified(&self, texts: &[String]) -> Result<EmbeddingBatch, ModelError> {
        Ok(EmbeddingBatch {
            model_sha256: linkcheck::MODEL_SHA256.into(),
            recipe_id: nw_llm::embedding::for_model(linkcheck::MODEL_SHA256)
                .unwrap()
                .id
                .into(),
            vectors: texts
                .iter()
                .map(|text| {
                    let matches = self.0.iter().all(|fact| text.contains(fact));
                    let mut vector = vec![0.0; linkcheck::DIMENSION];
                    vector[usize::from(!matches)] = 1.0;
                    vector
                })
                .collect(),
        })
    }
}
#[derive(Default)]
struct Capture(AtomicUsize);
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
        tokens: u32,
    ) -> Result<SecretString, CoreError> {
        let body = nw_net::ShapedRequest::history(request, "synthetic", tokens)
            .map_err(|_| CoreError::Blocked)?;
        assert!(nw_net::BYTE_BUCKETS.contains(&body.bytes().len()));
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok("generic remote gardening answer".into())
    }
}
#[tokio::test]
async fn all_twelve_original_linkage_cases_stop_before_disclosing_the_identifying_combination() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../models/privacy-v2.json")).unwrap();
    let mut tested = 0;
    for case in corpus["cases"].as_array().unwrap().iter().filter(|case| {
        matches!(
            case["group"].as_str(),
            Some("linkage" | "linkage_multiturn")
        )
    }) {
        let profile = corpus["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|profile| profile["id"] == case["profile_id"])
            .unwrap();
        let facts = profile["facts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|fact| fact.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let dossier = format!("{}\nSynthetic dossier reference", facts.join("\n"));
        let references = linkcheck::References::with_synthetic_decoys(dossier.into()).unwrap();
        let engine = Engine::new(
            ConjunctionModel(facts),
            Shield::new(vec![]).unwrap(),
            Profile::Standard,
        )
        .with_linkcheck(Some(references));
        let remote = Capture::default();
        let mut turns = vec![case["input"].as_str().unwrap()];
        if let Some(extra) = case["turns"].as_array() {
            turns.extend(extra.iter().map(|turn| turn.as_str().unwrap()));
        }
        let mut history = vec![];
        let mut conversation = String::from("new");
        for (index, turn) in turns.iter().enumerate() {
            history.push(Message {
                role: Role::User,
                content: (*turn).into(),
            });
            let reply = engine
                .chat_remote(&conversation, &history, 32, &remote, None)
                .await
                .unwrap();
            if index + 1 == turns.len() {
                assert_eq!(reply.trust, TrustLevel::L0, "{}", case["id"]);
                assert!(matches!(
                    reply.local_reason,
                    Some(linkcheck::LocalReason::IndependentSplitUnavailable)
                ));
            } else {
                assert_eq!(reply.trust, TrustLevel::L3);
            }
            conversation = reply.conversation;
            history.push(Message {
                role: Role::Assistant,
                content: reply.text.expose_secret().into(),
            });
        }
        assert_eq!(remote.0.load(Ordering::SeqCst), turns.len() - 1);
        history.push(Message {
            role: Role::User,
            content: "Explain a public gardening topic.".into(),
        });
        assert_eq!(
            engine
                .chat_remote(&conversation, &history, 32, &remote, None)
                .await
                .unwrap()
                .trust,
            TrustLevel::L0
        );
        assert_eq!(remote.0.load(Ordering::SeqCst), turns.len() - 1);
        tested += 1;
    }
    assert_eq!(tested, 12);
}
