use nw_core::{CoreError, RemoteCompletion, RemoteStep};
use nw_llm::{LocalModel, Message, ModelError, Role};
use nw_proto::{Profile, TrustLevel};
use nw_shield::{Prepared, Secret, SecretKind, Shield};
use secrecy::SecretString;
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "../src/link_fixture.rs"]
mod link_fixture;

struct Model;
impl LocalModel for Model {
    async fn complete(&self, _: &[Message]) -> Result<SecretString, ModelError> {
        Ok("synthetic local answer".into())
    }
    async fn canonicalize(&self, text: &str) -> Result<SecretString, ModelError> {
        Ok(text.to_owned().into())
    }
    async fn canonicalize_with_translation(
        &self,
        text: &str,
        _: bool,
    ) -> Result<SecretString, ModelError> {
        // The synthetic task is already English, including its placeholders.
        self.canonicalize(text).await
    }
    async fn identify_entities(&self, _: &str) -> Result<SecretString, ModelError> {
        Ok(r#"{"local_only":false,"entities":[]}"#.into())
    }
    async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, ModelError> {
        Err(ModelError::Unavailable)
    }
    async fn embed_identified(
        &self,
        texts: &[String],
    ) -> Result<nw_llm::EmbeddingBatch, ModelError> {
        Ok(link_fixture::identified(texts))
    }
}

struct UnsupportedRoute {
    trust: TrustLevel,
    calls: AtomicUsize,
}
impl RemoteCompletion for UnsupportedRoute {
    fn context(&self) -> &str {
        "synthetic-unavailable-route"
    }
    fn trust(&self) -> TrustLevel {
        self.trust
    }
    async fn complete(&self, _: &str, _: &Prepared, _: u32) -> Result<SecretString, CoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(CoreError::Transport)
    }
}

#[tokio::test]
async fn paranoid_never_invokes_l2_or_l3_and_sensitive_requests_remain_l0() {
    for trust in [TrustLevel::L2, TrustLevel::L3] {
        let canary = "PARANOID_LOCAL_ONLY_CANARY_59278";
        let shield = Shield::new(vec![
            Secret::new(SecretKind::Secret, canary.into(), true).unwrap(),
        ])
        .unwrap();
        let config = nw_core::config::Config::for_profile(Profile::Paranoid).unwrap();
        let engine = if trust == TrustLevel::L2 {
            link_fixture::configured(Model, shield, &config).unwrap()
        } else {
            link_fixture::engine(Model, shield, Profile::Paranoid)
        };
        let route = UnsupportedRoute {
            trust,
            calls: AtomicUsize::new(0),
        };
        let input = [Message {
            role: Role::User,
            content: "Explain pottery".into(),
        }];
        assert!(matches!(
            engine.review_remote("new", &input, 32, &route).await,
            Err(CoreError::Trust)
        ));
        let private = [Message {
            role: Role::User,
            content: format!("Explain pottery for {canary}"),
        }];
        let RemoteStep::Chat(reply) = engine
            .review_remote("new", &private, 32, &route)
            .await
            .unwrap()
        else {
            panic!("L0 expected")
        };
        assert_eq!(reply.trust, TrustLevel::L0);
        assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    }
}
