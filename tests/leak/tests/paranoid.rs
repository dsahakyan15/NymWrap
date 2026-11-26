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

#[test]
fn experimental_credentials_require_explicit_build_flags() {
    for transport in [
        nw_core::config::Transport::Tor,
        nw_core::config::Transport::Nym,
    ] {
        let mut config = nw_core::config::Config::for_profile(Profile::Paranoid).unwrap();
        config.net = nw_core::config::NetConfig {
            transport,
            provider_host: Some("example.test".into()),
            provider_path: Some("/v1/chat/completions".into()),
            credential_ref: Some("keyring:experimental-zkapi".into()),
            provider_model: Some("synthetic".into()),
            max_request_cost_microusd: Some(1),
        };
        let permitted = cfg!(feature = "experimental-zkapi")
            && (transport == nw_core::config::Transport::Tor || cfg!(feature = "experimental-nym"));
        assert_eq!(config.validate().is_ok(), permitted);
    }
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

#[cfg(feature = "experimental-zkapi")]
#[tokio::test]
async fn experimental_unavailable_upstream_never_offers_l1_l2_approval_or_blocks_l0() {
    struct Experiment(nw_net::zkapi::Route);
    impl RemoteCompletion for Experiment {
        fn check_available(&self) -> Result<(), CoreError> {
            self.0.ensure_available().map_err(|_| CoreError::Transport)
        }
        fn context(&self) -> &str {
            "experimental-not-deployed"
        }
        fn trust(&self) -> TrustLevel {
            self.0.candidate_trust()
        }
        async fn complete(&self, _: &str, _: &Prepared, _: u32) -> Result<SecretString, CoreError> {
            panic!("unavailable experiment must never reach a transport or key pool")
        }
    }
    let candidates = vec![nw_net::zkapi::Route::Tor];
    #[cfg(feature = "experimental-nym")]
    let candidates = {
        let mut candidates = candidates;
        candidates.push(nw_net::zkapi::Route::Nym);
        candidates
    };
    for candidate in candidates {
        for profile in [Profile::Strict, Profile::Paranoid] {
            let config = nw_core::config::Config::for_profile(profile).unwrap();
            let canary = "M7_LOCAL_ONLY_SYNTHETIC_CANARY_51716";
            let shield = Shield::new(vec![
                Secret::new(SecretKind::Secret, canary.into(), true).unwrap(),
            ])
            .unwrap();
            let engine = link_fixture::configured(Model, shield, &config).unwrap();
            let route = Experiment(candidate);
            let input = [Message {
                role: Role::User,
                content: "Explain pottery".into(),
            }];
            assert!(matches!(
                engine.review_remote("new", &input, 32, &route).await,
                Err(CoreError::Transport)
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
        }
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
