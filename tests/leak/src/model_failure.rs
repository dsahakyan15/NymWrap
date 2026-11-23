//! Model failures carry fixed codes across private IPC and never echo input.
use super::*;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use nw_llm::{LocalModel, ModelError};
use tower::ServiceExt;

struct Failed(bool);
impl Failed {
    fn error(&self) -> Error {
        if self.0 {
            Error::TooLarge
        } else {
            Error::Timeout
        }
    }
}
impl Inference for Failed {
    fn complete(&mut self, _: &[Message], _: u32) -> Result<String, Error> {
        Err(self.error())
    }
    fn embed(&mut self, _: &[String]) -> Result<Vec<Vec<f64>>, Error> {
        Err(self.error())
    }
}
const CANARY: &str = "SYNTHETIC_PRIVATE_MODEL_FAILURE_62491";

#[tokio::test]
async fn model_failure_preserves_timeout_and_limit_without_echoing_a_canary() {
    for large in [false, true] {
        let expected_status = if large { 413 } else { 504 };
        let expected_code = if large {
            "model_input_too_large"
        } else {
            "model_timeout"
        };
        for (path, body) in [
            (
                "/v1/chat/completions",
                serde_json::json!({"model":"default","messages":[{"role":"user","content":CANARY}],"max_tokens":16,"temperature":0,"stream":false}),
            ),
            (
                "/v1/embeddings",
                serde_json::json!({"model":"nomic-embed-text","input":[CANARY]}),
            ),
        ] {
            let reply = router(Failed(large))
                .oneshot(
                    Request::post(path)
                        .header("host", "localhost")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(reply.status().as_u16(), expected_status);
            let bytes = reply.into_body().collect().await.unwrap().to_bytes();
            assert!(!String::from_utf8_lossy(&bytes).contains(CANARY));
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                serde_json::json!({"error":{"code":expected_code}})
            );
        }
        let fixture = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let address = format!("nymwrap-model-failure-{}-{large}", std::process::id());
        #[cfg(unix)]
        let address = fixture
            .path()
            .join(format!("private/{large}.sock"))
            .to_string_lossy()
            .into_owned();
        let _keep = fixture;
        let listener = nw_ipc::Listener::bind(
            nw_ipc::Endpoint::new(address.clone(), nw_proto::Lane::Shadow).unwrap(),
        )
        .unwrap();
        let mut servers = tokio::task::JoinSet::new();
        servers.spawn(axum::serve(listener, router(Failed(large))).into_future());
        let model =
            nw_llm::UnixModel::new(address.into(), "default".into(), "nomic-embed-text".into())
                .unwrap();
        let error = model
            .complete_with_limit(
                &[Message {
                    role: nw_llm::Role::User,
                    content: CANARY.into(),
                }],
                16,
            )
            .await
            .err()
            .unwrap();
        assert_eq!(
            error,
            if large {
                ModelError::TooLarge
            } else {
                ModelError::Timeout
            }
        );
        let error = model.embed(&[CANARY.into()]).await.err().unwrap();
        assert_eq!(
            error,
            if large {
                ModelError::TooLarge
            } else {
                ModelError::Timeout
            }
        );
        servers.shutdown().await;
    }
}
