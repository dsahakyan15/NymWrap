//! HTTP boundary followed by the real Engine review/approval and shaped egress.
use super::*;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use nw_api::{Backend, RequestRoute};
use nw_core::service::{ChatResponse, RemoteSubmission};
use nw_core::workspace::{RemoteJobInfo, RemoteJobReply, RemoteJobState, RemoteJobView};
use tower::ServiceExt;

struct ReviewedBackend {
    engine: Engine<Model>,
    remote: Capture,
}
impl Backend for ReviewedBackend {
    async fn chat(
        &self,
        _: String,
        _: Vec<Message>,
        _: u32,
        _: RequestRoute,
    ) -> Result<ChatResponse, String> {
        Err("invalid_request".into())
    }
    async fn embed(&self, _: Vec<String>) -> Result<Vec<Vec<f64>>, String> {
        Err("invalid_request".into())
    }
    async fn submit_job(
        &self,
        id: String,
        messages: Vec<Message>,
        max_tokens: u32,
        min_trust: Option<TrustLevel>,
        idempotency_key: Option<String>,
        defer_hours: Option<u16>,
    ) -> Result<RemoteSubmission, String> {
        assert_eq!(id, "new");
        assert_eq!(defer_hours, Some(0));
        assert_eq!(min_trust, Some(TrustLevel::L3));
        assert_eq!(
            idempotency_key.as_deref(),
            Some("ASYNC_KEY_CANARY_ONLY_13759")
        );
        let step = self
            .engine
            .review_remote(&id, &messages, max_tokens, &self.remote)
            .await
            .map_err(|e| e.to_string())?;
        let nw_core::RemoteStep::Review(review) = step else {
            panic!("review expected")
        };
        assert!(self.remote.bodies.lock().unwrap().is_empty());
        let reply = self
            .engine
            .approve_remote(&review.approval_id, &review.hash, &self.remote)
            .await
            .map_err(|e| e.to_string())?;
        Ok(RemoteSubmission::Job {
            job: RemoteJobView {
                info: RemoteJobInfo {
                    id: "a".repeat(64),
                    conversation: reply.conversation.clone(),
                    created_at: 0,
                    updated_at: 0,
                    state: RemoteJobState::Done,
                    code: None,
                    trust: reply.trust,
                    not_before: 0,
                },
                reply: Some(RemoteJobReply {
                    local_reason: reply.local_reason,
                    conversation: reply.conversation,
                    text: reply.text.expose_secret().into(),
                    trust: reply.trust,
                }),
            },
        })
    }
}
#[tokio::test]
async fn async_http_preserves_final_gate_and_never_echoes_canary_in_job_metadata() {
    const CANARY: &str = "ASYNC_HTTP_SYNTHETIC_CANARY_ONLY_51357";
    for injection in [false, true] {
        let backend = Arc::new(ReviewedBackend {
            engine: test_engine(
                Model {
                    injection: injection.then(|| CANARY.into()),
                },
                Shield::new(vec![
                    Secret::new(SecretKind::Secret, CANARY.into(), false).unwrap(),
                ])
                .unwrap(),
                Profile::Standard,
            ),
            remote: route(),
        });
        let request = Request::builder().method("POST").uri("/v1/nymwrap/chat/jobs")
            .header("host", "localhost").header("content-type", "application/json")
            .header("x-nymwrap-min-trust", "L3")
            .header("idempotency-key", "ASYNC_KEY_CANARY_ONLY_13759")
            .header("x-nymwrap-defer", "0")
            .body(Body::from(serde_json::json!({"model":"nw/remote/default","messages":[{"role":"user","content":format!("Explain pottery for {CANARY}")}],"max_tokens":43}).to_string())).unwrap();
        let response = nw_api::router(backend.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.headers()["x-should-retry"], "false");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.status(), if injection { 422 } else { 202 });
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!std::str::from_utf8(&bytes).unwrap().contains(CANARY));
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains("ASYNC_KEY_CANARY_ONLY_13759")
        );
        let bodies = backend.remote.bodies.lock().unwrap();
        assert_eq!(bodies.len(), usize::from(!injection));
        if let Some(bytes) = bodies.first() {
            assert!(!std::str::from_utf8(bytes).unwrap().contains(CANARY));
            assert!(
                !std::str::from_utf8(bytes)
                    .unwrap()
                    .contains("ASYNC_KEY_CANARY_ONLY_13759")
            );
            let shaped: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(shaped["max_tokens"], 43);
        }
    }
}
