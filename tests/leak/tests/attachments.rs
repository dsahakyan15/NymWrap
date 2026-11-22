use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use nw_llm::{LocalModel, Message, ModelError};
use secrecy::SecretString;
use std::sync::Arc;
use tower::ServiceExt;
struct NeverCalled;
impl LocalModel for NeverCalled {
    async fn complete(&self, _: &[Message]) -> Result<SecretString, ModelError> {
        panic!("attachment reached model");
    }
    async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, ModelError> {
        panic!("attachment reached model");
    }
}
#[tokio::test]
async fn attachments_fail_explicitly_before_model_or_egress_without_echoing_metadata() {
    for path in ["/v1/chat/completions", "/v1/nymwrap/chat/jobs"] {
        for addition in [
            serde_json::json!({"attachments":[{"name":"CANARY_EXIF_SYNTHETIC_8835.jpg"}]}),
            serde_json::json!({"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:CANARY_EXIF_SYNTHETIC_8835"}}]}]}),
            serde_json::json!({"messages":[{"role":"user","content":"pottery","files":[]}]}),
        ] {
            let mut body = serde_json::json!({"model":"nw/remote/default", "messages":[{"role":"user","content":"pottery"}]});
            body.as_object_mut()
                .unwrap()
                .extend(addition.as_object().unwrap().clone());
            let app = nw_api::router(Arc::new(nw_core::Engine::new(
                NeverCalled,
                nw_shield::Shield::new(vec![]).unwrap(),
                nw_proto::Profile::Standard,
            )));
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("host", "localhost")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(text.contains("attachments_not_supported"));
            assert!(!text.contains("CANARY_EXIF"));
        }
    }
}
