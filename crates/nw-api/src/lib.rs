//! OpenAI-compatible L0 API over a private Unix socket. No TCP listener exists.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nw_core::Engine;
use nw_core::service::{ChatResponse, Client, Command, RemoteSubmission, Reply};
use nw_core::workspace::{RemoteJobState, RemoteJobView};
use nw_llm::{LocalModel, Message};
use nw_proto::{MAX_TEXT_BYTES, TrustLevel};
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::future::Future;
use std::sync::Arc;

pub trait Backend: Send + Sync {
    fn chat(
        &self,
        id: String,
        messages: Vec<Message>,
        max_tokens: u32,
        route: RequestRoute,
    ) -> impl Future<Output = Result<ChatResponse, String>> + Send;
    fn embed(
        &self,
        texts: Vec<String>,
    ) -> impl Future<Output = Result<Vec<Vec<f64>>, String>> + Send;
    fn submit_job(
        &self,
        _id: String,
        _messages: Vec<Message>,
        _max_tokens: u32,
        _min_trust: Option<TrustLevel>,
        _idempotency_key: Option<String>,
        _defer_hours: Option<u16>,
    ) -> impl Future<Output = Result<RemoteSubmission, String>> + Send {
        async { Err("remote_transport_unavailable".into()) }
    }
    fn load_job(&self, _id: String) -> impl Future<Output = Result<RemoteJobView, String>> + Send {
        async { Err("remote_transport_unavailable".into()) }
    }
    fn cancel_job(&self, _id: String) -> impl Future<Output = Result<(), String>> + Send {
        async { Err("remote_transport_unavailable".into()) }
    }
}
#[derive(Clone, Copy)]
pub struct RequestRoute {
    pub remote: bool,
    pub min_trust: Option<TrustLevel>,
}
impl<M: LocalModel> Backend for Engine<M> {
    async fn chat(
        &self,
        id: String,
        messages: Vec<Message>,
        max_tokens: u32,
        route: RequestRoute,
    ) -> Result<ChatResponse, String> {
        if route.remote {
            return Err("unsupported_model".into());
        }
        let result = self
            .chat_with_limit(&id, &messages, max_tokens)
            .await
            .map_err(|e| e.to_string())?;
        Ok(ChatResponse {
            conversation: result.conversation,
            text: result.text.expose_secret().into(),
            trust: result.trust,
        })
    }
    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f64>>, String> {
        Engine::embed(self, &texts).await.map_err(|e| e.to_string())
    }
}
impl Backend for Client {
    async fn submit_job(
        &self,
        conversation: String,
        messages: Vec<Message>,
        max_tokens: u32,
        min_trust: Option<TrustLevel>,
        idempotency_key: Option<String>,
        defer_hours: Option<u16>,
    ) -> Result<RemoteSubmission, String> {
        match self
            .request(Command::SubmitRemoteJob {
                conversation,
                messages,
                max_tokens: Some(max_tokens),
                min_trust,
                idempotency_key: idempotency_key.map(nw_core::service::Sensitive::new),
                defer_hours,
            })
            .await?
        {
            Reply::RemoteSubmission { value } => Ok(value),
            Reply::Error { code } => Err(code),
            _ => Err("invalid_daemon_response".into()),
        }
    }
    async fn load_job(&self, id: String) -> Result<RemoteJobView, String> {
        match self.request(Command::LoadRemoteJob { id }).await? {
            Reply::RemoteJob { value } => Ok(value),
            Reply::Error { code } => Err(code),
            _ => Err("invalid_daemon_response".into()),
        }
    }
    async fn cancel_job(&self, id: String) -> Result<(), String> {
        match self.request(Command::CancelRemoteJob { id }).await? {
            Reply::Ack {} => Ok(()),
            Reply::Error { code } => Err(code),
            _ => Err("invalid_daemon_response".into()),
        }
    }
    async fn chat(
        &self,
        conversation: String,
        messages: Vec<Message>,
        max_tokens: u32,
        route: RequestRoute,
    ) -> Result<ChatResponse, String> {
        let command = if route.remote {
            Command::RemoteChat {
                conversation,
                messages,
                max_tokens: Some(max_tokens),
                min_trust: route.min_trust,
            }
        } else {
            Command::Chat {
                conversation,
                messages,
                max_tokens: Some(max_tokens),
            }
        };
        match self.request(command).await? {
            Reply::Chat { value } => Ok(value),
            Reply::Error { code } => Err(code),
            _ => Err("invalid_daemon_response".into()),
        }
    }
    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f64>>, String> {
        match self.request(Command::Embeddings { texts }).await? {
            Reply::Embeddings { value } => Ok(value),
            Reply::Error { code } => Err(code),
            _ => Err("invalid_daemon_response".into()),
        }
    }
}

type ApiError = (StatusCode, Json<serde_json::Value>);
fn error(status: StatusCode, code: &str) -> ApiError {
    (
        status,
        Json(serde_json::json!({"error":{"message":code,"type":"nymwrap_error","code":code}})),
    )
}
fn core_error(code: String) -> ApiError {
    let (status, safe) = match code.as_str() {
        "local_model_unavailable" | "workspace_locked" | "ipc_unavailable" | "ipc_timeout" => {
            (StatusCode::SERVICE_UNAVAILABLE, code.as_str())
        }
        "shield_blocked" => (StatusCode::UNPROCESSABLE_ENTITY, code.as_str()),
        "conversation_limit" => (StatusCode::TOO_MANY_REQUESTS, code.as_str()),
        "request_in_progress" | "idempotency_conflict" | "idempotency_uncertain" => {
            (StatusCode::CONFLICT, code.as_str())
        }
        "idempotency_capacity" => (StatusCode::TOO_MANY_REQUESTS, code.as_str()),
        "idempotency_expired" => (StatusCode::GONE, code.as_str()),
        "network_budget_exhausted" | "credential_pool_unavailable" => {
            (StatusCode::PAYMENT_REQUIRED, code.as_str())
        }
        "trust_policy_violation" | "approval_required" => (StatusCode::FORBIDDEN, code.as_str()),
        "remote_transport_unavailable"
        | "session_changed"
        | "async_remote_required"
        | "device_probe_required" => (StatusCode::FAILED_DEPENDENCY, code.as_str()),
        "invalid_conversation"
        | "invalid_request"
        | "unsupported_model"
        | "invalid_idempotency_key" => (StatusCode::BAD_REQUEST, code.as_str()),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "daemon_request_failed"),
    };
    error(status, safe)
}
fn validate_headers(request: &axum::extract::Request) -> Result<(), ApiError> {
    let headers = request.headers();
    for name in [
        "host",
        "origin",
        "x-nymwrap-lane",
        "x-nymwrap-min-trust",
        "x-nymwrap-conversation",
        "idempotency-key",
        "x-nymwrap-defer",
    ] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(error(StatusCode::BAD_REQUEST, "duplicate_header"));
        }
    }
    if let Some(value) = headers.get("x-nymwrap-defer") {
        let hours = value
            .to_str()
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u16>().ok());
        if request.method() != axum::http::Method::POST
            || request.uri().path() != "/v1/nymwrap/chat/jobs"
            || hours.is_none_or(|n| n > 168)
        {
            return Err(error(StatusCode::BAD_REQUEST, "invalid_defer_window"));
        }
    }
    if let Some(key) = headers.get("idempotency-key")
        && (request.method() != axum::http::Method::POST
            || request.uri().path() != "/v1/nymwrap/chat/jobs"
            || !(16..=128).contains(&key.as_bytes().len())
            || !key
                .as_bytes()
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b)))
    {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_idempotency_key"));
    }
    if headers.contains_key("origin")
        || headers.get("x-nymwrap-lane").is_some_and(|v| v != "shadow")
    {
        return Err(error(StatusCode::FORBIDDEN, "wrong_lane_or_origin"));
    }
    if headers
        .get("host")
        .is_none_or(|v| v != "localhost" && v != "127.0.0.1")
    {
        return Err(error(StatusCode::FORBIDDEN, "invalid_host"));
    }
    if headers
        .get("x-nymwrap-min-trust")
        .is_some_and(|v| !["L0", "L1", "L2", "L3"].iter().any(|s| v == *s))
    {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_trust_level"));
    }
    Ok(())
}
async fn guard(request: axum::extract::Request, next: Next) -> Response {
    let mut response = match validate_headers(&request) {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    };
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response
        .headers_mut()
        .insert("x-should-retry", "false".parse().unwrap());
    response
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    #[serde(default)]
    stream: bool,
    temperature: Option<f64>,
    max_tokens: Option<u32>,
}
fn chat_payload(
    headers: &HeaderMap,
    payload: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<ChatRequest, ApiError> {
    let bytes = payload.map_err(|_| error(StatusCode::BAD_REQUEST, "invalid_request"))?;
    if headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| {
            let mime = v.split(';').next().unwrap_or("").trim();
            mime != "application/json"
                && !(mime.starts_with("application/") && mime.ends_with("+json"))
        })
    {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    // The strict typed parse is the ONLY success path. Parsing Value first would
    // silently collapse duplicate object keys and weaken deny_unknown_fields.
    if let Ok(request) = serde_json::from_slice::<ChatRequest>(&bytes) {
        return Ok(request);
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let has_attachment = |v: &serde_json::Value| {
        [
            "attachments",
            "files",
            "images",
            "image_url",
            "input_audio",
            "audio",
            "file",
        ]
        .iter()
        .any(|key| v.get(key).is_some())
    };
    if has_attachment(&value)
        || value
            .get("messages")
            .and_then(|v| v.as_array())
            .is_some_and(|messages| {
                messages.iter().any(|m| {
                    has_attachment(m)
                        || m.get("content")
                            .is_some_and(|c| c.is_array() || c.is_object())
                })
            })
    {
        return Err(error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "attachments_not_supported",
        ));
    }
    Err(error(StatusCode::BAD_REQUEST, "invalid_request"))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbedRequest {
    model: String,
    input: EmbedInput,
    encoding_format: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum EmbedInput {
    One(String),
    Many(Vec<String>),
}
async fn models() -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"object":"list","data":[{"id":"nw/local/default","object":"model","created":0,"owned_by":"local"},{"id":"nw/local/nomic-embed-text","object":"model","created":0,"owned_by":"local"},{"id":"nw/remote/default","object":"model","created":0,"owned_by":"configured"}]}),
    )
}
async fn chat<B: Backend + 'static>(
    State(engine): State<Arc<B>>,
    headers: HeaderMap,
    payload: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let request = chat_payload(&headers, payload)?;
    if !matches!(
        request.model.as_str(),
        "nw/local/default" | "nw/remote/default"
    ) || request.stream
        || request
            .temperature
            .is_some_and(|v| !v.is_finite() || !(0.0..=2.0).contains(&v))
        || request.max_tokens.is_some_and(|n| n == 0 || n > 2048)
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "unsupported_model_or_parameters",
        ));
    }
    let (id, min_trust) = chat_headers(&headers)?;
    let reply = engine
        .chat(
            id,
            request.messages,
            request.max_tokens.unwrap_or(2048),
            RequestRoute {
                remote: request.model == "nw/remote/default",
                min_trust,
            },
        )
        .await
        .map_err(core_error)?;
    chat_response(reply)
}
fn chat_headers(headers: &HeaderMap) -> Result<(String, Option<TrustLevel>), ApiError> {
    let id = headers
        .get("x-nymwrap-conversation")
        .map(|h| h.to_str())
        .transpose()
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid_conversation"))?
        .unwrap_or("new");
    if id.len() > 128 {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_conversation"));
    }
    let min_trust = headers
        .get("x-nymwrap-min-trust")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| match h {
            "L0" => Some(TrustLevel::L0),
            "L1" => Some(TrustLevel::L1),
            "L2" => Some(TrustLevel::L2),
            "L3" => Some(TrustLevel::L3),
            _ => None,
        });
    Ok((id.to_owned(), min_trust))
}
fn chat_value(conversation: &str, text: &str, trust: TrustLevel) -> serde_json::Value {
    let actual_model = if trust == TrustLevel::L0 {
        "nw/local/default"
    } else {
        "nw/remote/default"
    };
    serde_json::json!({"id":format!("chatcmpl-{conversation}"),"object":"chat.completion","created":0,"model":actual_model,"choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}],"nymwrap":{"trust":trust,"lane":"shadow"}})
}
fn chat_response(reply: ChatResponse) -> Result<Response, ApiError> {
    let mut response =
        Json(chat_value(&reply.conversation, &reply.text, reply.trust)).into_response();
    response.headers_mut().insert(
        "x-nymwrap-conversation",
        reply
            .conversation
            .parse()
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_conversation"))?,
    );
    Ok(response)
}
async fn submit_job<B: Backend + 'static>(
    State(engine): State<Arc<B>>,
    headers: HeaderMap,
    payload: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let request = chat_payload(&headers, payload)?;
    if request.model != "nw/remote/default"
        || request.stream
        || request
            .temperature
            .is_some_and(|v| !v.is_finite() || !(0.0..=2.0).contains(&v))
        || request.max_tokens.is_some_and(|n| n == 0 || n > 2048)
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "unsupported_model_or_parameters",
        ));
    }
    let (id, min_trust) = chat_headers(&headers)?;
    match engine
        .submit_job(
            id,
            request.messages,
            request.max_tokens.unwrap_or(2048),
            min_trust,
            headers
                .get("idempotency-key")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            headers
                .get("x-nymwrap-defer")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u16>().ok()),
        )
        .await
        .map_err(core_error)?
    {
        RemoteSubmission::Chat { reply } => chat_response(reply),
        RemoteSubmission::Job { job } => {
            let mut response = job_response(job)?;
            *response.status_mut() = StatusCode::ACCEPTED;
            Ok(response)
        }
    }
}
fn job_id(id: &str) -> Result<(), ApiError> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    Ok(())
}
fn job_response(job: RemoteJobView) -> Result<Response, ApiError> {
    job_id(&job.info.id)?;
    let result = job
        .reply
        .as_ref()
        .map(|r| chat_value(&r.conversation, &r.text, r.trust));
    let mut response = Json(serde_json::json!({
        "object":"nymwrap.job", "id":job.info.id, "conversation":job.info.conversation,
        "status":job.info.state, "code":job.info.code, "created_at":job.info.created_at,
        "updated_at":job.info.updated_at, "trust":job.info.trust, "result":result, "not_before":job.info.not_before,
        "poll_url":format!("/v1/nymwrap/jobs/{}",job.info.id)
    }))
    .into_response();
    response.headers_mut().insert(
        "location",
        format!("/v1/nymwrap/jobs/{}", job.info.id)
            .parse()
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_daemon_response"))?,
    );
    if matches!(
        job.info.state,
        RemoteJobState::Queued | RemoteJobState::Sending
    ) {
        response
            .headers_mut()
            .insert("retry-after", "2".parse().unwrap());
    }
    Ok(response)
}
async fn load_job<B: Backend + 'static>(
    State(engine): State<Arc<B>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    job_id(&id)?;
    job_response(engine.load_job(id).await.map_err(core_error)?)
}
async fn cancel_job<B: Backend + 'static>(
    State(engine): State<Arc<B>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    job_id(&id)?;
    engine.cancel_job(id).await.map_err(core_error)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn embeddings<B: Backend + 'static>(
    State(engine): State<Arc<B>>,
    payload: Result<Json<EmbedRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Json(request) = payload.map_err(|_| error(StatusCode::BAD_REQUEST, "invalid_request"))?;
    if request.model != "nw/local/nomic-embed-text"
        || request.encoding_format.is_some_and(|s| s != "float")
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "unsupported_model_or_parameters",
        ));
    }
    let texts = match request.input {
        EmbedInput::One(s) => vec![s],
        EmbedInput::Many(s) => s,
    };
    if texts.is_empty()
        || texts.len() > 64
        || texts.iter().map(String::len).sum::<usize>() > MAX_TEXT_BYTES
    {
        return Err(error(StatusCode::BAD_REQUEST, "input_too_large"));
    }
    let vectors = engine.embed(texts).await.map_err(core_error)?;
    let data: Vec<_> = vectors
        .into_iter()
        .enumerate()
        .map(|(i, v)| serde_json::json!({"object":"embedding","index":i,"embedding":v}))
        .collect();
    Ok(Json(
        serde_json::json!({"object":"list","model":"nw/local/nomic-embed-text","data":data}),
    ))
}
pub fn router<B: Backend + 'static>(engine: Arc<B>) -> Router {
    Router::new()
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat::<B>))
        .route("/v1/nymwrap/chat/jobs", post(submit_job::<B>))
        .route(
            "/v1/nymwrap/jobs/{id}",
            get(load_job::<B>).delete(cancel_job::<B>),
        )
        .route("/v1/embeddings", post(embeddings::<B>))
        .layer(DefaultBodyLimit::max(nw_proto::MAX_FRAME_BYTES))
        .layer(middleware::from_fn(guard))
        .with_state(engine)
}
pub fn bind_private(path: &std::path::Path) -> std::io::Result<nw_ipc::Listener> {
    let endpoint =
        nw_ipc::Endpoint::new(path.to_string_lossy().into_owned(), nw_proto::Lane::Shadow)
            .map_err(|_| std::io::Error::other("invalid_private_endpoint"))?;
    nw_ipc::Listener::bind(endpoint)
        .map_err(|_| std::io::Error::other("private_endpoint_bind_failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    struct Model;
    impl LocalModel for Model {
        async fn complete(
            &self,
            _: &[Message],
        ) -> Result<secrecy::SecretString, nw_llm::ModelError> {
            Ok(secrecy::SecretString::from("synthetic answer"))
        }
        async fn canonicalize(
            &self,
            text: &str,
        ) -> Result<secrecy::SecretString, nw_llm::ModelError> {
            Ok(secrecy::SecretString::from(text.to_owned()))
        }
        async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f64>>, nw_llm::ModelError> {
            Ok(vec![vec![1.0, 0.0]; texts.len()])
        }
    }
    fn app() -> Router {
        router(Arc::new(Engine::new(
            Model,
            nw_shield::Shield::new(vec![]).unwrap(),
            nw_proto::Profile::Standard,
        )))
    }
    #[tokio::test]
    async fn rejects_web_origins_wrong_lane_and_rebinding() {
        for (name, value) in [
            ("origin", "https://evil.test"),
            ("x-nymwrap-lane", "cover"),
            ("host", "evil.test"),
        ] {
            let request = Request::builder()
                .uri("/v1/models")
                .header("host", "localhost")
                .header(name, value)
                .body(Body::empty())
                .unwrap();
            assert!(matches!(
                app().oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST
            ));
        }
    }
    #[tokio::test]
    async fn openai_shapes_and_unknown_fields() {
        for (body, status) in [
            (
                r#"{"model":"nw/local/default","model":"nw/local/default","messages":[{"role":"user","content":"pottery"}]}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                r#"{"model":"nw/local/default","messages":[{"role":"user","content":"first","content":"last"}]}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                r#"{"model":"nw/local/default","messages":[{"role":"user","content":"pottery"}]}"#,
                StatusCode::OK,
            ),
            (
                r#"{"model":"nw/remote/x","messages":[{"role":"user","content":"pottery"}]}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                r#"{"model":"nw/local/default","messages":[],"tools":[]}"#,
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("host", "localhost")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            assert_eq!(app().oneshot(request).await.unwrap().status(), status);
        }
    }
    #[tokio::test]
    async fn defer_header_is_explicit_bounded_unique_and_async_only() {
        for (path, hours) in [
            ("/v1/chat/completions", "2"),
            ("/v1/models", "1"),
            ("/v1/nymwrap/chat/jobs", "169"),
            ("/v1/nymwrap/chat/jobs", "-1"),
            ("/v1/nymwrap/chat/jobs", "2.5"),
            ("/v1/nymwrap/chat/jobs", ""),
            ("/v1/nymwrap/chat/jobs", "CANARY_DEFER_73281"),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("host", "localhost")
                .header("x-nymwrap-defer", hours)
                .body(Body::empty())
                .unwrap();
            let reply = app().oneshot(request).await.unwrap();
            assert_eq!(reply.status(), StatusCode::BAD_REQUEST);
            let bytes = axum::body::to_bytes(reply.into_body(), 4096).await.unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("CANARY_DEFER"));
        }
        let request = Request::builder()
            .method("POST")
            .uri("/v1/nymwrap/chat/jobs")
            .header("host", "localhost")
            .header("x-nymwrap-defer", "1")
            .header("x-nymwrap-defer", "2")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn idempotency_headers_are_bounded_unique_and_endpoint_specific() {
        for (path, key) in [
            ("/v1/nymwrap/chat/jobs", "short".to_owned()),
            ("/v1/nymwrap/chat/jobs", "x".repeat(129)),
            (
                "/v1/nymwrap/chat/jobs",
                "synthetic key with spaces".to_owned(),
            ),
            ("/v1/chat/completions", "synthetic-key-001".to_owned()),
            ("/v1/embeddings", "synthetic-key-001".to_owned()),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("host", "localhost")
                .header("idempotency-key", key)
                .body(Body::empty())
                .unwrap();
            let response = app().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let request = Request::builder()
            .method("POST")
            .uri("/v1/nymwrap/chat/jobs")
            .header("host", "localhost")
            .header("idempotency-key", "synthetic-key-001")
            .header("idempotency-key", "synthetic-key-002")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        for (code, status) in [
            ("idempotency_conflict", 409),
            ("idempotency_uncertain", 409),
            ("idempotency_expired", 410),
            ("idempotency_capacity", 429),
        ] {
            assert_eq!(core_error(code.into()).0.as_u16(), status);
        }
    }
    #[tokio::test]
    async fn private_socket_openai_request() {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let path = directory.path().join("private/api.sock");
        #[cfg(windows)]
        let path = std::path::PathBuf::from(format!(
            "nymwrap-api-test-{}-{}",
            std::process::id(),
            directory.path().file_name().unwrap().to_str().unwrap()
        ));
        let listener = bind_private(&path).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app()).await.unwrap();
        });
        let stream =
            nw_ipc::Endpoint::new(path.to_string_lossy().into_owned(), nw_proto::Lane::Shadow)
                .unwrap()
                .connect()
                .await
                .unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .unwrap();
        let connection = tokio::spawn(connection);
        let request = hyper::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(
                br#"{"model":"nw/local/default","messages":[{"role":"user","content":"pottery"}]}"#,
            )))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["choices"][0]["message"]["content"],
            "synthetic answer"
        );
        connection.abort();
        server.abort();
    }
}
