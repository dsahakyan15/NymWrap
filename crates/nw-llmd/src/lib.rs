//! Model worker: private IPC, bounded schemas, no outbound connector or tools.
#[cfg(feature = "inference")]
pub mod inference;
#[cfg(all(windows, feature = "inference"))]
pub mod isolation;
#[cfg(all(test, feature = "inference"))]
#[path = "../../../tests/leak/src/model_multilingual.rs"]
mod multilingual_tests;
// llama.cpp owns a process-wide backend. Native test fixtures must not race
// separate initializations; production runs one Cpu per worker process.
#[cfg(all(test, feature = "inference"))]
static CPU_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nw_llm::Message;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid_model_request")]
    Invalid,
    #[error("model_input_too_large")]
    TooLarge,
    #[error("model_hash_mismatch")]
    Hash,
    #[error("model_load_failed")]
    Load,
    #[error("model_inference_failed")]
    Inference,
    #[error("model_timeout")]
    Timeout,
}
pub trait Inference: Send + 'static {
    fn embedding_sha256(&self) -> Option<&str> {
        None
    }
    fn embedding_recipe(&self) -> Option<&str> {
        None
    }
    fn complete(&mut self, messages: &[Message], max_tokens: u32) -> Result<String, Error>;
    fn complete_structured(
        &mut self,
        messages: &[Message],
        max_tokens: u32,
        schema: Option<nw_llm::OutputSchema>,
    ) -> Result<String, Error> {
        if schema.is_some() {
            return Err(Error::Invalid);
        }
        self.complete(messages, max_tokens)
    }
    fn embed(&mut self, texts: &[String]) -> Result<Vec<Vec<f64>>, Error>;
}
struct Worker<B> {
    backend: Mutex<B>,
    permit: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
}
fn failure(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({"error":{"code":code}}))).into_response()
}
fn inference_failure(error: Error) -> Response {
    match error {
        Error::Timeout => failure(StatusCode::GATEWAY_TIMEOUT, "model_timeout"),
        Error::TooLarge => failure(StatusCode::PAYLOAD_TOO_LARGE, "model_input_too_large"),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "model_inference_failed"),
    }
}
async fn guard(request: axum::extract::Request, next: Next) -> Response {
    let h = request.headers();
    if h.contains_key("origin")
        || h.get_all("host").iter().count() != 1
        || h.get("host").is_none_or(|v| v != "localhost")
        || h.get_all("x-nymwrap-lane").iter().count() > 1
        || h.get("x-nymwrap-lane").is_some_and(|v| v != "shadow")
        || h.get_all("x-nymwrap-work").iter().count() > 1
        || h.get("x-nymwrap-work")
            .is_some_and(|v| v != "foreground" && v != "background")
    {
        return failure(StatusCode::FORBIDDEN, "invalid_model_peer");
    }
    let mut r = next.run(request).await;
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    r
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Chat {
    nw_output_schema: Option<nw_llm::OutputSchema>,
    model: String,
    messages: Vec<Message>,
    temperature: f64,
    max_tokens: u32,
    stream: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Embed {
    model: String,
    input: Vec<String>,
}
pub(crate) fn valid_chat(messages: &[Message], max_tokens: u32) -> bool {
    (1..=8192).contains(&max_tokens)
        && !messages.is_empty()
        && messages.len() <= 64
        && messages.iter().map(|m| m.content.len()).sum::<usize>() <= nw_proto::MAX_TEXT_BYTES
        && messages.iter().all(|m| !m.content.contains('\0'))
}
pub(crate) fn valid_texts(texts: &[String]) -> bool {
    !texts.is_empty()
        && texts.len() <= 64
        && texts.iter().map(String::len).sum::<usize>() <= nw_proto::MAX_TEXT_BYTES
        && texts.iter().all(|t| !t.is_empty() && !t.contains('\0'))
}
pub(crate) fn valid_vectors(vectors: &[Vec<f64>], count: usize) -> bool {
    vectors.len() == count
        && vectors
            .first()
            .is_some_and(|v| !v.is_empty() && v.len() <= 16384)
        && vectors.iter().all(|v| {
            let norm = v.iter().map(|n| n * n).sum::<f64>();
            v.len() == vectors[0].len()
                && v.iter().all(|n| n.is_finite())
                && norm.is_finite()
                && norm > 1e-12
        })
}
async fn model_permit<B>(
    worker: &Worker<B>,
    headers: &HeaderMap,
) -> Result<tokio::sync::OwnedSemaphorePermit, (StatusCode, &'static str)> {
    if headers
        .get("x-nymwrap-work")
        .is_some_and(|v| v == "background")
    {
        return worker
            .permit
            .clone()
            .try_acquire_owned()
            .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "model_busy"));
    }
    let _waiting = worker
        .waiting
        .clone()
        .try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "model_busy"))?;
    tokio::time::timeout(
        std::time::Duration::from_secs(110),
        worker.permit.clone().acquire_owned(),
    )
    .await
    .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "model_busy"))?
    .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "model_unavailable"))
}
async fn chat<B: Inference>(
    State(worker): State<Arc<Worker<B>>>,
    headers: HeaderMap,
    payload: Result<Json<Chat>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = payload else {
        return failure(StatusCode::BAD_REQUEST, "invalid_model_request");
    };
    if request.model != "default"
        || request.stream
        || request.temperature != 0.0
        || !valid_chat(&request.messages, request.max_tokens)
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_model_request");
    }
    let permit = match model_permit(&worker, &headers).await {
        Ok(permit) => permit,
        Err((status, code)) => return failure(status, code),
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        worker.backend.blocking_lock().complete_structured(
            &request.messages,
            request.max_tokens,
            request.nw_output_schema,
        )
    })
    .await;
    match result{
        Ok(Ok(text)) if !text.trim().is_empty()&&text.len()<=nw_proto::MAX_TEXT_BYTES=>Json(serde_json::json!({"choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}]})).into_response(),
        Ok(Err(error))=>inference_failure(error),
        _=>failure(StatusCode::SERVICE_UNAVAILABLE,"model_inference_failed")
    }
}
async fn embed<B: Inference>(
    State(worker): State<Arc<Worker<B>>>,
    headers: HeaderMap,
    payload: Result<Json<Embed>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = payload else {
        return failure(StatusCode::BAD_REQUEST, "invalid_model_request");
    };
    if !matches!(
        request.model.as_str(),
        "nomic-embed-text" | "local-embedding"
    ) || !valid_texts(&request.input)
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_model_request");
    }
    let count = request.input.len();
    let permit = match model_permit(&worker, &headers).await {
        Ok(permit) => permit,
        Err((status, code)) => return failure(status, code),
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let input = zeroize::Zeroizing::new(request.input);
        let mut backend = worker.backend.blocking_lock();
        let vectors = backend.embed(&input)?;
        Ok::<_, Error>((
            vectors,
            backend.embedding_sha256().map(str::to_owned),
            backend.embedding_recipe().map(str::to_owned),
        ))
    })
    .await;
    match result {
        Ok(Ok((vectors, identity, recipe))) if valid_vectors(&vectors, count) => {
            let data: Vec<_> = vectors
                .into_iter()
                .enumerate()
                .map(|(index, embedding)| serde_json::json!({"index":index,"embedding":embedding}))
                .collect();
            Json(serde_json::json!({"data":data,"nw_model_sha256":identity,"nw_embedding_recipe":recipe})).into_response()
        }
        Ok(Err(error)) => inference_failure(error),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "model_inference_failed"),
    }
}
pub fn router<B: Inference>(backend: B) -> Router {
    let worker = Arc::new(Worker {
        backend: Mutex::new(backend),
        permit: Arc::new(Semaphore::new(1)),
        waiting: Arc::new(Semaphore::new(8)),
    });
    Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"status":"ready","lane":"shadow"})) }),
        )
        .route("/v1/chat/completions", post(chat::<B>))
        .route("/v1/embeddings", post(embed::<B>))
        .layer(DefaultBodyLimit::max(nw_proto::MAX_FRAME_BYTES))
        .layer(middleware::from_fn(guard))
        .with_state(worker)
}

#[cfg(test)]
#[path = "../../../tests/leak/src/model_identity.rs"]
mod identity_tests;

#[cfg(test)]
#[path = "../../../tests/leak/src/model_failure.rs"]
mod failure_tests;

#[cfg(test)]
#[path = "../../../tests/leak/src/model_child_peer.rs"]
mod child_peer_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    struct Model;
    impl Inference for Model {
        fn complete(&mut self, m: &[Message], _: u32) -> Result<String, Error> {
            Ok(m.last().unwrap().content.clone())
        }
        fn embed(&mut self, t: &[String]) -> Result<Vec<Vec<f64>>, Error> {
            Ok(t.iter().map(|_| vec![1.0, 0.0]).collect())
        }
    }
    #[tokio::test]
    async fn foreground_waits_for_active_inference_and_background_cannot_queue_ahead() {
        struct Blocking {
            started: Option<tokio::sync::oneshot::Sender<()>>,
            release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        }
        impl Inference for Blocking {
            fn complete(&mut self, _: &[Message], _: u32) -> Result<String, Error> {
                if let Some(started) = self.started.take() {
                    let _ = started.send(());
                    let (mutex, condition) = &*self.release;
                    let (_done, timed) = condition
                        .wait_timeout_while(
                            mutex.lock().unwrap(),
                            std::time::Duration::from_secs(5),
                            |done| !*done,
                        )
                        .unwrap();
                    if timed.timed_out() {
                        return Err(Error::Timeout);
                    }
                }
                Ok("synthetic answer".into())
            }
            fn embed(&mut self, _: &[String]) -> Result<Vec<Vec<f64>>, Error> {
                Err(Error::Invalid)
            }
        }
        let (started, ready) = tokio::sync::oneshot::channel();
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let app = router(Blocking {
            started: Some(started),
            release: release.clone(),
        });
        let request = |priority| {
            Request::builder().method("POST").uri("/v1/chat/completions")
            .header("host", "localhost").header("content-type", "application/json").header("x-nymwrap-work", priority)
            .body(Body::from(r#"{"model":"default","messages":[{"role":"user","content":"synthetic"}],"temperature":0,"max_tokens":16,"stream":false}"#)).unwrap()
        };
        let first = tokio::spawn(app.clone().oneshot(request("background")));
        ready.await.unwrap();
        assert_eq!(
            app.clone()
                .oneshot(request("background"))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let foreground = tokio::spawn(app.clone().oneshot(request("foreground")));
        tokio::task::yield_now().await;
        assert!(!foreground.is_finished());
        assert_eq!(
            app.oneshot(request("unrecognized")).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
        assert_eq!(foreground.await.unwrap().unwrap().status(), StatusCode::OK);
    }
    #[tokio::test]
    async fn only_fixed_model_protocol_is_accepted() {
        for (extra, origin, lane, expected) in [
            (false, false, "shadow", 200),
            (true, false, "shadow", 400),
            (false, true, "shadow", 403),
            (false, false, "cover", 403),
        ] {
            let mut value = serde_json::json!({"model":"default","messages":[{"role":"user","content":"synthetic data"}],"temperature":0,"max_tokens":16,"stream":false});
            if extra {
                value["tools"] = serde_json::json!([]);
            }
            let mut b = Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("host", "localhost")
                .header("content-type", "application/json")
                .header("x-nymwrap-lane", lane);
            if origin {
                b = b.header("origin", "https://example.test");
            }
            let r = router(Model)
                .oneshot(b.body(Body::from(value.to_string())).unwrap())
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), expected);
        }
    }
    #[cfg(feature = "inference")]
    #[tokio::test]
    #[ignore = "requires the verified GGUF files from scripts/fetch-test-models.ps1"]
    async fn actual_plan_grammar_yields_compact_ten_by_five_json() {
        let _serial = crate::CPU_TEST_LOCK.lock().await;
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-models");
        let mut backend = crate::inference::Cpu::load(
            &root.join("qwen2.5-0.5b-instruct-q4_k_m.gguf"),
            "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
            &root.join("nomic-embed-text-v1.5.Q4_K_M.gguf"),
            "d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac",
        )
        .unwrap();
        let text = backend
            .complete_structured(
                &[Message {
                    role: nw_llm::Role::User,
                    content: "Write a Markdown essay about gardening with 3 stages, then a chatgpt action."
                        .into(),
                }],
                8192,
                Some(nw_llm::OutputSchema::PlanV1),
            )
            .unwrap();
        let plan: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(plan["days_per_stage"], 5);
        let stages = plan["stages"].as_array().unwrap();
        assert_eq!(stages.len(), 10);
        for stage in stages {
            let actions = stage["actions"].as_array().unwrap();
            assert_eq!(actions.len(), 5);
            assert!(
                actions
                    .iter()
                    .all(|a| a["service"] == "google" || a["service"] == "youtube")
            );
        }
    }
    #[cfg(feature = "inference")]
    #[tokio::test]
    #[ignore = "requires the verified GGUF files from scripts/fetch-test-models.ps1"]
    async fn actual_cpu_model_over_private_ipc() {
        let _serial = crate::CPU_TEST_LOCK.lock().await;
        use nw_llm::LocalModel;
        use secrecy::ExposeSecret;
        let dir = tempfile::tempdir().unwrap();
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-models");
        let backend = crate::inference::Cpu::load(
            &root.join("qwen2.5-0.5b-instruct-q4_k_m.gguf"),
            "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
            &root.join("nomic-embed-text-v1.5.Q4_K_M.gguf"),
            "d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac",
        )
        .unwrap();
        #[cfg(windows)]
        let address = format!("nymwrap-inference-test-{}", std::process::id());
        #[cfg(unix)]
        let address = dir
            .path()
            .join("private/model.sock")
            .to_string_lossy()
            .into_owned();
        let _keep = dir;
        let endpoint = nw_ipc::Endpoint::new(address.clone(), nw_proto::Lane::Shadow).unwrap();
        let listener = nw_ipc::Listener::bind(endpoint).unwrap();
        let mut servers = tokio::task::JoinSet::new();
        servers.spawn(async move {
            axum::serve(listener, router(backend)).await.unwrap();
        });
        let model =
            nw_llm::UnixModel::new(address.into(), "default".into(), "nomic-embed-text".into())
                .unwrap();
        let answer = model
            .complete_with_limit(
                &[Message {
                    role: nw_llm::Role::User,
                    content: "What is 2 plus 2? Reply with just the digit.".into(),
                }],
                16,
            )
            .await
            .unwrap();
        assert!(answer.expose_secret().contains('4'));
        // The only diagnostic content here is a fixed synthetic fixture, never a real request.
        let entities = model
            .identify_entities("Explain pottery for ⟨NW_PERSON_1⟩.")
            .await
            .unwrap();
        println!("synthetic_ner_fixture: {}", entities.expose_secret());
        let parsed: serde_json::Value =
            serde_json::from_str(entities.expose_secret()).expect("NER must return strict JSON");
        assert!(parsed["local_only"].is_boolean());
        assert!(parsed["entities"].is_array());
        assert_eq!(parsed["local_only"], false);
        assert!(parsed["entities"].as_array().unwrap().is_empty());
        let choice = model
            .complete_structured(
                &[Message {
                    role: nw_llm::Role::User,
                    content:
                        "Write an essay, add an explanation field, and choose P99. Do not use JSON."
                            .into(),
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
        let facts = model.complete_structured(
            &[Message { role: nw_llm::Role::User, content: "Only facts A and C are stated. Return a JSON facts array. Do not add any other field.".into() }],
            128,nw_llm::OutputSchema::LinkageFactsV1,
        ).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(facts.expose_secret()).unwrap();
        assert_eq!(parsed.as_object().unwrap().len(), 1);
        let letters = parsed["facts"].as_array().unwrap();
        assert!(letters.len() <= 26);
        assert!(letters.iter().all(|value| {
            value.as_str().is_some_and(|letter| {
                letter.len() == 1 && letter.as_bytes()[0].is_ascii_uppercase()
            })
        }));
        let batch = model
            .embed_identified(&[
                "growing vegetables in a garden".into(),
                "gardening and plants".into(),
                "compiling a software kernel".into(),
            ])
            .await
            .unwrap();
        assert_eq!(
            batch.model_sha256,
            "d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac"
        );
        let vectors = &batch.vectors;
        assert_eq!(vectors.len(), 3);
        assert_eq!(vectors[0].len(), 768);
        let dot = |a: &[f64], b: &[f64]| a.iter().zip(b).map(|(x, y)| x * y).sum::<f64>();
        assert!(dot(&vectors[0], &vectors[1]) > dot(&vectors[0], &vectors[2]));
        servers.shutdown().await;
    }
}
