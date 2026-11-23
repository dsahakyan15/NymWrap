#[path = "multilingual_assertions.rs"]
mod assertions;

#[tokio::test]
#[ignore = "requires fetch-test-models.ps1 -IncludeMultilingualEmbedding; native model/private IPC"]
async fn actual_multilingual_embeddings_over_private_ipc() {
    let _serial = crate::CPU_TEST_LOCK.lock().await;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-models");
    let backend = crate::inference::Cpu::load(
        &root.join("qwen2.5-0.5b-instruct-q4_k_m.gguf"),
        "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
        &root.join("Qwen3-Embedding-0.6B-Q8_0.gguf"),
        nw_llm::embedding::QWEN3_SHA256,
    )
    .unwrap();
    let fixture = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let address = format!("nymwrap-multilingual-model-test-{}", std::process::id());
    #[cfg(unix)]
    let address = fixture
        .path()
        .join("private/model.sock")
        .to_string_lossy()
        .into_owned();
    let endpoint = nw_ipc::Endpoint::new(address.clone(), nw_proto::Lane::Shadow).unwrap();
    let listener = nw_ipc::Listener::bind(endpoint).unwrap();
    let mut servers = tokio::task::JoinSet::new();
    servers.spawn(async move {
        axum::serve(listener, crate::router(backend)).await.unwrap();
    });
    let model =
        nw_llm::UnixModel::new(address.into(), "default".into(), "local-embedding".into()).unwrap();
    assertions::verify(&model).await;
    servers.shutdown().await;
    drop(fixture);
}
