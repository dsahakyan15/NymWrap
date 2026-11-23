use super::*;
use nw_llm::LocalModel;
struct Model(Option<String>);
impl Inference for Model {
    fn embedding_sha256(&self) -> Option<&str> {
        self.0.as_deref()
    }
    fn complete(&mut self, _: &[Message], _: u32) -> Result<String, Error> {
        Err(Error::Inference)
    }
    fn embed(&mut self, texts: &[String]) -> Result<Vec<Vec<f64>>, Error> {
        Ok(texts
            .iter()
            .map(|_| {
                let mut v = vec![0.0; 768];
                v[0] = 1.0;
                v
            })
            .collect())
    }
}
#[tokio::test]
async fn embedding_identity_comes_from_the_backend_and_legacy_responses_cannot_authorize_linkcheck()
{
    for (index, hash) in [None, Some("a".repeat(64)), Some("malformed".into())]
        .into_iter()
        .enumerate()
    {
        let fixture = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let address = format!("nymwrap-embedding-identity-{}-{index}", std::process::id());
        #[cfg(unix)]
        let address = fixture
            .path()
            .join(format!("private/{index}.sock"))
            .to_string_lossy()
            .into_owned();
        let _keep = fixture;
        let endpoint = nw_ipc::Endpoint::new(address.clone(), nw_proto::Lane::Shadow).unwrap();
        let listener = nw_ipc::Listener::bind(endpoint).unwrap();
        let mut servers = tokio::task::JoinSet::new();
        servers.spawn(axum::serve(listener, router(Model(hash.clone()))).into_future());
        let model =
            nw_llm::UnixModel::new(address.into(), "default".into(), "nomic-embed-text".into())
                .unwrap();
        let texts = ["SYNTHETIC_EMBEDDING_CANARY_73815".into()];
        let result = model.embed_identified(&texts).await;
        if index == 1 {
            let identified = result.unwrap();
            assert_eq!(Some(&identified.model_sha256), hash.as_ref());
            assert_eq!(identified.vectors.len(), 1);
        } else {
            assert!(result.is_err());
        }
        if index == 0 {
            assert_eq!(model.embed(&texts).await.unwrap().len(), 1);
        }
        servers.shutdown().await;
    }
}

#[tokio::test]
async fn a_same_user_endpoint_with_the_wrong_process_image_receives_no_dossier_body() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Observed(Arc<AtomicUsize>);
    impl Inference for Observed {
        fn embedding_sha256(&self) -> Option<&str> {
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        }
        fn complete(&mut self, _: &[Message], _: u32) -> Result<String, Error> {
            Err(Error::Inference)
        }
        fn embed(&mut self, texts: &[String]) -> Result<Vec<Vec<f64>>, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Model(None).embed(texts)
        }
    }
    let fixture = tempfile::tempdir().unwrap();
    let wrong = fixture.path().join("foreign-image");
    std::fs::write(&wrong, b"SYNTHETIC_UNEXECUTED_IMAGE").unwrap();
    #[cfg(windows)]
    let address = format!("nymwrap-model-peer-{}", std::process::id());
    #[cfg(unix)]
    let address = fixture
        .path()
        .join("private/peer.sock")
        .to_string_lossy()
        .into_owned();
    let listener = nw_ipc::Listener::bind(
        nw_ipc::Endpoint::new(address.clone(), nw_proto::Lane::Shadow).unwrap(),
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut servers = tokio::task::JoinSet::new();
    servers.spawn(axum::serve(listener, router(Observed(calls.clone()))).into_future());
    let model = nw_llm::UnixModel::new(address.into(), "default".into(), "nomic-embed-text".into())
        .unwrap();
    let texts = ["SYNTHETIC_PRIVATE_DOSSIER_CANARY_73984".into()];
    assert!(
        model
            .clone()
            .expect_peer_image(wrong)
            .unwrap()
            .embed_identified(&texts)
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        model
            .expect_peer_image(std::env::current_exe().unwrap())
            .unwrap()
            .embed_identified(&texts)
            .await
            .is_ok()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    servers.shutdown().await;
}
