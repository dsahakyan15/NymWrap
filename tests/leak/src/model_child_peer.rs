//! The retained child handle authenticates a hardened worker, even when /proc
//! image lookup is deliberately unavailable. Same-image strangers get no body.
use super::*;
use nw_llm::LocalModel;
use std::{process::Stdio, time::Duration};

struct Count(usize);
impl Inference for Count {
    fn embedding_recipe(&self) -> Option<&str> {
        Some("synthetic_peer_test_v1")
    }
    fn embedding_sha256(&self) -> Option<&str> {
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    }
    fn complete(&mut self, _: &[Message], _: u32) -> Result<String, Error> {
        Err(Error::Inference)
    }
    fn embed(&mut self, texts: &[String]) -> Result<Vec<Vec<f64>>, Error> {
        self.0 += 1;
        Ok(texts.iter().map(|_| vec![self.0 as f64, 1.0]).collect())
    }
}
#[tokio::test]
#[ignore = "helper subprocess invoked by spawned_peer_receipt; not a standalone acceptance check"]
async fn hardened_model_child_helper() {
    let address =
        std::env::var("NYMWRAP_TEST_CHILD_ENDPOINT").expect("helper requires a synthetic endpoint");
    nw_platform::harden_process().unwrap();
    std::thread::spawn(|| {
        use std::io::Read;
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte);
        std::process::exit(0);
    });
    let listener =
        nw_ipc::Listener::bind(nw_ipc::Endpoint::new(address, nw_proto::Lane::Shadow).unwrap())
            .unwrap();
    axum::serve(listener, router(Count(0))).await.unwrap();
}
struct Worker {
    child: Arc<std::sync::Mutex<tokio::process::Child>>,
    endpoint: String,
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            drop(child.stdin.take());
            let _ = child.start_kill();
        }
    }
}
impl Worker {
    async fn start(endpoint: String) -> Self {
        let name = concat!(module_path!(), "::hardened_model_child_helper");
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", name.split_once("::").unwrap().1, "--ignored"])
            .env("NYMWRAP_TEST_CHILD_ENDPOINT", &endpoint)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let child = Arc::new(std::sync::Mutex::new(command.spawn().unwrap()));
        let result = Self { child, endpoint };
        let address =
            nw_ipc::Endpoint::new(result.endpoint.clone(), nw_proto::Lane::Shadow).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                assert!(
                    result.child.lock().unwrap().try_wait().unwrap().is_none(),
                    "helper_exited"
                );
                if address.connect().await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        result
    }
    fn model(&self) -> nw_llm::UnixModel {
        nw_llm::UnixModel::new(
            self.endpoint.clone().into(),
            "default".into(),
            "nomic-embed-text".into(),
        )
        .unwrap()
        .expect_spawned_peer(&self.child)
    }
}
#[tokio::test]
async fn spawned_peer_receipt_rejects_same_image_strangers_and_expired_owners_before_dossier() {
    let fixture = tempfile::tempdir().unwrap();
    let endpoint = |index| {
        if cfg!(windows) {
            format!("nymwrap-model-child-{}-{index}", std::process::id())
        } else {
            fixture
                .path()
                .join(format!("private/{index}.sock"))
                .to_string_lossy()
                .into_owned()
        }
    };
    let a = Worker::start(endpoint(0)).await;
    let b = Worker::start(endpoint(1)).await;
    #[cfg(target_os = "linux")]
    {
        assert_ne!(
            nw_platform::current_user_id().unwrap(),
            "0",
            "run peer-hardening check as an unprivileged user"
        );
        assert!(nw_platform::process_image(a.child.lock().unwrap().id().unwrap()).is_err());
    }
    let canary = ["SYNTHETIC_PRIVATE_CHILD_DOSSIER_62491".into()];
    let foreign = nw_llm::UnixModel::new(
        b.endpoint.clone().into(),
        "default".into(),
        "nomic-embed-text".into(),
    )
    .unwrap()
    .expect_spawned_peer(&a.child);
    assert!(foreign.embed_identified(&canary).await.is_err());
    // A normal answer from the other process proves it was available, and its
    // count proves the rejected request never reached its inference backend.
    assert_eq!(b.model().embed(&canary).await.unwrap()[0][0], 1.0);
    let owner_model = a.model();
    assert_eq!(owner_model.embed(&canary).await.unwrap()[0][0], 1.0);
    drop(a);
    assert!(owner_model.embed_identified(&canary).await.is_err());
    assert!(foreign.embed_identified(&canary).await.is_err());
    assert_eq!(b.model().embed(&canary).await.unwrap()[0][0], 2.0);
}
