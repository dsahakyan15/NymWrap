//! Synthetic canaries at the actual MicroVM -> private HTTP socket boundary.
#[test]
fn microvm_unavailable_platform_does_not_start_a_host_program() {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    assert_eq!(
        nw_sandbox::microvm::run(
            std::path::Path::new("."),
            std::path::Path::new("/bin/sh"),
            &[],
            std::path::Path::new("api.sock"),
            std::path::Path::new(".")
        ),
        Err(nw_sandbox::microvm::MicroVmError::Unsupported)
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::{
        path::Path,
        process::{Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };
    struct Model(Arc<AtomicBool>);
    impl nw_llm::LocalModel for Model {
        async fn complete(
            &self,
            messages: &[nw_llm::Message],
        ) -> Result<secrecy::SecretString, nw_llm::ModelError> {
            assert!(
                messages
                    .iter()
                    .any(|m| m.content.contains("synthetic-microvm-canary"))
            );
            assert!(
                messages
                    .iter()
                    .all(|m| !m.content.contains("SYNTHETIC-HOST-SECRET"))
            );
            self.0.store(true, Ordering::SeqCst);
            Ok("synthetic-nymwrap-answer".into())
        }
        async fn canonicalize(
            &self,
            text: &str,
        ) -> Result<secrecy::SecretString, nw_llm::ModelError> {
            Ok(text.to_owned().into())
        }
        async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f64>>, nw_llm::ModelError> {
            Ok(vec![vec![1.0, 0.0]; texts.len()])
        }
    }
    #[test]
    fn microvm_worker() {
        if std::env::var("NW_MICROVM_WORKER").as_deref() != Ok("1") {
            return;
        }
        let work = std::env::var_os("NW_MICROVM_WORK").unwrap();
        let api = std::env::var_os("NW_MICROVM_API").unwrap();
        assert_eq!(
            nw_sandbox::microvm::run(
                Path::new(&work),
                Path::new("/init"),
                &["--probe".into()],
                Path::new(&api),
                &Path::new(&work).join("missing-tools")
            ),
            Err(nw_sandbox::microvm::MicroVmError::Tools)
        );
        let result = nw_sandbox::microvm::run(
            Path::new(&work),
            Path::new("/init"),
            &["--probe".into()],
            Path::new(&api),
            Path::new(&std::env::var_os("NW_MICROVM_TOOLS").unwrap()),
        );
        assert_eq!(result, Ok(0), "microvm_probe_failed");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires actual Linux /dev/kvm, no swap and pinned Firecracker tools; mandatory in linux-microvm CI"]
    async fn actual_microvm_normalization_and_socket_only_egress() {
        let directory = tempfile::tempdir().unwrap();
        let work = directory.path().join("project");
        std::fs::create_dir(&work).unwrap();
        std::fs::write(work.join("fixture"), b"synthetic-project-only").unwrap();
        let outside = directory.path().join("private-host-canary");
        std::fs::write(&outside, b"SYNTHETIC-HOST-SECRET").unwrap();
        let api = directory.path().join("private/api.sock");
        let listener = nw_api::bind_private(&api).unwrap();
        let reached = Arc::new(AtomicBool::new(false));
        let engine = nw_core::Engine::new(
            Model(reached.clone()),
            nw_shield::Shield::new(vec![]).unwrap(),
            nw_proto::Profile::Standard,
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, nw_api::router(Arc::new(engine)))
                .await
                .unwrap();
        });
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "linux::microvm_worker", "--nocapture"])
            .env("NW_MICROVM_WORKER", "1")
            .env("NW_MICROVM_WORK", &work)
            .env("NW_MICROVM_API", &api)
            .env("NW_MICROVM_HOST_CANARY", "SYNTHETIC-HOST-SECRET")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(50);
        while Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if child.try_wait().unwrap().is_none() {
            let _ = child.kill();
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            reached.load(Ordering::SeqCst) && output.status.success(),
            "microvm acceptance failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !work.join("ephemeral-result").exists(),
            "guest wrote into the host project"
        );
        server.abort();
    }
}
