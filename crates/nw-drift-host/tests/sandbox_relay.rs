#![cfg(any(windows, target_os = "linux"))]
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Cover;
impl nw_bridge::Handler for Cover {
    async fn handle(&self, command: nw_bridge::Command) -> nw_bridge::Result {
        assert!(matches!(command, nw_bridge::Command::Status {}));
        nw_bridge::Result::Status {
            paused: false,
            mode: nw_bridge::Mode::Assisted,
            ai_web_automation: false,
        }
    }
}

#[test]
fn relay_fixture() {
    if std::env::var("NYMWRAP_RELAY_FIXTURE").as_deref() != Ok("1") {
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(15), async {
                let endpoint = nw_bridge::endpoint().unwrap();
                let listener = nw_ipc::Listener::bind(endpoint).unwrap();
                let server = tokio::spawn(nw_bridge::serve(listener, Cover));
                let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_nw-drift-host"))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()
                    .unwrap();
                let request = serde_json::to_vec(&nw_bridge::Request {
                    version: nw_proto::SCHEMA_VERSION,
                    id: 47,
                    command: nw_bridge::Command::Status {},
                })
                .unwrap();
                let mut input = child.stdin.take().unwrap();
                input.write_u32_le(request.len() as u32).await.unwrap();
                input.write_all(&request).await.unwrap();
                input.flush().await.unwrap();
                drop(input);
                let mut output = vec![];
                child
                    .stdout
                    .take()
                    .unwrap()
                    .take(65537)
                    .read_to_end(&mut output)
                    .await
                    .unwrap();
                assert!(child.wait().await.unwrap().success());
                assert!((5..=65536).contains(&output.len()));
                assert_eq!(
                    u32::from_le_bytes(output[..4].try_into().unwrap()) as usize,
                    output.len() - 4
                );
                let reply: nw_bridge::Reply = serde_json::from_slice(&output[4..]).unwrap();
                assert_eq!(reply.version, nw_proto::SCHEMA_VERSION);
                assert_eq!(reply.id, 47);
                assert!(matches!(
                    reply.result,
                    nw_bridge::Result::Status { paused: false, .. }
                ));
                server.abort();
                let _ = server.await;
            })
            .await
            .unwrap();
        });
}

#[tokio::test]
#[ignore = "launches the actual native host and sandboxed relay with synthetic cover IPC"]
async fn actual_native_host_reaches_the_launcher_selected_cover_endpoint() {
    // A separate parent fixture avoids global environment mutation and never
    // opens the user's installed workspace or live cover endpoint.
    let directory = tempfile::tempdir().unwrap();
    let runtime = directory.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    let child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "relay_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("NYMWRAP_RELAY_FIXTURE", "1")
        .env("LOCALAPPDATA", directory.path())
        .env("XDG_DATA_HOME", directory.path())
        .env("XDG_RUNTIME_DIR", runtime)
        .env("HOME", directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let output = tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
