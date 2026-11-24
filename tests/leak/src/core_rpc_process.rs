//! Real core/API bootstrap in a disposable instance; no OS keyring or accounts.
use nw_core::service::{Client, Command, Reply};
use nw_ipc::{Endpoint, Packet};
use nw_proto::Lane;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const OWNER_MODE: &str = "NYMWRAP_RPC_TEST_OWNER";
const INTRUDER_MODE: &str = "NYMWRAP_RPC_TEST_INTRUDER";

fn hidden(command: &mut tokio::process::Command) {
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    #[cfg(not(windows))]
    let _ = command;
}
fn self_command(test: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    hidden(&mut command);
    command
}
async fn ready(client: &Client) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match client.request(Command::Status {}).await {
                Ok(Reply::Status { .. }) => return Ok(()),
                Err(code) if code == "ipc_unavailable" => {
                    tokio::time::sleep(Duration::from_millis(40)).await
                }
                _ => return Err("unexpected_core_startup_result".into()),
            }
        }
    })
    .await
    .map_err(|_| "core_startup_timeout")?
}
async fn stopped(endpoint: &Endpoint) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match endpoint.connect().await {
                Err(_) => return,
                Ok(stream) => drop(stream),
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .map_err(|_| "child_endpoint_remained_live".into())
}
async fn api_locked(endpoint: &Endpoint) -> Result<(), String> {
    let mut stream = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match endpoint.connect().await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(40)).await,
            }
        }
    })
    .await
    .map_err(|_| "api_startup_timeout")?;
    let body = r#"{"model":"nw/local/default","messages":[{"role":"user","content":"SYNTHETIC_RPC_INPUT_CANARY_51827"}]}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| "api_write_failed")?;
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        stream.take(8193).read_to_end(&mut response),
    )
    .await
    .map_err(|_| "api_response_timeout")?
    .map_err(|_| "api_read_failed")?;
    let text = std::str::from_utf8(&response).map_err(|_| "invalid_api_response")?;
    if response.len() > 8192
        || !text.starts_with("HTTP/1.1 503")
        || !text.contains("workspace_locked")
        || text.contains("SYNTHETIC_RPC_INPUT_CANARY")
    {
        return Err("unexpected_locked_api_response".into());
    }
    Ok(())
}

#[tokio::test]
async fn rpc_intruder_fixture() {
    let Some(address) = std::env::var_os(INTRUDER_MODE) else {
        return;
    };
    let endpoint = Endpoint::new(address.into_string().unwrap(), Lane::Shadow).unwrap();
    let mut stream = endpoint.connect().await.unwrap();
    let bytes =
        serde_json::to_vec(&Packet::new(Lane::Shadow, 71, Command::LoadSecrets {})).unwrap();
    let _ = nw_ipc::write_frame(&mut stream, &bytes, 4096).await;
    let reply = nw_ipc::read_frame_timeout(&mut stream, 4096, Duration::from_secs(2)).await;
    assert!(
        reply.is_err(),
        "a foreign PID must be rejected before any RPC challenge or command"
    );
    println!("NYMWRAP_RPC_INTRUDER_REJECTED");
}

#[tokio::test]
async fn rpc_owner_fixture() {
    let Some(binary) = std::env::var_os(OWNER_MODE) else {
        return;
    };
    let paths = nw_core::config::Paths::discover().unwrap();
    assert_ne!(
        paths.core_shadow,
        std::env::var("NYMWRAP_RPC_FORBIDDEN_ENDPOINT").unwrap(),
        "a disposable instance must never use the live user's pipe namespace"
    );
    let core = Endpoint::new(paths.core_shadow, Lane::Shadow).unwrap();
    let api = Endpoint::new(paths.api, Lane::Shadow).unwrap();
    let client = Client::spawn_daemon(Path::new(&binary)).await.unwrap();
    let outcome: Result<(), String> = async {
        ready(&client).await?;
        api_locked(&api).await?;
        // Another instance of the very same trusted image cannot be substituted
        // for the exact child retained by this client.
        let other = Client::spawn_daemon(Path::new(&binary)).await?;
        let wrong_peer = other.request(Command::LoadSecrets {}).await;
        drop(other);
        if !matches!(wrong_peer, Err(code) if code == "ipc_wrong_peer") {
            return Err("unowned_core_was_accepted".into());
        }
        let mut intruder = self_command("regressions::rpc_intruder_fixture");
        intruder.env(INTRUDER_MODE, core.value());
        let output = tokio::time::timeout(Duration::from_secs(8), intruder.output())
            .await.map_err(|_| "intruder_fixture_timeout")?.map_err(|_| "intruder_fixture_failed")?;
        if !output.status.success() || !String::from_utf8_lossy(&output.stdout).contains("NYMWRAP_RPC_INTRUDER_REJECTED") {
            return Err("foreign_process_was_not_rejected".into());
        }
        if !matches!(client.request(Command::LoadSecrets {}).await?, Reply::Error { code } if code == "workspace_locked") {
            return Err("control_request_not_dispatched".into());
        }
        Ok(())
    }.await;
    // Cleanup precedes assertions, including a failed intermediate operation.
    let locked = client.request(Command::Lock {}).await;
    drop(client);
    let core_stopped = stopped(&core).await;
    let api_stopped = stopped(&api).await;
    outcome.unwrap();
    assert!(matches!(locked.unwrap(), Reply::Ack {}));
    core_stopped.unwrap();
    api_stopped.unwrap();
    // Closing the inherited parent pipe without an RPC lock must also stop a
    // default locked session and its API. No workspace or keyring is created.
    let client = Client::spawn_daemon(Path::new(&binary)).await.unwrap();
    let ready_result = ready(&client).await;
    let api_result = api_locked(&api).await;
    drop(client);
    let core_stopped = stopped(&core).await;
    let api_stopped = stopped(&api).await;
    ready_result.unwrap();
    api_result.unwrap();
    core_stopped.unwrap();
    api_stopped.unwrap();
    println!("NYMWRAP_RPC_PROCESS_PROBE_OK");
}

#[tokio::test]
#[ignore = "requires built nw-api and nymwrapd; runs only in its disposable data/runtime namespace"]
async fn actual_core_api_bootstrap_rejects_foreign_processes_and_exits_with_parent() {
    let binary = Path::new(env!("CARGO_BIN_EXE_nymwrapd"));
    assert!(
        binary
            .with_file_name(format!("nw-api{}", std::env::consts::EXE_SUFFIX))
            .is_file(),
        "build nw-api before running the actual process regression"
    );
    #[cfg(unix)]
    let directory = tempfile::Builder::new()
        .prefix("nw-rpc-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(windows)]
    let directory = tempfile::Builder::new()
        .prefix("nw-rpc-")
        .tempdir()
        .unwrap();
    let forbidden = nw_core::config::Paths::discover().unwrap().core_shadow;
    let mut command = self_command("regressions::rpc_owner_fixture");
    command
        .env(OWNER_MODE, binary)
        .env_remove(INTRUDER_MODE)
        .env("NYMWRAP_RPC_FORBIDDEN_ENDPOINT", forbidden)
        .env("LOCALAPPDATA", directory.path())
        .env("XDG_DATA_HOME", directory.path())
        .env("XDG_RUNTIME_DIR", directory.path());
    let result = tokio::time::timeout(Duration::from_secs(45), command.output()).await;
    // Every path in this test was created under this guarded TempDir. No real
    // workspace, credential entry, account or ordinary runtime endpoint is used.
    directory.close().unwrap();
    let output = result.expect("native RPC probe timed out").unwrap();
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("NYMWRAP_RPC_PROCESS_PROBE_OK"));
}
