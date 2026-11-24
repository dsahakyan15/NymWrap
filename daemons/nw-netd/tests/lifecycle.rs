use nw_net::{ShapedRequest, client::Client};
use nw_proto::Lane;
#[tokio::test]
async fn authenticated_child_starts_offline_and_dies_with_parent_handle() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let address = format!("nymwrap-netd-test-{}", std::process::id());
    #[cfg(unix)]
    let address = directory
        .path()
        .join("private/net.sock")
        .to_string_lossy()
        .into_owned();
    let endpoint = nw_ipc::Endpoint::new(address, Lane::Shadow).unwrap();
    let client = Client::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_nw-netd")),
        endpoint.clone(),
    )
    .await
    .unwrap();
    client.reset().await.unwrap(); // No bootstrap or external contact.
    assert!(
        client
            .initialize(&directory.path().join("never-created"), "127.0.0.1", "/")
            .await
            .is_err()
    );
    assert!(!directory.path().join("never-created").exists());
    let prepared = nw_shield_for_test().unwrap();
    let shaped = ShapedRequest::new(&prepared).unwrap();
    assert!(
        client
            .send(&"a".repeat(32), &shaped, "synthetic-provider-key")
            .await
            .is_err()
    );
    client.reset().await.unwrap(); // An authenticated provider error does not desynchronize IPC.
    assert!(
        client
            .send_once(&"b".repeat(32), &shaped, "synthetic-decoy-key")
            .await
            .is_err()
    );
    client.reset().await.unwrap();
    let mut stream = endpoint.connect().await.unwrap();
    nw_ipc::write_frame(
        &mut stream,
        br#"{"sequence":999,"nonce":[],"ciphertext":[]}"#,
        65536,
    )
    .await
    .unwrap();
    drop(stream);
    client.reset().await.unwrap();
    drop(client);
    let mut stopped = false;
    for _ in 0..50 {
        if endpoint.connect().await.is_err() {
            stopped = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(stopped, "egress child outlived its owner");
}
fn nw_shield_for_test() -> Result<nw_shield::Prepared, nw_shield::Block> {
    nw_shield::Shield::new(vec![])?.prepare(
        "Explain pottery.",
        &mut nw_shield::ConversationVault::default(),
        |text| Ok(text.into()),
    )
}

#[tokio::test]
async fn prepared_command_still_uses_an_owned_child_and_a_private_bootstrap_pipe() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let address = format!("nymwrap-netd-prepared-test-{}", std::process::id());
    #[cfg(unix)]
    let address = directory
        .path()
        .join("private/prepared.sock")
        .to_string_lossy()
        .into_owned();
    let endpoint = nw_ipc::Endpoint::new(address, Lane::Shadow).unwrap();
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_nw-netd"))
        .canonicalize()
        .unwrap();
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["--socket", endpoint.value()])
        .env_clear()
        .stdin(std::process::Stdio::null());
    for name in [
        "SystemRoot",
        "WINDIR",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "HOME",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let client = Client::spawn_prepared(command, endpoint.clone())
        .await
        .unwrap();
    let reset = client.reset().await;
    drop(client);
    let mut stopped = false;
    for _ in 0..50 {
        if endpoint.connect().await.is_err() {
            stopped = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    directory.close().unwrap();
    reset.unwrap();
    assert!(
        stopped,
        "the prepared launch must retain the same parent/child lifetime rule"
    );
}

#[tokio::test]
async fn one_idle_unauthenticated_peer_cannot_hold_the_transport_for_the_general_frame_timeout() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let address = format!("nymwrap-netd-idle-test-{}", std::process::id());
    #[cfg(unix)]
    let address = directory
        .path()
        .join("private/idle.sock")
        .to_string_lossy()
        .into_owned();
    let endpoint = nw_ipc::Endpoint::new(address, Lane::Shadow).unwrap();
    let client = Client::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_nw-netd")),
        endpoint.clone(),
    )
    .await
    .unwrap();
    client.reset().await.unwrap();
    let idle = endpoint.connect().await.unwrap();
    let reset = tokio::time::timeout(std::time::Duration::from_secs(4), client.reset()).await;
    drop(idle);
    drop(client);
    directory.close().unwrap();
    assert!(
        matches!(reset, Ok(Ok(()))),
        "one empty peer must be disconnected within the authentication deadline"
    );
}
