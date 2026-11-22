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
