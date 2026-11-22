use super::*;

#[cfg(unix)]
#[test]
fn an_existing_public_ipc_parent_is_rejected_without_relaxing_its_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let endpoint = Endpoint::new(
        directory
            .path()
            .join("public.sock")
            .to_string_lossy()
            .into_owned(),
        Lane::Shadow,
    )
    .unwrap();
    assert!(matches!(Listener::bind(endpoint), Err(IpcError::Peer)));
    assert_eq!(
        std::fs::metadata(directory.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[tokio::test]
async fn kernel_peer_pid_and_image_are_required_on_both_ends_before_a_canary_roundtrip() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let address = directory
        .path()
        .join("new/private/ipc.sock")
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let address = format!(
        "nymwrap-identity-{}-{}",
        std::process::id(),
        directory.path().file_name().unwrap().to_string_lossy()
    );
    let endpoint = Endpoint::new(address, Lane::Shadow).unwrap();
    let listener = Listener::bind(endpoint.clone()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for part in ["new", "new/private"] {
            assert_eq!(
                std::fs::metadata(directory.path().join(part))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }
    let check = |stream: &LocalStream| {
        let pid = peer_process(stream).unwrap();
        assert_eq!(pid, std::process::id());
        assert_eq!(
            nw_platform::process_image(pid)
                .unwrap()
                .canonicalize()
                .unwrap(),
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
    };
    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        check(&stream);
        let frame = read_frame(&mut stream, 1024).await.unwrap();
        write_frame(&mut stream, &frame, 1024).await.unwrap();
    });
    let mut stream = endpoint.connect().await.unwrap();
    check(&stream);
    let canary = b"SYNTHETIC_LOCAL_IPC_CANARY_78214";
    write_frame(&mut stream, canary, 1024).await.unwrap();
    assert_eq!(&*read_frame(&mut stream, 1024).await.unwrap(), canary);
    server.await.unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn a_non_socket_cannot_supply_a_darwin_peer_pid() {
    use std::os::fd::AsFd;
    let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    assert!(nw_platform::local_peer_process(file.as_fd()).is_err());
}
