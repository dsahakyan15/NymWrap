use nw_sandbox::daemon::{Launch, Profile};
use std::{io::Read, path::PathBuf, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn daemon_negative_probe() {
    #[cfg(windows)]
    if !nw_platform::is_appcontainer().unwrap() {
        return;
    }
    #[cfg(target_os = "linux")]
    if !std::path::Path::new("/run/nymwrap/leaf-profile").exists() {
        return;
    }
    nw_sandbox::daemon::seal().unwrap();
    let mut bytes = String::new();
    std::io::stdin()
        .take(4097)
        .read_to_string(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 4096);
    let input: serde_json::Value = serde_json::from_str(&bytes).unwrap();
    assert!(std::fs::read(input["read"].as_str().unwrap()).is_err());
    assert!(
        std::fs::write(
            input["write"].as_str().unwrap(),
            b"SYNTHETIC_LEAF_CANARY_72941"
        )
        .is_err()
    );
    for address in ["127.0.0.1:0", "[::1]:0"] {
        assert!(
            std::panic::catch_unwind(|| std::net::TcpListener::bind(address))
                .map_or(true, |r| r.is_err())
        );
        assert!(
            std::panic::catch_unwind(|| std::net::UdpSocket::bind(address))
                .map_or(true, |r| r.is_err())
        );
    }
    let destination = input["address"].as_str().unwrap().parse().unwrap();
    assert!(
        std::panic::catch_unwind(|| std::net::TcpStream::connect_timeout(
            &destination,
            Duration::from_millis(300)
        ))
        .map_or(true, |r| r.is_err())
    );
    #[cfg(windows)]
    let executable = std::env::current_exe().unwrap();
    #[cfg(target_os = "linux")]
    let executable = std::path::PathBuf::from("/daemon");
    assert!(
        std::process::Command::new(executable)
            .arg("--list")
            .spawn()
            .is_err()
    );
    #[cfg(target_os = "linux")]
    {
        assert!(!std::path::Path::new("/proc").exists());
        assert!(!std::path::Path::new("/sys").exists());
        assert!(
            std::fs::write("/tmp/forbidden-plaintext", b"SYNTHETIC_LEAF_CANARY_72941").is_err()
        );
    }
    // Threads remain available for Tokio/inference; process creation does not.
    std::thread::spawn(|| assert_eq!(2 + 2, 4)).join().unwrap();
    println!("NYMWRAP_LEAF_DENIALS_OK");
}

async fn negative(profile: Profile) {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    std::fs::write(&source, b"SYNTHETIC_LEAF_CANARY_72941").unwrap();
    let write = directory.path().join("forbidden");
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let baseline = std::net::TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    drop(tcp.accept().unwrap());
    drop(baseline);
    tcp.set_nonblocking(true).unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"SYNTHETIC_BASELINE", udp.local_addr().unwrap())
        .unwrap();
    udp.recv_from(&mut [0; 64]).unwrap();
    udp.set_nonblocking(true).unwrap();
    let mut child = Launch {
        profile,
        binary: std::env::current_exe().unwrap(),
        arguments: vec![
            "--exact".into(),
            "daemon_negative_probe".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        listener: None,
        upstream: vec![],
        files: vec![],
        environment: vec![],
    }
    .spawn()
    .await
    .unwrap();
    let input=serde_json::to_vec(&serde_json::json!({"read":source,"write":write,"address":tcp.local_addr().unwrap().to_string()})).unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&input).await.unwrap();
    stdin.flush().await.unwrap();
    drop(stdin);
    let mut text = String::new();
    tokio::time::timeout(
        Duration::from_secs(15),
        child
            .stdout
            .take()
            .unwrap()
            .take(8193)
            .read_to_string(&mut text),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        child.wait().await.unwrap().success(),
        "profile={profile:?}: {text}"
    );
    assert!(
        text.contains("NYMWRAP_LEAF_DENIALS_OK"),
        "profile={profile:?}: {text}"
    );
    assert!(!text.contains("SYNTHETIC_LEAF_CANARY_72941"));
    assert!(!write.exists());
    assert!(tcp.accept().is_err());
    assert!(udp.recv_from(&mut [0; 64]).is_err());
}
#[tokio::test]
#[ignore = "requires native AppContainer or working bwrap/user namespaces"]
async fn actual_api_profile_denies_network_files_and_children() {
    negative(Profile::Api).await;
}
#[tokio::test]
#[ignore = "requires native AppContainer or working bwrap/user namespaces"]
async fn actual_model_profile_denies_network_files_and_children() {
    negative(Profile::Model).await;
}
#[tokio::test]
#[ignore = "requires native AppContainer or working bwrap/user namespaces"]
async fn actual_cover_host_profile_denies_network_files_and_children() {
    negative(Profile::DriftHost).await;
}

#[tokio::test]
async fn unavailable_or_relative_program_never_launches_unconfined() {
    let result = Launch {
        profile: Profile::Api,
        binary: PathBuf::from("missing"),
        arguments: vec![],
        listener: None,
        upstream: vec![],
        files: vec![],
        environment: vec![],
    }
    .spawn()
    .await;
    assert!(result.is_err());
}

#[test]
fn daemon_ipc_probe() {
    #[cfg(windows)]
    if !nw_platform::is_appcontainer().unwrap() {
        return;
    }
    #[cfg(target_os = "linux")]
    if !std::path::Path::new("/run/nymwrap/leaf-profile").exists() {
        return;
    }
    nw_sandbox::daemon::seal().unwrap();
    assert!(nw_platform::LockedString::new("SYNTHETIC_LOCKED_BOOTSTRAP".to_owned().into()).is_ok());
    let mut bytes = String::new();
    std::io::stdin()
        .take(4097)
        .read_to_string(&mut bytes)
        .unwrap();
    let socket: String = serde_json::from_str(&bytes).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let endpoint = nw_ipc::Endpoint::new(socket, nw_proto::Lane::Shadow)
                .unwrap()
                .sandboxed();
            let listener = nw_ipc::Listener::bind(endpoint).unwrap();
            println!("NYMWRAP_LEAF_IPC_READY");
            let mut stream = listener.accept().await.unwrap();
            let bytes = nw_ipc::read_frame(&mut stream, 64).await.unwrap();
            assert_eq!(&*bytes, b"SYNTHETIC_LEAF_PING");
            nw_ipc::write_frame(&mut stream, b"SYNTHETIC_LEAF_PONG", 64)
                .await
                .unwrap();
        });
}
#[tokio::test]
#[ignore = "requires native AppContainer or working bwrap/user namespaces"]
async fn actual_sandbox_preserves_private_ipc_and_payload_identity() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let address = format!("nymwrap-leaf-ipc-{}", std::process::id());
    #[cfg(target_os = "linux")]
    let address = directory
        .path()
        .join("ipc/leaf.sock")
        .to_str()
        .unwrap()
        .to_owned();
    let endpoint = nw_ipc::Endpoint::new(address.clone(), nw_proto::Lane::Shadow)
        .unwrap()
        .sandboxed();
    let mut child = Launch {
        profile: Profile::Api,
        binary: std::env::current_exe().unwrap(),
        arguments: vec![
            "--exact".into(),
            "daemon_ipc_probe".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        listener: Some(address.clone().into()),
        upstream: vec![],
        files: vec![],
        environment: vec![],
    }
    .spawn()
    .await
    .unwrap();
    let mut input = child.stdin.take().unwrap();
    input
        .write_all(&serde_json::to_vec(&address).unwrap())
        .await
        .unwrap();
    input.flush().await.unwrap();
    drop(input);
    let connection = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if child.try_wait().unwrap().is_some() {
                return None;
            }
            if let Ok(stream) = endpoint.connect().await {
                return Some(stream);
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap_or(None);
    if let Some(mut stream) = connection {
        assert_eq!(nw_ipc::peer_process(&stream).unwrap(), child.id().unwrap());
        nw_ipc::write_frame(&mut stream, b"SYNTHETIC_LEAF_PING", 64)
            .await
            .unwrap();
        assert_eq!(
            &*nw_ipc::read_frame(&mut stream, 64).await.unwrap(),
            b"SYNTHETIC_LEAF_PONG"
        );
        assert!(child.wait().await.unwrap().success());
    } else {
        child.start_kill().unwrap();
        child.wait().await.unwrap();
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .take(8193)
            .read_to_string(&mut output)
            .await
            .unwrap();
        panic!("leaf IPC startup failed: {output}");
    }
    drop(directory);
}

#[test]
fn daemon_upstream_probe() {
    #[cfg(windows)]
    if !nw_platform::is_appcontainer().unwrap() {
        return;
    }
    #[cfg(target_os = "linux")]
    if !std::path::Path::new("/run/nymwrap/leaf-profile").exists() {
        return;
    }
    nw_sandbox::daemon::seal().unwrap();
    let mut bytes = String::new();
    std::io::stdin()
        .take(4097)
        .read_to_string(&mut bytes)
        .unwrap();
    let endpoints: Vec<String> = serde_json::from_str(&bytes).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let allowed =
                nw_ipc::Endpoint::new(endpoints[0].clone(), nw_proto::Lane::Cover).unwrap();
            let forbidden =
                nw_ipc::Endpoint::new(endpoints[1].clone(), nw_proto::Lane::Shadow).unwrap();
            let mut stream = allowed.connect().await.unwrap();
            assert!(forbidden.connect().await.is_err());
            nw_ipc::write_frame(&mut stream, b"SYNTHETIC_COVER_ONLY", 64)
                .await
                .unwrap();
        });
    println!("NYMWRAP_LEAF_UPSTREAM_OK");
}
#[tokio::test]
#[ignore = "requires native AppContainer or working bwrap/user namespaces"]
async fn actual_cover_cannot_open_shadow_ipc() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let names = vec![
        format!("nymwrap-leaf-cover-{}", std::process::id()),
        format!("nymwrap-leaf-shadow-{}", std::process::id()),
    ];
    #[cfg(target_os = "linux")]
    let names = vec![
        directory
            .path()
            .join("cover/socket")
            .to_str()
            .unwrap()
            .to_owned(),
        directory
            .path()
            .join("shadow/socket")
            .to_str()
            .unwrap()
            .to_owned(),
    ];
    let listener = nw_ipc::Listener::bind(
        nw_ipc::Endpoint::new(names[0].clone(), nw_proto::Lane::Cover).unwrap(),
    )
    .unwrap();
    let _forbidden = nw_ipc::Listener::bind(
        nw_ipc::Endpoint::new(names[1].clone(), nw_proto::Lane::Shadow).unwrap(),
    )
    .unwrap();
    let mut child = Launch {
        profile: Profile::DriftHost,
        binary: std::env::current_exe().unwrap(),
        arguments: vec![
            "--exact".into(),
            "daemon_upstream_probe".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        listener: None,
        upstream: vec![names[0].clone().into()],
        files: vec![],
        environment: vec![],
    }
    .spawn()
    .await
    .unwrap();
    let mut input = child.stdin.take().unwrap();
    input
        .write_all(&serde_json::to_vec(&names).unwrap())
        .await
        .unwrap();
    input.flush().await.unwrap();
    drop(input);
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = listener.accept().await.unwrap();
        assert_eq!(nw_ipc::peer_process(&stream).unwrap(), child.id().unwrap());
        assert_eq!(
            &*nw_ipc::read_frame(&mut stream, 64).await.unwrap(),
            b"SYNTHETIC_COVER_ONLY"
        );
    })
    .await;
    if result.is_err() {
        child.start_kill().unwrap();
    }
    let status = child.wait().await.unwrap();
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(8193)
        .read_to_string(&mut output)
        .await
        .unwrap();
    assert!(
        result.is_ok() && status.success() && output.contains("NYMWRAP_LEAF_UPSTREAM_OK"),
        "{output}"
    );
    drop(directory);
}
