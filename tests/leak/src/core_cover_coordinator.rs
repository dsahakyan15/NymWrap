//! CI-only M3 coordinator; production core slots/accounting, launcher and authenticated IPC.
#[cfg(any(target_os = "linux", test))]
mod core_cover_week;
#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
fn main() {
    use std::path::PathBuf;
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    let probe = if args.first().is_some_and(|arg| arg.starts_with("--")) {
        Some(args.remove(0))
    } else {
        None
    };
    assert_eq!(args.len(), 4);
    let fixture = PathBuf::from(&args[0]);
    let host = std::fs::read_link("/proc/self/ns/net").unwrap();
    // Positive controls before the production coordinator removes its network.
    std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let launch = nw_net::launcher::LinuxNamespace::prepare(
        std::path::Path::new(&args[1]),
        args[2].parse().unwrap(),
        args[3].parse().unwrap(),
    )
    .unwrap();
    let core = std::fs::read_link("/proc/self/ns/net").unwrap();
    assert_ne!(host, core);
    if let Some(mode) = probe {
        let endpoint = nw_ipc::Endpoint::new(
            fixture.join("runtime/net.sock").to_str().unwrap().into(),
            nw_proto::Lane::Shadow,
        )
        .unwrap();
        match mode.as_str() {
            "--failure-probe" => {
                let result = tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(launch.spawn(&fixture.join("missing-netd"), endpoint));
                assert!(matches!(result, Err("transport_component_missing")));
            }
            "--cancel-probe" => {
                // Cancellation before the future is first polled must also
                // destroy the administrative capability and seal core.
                drop(launch.spawn(&fixture.join("missing-netd"), endpoint));
            }
            _ => panic!("invalid_launcher_probe"),
        }
        assert_eq!(nw_platform::current_user_id().unwrap(), args[2]);
        assert_eq!(nw_platform::current_group_id(), args[3]);
        std::thread::spawn(|| {
            assert_eq!(
                std::net::TcpListener::bind("0.0.0.0:0").unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                std::net::UdpSocket::bind("[::]:0").unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        })
        .join()
        .unwrap();
        println!("NW_LAUNCHER_PROBE_VERIFIED:{mode}");
        return;
    }
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(exercise(launch, fixture, core, host));
}

#[cfg(target_os = "linux")]
async fn exercise(
    launch: nw_net::launcher::LinuxNamespace,
    fixture: std::path::PathBuf,
    core: std::path::PathBuf,
    host: std::path::PathBuf,
) {
    use std::time::Duration;
    let endpoint = nw_ipc::Endpoint::new(
        fixture.join("runtime/net.sock").to_str().unwrap().into(),
        nw_proto::Lane::Shadow,
    )
    .unwrap();
    let client = launch
        .spawn(&fixture.join("bin/nw-netd"), endpoint)
        .await
        .unwrap();
    assert_ne!(nw_platform::current_user_id().unwrap(), "0");
    // Check actual syscall errors, not a timeout or an unavailable destination.
    for address in ["0.0.0.0:0", "[::]:0"] {
        assert_eq!(
            std::net::TcpListener::bind(address).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::net::UdpSocket::bind(address).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    assert_eq!(
        std::net::TcpStream::connect("192.0.2.2:443")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    client
        .initialize(
            &fixture.join("mount/private"),
            "api.example.test",
            "/v1/chat/completions",
        )
        .await
        .unwrap();
    let canaries: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/pcap-canaries.json")).unwrap();
    let facts: Vec<_> = ["device", "detectors"]
        .iter()
        .flat_map(|key| {
            canaries[key]
                .as_object()
                .unwrap()
                .values()
                .map(|v| v.as_str().unwrap())
        })
        .collect();
    let shield = nw_shield::Shield::new(
        canaries["device"]
            .as_object()
            .unwrap()
            .values()
            .map(|value| {
                nw_shield::Secret::new(
                    nw_shield::SecretKind::Device,
                    value.as_str().unwrap().into(),
                    false,
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let request = |fact: &str, length: usize| {
        let prepared = shield
            .prepare(
                &format!("Explain pottery for {fact}. {}", "x".repeat(length)),
                &mut nw_shield::ConversationVault::default(),
                |text| Ok(serde_json::json!([{"role":"user","content":text}]).to_string()),
            )
            .unwrap();
        nw_net::ShapedRequest::history(&prepared, "synthetic", 16).unwrap()
    };
    assert_eq!(facts.len(), 16);
    for (index, fact) in facts.iter().enumerate() {
        assert_eq!(
            client
                .send(
                    &format!("{index:032x}"),
                    &request(fact, [32, 2200, 4400, 8500, 17000][index % 5]),
                    "synthetic-provider-token"
                )
                .await
                .unwrap(),
            "synthetic safe answer"
        );
    }
    let week = core_cover_week::exercise(
        &fixture.join("mount/private/cover-week"),
        |index| {
            request(
                facts[index % facts.len()],
                [32, 2200, 4400, 8500, 17000][index % 5],
            )
        },
        |conversation, body, real| {
            let client = &client;
            async move {
                let result = if real {
                    client
                        .send(&conversation, &body, "synthetic-provider-token")
                        .await
                } else {
                    client
                        .send_once(&conversation, &body, "synthetic-provider-token")
                        .await
                };
                assert_eq!(result.unwrap(), "synthetic safe answer");
            }
        },
    )
    .await;
    std::fs::write(
        fixture.join("cover-week.json"),
        serde_json::to_vec(&week).unwrap(),
    )
    .unwrap();
    let worker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("worker-state.json")).unwrap()).unwrap();
    assert_ne!(
        worker["namespace"].as_str().unwrap(),
        core.to_str().unwrap()
    );
    std::fs::write(fixture.join("ready-to-stop"), b"ready").unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !fixture.join("transport-stopped").is_file() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    // Require an explicit transport error returned through AEAD. An outer
    // timeout/cancellation is a failed test, never evidence of fail-closed.
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(125),
            client.send(
                &format!("{:032x}", 100),
                &request("plain public task", 32),
                "synthetic-provider-token"
            )
        )
        .await
        .unwrap(),
        Err("remote_request_failed")
    );
    std::fs::write(fixture.join("rust-result.json"), serde_json::to_vec(&serde_json::json!({
            "complete":true, "requests":100, "different_circuits":true,
            "transport_stop_failed_closed":true, "direct_provider_connection_denied":worker["direct_provider_connection_denied"],
            "production_launcher":true,"authenticated_dispatcher":true,"core_socket_denied":true,
            "core_namespace":core.to_str().unwrap(),"worker_namespace":worker["namespace"],
            "host_namespace":host.to_str().unwrap()
        })).unwrap()).unwrap();
    drop(client);
}
