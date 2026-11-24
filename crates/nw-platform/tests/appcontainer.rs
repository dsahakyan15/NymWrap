#![cfg(windows)]
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    time::Duration,
};
#[test]
fn appcontainer_child_probe() {
    if !nw_platform::is_appcontainer().unwrap() {
        return;
    }
    if nw_platform::harden_process().is_err() {
        println!("PROBE_HARDEN_FAILED");
        return;
    }
    let mut input = String::new();
    std::io::stdin()
        .take(8192)
        .read_to_string(&mut input)
        .unwrap();
    let mut lines = input.lines();
    assert_eq!(lines.next(), Some("NYMWRAP_SANDBOX_PROBE_V2"));
    let read = lines.next().unwrap();
    let write = lines.next().unwrap();
    let address = lines.next().unwrap().parse().unwrap();
    let udp_address: std::net::SocketAddr = lines.next().unwrap().parse().unwrap();
    assert!(lines.next().is_none());
    let read_denied = std::fs::read(read).is_err();
    let write_denied = std::fs::write(write, b"SYNTHETIC_SANDBOX_PROBE").is_err();
    let temp_denied = std::fs::write(
        std::env::temp_dir().join("synthetic-probe"),
        b"SYNTHETIC_TEMP",
    )
    .is_err();
    // A zero-capability LPAC can reject Winsock provider initialization itself.
    // Rust's std currently panics on that WSAStartup failure; either failure is closed.
    let tcp_denied = std::panic::catch_unwind(|| {
        TcpStream::connect_timeout(&address, Duration::from_millis(500))
    })
    .map_or(true, |result| result.is_err());
    let udp_denied = std::panic::catch_unwind(|| {
        UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.send_to(b"SYNTHETIC_SANDBOX_PROBE", udp_address))
    })
    .map_or(true, |result| result.is_err());
    let child_denied = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .stdout(std::process::Stdio::null())
        .spawn()
        .is_err();
    println!("temp={temp_denied}");
    println!(
        "probe: read={read_denied} write={write_denied} tcp={tcp_denied} udp={udp_denied} child={child_denied}"
    );
    // UDP send completion alone does not prove delivery through the WFP filter.
    // The parent independently asserts that neither TCP nor UDP reaches its sockets.
    if read_denied && write_denied && temp_denied && tcp_denied && child_denied {
        std::io::stdout().write_all(b"NYMWRAP_PROBE_OK\n").unwrap();
    }
}
#[test]
fn appcontainer_read_handle_probe() {
    if !nw_platform::is_appcontainer().unwrap() {
        assert!(nw_platform::inherited_read_file(0).is_err());
        return;
    }
    nw_platform::harden_process().unwrap();
    let args: Vec<_> = std::env::args().collect();
    let value = args.windows(2).find(|a| a[0] == "--skip").unwrap()[1]
        .parse()
        .unwrap();
    let mut file = nw_platform::inherited_read_file(value).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    assert_eq!(data, "SYNTHETIC_READ_HANDLE");
    assert!(file.write_all(b"FORBIDDEN").is_err());
    let mut path = String::new();
    std::io::stdin()
        .take(8192)
        .read_to_string(&mut path)
        .unwrap();
    assert!(std::fs::read(path).is_err());
    println!("NYMWRAP_READ_HANDLE_OK");
}
#[test]
#[ignore = "creates a temporary AppContainer with an inherited read-only fixture"]
fn actual_appcontainer_reads_only_explicit_read_handle() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("read-handle");
    nw_platform::create_private_directory_all(&root).unwrap();
    let path = root.join("synthetic-model");
    std::fs::write(&path, b"SYNTHETIC_READ_HANDLE").unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let result = nw_platform::appcontainer_exchange_with_files(
        &std::env::current_exe().unwrap(),
        &[
            "--exact".into(),
            "appcontainer_read_handle_probe".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
            "--skip".into(),
            "@handle:model".into(),
        ],
        &[("model", &file)],
        zeroize::Zeroizing::new(path.to_str().unwrap().as_bytes().to_vec()),
        8192,
        Duration::from_secs(30),
        512 * 1024 * 1024,
    )
    .unwrap();
    let text = String::from_utf8_lossy(&result.stdout);
    assert_eq!(result.exit_code, 0, "{text}");
    assert!(text.contains("NYMWRAP_READ_HANDLE_OK"), "{text}");
    assert_eq!(std::fs::read(&path).unwrap(), b"SYNTHETIC_READ_HANDLE");
    drop(file);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(root).unwrap();
}
#[test]
#[ignore = "creates a temporary AppContainer profile with a denied data directory"]
fn actual_appcontainer_denies_network_host_files_and_children() {
    check_network_files_and_children(false);
}
#[test]
#[ignore = "checks the trusted device-probe AppContainer profile without network capabilities"]
fn actual_probe_appcontainer_denies_network_host_files_and_children() {
    check_network_files_and_children(true);
}
fn check_network_files_and_children(device: bool) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("sandbox");
    nw_platform::create_private_directory_all(&root).unwrap();
    let source = root.join("synthetic-source");
    let target = root.join("forbidden-write");
    std::fs::write(&source, b"SYNTHETIC_PARSER_SOURCE").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // TCP's allocated ephemeral port can be excluded or occupied for UDP.
    // Let Windows allocate each protocol's port independently.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    // Prove both receivers work before testing the confined child's denial.
    let connection =
        TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(2))
            .unwrap();
    let (accepted, _) = listener.accept().unwrap();
    drop((connection, accepted));
    listener.set_nonblocking(true).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"SYNTHETIC_BASELINE", udp.local_addr().unwrap())
        .unwrap();
    let mut packet = [0; 64];
    let (size, _) = udp.recv_from(&mut packet).unwrap();
    assert_eq!(&packet[..size], b"SYNTHETIC_BASELINE");
    drop(sender);
    let input = format!(
        "NYMWRAP_SANDBOX_PROBE_V2\n{}\n{}\n{}\n{}\n",
        source.display(),
        target.display(),
        listener.local_addr().unwrap(),
        udp.local_addr().unwrap()
    );
    let args = [
        "--exact".into(),
        "appcontainer_child_probe".into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
    ];
    let result = if device {
        nw_platform::appcontainer_probe_exchange(
            &std::env::current_exe().unwrap(),
            &args,
            &[],
            zeroize::Zeroizing::new(input.into_bytes()),
        )
    } else {
        nw_platform::appcontainer_exchange(
            &std::env::current_exe().unwrap(),
            &args,
            zeroize::Zeroizing::new(input.into_bytes()),
            8192,
            Duration::from_secs(15),
        )
    };
    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_dir(&root);
    let output = result.unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.exit_code, 0, "{text}");
    let output = text;
    assert!(output.contains("NYMWRAP_PROBE_OK"), "{output}");
    assert!(listener.accept().is_err());
    assert!(
        udp.recv_from(&mut [0u8; 64]).is_err(),
        "AppContainer UDP reached the host"
    );
}
