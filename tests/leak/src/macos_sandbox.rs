// Kernel operations, not entitlement inspection or socket-fd creation (ADR 0085).
use nw_sandbox::macos::{Lane, Process, Profile};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    process::Command,
    time::Duration,
};

const CANARY: &[u8] = b"SYNTHETIC_MACOS_CONTAINER_CANARY_83921";
const PROFILES: [(Process, Lane); 9] = [
    (Process::Core, Lane::Shadow),
    (Process::Core, Lane::Cover),
    (Process::Api, Lane::Shadow),
    (Process::Llmd, Lane::Shadow),
    (Process::DriftHost, Lane::Cover),
    (Process::Audit, Lane::Shadow),
    (Process::Ui, Lane::Shadow),
    (Process::Ui, Lane::Cover),
    (Process::Netd, Lane::Shadow),
];
fn denied<T: std::fmt::Debug>(result: std::io::Result<T>) {
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn every_macos_process_enforces_its_profile() {
    if std::env::var_os("NW_MACOS_SANDBOX_CHILD").is_some() {
        let private = std::env::var_os("NW_MACOS_PRIVATE").unwrap();
        let inside = std::env::var_os("NW_MACOS_INSIDE").unwrap();
        let socket = std::env::var_os("NW_MACOS_SOCKET").unwrap();
        denied(std::fs::read(&private));
        denied(std::fs::write(&private, CANARY));
        let model = std::env::var_os("NW_MACOS_MODEL").unwrap();
        if std::env::var_os("NW_MACOS_READ_ONLY").is_some() {
            assert_eq!(std::fs::read(&model).unwrap(), b"synthetic model");
            let nested = Path::new(&inside).join("immutable-model");
            assert_eq!(std::fs::read(&nested).unwrap(), b"synthetic model");
            denied(std::fs::write(nested, CANARY));
        } else {
            denied(std::fs::read(&model));
        }
        denied(std::fs::write(&model, CANARY));
        UnixListener::bind(Path::new(&inside).join("owned.sock")).unwrap();
        denied(UnixListener::bind(
            Path::new(&private).with_extension("sock"),
        ));
        // A symlink inside an allowed container must not cross its boundary.
        denied(std::fs::read(Path::new(&inside).join("escape")));
        std::fs::write(
            Path::new(&inside).join("ciphertext-fixture"),
            b"synthetic ciphertext",
        )
        .unwrap();
        assert_eq!(
            std::fs::read(Path::new(&inside).join("ciphertext-fixture")).unwrap(),
            b"synthetic ciphertext"
        );
        let mut ipc = UnixStream::connect(socket).unwrap();
        ipc.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        ipc.write_all(b"ipc").unwrap();
        let mut reply = [0; 3];
        ipc.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ipc");
        denied(Command::new("/usr/bin/true").status());
        denied(UnixStream::connect(
            std::env::var_os("NW_MACOS_OTHER_SOCKET").unwrap(),
        ));
        let tcp = std::env::var("NW_MACOS_TCP").unwrap();
        let udp = std::env::var("NW_MACOS_UDP").unwrap();
        if std::env::var_os("NW_MACOS_NETD").is_some() {
            let mut stream =
                TcpStream::connect_timeout(&tcp.parse().unwrap(), Duration::from_secs(3)).unwrap();
            stream.write_all(b"netd").unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.send_to(b"netd", udp).unwrap();
        } else {
            denied(TcpStream::connect_timeout(
                &tcp.parse().unwrap(),
                Duration::from_secs(3),
            ));
            for address in ["0.0.0.0:0", "[::]:0"] {
                denied(TcpListener::bind(address));
                denied(UdpSocket::bind(address));
            }
        }
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap();
    let private = root.join("private-canary");
    std::fs::write(&private, CANARY).unwrap();
    // A parameter value containing SBPL syntax must remain a literal path.
    let model = root.join("model\")(allow default)\\fixture");
    std::fs::write(&model, b"synthetic model").unwrap();
    assert_eq!(std::fs::read(&private).unwrap(), CANARY);
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    // Positive controls prove reachable TCP and UDP before any sandbox runs.
    TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    tcp.accept().unwrap();
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"control", udp.local_addr().unwrap())
        .unwrap();
    let mut buffer = [0; 64];
    udp.recv_from(&mut buffer).unwrap();
    let socket = root.join("ipc.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let other = root.join("other.sock");
    let _other = UnixListener::bind(&other).unwrap();
    for (process, lane) in PROFILES {
        let container = root.join(format!("{process:?}-{lane:?}"));
        std::fs::create_dir(&container).unwrap();
        std::fs::set_permissions(&container, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&private, container.join("escape")).unwrap();
        let nested_model = container.join("immutable-model");
        std::fs::write(&nested_model, b"synthetic model").unwrap();
        let read_only = [model.as_path(), nested_model.as_path()];
        let reads = matches!(process, Process::Llmd | Process::Audit);
        let mut command = Profile {
            process,
            lane,
            container: Some(&container),
            read_only: if reads { &read_only } else { &[] },
            sockets: &[&socket],
        }
        .command(
            &executable,
            &[
                "--exact".into(),
                "every_macos_process_enforces_its_profile".into(),
                "--nocapture".into(),
            ],
        )
        .unwrap();
        command
            .env("NW_MACOS_SANDBOX_CHILD", "1")
            .env("NW_MACOS_PRIVATE", &private)
            .env("NW_MACOS_MODEL", &model)
            .env("NW_MACOS_INSIDE", &container)
            .env("NW_MACOS_SOCKET", &socket)
            .env("NW_MACOS_OTHER_SOCKET", &other)
            .env("NW_MACOS_TCP", tcp.local_addr().unwrap().to_string())
            .env("NW_MACOS_UDP", udp.local_addr().unwrap().to_string());
        if process == Process::Netd {
            command.env("NW_MACOS_NETD", "1");
        }
        if reads {
            command.env("NW_MACOS_READ_ONLY", "1");
        }
        // Bounded nonblocking IPC service: a failed child cannot hang this test.
        listener.set_nonblocking(true).unwrap();
        let server = listener.try_clone().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let responder = std::thread::spawn(move || {
            while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok((mut stream, _)) = server.accept() {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut buffer = [0; 3];
                    stream.read_exact(&mut buffer).unwrap();
                    stream.write_all(&buffer).unwrap();
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let output = command.output().unwrap();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        responder.join().unwrap();
        assert!(
            output.status.success(),
            "{process:?}/{lane:?}: status={}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        assert!(!output.stdout.windows(CANARY.len()).any(|w| w == CANARY));
        assert!(!output.stderr.windows(CANARY.len()).any(|w| w == CANARY));
        assert_eq!(std::fs::read(&private).unwrap(), CANARY);
        if process == Process::Netd {
            let (mut stream, _) = tcp.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"netd");
            let (length, _) = udp.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], b"netd");
        } else {
            assert_eq!(
                tcp.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
}

#[test]
fn invalid_macos_authority_is_rejected_before_spawn() {
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let mut profile = Profile {
        process: Process::DriftHost,
        lane: Lane::Shadow,
        container: None,
        read_only: &[],
        sockets: &[],
    };
    assert!(profile.command(&executable, &[]).is_err());
    profile.lane = Lane::Cover;
    profile.container = Some(Path::new("/"));
    assert!(profile.command(&executable, &[]).is_err());
    profile.container = None;
    assert!(profile.command(Path::new("relative"), &[]).is_err());
    let read_only = [executable.as_path()];
    profile.read_only = &read_only;
    assert!(profile.command(&executable, &[]).is_err());
}

#[test]
fn profiles_allow_cpu_discovery_but_deny_host_identifier_sysctls() {
    if std::env::var_os("NW_MACOS_SYSCTL_CHILD").is_some() {
        nw_sandbox::macos::verify_runtime_sysctl_policy().unwrap();
        return;
    }
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    for (process, lane) in PROFILES {
        let profile = Profile {
            process,
            lane,
            container: None,
            read_only: &[],
            sockets: &[],
        };
        let output = profile
            .command(
                &executable,
                &[
                    "--exact".into(),
                    "profiles_allow_cpu_discovery_but_deny_host_identifier_sysctls".into(),
                    "--nocapture".into(),
                ],
            )
            .unwrap()
            .env("NW_MACOS_SYSCTL_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{process:?}/{lane:?}: status={}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    }
}
