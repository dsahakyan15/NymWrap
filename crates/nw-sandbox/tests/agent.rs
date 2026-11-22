#![cfg(target_os = "linux")]
use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn agent_probe() {
    if std::env::var_os("NW_SANDBOX_AGENT_PROBE").is_none() {
        return;
    }
    nw_platform::harden_process().unwrap();
    nw_platform::deny_remote_sockets().unwrap();
    let work = std::env::var_os("NW_SANDBOX_WORK").unwrap();
    let api = std::env::var_os("NW_SANDBOX_API").unwrap();
    let outside = std::env::var_os("NW_SANDBOX_OUTSIDE").unwrap();
    let script = r#"
import os, socket, sys
assert socket.gethostname() == 'localhost', 'host_hostname_visible'
assert os.environ['TZ'] == 'UTC'
assert os.environ['LANG'] == os.environ['LC_ALL'] == 'C.UTF-8'
assert os.environ['HOME'] == '/home/user'
assert os.environ['USER'] == os.environ['LOGNAME'] == 'user'
assert os.getuid() == os.getgid() == 1000
assert os.getcwd() == '/work'
assert open('/etc/machine-id').read().strip() == '00000000000000000000000000000001'
assert open('/etc/passwd').read() == 'user:x:1000:1000:user:/home/user:/bin/sh\n'
assert open('/etc/group').read() == 'user:x:1000:\n'
assert open('/home/user/.gitconfig').read() == '[user]\n\tname = user\n\temail = user@localhost\n'
for hidden in ('/sys', '/run/dbus', '/run/NetworkManager', '/var/lib/dbus'):
    assert not os.path.exists(hidden), 'host_service_visible'
assert not os.path.exists(sys.argv[1]), 'host_file_visible'
assert not os.path.exists('/run/nymwrap/core-shadow.sock'), 'core_socket_visible'
assert os.environ['NYMWRAP_API_SOCKET'] == '/run/nymwrap/api.sock'
assert os.environ['OPENAI_BASE_URL'] == 'http://localhost/v1'
for family in (socket.AF_INET, socket.AF_INET6):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        try:
            remote = socket.socket(family, kind)
        except PermissionError:
            continue
        else:
            remote.close()
            raise AssertionError('external_socket_allowed')
private = socket.socket(socket.AF_UNIX)
private.settimeout(3)
private.connect(os.environ['NYMWRAP_API_SOCKET'])
private.sendall(b'synthetic-shadow-request')
assert private.makefile('rb').read(22) == b'synthetic-local-answer'
private.close()
with open('/work/result.txt', 'w') as output:
    output.write('synthetic-agent-completed')
"#;
    let status = nw_sandbox::agent_command(
        std::path::Path::new(&work),
        std::path::Path::new("/usr/bin/python3"),
        &["-c".into(), script.into(), outside],
        std::path::Path::new(&api),
    )
    .unwrap()
    .status()
    .unwrap();
    assert!(status.success());
}
#[test]
#[ignore = "requires Linux user namespaces and bubblewrap; run explicitly in Linux CI"]
fn actual_agent_sees_only_http_socket_and_cannot_open_external_sockets() {
    let directory = tempfile::tempdir().unwrap();
    let work = directory.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let outside = directory.path().join("private.txt");
    std::fs::write(&outside, b"synthetic-private-fixture").unwrap();
    let api = directory.path().join("api.sock");
    let listener = UnixListener::bind(&api).unwrap();
    std::fs::set_permissions(&api, std::fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    // Wrong socket names and broad permissions cannot expose another private interface.
    let broad =
        nw_sandbox::agent_command(&work, std::path::Path::new("/usr/bin/python3"), &[], &api);
    assert!(broad.is_ok());
    std::fs::set_permissions(&api, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        nw_sandbox::agent_command(&work, std::path::Path::new("/usr/bin/python3"), &[], &api),
        Err(nw_sandbox::SandboxError::Api)
    ));
    std::fs::set_permissions(&api, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "agent_probe", "--nocapture"])
        .env("NW_SANDBOX_AGENT_PROBE", "1")
        .env("NW_SANDBOX_WORK", &work)
        .env("NW_SANDBOX_API", &api)
        .env("NW_SANDBOX_OUTSIDE", &outside)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut answered = false;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut input = [0; 24];
                stream.read_exact(&mut input).unwrap();
                assert_eq!(&input, b"synthetic-shadow-request");
                stream.write_all(b"synthetic-local-answer").unwrap();
                answered = true;
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("private socket failed: {e}"),
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !answered {
        let _ = child.kill();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        answered && output.status.success(),
        "sandbox probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(work.join("result.txt")).unwrap(),
        b"synthetic-agent-completed"
    );
}
