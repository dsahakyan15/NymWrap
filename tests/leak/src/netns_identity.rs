//! Administrative regression uses only disposable namespaces and synthetic files.
use super::*;
use std::{
    fs::{File, Permissions},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
const MODE: &str = "NYMWRAP_NETNS_IDENTITY_FIXTURE";
struct Managed(Child);
impl Drop for Managed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn fixture(mode: &str, root: &std::path::Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "sys::namespace_tests::namespace_identity_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, mode)
        .env("NW_IDENTITY_ROOT", root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
fn output(value: Output) {
    assert!(
        value.status.success(),
        "{}",
        String::from_utf8_lossy(&value.stdout)
    );
    assert!(String::from_utf8_lossy(&value.stdout).contains("NW_NAMESPACE_IDENTITY_VERIFIED"));
}
fn identity() {
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    unsafe {
        assert_eq!(libc::getresuid(&mut real, &mut effective, &mut saved), 0);
        assert_eq!((real, effective, saved), (1000, 1000, 1000));
        assert_eq!(libc::getresgid(&mut real, &mut effective, &mut saved), 0);
        assert_eq!((real, effective, saved), (1000, 1000, 1000));
        assert_eq!(libc::getgroups(0, std::ptr::null_mut()), 0);
        assert_eq!(libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), 1);
        assert_ne!(
            libc::setresuid(0, 0, 0),
            0,
            "kernel must deny recovering root UID"
        );
        assert_ne!(
            libc::setresgid(0, 0, 0),
            0,
            "kernel must deny recovering root GID"
        );
    }
}
#[test]
fn namespace_identity_fixture() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os("NW_IDENTITY_ROOT").unwrap());
    match mode.as_str() {
        "keeper" => {
            assert_eq!(unsafe { libc::geteuid() }, 0);
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            let cookie = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
            std::fs::write(
                root.join("ready.tmp"),
                format!("{tid} {}", cookie.display()),
            )
            .unwrap();
            std::fs::rename(root.join("ready.tmp"), root.join("ready")).unwrap();
            loop {
                std::thread::park();
            }
        }
        "child" => {
            identity();
            let cookie = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
            assert_eq!(
                cookie.to_str().unwrap(),
                std::env::var("NW_EXPECTED_NETNS").unwrap()
            );
            assert!(std::fs::read(root.join("private/root-only-canary")).is_err());
        }
        "coordinator" => {
            let (trigger, check) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                check.recv().unwrap();
                identity();
            });
            drop_process_identity(ChildIdentity::new(1000, 1000).unwrap()).unwrap();
            // Install TSYNC before handling data: NNP is otherwise per-thread.
            deny_remote_sockets().unwrap();
            identity();
            trigger.send(()).unwrap();
            thread.join().unwrap();
            assert!(
                std::net::TcpStream::connect_timeout(
                    &"192.0.2.99:443".parse().unwrap(),
                    Duration::from_millis(100)
                )
                .is_err()
            );
            assert!(std::fs::read(root.join("private/root-only-canary")).is_err());
        }
        "forbidden-payload" => {
            std::fs::write(root.join("payload-ran"), b"SYNTHETIC_PAYLOAD").unwrap();
        }
        _ => panic!("unknown_namespace_fixture_mode"),
    }
    println!("NW_NAMESPACE_IDENTITY_VERIFIED");
}
#[test]
#[ignore = "requires disposable root Linux coordinator; exercised explicitly by the QEMU/CI fixture"]
fn actual_child_network_namespace_and_identity_cannot_escalate() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), Permissions::from_mode(0o755)).unwrap();
    std::fs::create_dir(directory.path().join("private")).unwrap();
    std::fs::set_permissions(
        directory.path().join("private"),
        Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("private/root-only-canary"),
        b"SYNTHETIC_ROOT_DATA_CANARY",
    )
    .unwrap();
    let keeper = Managed(fixture("keeper", directory.path()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !directory.path().join("ready").is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let ready = std::fs::read_to_string(directory.path().join("ready")).unwrap();
    let (tid, cookie) = ready.split_once(' ').unwrap();
    let tid: u32 = tid.parse().unwrap();
    assert_ne!(
        cookie,
        std::fs::read_link("/proc/thread-self/ns/net")
            .unwrap()
            .to_str()
            .unwrap()
    );
    let namespace = File::open(format!("/proc/{}/task/{tid}/ns/net", keeper.0.id())).unwrap();
    let who = ChildIdentity::new(1000, 1000).unwrap();
    for (uid, gid) in [(0, 1000), (1000, 0), (u32::MAX, 1000), (1000, u32::MAX)] {
        assert!(ChildIdentity::new(uid, gid).is_err());
    }
    let mut command = fixture("child", directory.path());
    command.env("NW_EXPECTED_NETNS", cookie);
    enter_child_network_namespace(&mut command, &namespace, who).unwrap();
    let child = command.output().unwrap();
    let coordinator = fixture("coordinator", directory.path()).output().unwrap();
    let wrong = File::open(directory.path().join("private/root-only-canary")).unwrap();
    let mut command = fixture("forbidden-payload", directory.path());
    enter_child_network_namespace(&mut command, &wrong, who).unwrap();
    let rejected = command.output().is_err();
    let never_ran = !directory.path().join("payload-ran").exists();
    drop(keeper);
    drop(namespace);
    drop(wrong);
    directory.close().unwrap();
    output(child);
    output(coordinator);
    assert!(
        rejected && never_ran,
        "wrong namespace fd must stop before payload exec, without fallback"
    );
}
