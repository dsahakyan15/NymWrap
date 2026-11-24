use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};
const MARKER: &[u8] = b"SYNTHETIC_STDIN_PIPE_CANARY";
const MODE: &str = "NYMWRAP_STDIN_PIPE_TEST_MODE";
fn fixture(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "stdin_pipe_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command
}
#[test]
fn stdin_pipe_fixture() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let pipe = nw_platform::inherited_stdin_pipe();
    match mode.as_str() {
        "pipe" => {
            let mut pipe = pipe.unwrap();
            let mut bytes = vec![0; MARKER.len()];
            pipe.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, MARKER);
            assert!(pipe.write_all(b"FORBIDDEN_WRITE").is_err());
        }
        "file" | "null" => assert!(pipe.is_err()),
        _ => panic!("unknown_fixture_mode"),
    }
    println!("NYMWRAP_STDIN_PIPE_CHECKED");
}
#[test]
fn inherited_stdin_is_an_owned_read_only_pipe_and_rejects_file_or_null() {
    let mut child = fixture("pipe").stdin(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(MARKER).unwrap();
    let pipe = child.wait_with_output().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-input");
    std::fs::write(&path, MARKER).unwrap();
    let file = fixture("file")
        .stdin(std::fs::File::open(path).unwrap())
        .output()
        .unwrap();
    let null = fixture("null").stdin(Stdio::null()).output().unwrap();
    directory.close().unwrap();
    for output in [pipe, file, null] {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("NYMWRAP_STDIN_PIPE_CHECKED"));
    }
}
