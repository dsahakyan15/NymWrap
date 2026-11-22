use std::{
    io::Write,
    process::{Command, Stdio},
};
fn run() -> Vec<u8> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nw-audit-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let body=b"\"takeout\"\n[{\"title\":\"Synthetic <script>data</script>\",\"titleUrl\":\"https://example.test/lesson\",\"time\":\"2026-01-01T12:00:00Z\"}]";
    let mut input = child.stdin.take().unwrap();
    input.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
    input.write_all(body).unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    output.stdout
}
#[test]
fn import_runs_in_a_separate_bounded_process() {
    let first = run();
    assert_eq!(first, run());
    let size = u32::from_le_bytes(first[..4].try_into().unwrap()) as usize;
    assert_eq!(size, first.len() - 4);
    let value: serde_json::Value = serde_json::from_slice(&first[4..]).unwrap();
    assert_eq!(value["summary"]["records"], 1);
    assert_eq!(
        value["summary"]["titles"][0],
        "Synthetic <script>data</script>"
    );
}
