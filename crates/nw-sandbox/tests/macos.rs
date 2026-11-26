#![cfg(target_os = "macos")]
// Share the native canary regression with tests/leak, so this small crate can
// also type-check it on Windows for aarch64-apple-darwin without OpenSSL.
include!("../../../tests/leak/src/macos_sandbox.rs");

#[test]
fn cli_executes_only_with_an_explicit_valid_profile() {
    let executable = env!("CARGO_BIN_EXE_nw-sandbox");
    let status = std::process::Command::new(executable)
        .args([
            "--process",
            "nw-api",
            "--lane",
            "shadow",
            "--",
            "/usr/bin/true",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "native CLI status={status}");
    for args in [
        vec![
            "--process",
            "nw-netd",
            "--lane",
            "cover",
            "--",
            "/usr/bin/true",
        ],
        vec![
            "--process",
            "nw-probe",
            "--lane",
            "shadow",
            "--",
            "/usr/bin/true",
        ],
        vec!["--process", "SYNTHETIC_PRIVATE_ARG_42819"],
    ] {
        let output = std::process::Command::new(executable)
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"sandbox_launch_failed\n");
    }
}
