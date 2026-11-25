#![cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Write;
use std::path::PathBuf;
use zeroize::Zeroizing;
#[test]
#[ignore = "requires native LPAC, bubblewrap/user namespaces or macOS Seatbelt"]
fn actual_device_probe_is_confined_and_uses_only_bounded_shadow_frames() {
    let directory = tempfile::tempdir().unwrap();
    let git = directory.path().join("gitconfig");
    std::fs::write(&git,b"[user]\nname = Synthetic Probe User\nemail = synthetic-probe@example.test\n[alias]\nrun = !NEVER_EXECUTE\n").unwrap();
    let file = nw_platform::open_device_config(&git).unwrap();
    let hints = nw_probe::Hints {
        user: vec!["SYNTHETIC_USER_CANARY_7361".into()],
        host: vec!["SYNTHETIC_HOST_CANARY_7361".into()],
        home: Some(r"C:\Users\synthetic-probe".into()),
        ..Default::default()
    };
    let json = Zeroizing::new(serde_json::to_vec(&hints).unwrap());
    let mut input = Zeroizing::new((json.len() as u32).to_le_bytes().to_vec());
    input.extend_from_slice(&json);
    let program = std::env::var_os("NW_PROBE_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_nw-probe")));
    #[cfg(windows)]
    let output = {
        let output = nw_sandbox::probe_exchange(&program, Some(&file), input).unwrap();
        assert_eq!(output.exit_code, 0);
        output.stdout
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let output = {
        use std::process::Stdio;
        let mut child = nw_sandbox::probe_command(&program, Some(&file))
            .unwrap()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        Zeroizing::new(output.stdout)
    };
    assert!(output.len() <= nw_probe::MAX_FRAME + 4 && output.len() > 4);
    let length = u32::from_le_bytes(output[..4].try_into().unwrap()) as usize;
    assert_eq!(output.len(), length + 4);
    let report: nw_probe::Report = serde_json::from_slice(&output[4..]).unwrap();
    assert!(report.valid());
    for source in nw_probe::Source::ALL {
        assert_ne!(
            report.observed.contains(&source),
            report.unavailable.contains(&source),
            "every source needs an explicit complete/unknown result"
        );
    }
    println!(
        "probe_unavailable_sources={}",
        serde_json::to_string(&report.unavailable).unwrap()
    );
    for canary in [
        "SYNTHETIC_USER_CANARY_7361",
        "SYNTHETIC_HOST_CANARY_7361",
        "synthetic-probe@example.test",
    ] {
        assert!(report.values.iter().any(|v| v.value == canary));
    }
    // Do not print real identifiers returned by the OS: only assertions/exit state.
    #[cfg(windows)]
    assert!(
        !std::process::Command::new(&program)
            .arg("--stdio")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}
