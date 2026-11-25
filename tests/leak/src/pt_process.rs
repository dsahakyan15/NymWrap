//! Real synthetic PT via the production tor-ptmgr API. No remote sockets/accounts.
use std::{
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_ptmgr::ipc::{
    PluggableClientTransport, PtClientParametersBuilder, PtCommonParametersBuilder,
};

fn arguments(name: &str) -> Vec<String> {
    vec![
        "--exact".into(),
        format!("pt_process::{name}"),
        "--ignored".into(),
        "--nocapture".into(),
    ]
}

#[test]
#[ignore = "synthetic error child, invoked by the control-error canary regression"]
fn nymwrap_error_child() {
    let case: usize = std::env::args()
        .find_map(|value| value.strip_prefix("case=").map(str::to_owned))
        .unwrap()
        .parse()
        .unwrap();
    let lines = [
        "CMETHOD-ERROR obfs4 PT_ERROR_CANARY_61843",
        "ENV-ERROR PT_ERROR_CANARY_61843",
        "PROXY-ERROR PT_ERROR_CANARY_61843",
        "VERSION PT_ERROR_CANARY_61843",
        "CMETHOD obfs4 socks5 PT_ERROR_CANARY_61843",
        "SMETHOD obfs4 127.0.0.1:1 cert=PT_ERROR_CANARY_61843",
        "CMETHOD obfs4 PT_ERROR_CANARY_61843 127.0.0.1:1",
        "CMETHOD PT_ERROR_CANARY_61843 socks5 127.0.0.1:1",
    ];
    println!("VERSION 1\n{}", lines[case]);
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(2));
}

#[tokio::test]
async fn nymwrap_pt_control_errors_cannot_echo_private_parameters_into_parent_logs() {
    let directory = tempfile::tempdir().unwrap();
    for (case, code) in [
        "pt_transport_launch_failed",
        "pt_environment_rejected",
        "pt_proxy_failed",
        "pt_invalid_version",
        "pt_invalid_control_line",
        "pt_unexpected_client_message",
        "pt_unknown_socks_protocol",
        "pt_unwanted_transport",
    ]
    .into_iter()
    .enumerate()
    {
        let mut args = arguments("nymwrap_error_child");
        args.push(format!("case={case}"));
        let common = PtCommonParametersBuilder::default()
            .state_location(directory.path().to_path_buf())
            .timeout(Some(Duration::from_secs(3)))
            .build()
            .unwrap();
        let client = PtClientParametersBuilder::default()
            .transports(vec!["obfs4".parse().unwrap()])
            .build()
            .unwrap();
        let mut pt =
            PluggableClientTransport::new(std::env::current_exe().unwrap(), args, common, client);
        let error = pt
            .launch(tor_rtcompat::PreferredRuntime::current().unwrap())
            .await
            .unwrap_err();
        let loggable = format!("{error:?} {error}");
        assert!(
            loggable.contains(code),
            "expected a processed control error"
        );
        assert!(!loggable.contains("PT_ERROR_CANARY_61843"));
    }
}

#[tokio::test]
#[ignore = "synthetic child, invoked by the PT lifetime regression"]
async fn nymwrap_clean_quiet_child() {
    assert!(std::env::var_os("NW_SYNTHETIC_PT_PARENT_CANARY").is_none());
    assert!(std::env::var_os("HTTP_PROXY").is_none());
    for (key, value) in [
        ("USER", "user"),
        ("HOSTNAME", "localhost"),
        ("TZ", "UTC"),
        ("LANG", "C.UTF-8"),
    ] {
        assert!(std::env::var(key).as_deref() == Ok(value));
    }
    assert!(std::env::var_os("HOME") == std::env::var_os("TOR_PT_STATE_LOCATION"));
    let address = std::env::args()
        .find_map(|s| s.strip_prefix("cleanup=").map(str::to_owned))
        .unwrap();
    let mut stream = nw_ipc::Endpoint::new(address, nw_proto::Lane::Shadow)
        .unwrap()
        .connect()
        .await
        .unwrap();
    println!("VERSION 1\nCMETHOD obfs4 socks5 127.0.0.1:1\nCMETHODS DONE");
    std::io::stdout().flush().unwrap();
    // Independent cleanup: this synthetic child always exits even if the test fails.
    let _ = tokio::time::timeout(Duration::from_secs(8), stream.read_u8()).await;
}

#[tokio::test]
#[ignore = "synthetic parent, invoked with an inherited canary by the regression"]
async fn nymwrap_canary_parent() {
    assert!(std::env::var_os("NW_SYNTHETIC_PT_PARENT_CANARY").is_some());
    let dir = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let address = format!("nymwrap-pt-cleanup-{}", std::process::id());
    #[cfg(unix)]
    let address = dir
        .path()
        .join("private/cleanup.sock")
        .to_string_lossy()
        .into_owned();
    let endpoint = nw_ipc::Endpoint::new(address.clone(), nw_proto::Lane::Shadow).unwrap();
    let listener = nw_ipc::Listener::bind(endpoint).unwrap();
    let mut args = arguments("nymwrap_clean_quiet_child");
    args.push(format!("cleanup={address}"));
    let common = PtCommonParametersBuilder::default()
        .state_location(dir.path().to_path_buf())
        .timeout(Some(Duration::from_secs(3)))
        .build()
        .unwrap();
    let client = PtClientParametersBuilder::default()
        .transports(vec!["obfs4".parse().unwrap()])
        .build()
        .unwrap();
    let mut pt =
        PluggableClientTransport::new(std::env::current_exe().unwrap(), args, common, client);
    pt.launch(tor_rtcompat::PreferredRuntime::current().unwrap())
        .await
        .expect("synthetic PT must pass its environment gate");
    let mut stream = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    drop(pt);
    let stopped = matches!(tokio::time::timeout(Duration::from_secs(1),stream.read_u8()).await,Ok(Err(error))if error.kind()==std::io::ErrorKind::UnexpectedEof);
    if !stopped {
        let _ = stream.write_u8(1).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), stream.read_u8()).await;
    }
    assert!(
        stopped,
        "dropping a quiet PT must close its process, not wait for another stdout line"
    );
}

#[test]
fn nymwrap_managed_pt_clears_environment_and_dies_on_drop() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(arguments("nymwrap_canary_parent"))
        .env("NW_SYNTHETIC_PT_PARENT_CANARY", "PT_PARENT_CANARY_75124")
        .env("HTTP_PROXY", "http://PT_PARENT_CANARY_75124.invalid")
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "synthetic managed PT failed its environment/lifetime gate"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PT_PARENT_CANARY_75124"));
}
