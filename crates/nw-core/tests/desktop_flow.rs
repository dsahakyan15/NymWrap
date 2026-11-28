//! Opt-in end-to-end check of the backend flow the desktop UI drives, through the
//! same authorized `Client::spawn_daemon` path as the Tauri proxy. `nymwrap rpc`
//! is intentionally disabled (ADR 0076), so this replaces the old JS RPC driver.
//! Synthetic data only; a disposable LOCALAPPDATA/XDG directory; the real OS key
//! store is used and the workspace is destroyed before the test returns.
//!
//! cargo build --workspace --bins --locked
//! $env:NYMWRAP_E2E_OS_KEYSTORE='1'
//! cargo test -p nw-core --test desktop_flow --locked -- --ignored --nocapture
use nw_core::service::{Client, Command};
use nw_ipc::Endpoint;
use nw_proto::Lane;
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const OWNER_MODE: &str = "NYMWRAP_DESKTOP_FLOW_OWNER";
const OPT_IN: &str = "NYMWRAP_E2E_OS_KEYSTORE";
const CHAT_MODEL: (&str, &str) = (
    "qwen2.5-0.5b-instruct-q4_k_m.gguf",
    "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
);
const EMBED_MODEL: (&str, &str) = (
    "nomic-embed-text-v1.5.Q4_K_M.gguf",
    "d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac",
);
const TAKEOUT: &str = include_str!("../../../tests/fixtures/takeout.json");
const CANARY: &str = "Synthetic Qeravina Zoltessa";

/// Default: pinned Qwen2.5-0.5B. NYMWRAP_E2E_CHAT_MODEL=7b selects the prepared
/// merged 7B GGUF described by target/test-models/qwen2.5-7b-q4_k_m.merged.json.
fn chat_model(models: &Path) -> Result<(String, String), String> {
    if std::env::var("NYMWRAP_E2E_CHAT_MODEL").as_deref() != Ok("7b") {
        return Ok((CHAT_MODEL.0.into(), CHAT_MODEL.1.into()));
    }
    let meta: Value = serde_json::from_slice(
        &std::fs::read(models.join("qwen2.5-7b-q4_k_m.merged.json"))
            .map_err(|_| "7b_metadata_missing")?,
    )
    .map_err(|_| "invalid_7b_metadata")?;
    match (meta["file"].as_str(), meta["sha256"].as_str()) {
        (Some(file @ "qwen2.5-7b-instruct-q4_k_m.gguf"), Some(sha))
            if sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Ok((file.into(), sha.into()))
        }
        _ => Err("invalid_7b_metadata".into()),
    }
}
async fn call(client: &Client, command: Value) -> Result<Value, String> {
    let op = command["op"].as_str().unwrap_or("unknown").to_owned();
    let command: Command =
        serde_json::from_value(command).map_err(|_| format!("{op}: invalid_command"))?;
    client
        .request(command)
        .await
        .and_then(|reply| reply.into_json())
        .map_err(|code| format!("{op}: {code}"))
}
async fn ready(client: &Client) -> Result<(), String> {
    for _ in 0..250 {
        match call(client, json!({"op":"status"})).await {
            Ok(_) => return Ok(()),
            Err(code) if code.ends_with("ipc_unavailable") => {}
            Err(code) => return Err(code),
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    Err("core_startup_timeout".into())
}
/// Plain HTTP/1.1 over the private API pipe/socket, as an OpenAI client would.
async fn http(endpoint: &Endpoint, body: &Value) -> Result<(u16, String, Value), String> {
    let mut stream = None;
    for _ in 0..250 {
        if let Ok(s) = endpoint.connect().await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    let mut stream = stream.ok_or("api_unavailable")?;
    let body = body.to_string();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| "api_write_failed")?;
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(300),
        stream.take(1 << 20).read_to_end(&mut response),
    )
    .await
    .map_err(|_| "api_timeout")?
    .map_err(|_| "api_read_failed")?;
    let text = String::from_utf8(response).map_err(|_| "invalid_api_response")?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("invalid_api_response")?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("invalid_api_response")?;
    let conversation = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("x-nymwrap-conversation:")
                .map(|v| v.trim().to_owned())
        })
        .unwrap_or_default();
    Ok((
        status,
        conversation,
        serde_json::from_str(body).map_err(|_| "invalid_api_json")?,
    ))
}

async fn drift(client: &Client, review: &Value) -> Result<(), String> {
    let hash = review["hash"].as_str().ok_or("generate_plan: no hash")?;
    if review["approved"] != false {
        return Err("generate_plan: plan approved without the user".into());
    }
    if call(client, json!({"op":"approve_plan","hash":"0".repeat(64)}))
        .await
        .is_ok()
    {
        return Err("approve_plan: accepted a hash that was not shown".into());
    }
    call(client, json!({"op":"approve_plan","hash":hash})).await?;
    let day = call(client, json!({"op":"generate_day"})).await?;
    let day_hash = day["hash"].as_str().ok_or("generate_day: no hash")?;
    call(client, json!({"op":"approve_day","hash":day_hash})).await?;
    let tasks = call(client, json!({"op":"daily_tasks"})).await?;
    if !tasks.as_array().is_some_and(|t| !t.is_empty()) {
        return Err("daily_tasks: empty after approval".into());
    }
    println!(
        "PASS: Drift plan checked by code, approved by hash; day wording approved; tasks issued"
    );
    Ok(())
}
async fn flow(client: &Client, models: &Path, data: &Path) -> Result<(), String> {
    let chat = chat_model(models)?;
    let small = chat.0 == CHAT_MODEL.0;
    let paths = nw_core::config::Paths::discover().map_err(|e| e.to_string())?;
    let opened = call(
        client,
        json!({"op":"open_workspace","password":"","create":true,"profile":"standard"}),
    )
    .await?;
    let store = opened["path"].as_str().ok_or("open_workspace: no path")?;
    if opened["unlocked"] != true || !Path::new(store).starts_with(data) {
        return Err("open_workspace: not unlocked inside the fixture".into());
    }
    println!("PASS: Standard space created with an empty password");

    use base64::Engine as _;
    let imported = call(
        client,
        json!({"op":"audit_import","format":"takeout","encoding":"base64",
        "content":base64::engine::general_purpose::STANDARD.encode(TAKEOUT)}),
    )
    .await?;
    if imported["records"] != 3
        || !imported["titles"].as_array().is_some_and(|t| {
            t.iter()
                .any(|t| t == "<script>synthetic_xss_canary</script>")
        })
    {
        return Err(format!("audit_import: unexpected summary {imported}"));
    }
    println!("PASS: synthetic Takeout imported in the isolated worker; hostile title kept as data");

    let mut config = call(client, json!({"op":"load_config"})).await?;
    config["llm"]["model_path"] = json!(models.join(&chat.0));
    config["llm"]["model_sha256"] = json!(chat.1);
    config["llm"]["embed_path"] = json!(models.join(EMBED_MODEL.0));
    config["llm"]["embed_sha256"] = json!(EMBED_MODEL.1);
    call(client, json!({"op":"save_config","config":config})).await?;
    let started = call(client, json!({"op":"start_model"})).await?;
    if started["model_managed"] != true {
        return Err(format!("start_model: {started}"));
    }
    println!(
        "PASS: pinned {} and nomic started after SHA-256 verification",
        chat.0
    );

    let api = Endpoint::new(paths.api, Lane::Shadow).map_err(|e| e.to_string())?;
    let (status, conversation, body) = http(&api, &json!({"model":"nw/local/default","max_tokens":24,
        "messages":[{"role":"user","content":format!("My name is {CANARY}. What is 2 + 2? Answer briefly.")}]})).await?;
    if status != 200 || body["nymwrap"]["trust"] != "L0" || conversation.len() != 32 {
        return Err(format!("api chat: {status} {body}"));
    }
    let history = call(
        client,
        json!({"op":"load_history","conversation":conversation}),
    )
    .await?;
    let mut messages = history
        .as_array()
        .cloned()
        .ok_or("load_history: not a list")?;
    if messages.len() != 2 {
        return Err("load_history: expected one exchange".into());
    }
    messages.push(json!({"role":"user","content":"Repeat only the number."}));
    let continued = call(
        client,
        json!({"op":"chat","conversation":conversation,"messages":messages,"max_tokens":8}),
    )
    .await?;
    if continued["trust"] != "L0" || continued["conversation"] != conversation.as_str() {
        return Err(format!("chat: {continued}"));
    }
    println!(
        "PASS: L0 chat over the private OpenAI-compatible API and the UI chat path share history"
    );

    let persona = call(client, json!({"op":"research_persona"})).await?;
    let choices: Vec<Value> = persona["traits"]
        .as_array()
        .map(|t| t.iter().map(|t| json!([t["id"], true])).collect())
        .unwrap_or_default();
    call(client, json!({"op":"confirm_traits","choices":choices})).await?;
    println!(
        "PASS: local persona research returned {} trait(s); confirmations saved",
        choices.len()
    );

    let plan = call(client, json!({"op":"generate_plan","socket":"","secrets":[],"input":{
        "confirmed_interests":["pottery","cloud science"],"cover":"gardening and nature","sensitive_consent":false,
        "activity":{"start_hour_utc":12,"target_hour_utc":12,"width_hours":6}}})).await;
    let planned = match plan {
        Ok(review) => {
            drift(client, &review).await?;
            true
        }
        // Documented: the 0.5B test model often fails the plan checks. The code
        // gate holds; the approval path needs NYMWRAP_E2E_CHAT_MODEL=7b.
        Err(code) if small && code.ends_with("plan_checks_failed") => {
            println!(
                "NOT VERIFIED: 0.5B plan rejected by code checks (plan_checks_failed); rerun with NYMWRAP_E2E_CHAT_MODEL=7b"
            );
            false
        }
        Err(code) => return Err(code),
    };
    if planned {
        purge_and_mirror(client).await?;
    } else {
        // Ranking and Mirror positions need the approved persona->cover axis.
        for command in [
            json!({"op":"purge_candidates"}),
            json!({"op":"save_snapshot","kind":"ad_topics","items":["Home gardening tools"]}),
        ] {
            match call(client, command).await {
                Err(code) if code.ends_with("plan_approval_required") => {}
                other => return Err(format!("missing plan gate: {other:?}")),
            }
        }
        // A manually chosen batch is still approved by hash without a plan.
        use sha2::Digest as _;
        let id = format!("{:x}", sha2::Sha256::digest("Watched: how clouds form"));
        let batch = json!({"service":"google","record_ids":[id]});
        let purge_hash = call(client, json!({"op":"purge_hash","batch":batch})).await?;
        call(
            client,
            json!({"op":"approve_purge","batch":batch,"hash":purge_hash}),
        )
        .await?;
        if !call(client, json!({"op":"load_purge_batches"}))
            .await?
            .as_array()
            .is_some_and(|b| b.len() == 1)
        {
            return Err("load_purge_batches: approved batch missing".into());
        }
        println!(
            "PASS: Purge batch approved by hash; ranking and Mirror correctly require an approved plan"
        );
        println!(
            "NOT VERIFIED: Purge ranking and Mirror snapshot (need an approved plan; use NYMWRAP_E2E_CHAT_MODEL=7b)"
        );
    }
    Ok(())
}
async fn purge_and_mirror(client: &Client) -> Result<(), String> {
    let candidates = call(client, json!({"op":"purge_candidates"})).await?;
    let ids: Vec<Value> = candidates
        .as_array()
        .ok_or("purge_candidates: not a list")?
        .iter()
        .take(2)
        .map(|c| c["id"].clone())
        .collect();
    if ids.is_empty() {
        return Err("purge_candidates: nothing ranked".into());
    }
    let batch = json!({"service":"google","record_ids":ids});
    let purge_hash = call(client, json!({"op":"purge_hash","batch":batch})).await?;
    call(
        client,
        json!({"op":"approve_purge","batch":batch,"hash":purge_hash}),
    )
    .await?;
    if !call(client, json!({"op":"load_purge_batches"}))
        .await?
        .as_array()
        .is_some_and(|b| b.len() == 1)
    {
        return Err("load_purge_batches: approved batch missing".into());
    }
    println!(
        "PASS: Purge ranked {} candidate(s); batch approved by hash",
        candidates.as_array().map_or(0, Vec::len)
    );

    call(client, json!({"op":"save_snapshot","kind":"ad_topics",
        "items":["Home gardening tools","Seasonal planting guides","Cloud formation documentaries"]})).await?;
    let overview = call(client, json!({"op":"workspace_status"})).await?;
    if overview["unlocked"] != true {
        return Err("workspace_status: locked after flow".into());
    }
    println!("PASS: Mirror snapshot embedded locally and stored");
    Ok(())
}

#[tokio::test]
async fn desktop_flow_owner_fixture() {
    let Some(binary) = std::env::var_os(OWNER_MODE) else {
        return;
    };
    let data = std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
    let models = std::path::PathBuf::from(std::env::var_os("NYMWRAP_E2E_MODELS").unwrap());
    let mut client = Client::spawn_daemon(Path::new(&binary)).await.unwrap();
    ready(&client).await.unwrap();
    let mut outcome = flow(&client, &models, &data).await;
    if outcome.is_ok() {
        // Lock closes SQLCipher handles and stops core; scan the store at rest,
        // then reopen in a fresh core for cleanup like the UI would.
        outcome = async {
            call(&client, json!({"op":"lock"})).await?;
            drop(client);
            tokio::time::sleep(Duration::from_secs(2)).await;
            for file in walk(&data) {
                let bytes = std::fs::read(&file).unwrap_or_default();
                for marker in [CANARY, "synthetic_xss_canary", "Repeat only the number"] {
                    if bytes.windows(marker.len()).any(|w| w == marker.as_bytes()) {
                        return Err(format!("plaintext_persisted: {}", file.display()));
                    }
                }
            }
            Ok(())
        }
        .await;
        client = Client::spawn_daemon(Path::new(&binary)).await.unwrap();
        ready(&client).await.unwrap();
        call(
            &client,
            json!({"op":"open_workspace","password":"","create":false,"profile":"standard"}),
        )
        .await
        .unwrap();
        if outcome.is_ok() {
            println!(
                "PASS: no synthetic plaintext in any file under the data directory after lock"
            );
        }
    }
    // Cleanup precedes assertions: the synthetic workspace and its OS key entry go.
    let destroyed = match call(&client, json!({"op":"workspace_status"})).await {
        Ok(status) if status["unlocked"] == true => call(
            &client,
            json!({"op":"destroy_data","confirmation":"СТЕРЕТЬ ВСЁ"}),
        )
        .await
        .map(drop),
        Ok(_) => Ok(()),
        Err(code) => Err(code),
    };
    drop(client);
    outcome.unwrap();
    destroyed.unwrap();
    println!("NYMWRAP_DESKTOP_FLOW_OK");
}

#[tokio::test]
#[ignore = "opt-in: real OS key store, built daemons and pinned GGUFs in target/test-models"]
async fn actual_desktop_backend_flow_with_local_models() {
    assert_eq!(
        std::env::var(OPT_IN).as_deref(),
        Ok("1"),
        "set {OPT_IN}=1 to allow a disposable OS key store entry"
    );
    let binary = Path::new(env!("CARGO_BIN_EXE_nymwrapd"));
    for worker in ["nw-api", "nw-llmd", "nw-audit-worker"] {
        assert!(
            binary
                .with_file_name(format!("{worker}{}", std::env::consts::EXE_SUFFIX))
                .is_file(),
            "build {worker} first: cargo build --workspace --bins --locked"
        );
    }
    let models = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-models");
    for (file, _) in [CHAT_MODEL, EMBED_MODEL] {
        assert!(
            models.join(file).is_file(),
            "run scripts/fetch-test-models.ps1 first"
        );
    }
    #[cfg(unix)]
    let directory = tempfile::Builder::new()
        .prefix("nw-flow-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(windows)]
    let directory = tempfile::Builder::new()
        .prefix("nw-flow-")
        .tempdir()
        .unwrap();
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "desktop_flow_owner_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(OWNER_MODE, binary)
        .env("NYMWRAP_E2E_MODELS", models.canonicalize().unwrap())
        .env("LOCALAPPDATA", directory.path())
        .env("XDG_DATA_HOME", directory.path())
        .env("XDG_RUNTIME_DIR", directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let result = tokio::time::timeout(Duration::from_secs(1500), command.output()).await;
    let output = result.expect("desktop flow timed out").unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{stdout}");
    directory.close().unwrap();
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("NYMWRAP_DESKTOP_FLOW_OK"));
}
fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}
