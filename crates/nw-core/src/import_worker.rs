//! Treat the parser as an untrusted child; only a bounded summary comes back.
#[cfg(target_os = "linux")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(any(windows, target_os = "linux"))]
use zeroize::Zeroizing;
#[cfg(not(any(windows, target_os = "linux")))]
pub async fn import(
    _bytes: &[u8],
    _format: nw_audit::Format,
) -> Result<nw_audit::Summary, &'static str> {
    Err("import_sandbox_unavailable")
}
#[cfg(windows)]
pub async fn import(
    bytes: &[u8],
    format: nw_audit::Format,
) -> Result<nw_audit::Summary, &'static str> {
    if bytes.len() > nw_audit::MAX_IMPORT_BYTES {
        return Err("import_too_large");
    }
    let program = std::env::current_exe()
        .map_err(|_| "import_worker_unavailable")?
        .parent()
        .ok_or("import_worker_unavailable")?
        .join("nw-audit-worker.exe");
    let mut header = serde_json::to_vec(&format).map_err(|_| "invalid_import")?;
    header.push(b'\n');
    let mut request = Zeroizing::new(Vec::with_capacity(4 + header.len() + bytes.len()));
    request.extend_from_slice(&((header.len() + bytes.len()) as u32).to_le_bytes());
    request.extend_from_slice(&header);
    request.extend_from_slice(bytes);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        tokio::task::spawn_blocking(move || nw_sandbox::parser_exchange(&program, request)),
    )
    .await
    .map_err(|_| "import_worker_timeout")?
    .map_err(|_| "import_worker_failed")?
    .map_err(|_| "import_sandbox_unavailable")?;
    if output.exit_code != 0 || output.stdout.len() < 4 {
        return Err("import_worker_failed");
    }
    let size = u32::from_le_bytes(
        output.stdout[..4]
            .try_into()
            .map_err(|_| "invalid_import_result")?,
    ) as usize;
    if size == 0 || size > 4 * 1024 * 1024 || output.stdout.len() != 4 + size {
        return Err("invalid_import_result");
    }
    decode_response(&output.stdout[4..])
}
#[cfg(target_os = "linux")]
pub async fn import(
    bytes: &[u8],
    format: nw_audit::Format,
) -> Result<nw_audit::Summary, &'static str> {
    if bytes.len() > nw_audit::MAX_IMPORT_BYTES {
        return Err("import_too_large");
    }
    let program = std::env::current_exe()
        .map_err(|_| "import_worker_unavailable")?
        .parent()
        .ok_or("import_worker_unavailable")?
        .join(format!("nw-audit-worker{}", std::env::consts::EXE_SUFFIX));
    let command =
        nw_sandbox::isolated_worker(&program).map_err(|_| "import_sandbox_unavailable")?;
    let mut command = tokio::process::Command::from(command);
    command
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    for name in ["SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().map_err(|_| "import_worker_unavailable")?;
    let operation = async {
        let mut input = child.stdin.take().ok_or("import_worker_failed")?;
        let mut output = child.stdout.take().ok_or("import_worker_failed")?;
        let mut header = serde_json::to_vec(&format).map_err(|_| "invalid_import")?;
        header.push(b'\n');
        input
            .write_u32_le((header.len() + bytes.len()) as u32)
            .await
            .map_err(|_| "import_worker_failed")?;
        input
            .write_all(&header)
            .await
            .map_err(|_| "import_worker_failed")?;
        input
            .write_all(bytes)
            .await
            .map_err(|_| "import_worker_failed")?;
        input.shutdown().await.map_err(|_| "import_worker_failed")?;
        drop(input);
        let size = output
            .read_u32_le()
            .await
            .map_err(|_| "import_worker_failed")? as usize;
        if size == 0 || size > 4 * 1024 * 1024 {
            return Err("invalid_import_result");
        }
        let mut response = Zeroizing::new(vec![0; size]);
        output
            .read_exact(&mut response)
            .await
            .map_err(|_| "import_worker_failed")?;
        if !child
            .wait()
            .await
            .map_err(|_| "import_worker_failed")?
            .success()
        {
            return Err("import_worker_failed");
        }
        decode_response(&response)
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), operation)
        .await
        .map_err(|_| "import_worker_timeout")?
}
#[cfg(any(windows, target_os = "linux"))]
fn decode_response(response: &[u8]) -> Result<nw_audit::Summary, &'static str> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        summary: Option<nw_audit::Summary>,
        error: Option<String>,
    }
    let reply: Reply = serde_json::from_slice(response).map_err(|_| "invalid_import_result")?;
    match (reply.summary, reply.error) {
        (Some(summary), None) if valid_summary(&summary) => Ok(summary),
        (None, Some(error)) => Err(match error.as_str() {
            "import_too_large" => "import_too_large",
            "wal_snapshot_requires_backup" => "wal_snapshot_requires_backup",
            _ => "invalid_import",
        }),
        _ => Err("invalid_import_result"),
    }
}
#[cfg(any(windows, target_os = "linux"))]
fn valid_summary(summary: &nw_audit::Summary) -> bool {
    summary.records <= 50_000
        && summary.skipped_files <= 2000
        && summary.domains.len() <= 50_000
        && summary.domains.iter().all(|(domain, n)| {
            domain.len() <= 253
                && !domain.is_empty()
                && domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                && *n <= summary.records
        })
        && summary
            .activity_hours
            .iter()
            .all(|(hour, n)| *hour < 24 && *n <= summary.records)
        && [
            (&summary.titles, 300, 1024),
            (&summary.searches, 300, 2048),
            (&summary.prompt_samples, 30, 2048),
        ]
        .iter()
        .all(|(texts, count, length)| {
            texts.len() <= *count
                && texts
                    .iter()
                    .all(|s| s.chars().count() <= *length && !s.chars().any(char::is_control))
        })
}
