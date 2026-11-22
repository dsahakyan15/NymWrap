//! A short-lived trusted inventory worker. Never run it without OS confinement.
#[cfg(any(windows, target_os = "linux"))]
use nw_probe::Hints;
#[cfg(any(windows, target_os = "linux", test))]
use nw_probe::MAX_FRAME;
use nw_probe::Report;
#[cfg(any(windows, target_os = "linux"))]
use std::path::PathBuf;
#[cfg(any(windows, target_os = "linux"))]
use zeroize::Zeroizing;
pub(crate) async fn collect() -> Result<Report, &'static str> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("probe_sandbox_unavailable")
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let program = std::env::current_exe()
            .map_err(|_| "probe_unavailable")?
            .parent()
            .ok_or("probe_unavailable")?
            .join(format!("nw-probe{}", std::env::consts::EXE_SUFFIX));
        let hints = Hints::from_environment();
        if !hints.valid() {
            return Err("invalid_probe_request");
        }
        let git = hints
            .home
            .as_ref()
            .and_then(|home| open_git(PathBuf::from(home).join(".gitconfig")));
        let bytes =
            Zeroizing::new(serde_json::to_vec(&hints).map_err(|_| "invalid_probe_request")?);
        let mut input = Zeroizing::new(Vec::with_capacity(4 + bytes.len()));
        input.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        input.extend_from_slice(&bytes);
        #[cfg(windows)]
        let output = {
            tokio::task::spawn_blocking(move || {
                nw_sandbox::probe_exchange(&program, git.as_ref(), input)
            })
            .await
            .map_err(|_| "probe_failed")?
            .map_err(|_| "probe_sandbox_unavailable")?
        };
        #[cfg(windows)]
        {
            if output.exit_code != 0 {
                return Err("probe_failed");
            }
            decode(&output.stdout)
        }
        #[cfg(target_os = "linux")]
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let command = nw_sandbox::probe_command(&program, git.as_ref())
                .map_err(|_| "probe_sandbox_unavailable")?;
            let mut child = tokio::process::Command::from(command)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| "probe_sandbox_unavailable")?;
            let operation = async {
                let mut stdin = child.stdin.take().ok_or("probe_failed")?;
                let stdout = child.stdout.take().ok_or("probe_failed")?;
                stdin.write_all(&input).await.map_err(|_| "probe_failed")?;
                stdin.shutdown().await.map_err(|_| "probe_failed")?;
                drop(stdin);
                let mut result = Zeroizing::new(vec![]);
                stdout
                    .take(MAX_FRAME as u64 + 5)
                    .read_to_end(&mut result)
                    .await
                    .map_err(|_| "probe_failed")?;
                if !child.wait().await.map_err(|_| "probe_failed")?.success() {
                    return Err("probe_failed");
                }
                decode(&result)
            };
            tokio::time::timeout(std::time::Duration::from_secs(30), operation)
                .await
                .map_err(|_| "probe_timeout")?
        }
    }
}
#[cfg(any(windows, target_os = "linux"))]
fn open_git(path: PathBuf) -> Option<std::fs::File> {
    nw_platform::open_device_config(&path).ok()
}
#[cfg(any(windows, target_os = "linux", test))]
fn decode(bytes: &[u8]) -> Result<Report, &'static str> {
    if bytes.len() < 4 || bytes.len() > MAX_FRAME + 4 {
        return Err("invalid_probe_result");
    }
    let len =
        u32::from_le_bytes(bytes[..4].try_into().map_err(|_| "invalid_probe_result")?) as usize;
    if len == 0 || len > MAX_FRAME || bytes.len() != 4 + len {
        return Err("invalid_probe_result");
    }
    let report: Report = serde_json::from_slice(&bytes[4..]).map_err(|_| "invalid_probe_result")?;
    if !report.valid() {
        return Err("invalid_probe_result");
    }
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_probe_frame_and_schema_are_required_without_echoing_content() {
        for bytes in [vec![], vec![0; 4], vec![255; 4]] {
            assert!(decode(&bytes).is_err());
        }
        let payload=br#"{"version":1,"lane":"shadow","values":[{"source":"host","value":"SYNTHETIC_PROBE_CANARY_7746"}],"unavailable":[]}"#;
        let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(payload);
        assert!(decode(&frame).unwrap().valid());
        frame.push(0);
        assert!(decode(&frame).is_err());
    }
}
