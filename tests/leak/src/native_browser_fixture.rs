//! Test-only parent of the actual release core, using the desktop's Client.
//! Never packaged as a runtime component; stdin/stdout carry synthetic data only.
use nw_core::service::{Client, Command, Reply};
use std::{
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    time::Duration,
};
use zeroize::Zeroizing;

#[tokio::main]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    nw_platform::harden_process()?;
    let binary = PathBuf::from(std::env::args_os().nth(1).ok_or("missing_core_binary")?);
    let client = Client::spawn_daemon(&binary).await?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = Zeroizing::new(Vec::new());
        let size = (&mut input).take(4097).read_until(b'\n', &mut line)?;
        if size == 0 {
            break;
        }
        if size > 4096 || !line.ends_with(b"\n") {
            return Err("invalid_fixture_frame".into());
        }
        let command: Command = serde_json::from_slice(&line)?;
        if !matches!(
            command,
            Command::Status {}
                | Command::OpenWorkspace { .. }
                | Command::WorkspaceStatus {}
                | Command::LoadNetworkUsage {}
                | Command::DestroyData { .. }
        ) {
            return Err("invalid_fixture_command".into());
        }
        let result = client.request(command).await.and_then(Reply::into_json);
        // Only responses requested by the synthetic fixture cross this pipe.
        let response = match result {
            Ok(value) => serde_json::json!({"value": value}),
            Err(code) => serde_json::json!({"error": code}),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&response)?);
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    // EOF revokes the retained session even if the JS fixture failed midway.
    let _ = tokio::time::timeout(Duration::from_secs(5), client.request(Command::Lock {})).await;
    Ok(())
}
