//! Browser native messaging host. Stdout is reserved exclusively for framed replies.
fn main() {
    if start().is_err() {
        eprintln!("cover_native_host_stopped");
        std::process::exit(1);
    }
}
fn start() -> std::io::Result<()> {
    #[cfg(any(windows, target_os = "linux"))]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|s| s == "--sandbox-relay")
    {
        nw_sandbox::daemon::seal().map_err(std::io::Error::other)?;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            #[cfg(any(windows, target_os = "linux"))]
            if std::env::args_os()
                .nth(1)
                .is_none_or(|s| s != "--sandbox-relay")
            {
                return launch_relay().await;
            }
            run().await
        })
}
#[cfg(any(windows, target_os = "linux"))]
async fn launch_relay() -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let endpoint = nw_bridge::endpoint().map_err(std::io::Error::other)?;
    let mut child = nw_sandbox::daemon::Launch {
        profile: nw_sandbox::daemon::Profile::DriftHost,
        binary: std::env::current_exe()?,
        arguments: vec![
            "--sandbox-relay".into(),
            "--cover-socket".into(),
            endpoint.value().into(),
        ],
        listener: None,
        upstream: vec![endpoint.value().into()],
        files: vec![],
        environment: vec![],
    }
    .spawn()
    .await
    .map_err(std::io::Error::other)?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("host_pipe_unavailable"))?;
    let mut output = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("host_pipe_unavailable"))?;
    let mut browser_input = tokio::io::stdin();
    let mut browser_output = tokio::io::stdout();
    loop {
        let mut length = [0; 4];
        match browser_input.read_exact(&mut length).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let size = u32::from_le_bytes(length) as usize;
        if size == 0 || size > nw_proto::MAX_FRAME_BYTES {
            return Err(std::io::Error::other("invalid_native_frame"));
        }
        let mut bytes = vec![0; size];
        browser_input.read_exact(&mut bytes).await?;
        input.write_all(&length).await?;
        input.write_all(&bytes).await?;
        input.flush().await?;
        output.read_exact(&mut length).await?;
        let size = u32::from_le_bytes(length) as usize;
        if size == 0 || size > nw_proto::MAX_FRAME_BYTES {
            return Err(std::io::Error::other("invalid_native_frame"));
        }
        bytes.resize(size, 0);
        output.read_exact(&mut bytes).await?;
        browser_output.write_all(&length).await?;
        browser_output.write_all(&bytes).await?;
        browser_output.flush().await?;
    }
    drop(input);
    tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
        .await
        .map_err(std::io::Error::other)??;
    Ok(())
}
async fn run() -> std::io::Result<()> {
    nw_platform::harden_process()?;
    #[cfg(any(windows, target_os = "linux"))]
    let endpoint = {
        let arguments: Vec<_> = std::env::args().skip(1).collect();
        if arguments.len() != 3
            || arguments[0] != "--sandbox-relay"
            || arguments[1] != "--cover-socket"
        {
            return Err(std::io::Error::other("invalid_relay_arguments"));
        }
        nw_ipc::Endpoint::new(arguments[2].clone(), nw_proto::Lane::Cover)
            .map_err(std::io::Error::other)?
    };
    #[cfg(not(any(windows, target_os = "linux")))]
    let endpoint = nw_bridge::endpoint().map_err(std::io::Error::other)?;
    let (mut input, mut output) = (std::io::stdin().lock(), std::io::stdout().lock());
    nw_drift_host::relay(&endpoint, &mut input, &mut output).await
}
