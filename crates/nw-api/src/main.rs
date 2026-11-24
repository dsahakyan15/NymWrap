#[tokio::main]
async fn main() {
    if let Err(code) = run().await {
        eprintln!("nw-api: {code}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|s| s == "--help") {
        println!(
            "nw-api --bootstrap-stdin [--socket <private endpoint>]\nStarted by the NymWrap core with an inherited API session. Unlock the workspace in NymWrap."
        );
        return Ok(());
    }
    {
        use std::sync::Arc;
        nw_platform::harden_process().map_err(|_| "process_hardening_failed")?;
        #[cfg(target_os = "linux")]
        nw_platform::deny_remote_sockets().map_err(|_| "sandbox_unavailable")?;
        let paths = nw_core::config::Paths::discover().map_err(|_| "runtime_path_unavailable")?;
        let Some(options) = args.strip_prefix(&["--bootstrap-stdin".to_owned()]) else {
            return Err("api_requires_desktop_session");
        };
        if !options.len().is_multiple_of(2)
            || options
                .as_chunks::<2>()
                .0
                .iter()
                .any(|p| p[0] != "--socket")
            || options.len() > 2
        {
            return Err("invalid_arguments");
        }
        let value = |flag: &str| args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone());
        let socket = value("--socket").unwrap_or(paths.api);
        let parent = nw_core::service::ParentSession::read(nw_core::service::RpcRole::Api)
            .await
            .map_err(|_| "ipc_bootstrap_failed")?;
        let (client, parent_closed) =
            nw_core::service::Client::from_parent(parent).map_err(|_| "invalid_core_endpoint")?;
        let engine = Arc::new(client);
        let listener = nw_api::bind_private(std::path::Path::new(&socket))
            .map_err(|_| "private_socket_bind_failed")?;
        tokio::select! {
            result = axum::serve(listener, nw_api::router(engine)).into_future() =>
                result.map_err(|_| "api_server_failed"),
            _closed = parent_closed => Ok(()),
        }
    }
}
