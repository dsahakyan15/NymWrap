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
            "nw-api [--socket <private endpoint>]\nL0 API via Unix socket / Windows named pipe. Unlock the workspace in NymWrap first."
        );
        return Ok(());
    }
    {
        use std::sync::Arc;
        nw_platform::harden_process().map_err(|_| "process_hardening_failed")?;
        #[cfg(target_os = "linux")]
        nw_platform::deny_remote_sockets().map_err(|_| "sandbox_unavailable")?;
        let paths = nw_core::config::Paths::discover().map_err(|_| "runtime_path_unavailable")?;
        if !args.len().is_multiple_of(2)
            || args.as_chunks::<2>().0.iter().any(|p| p[0] != "--socket")
            || args.len() > 2
        {
            return Err("invalid_arguments");
        }
        let value = |flag: &str| args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone());
        let socket = value("--socket").unwrap_or(paths.api);
        let engine = Arc::new(
            nw_core::service::Client::current_user().map_err(|_| "invalid_core_endpoint")?,
        );
        let listener = nw_api::bind_private(std::path::Path::new(&socket))
            .map_err(|_| "private_socket_bind_failed")?;
        axum::serve(listener, nw_api::router(engine))
            .await
            .map_err(|_| "api_server_failed")
    }
}
