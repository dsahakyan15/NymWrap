#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("nymwrapd_stopped");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!(
            "nymwrapd\nPrivate per-user shadow and cover IPC. Unlock the encrypted workspace in NymWrap."
        );
        return Ok(());
    }
    if !args.is_empty() {
        return Err("invalid_arguments".into());
    }
    nw_platform::harden_process()?;
    let paths = nw_core::config::Paths::discover()?;
    let egress = spawn_egress(&paths).await;
    // The idle network child already exists. This filter is never weakened.
    #[cfg(target_os = "linux")]
    nw_platform::deny_remote_sockets()?;
    let shadow = nw_ipc::Listener::bind(nw_ipc::Endpoint::new(
        paths.core_shadow,
        nw_proto::Lane::Shadow,
    )?)?;
    let cover = nw_ipc::Listener::bind(nw_bridge::endpoint()?)?;
    let service = nw_core::service::Service::runtime(egress);
    tokio::select! {
        result=service.serve_shadow(shadow)=>{result?;},
        result=service.serve_cover(cover)=>{result?;},
        _traffic=service.run_traffic()=>{},
        _signal=tokio::signal::ctrl_c()=>{},
        _stopped=service.stopped()=>{},
    }
    let _ = service.handle(nw_core::service::Command::Lock {}).await;
    Ok(())
}
async fn spawn_egress(
    paths: &nw_core::config::Paths,
) -> Option<std::sync::Arc<nw_net::client::Client>> {
    let name = format!("nw-netd{}", std::env::consts::EXE_SUFFIX);
    let mut candidates = vec![std::env::current_exe().ok()?.parent()?.join(&name)];
    if cfg!(debug_assertions) {
        candidates.push(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../daemons/nw-netd/target/debug")
                .join(name),
        );
    }
    let binary = candidates.into_iter().find(|p| p.is_file())?;
    let endpoint = nw_ipc::Endpoint::new(paths.net.clone(), nw_proto::Lane::Shadow).ok()?;
    Some(std::sync::Arc::new(
        nw_net::client::Client::spawn(&binary, endpoint)
            .await
            .ok()?,
    ))
}
