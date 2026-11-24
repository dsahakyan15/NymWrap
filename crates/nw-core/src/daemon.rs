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
    if args.len() != 1 || args[0] != "--bootstrap-stdin" {
        return Err("invalid_arguments".into());
    }
    nw_platform::harden_process()?;
    let parent = nw_core::service::ParentSession::read(nw_core::service::RpcRole::Control).await?;
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
    let mut service = nw_core::service::Service::runtime(egress);
    let mut parent_closed = service.authorize_parent(parent)?;
    let api_binary = std::env::current_exe()?
        .parent()
        .ok_or("runtime_component_missing")?
        .join(format!("nw-api{}", std::env::consts::EXE_SUFFIX));
    let _api = service.spawn_api(&api_binary).await?;
    let mut parent_gone = false;
    let shadow_service = service.serve_shadow(shadow);
    let cover_service = service.serve_cover(cover);
    let traffic_service = service.run_traffic();
    tokio::pin!(shadow_service, cover_service, traffic_service);
    loop {
        tokio::select! {
          result=&mut shadow_service=>{result?;},
          result=&mut cover_service=>{result?;},
          _traffic=&mut traffic_service=>{},
          _signal=tokio::signal::ctrl_c()=>{},
          _stopped=service.stopped()=>{},
          _parent=&mut parent_closed, if !parent_gone=>{
              parent_gone = true;
              let reply = service.handle(nw_core::service::Command::CloseSession {}).await;
              if matches!(reply, nw_core::service::Reply::SessionTiming {
                  value: nw_core::service::SessionTiming {
                      phase: nw_core::service::SessionPhase::Tail, ..
                  }
              }) {
                  continue;
              }
          },
        }
        break;
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
