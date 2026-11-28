fn main() {
    if start().is_err() {
        eprintln!("nymwrapd_stopped");
        std::process::exit(1);
    }
}
struct Launch {
    #[cfg(target_os = "linux")]
    namespace: Option<nw_net::launcher::LinuxNamespace>,
}
fn start() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!(
            "nymwrapd --bootstrap-stdin\nLinux administrative mode: --bootstrap-stdin --netns <absolute path> --uid <nonzero uid> --gid <nonzero gid>. Provision the transport namespace before launch; no privilege escalation or host-network fallback."
        );
        return Ok(());
    }
    if args.first().is_none_or(|arg| arg != "--bootstrap-stdin") {
        return Err("invalid_arguments".into());
    }
    // Disable crash dumps before any session key exists. Repeat after the
    // identity transition, which can reset the kernel's dumpable attribute.
    nw_platform::harden_process()?;
    #[cfg(target_os = "linux")]
    let namespace = match args.as_slice() {
        [_] if nw_platform::current_user_id()? != "0" => None,
        [_, netns, path, uid, user, gid, group]
            if netns == "--netns" && uid == "--uid" && gid == "--gid" =>
        {
            Some(nw_net::launcher::LinuxNamespace::prepare(
                std::path::Path::new(path),
                user.to_str().ok_or("invalid_uid")?.parse()?,
                group.to_str().ok_or("invalid_gid")?.parse()?,
            )?)
        }
        _ => return Err("invalid_arguments".into()),
    };
    #[cfg(not(target_os = "linux"))]
    if args.len() != 1 {
        return Err("invalid_arguments".into());
    }
    let launch = Launch {
        #[cfg(target_os = "linux")]
        namespace,
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(launch))
}
async fn run(launch: Launch) -> Result<(), Box<dyn std::error::Error>> {
    let paths = nw_core::config::Paths::discover()?;
    let egress = spawn_egress(&paths, launch).await?;
    nw_platform::harden_process()?;
    // The idle network child already exists. This filter is never weakened.
    #[cfg(target_os = "linux")]
    nw_platform::deny_remote_sockets()?;
    let parent = nw_core::service::ParentSession::read(nw_core::service::RpcRole::Control).await?;
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
    let api = service.spawn_api(&api_binary).await?;
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
    api.shutdown().await?;
    Ok(())
}
async fn spawn_egress(
    paths: &nw_core::config::Paths,
    launch: Launch,
) -> Result<Option<std::sync::Arc<nw_net::client::Client>>, Box<dyn std::error::Error>> {
    let candidates = egress_candidates(
        std::env::current_exe()?
            .parent()
            .ok_or("runtime_path_unavailable")?,
        cfg!(debug_assertions),
    );
    let binary = candidates
        .iter()
        .find(|p| p.is_file())
        .unwrap_or(&candidates[0]);
    let endpoint = nw_ipc::Endpoint::new(paths.net.clone(), nw_proto::Lane::Shadow)?;
    #[cfg(target_os = "linux")]
    let client = match launch.namespace {
        Some(namespace) => Some(namespace.spawn(binary, endpoint).await?),
        None => None, // L0 only: never silently start netd on the host network.
    };
    #[cfg(not(target_os = "linux"))]
    let client = {
        let _ = launch;
        nw_net::client::Client::spawn(binary, endpoint).await.ok()
    };
    Ok(client.map(std::sync::Arc::new))
}
/// nw-netd is outside the root workspace, so `cargo build --workspace` never
/// refreshes target/debug/nw-netd. In debug builds the separately built netd
/// comes first; a stale sibling left by an older layout must not shadow it.
fn egress_candidates(exe_dir: &std::path::Path, debug: bool) -> Vec<std::path::PathBuf> {
    let name = format!("nw-netd{}", std::env::consts::EXE_SUFFIX);
    let sibling = exe_dir.join(&name);
    if !debug {
        return vec![sibling];
    }
    vec![
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../daemons/nw-netd/target/debug")
            .join(name),
        sibling,
    ]
}
#[cfg(test)]
mod tests {
    use super::egress_candidates;
    #[test]
    fn debug_prefers_separately_built_netd_over_stale_workspace_sibling() {
        let exe_dir = std::path::Path::new("synthetic-target").join("debug");
        let debug = egress_candidates(&exe_dir, true);
        assert_eq!(debug.len(), 2);
        assert!(
            debug[0].ends_with(
                std::path::Path::new("daemons/nw-netd/target/debug")
                    .join(format!("nw-netd{}", std::env::consts::EXE_SUFFIX))
            )
        );
        assert_eq!(debug[1].parent(), Some(exe_dir.as_path()));
        assert_eq!(
            egress_candidates(&exe_dir, false),
            vec![exe_dir.join(format!("nw-netd{}", std::env::consts::EXE_SUFFIX))]
        );
    }
}
