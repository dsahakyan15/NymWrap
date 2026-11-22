#[cfg(feature = "inference")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    nw_platform::harden_process()?;
    #[cfg(target_os = "linux")]
    nw_platform::deny_remote_sockets()?;
    let mut args = std::env::args().skip(1);
    let (mut socket, mut model, mut hash, mut embed, mut embed_hash) =
        (None, None, None, None, None);
    let mut parent_stdio = false;
    let mut worker_stdio = false;
    let (mut chat_handle, mut embed_handle) = (None, None);
    while let Some(flag) = args.next() {
        if flag == "--worker-stdio" {
            if worker_stdio {
                return Err("duplicate_argument".into());
            }
            worker_stdio = true;
            continue;
        }
        if flag == "--parent-stdio" {
            if parent_stdio {
                return Err("duplicate_argument".into());
            }
            parent_stdio = true;
            continue;
        }
        if flag == "--help" {
            println!(
                "nw-llmd --socket PRIVATE_ENDPOINT --model ABSOLUTE_GGUF --sha256 HASH --embed-model ABSOLUTE_GGUF --embed-sha256 HASH"
            );
            return Ok(());
        }
        let value = args.next().ok_or("missing_argument")?;
        let target = match flag.as_str() {
            "--socket" => &mut socket,
            "--model" => &mut model,
            "--sha256" => &mut hash,
            "--embed-model" => &mut embed,
            "--embed-sha256" => &mut embed_hash,
            "--chat-handle" => &mut chat_handle,
            "--embed-handle" => &mut embed_handle,
            _ => return Err("invalid_argument".into()),
        };
        if target.replace(value).is_some() {
            return Err("duplicate_argument".into());
        }
    }
    if worker_stdio {
        if socket.is_some() || model.is_some() || embed.is_some() || parent_stdio {
            return Err("invalid_worker_argument".into());
        }
        #[cfg(windows)]
        return nw_llmd::isolation::worker(
            chat_handle.ok_or("chat_handle_required")?.parse()?,
            &hash.ok_or("model_hash_required")?,
            embed_handle.ok_or("embed_handle_required")?.parse()?,
            &embed_hash.ok_or("embedding_hash_required")?,
        )
        .map_err(Into::into);
        #[cfg(not(windows))]
        return Err("worker_platform_unsupported".into());
    }
    if chat_handle.is_some() || embed_handle.is_some() {
        return Err("invalid_argument".into());
    }
    let endpoint = nw_ipc::Endpoint::new(socket.ok_or("socket_required")?, nw_proto::Lane::Shadow)?;
    if parent_stdio {
        std::thread::spawn(|| {
            use std::io::Read;
            let mut byte = [0];
            let _ = std::io::stdin().read(&mut byte);
            std::process::exit(0);
        });
    }
    #[cfg(not(windows))]
    use nw_llmd::inference::Cpu as Backend;
    #[cfg(windows)]
    use nw_llmd::isolation::Isolated as Backend;
    let backend = Backend::load(
        std::path::Path::new(&model.ok_or("model_required")?),
        &hash.ok_or("model_hash_required")?,
        std::path::Path::new(&embed.ok_or("embedding_model_required")?),
        &embed_hash.ok_or("embedding_hash_required")?,
    )?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = nw_ipc::Listener::bind(endpoint)?;
            axum::serve(listener, nw_llmd::router(backend))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
            Ok(())
        })
}
#[cfg(not(feature = "inference"))]
fn main() {
    eprintln!("inference_feature_required");
    std::process::exit(1);
}
