use nw_net::wire::{Command, Envelope, MAX_WIRE, Response, SessionKey};
use nw_proto::Lane;
use zeroize::{Zeroize, Zeroizing};
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("nw_netd_stopped");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "nw-netd --socket <private endpoint>\nSession key: exactly 32 bytes on inherited stdin. Authenticated initialization is required before any Tor bootstrap. Stdin EOF stops the daemon."
        );
        return Ok(());
    }
    if args.len() != 2 || args[0] != "--socket" {
        return Err("invalid_arguments".into());
    }
    nw_platform::harden_process()?;
    let endpoint = nw_ipc::Endpoint::new(args[1].clone(), Lane::Shadow)?;
    let mut bytes = Zeroizing::new([0; 32]);
    use std::io::Read;
    std::io::stdin().read_exact(&mut *bytes)?;
    let key = SessionKey::new(*bytes)?;
    bytes.zeroize();
    // EOF on the parent-owned pipe cancels all network work after parent death.
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte);
        let _ = tx.send(());
    });
    let listener = nw_ipc::Listener::bind(endpoint)?;
    let serve = async {
        let mut expected = 1u64;
        let mut tor: Option<nw_netd::Tor> = None;
        loop {
            let mut stream = listener.accept().await?;
            let bytes = match nw_ipc::read_frame(&mut stream, MAX_WIRE * 5).await {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let envelope: Envelope = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let command: Command = match key.open(&envelope, expected) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let sequence = expected;
            expected = expected.checked_add(1).ok_or("egress_sequence_exhausted")?;
            let response = match &command {
                Command::Initialize {
                    state,
                    host,
                    path,
                    bridges,
                } if tor.is_none() => {
                    let result = async {
                        let provider = nw_netd::Provider::new(host.clone(), path.clone())?;
                        nw_netd::Tor::bootstrap_with_bridges(
                            std::path::Path::new(state),
                            provider,
                            bridges.as_ref(),
                        )
                        .await
                    }
                    .await;
                    match result {
                        Ok(client) => {
                            tor = Some(client);
                            Response::Ready {}
                        }
                        Err(code) => Response::Error { code: code.into() },
                    }
                }
                Command::Initialize { .. } => Response::Error {
                    code: "transport_already_initialized".into(),
                },
                Command::Reset {} => {
                    tor = None;
                    Response::Ready {}
                }
                Command::Send { request } => match &tor {
                    Some(tor) => match tor.send(request).await {
                        Ok(text) => Response::Answer { text },
                        Err(code) => Response::Error { code: code.into() },
                    },
                    None => Response::Error {
                        code: "transport_not_initialized".into(),
                    },
                },
                Command::SendOnce { request } => match &tor {
                    Some(tor) => match tor.send_once(request).await {
                        Ok(text) => Response::Answer { text },
                        Err(code) => Response::Error { code: code.into() },
                    },
                    None => Response::Error {
                        code: "transport_not_initialized".into(),
                    },
                },
            };
            let envelope = key.seal(sequence, &response)?;
            let bytes = Zeroizing::new(serde_json::to_vec(&envelope)?);
            // Failure is never retried: a provider may already have received the request.
            let _ = nw_ipc::write_frame(&mut stream, &bytes, MAX_WIRE * 5).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    tokio::select! {result=serve=>result?,_=&mut rx=>{},_=tokio::signal::ctrl_c()=>{}}
    Ok(())
}
