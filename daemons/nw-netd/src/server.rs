//! One authenticated dispatcher for the daemon and test-only private transports.
use crate::{Provider, Tor};
use nw_ipc::Listener;
use nw_net::{
    bridges::BridgeConfig,
    wire::{Command, Envelope, MAX_WIRE, Request, Response, SessionKey},
};
use nw_proto::Lane;
use std::{future::Future, path::Path, time::Duration};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "../../../tests/leak/src/netd_dispatcher.rs"]
mod tests;

const AUTHENTICATION_DEADLINE: Duration = Duration::from_secs(2);

pub(crate) trait Connection: Send + Sync {
    fn transmit(
        &self,
        request: &Request,
        once: bool,
    ) -> impl Future<Output = Result<String, &'static str>> + Send;
}
impl Connection for Tor {
    async fn transmit(&self, request: &Request, once: bool) -> Result<String, &'static str> {
        if once {
            Tor::send_once(self, request).await
        } else {
            Tor::send(self, request).await
        }
    }
}
pub(crate) trait Factory: Send + Sync {
    type Transport: Connection;
    fn bootstrap(
        &self,
        directory: &Path,
        provider: Provider,
        bridges: Option<&BridgeConfig>,
    ) -> impl Future<Output = Result<Self::Transport, &'static str>> + Send;
}
struct Production;
impl Factory for Production {
    type Transport = Tor;
    async fn bootstrap(
        &self,
        directory: &Path,
        provider: Provider,
        bridges: Option<&BridgeConfig>,
    ) -> Result<Tor, &'static str> {
        Tor::bootstrap_with_bridges(directory, provider, bridges).await
    }
}
/// Release always uses the production Tor constructor. Alternate factories are
/// crate-private, with no CLI flag, environment switch or wire operation.
pub async fn serve(listener: Listener, key: SessionKey) -> Result<(), &'static str> {
    serve_with(listener, key, Production).await
}
pub(crate) async fn serve_with<F: Factory>(
    listener: Listener,
    key: SessionKey,
    factory: F,
) -> Result<(), &'static str> {
    if listener.lane() != Lane::Shadow {
        return Err("ipc_wrong_lane");
    }
    let mut expected = 1u64;
    let mut transport: Option<F::Transport> = None;
    loop {
        let mut stream = listener
            .accept()
            .await
            .map_err(|_| "egress_accept_failed")?;
        // The connection has not proved possession of the session key and must
        // not inherit the 120-second deadline of authenticated bulk I/O.
        let bytes =
            match nw_ipc::read_frame_timeout(&mut stream, MAX_WIRE * 5, AUTHENTICATION_DEADLINE)
                .await
            {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
        let envelope: Envelope = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let command: Command = match key.open(&envelope, expected) {
            Ok(command) => command,
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
            } if transport.is_none() => {
                let initialized = async {
                    let provider = Provider::new(host.clone(), path.clone())?;
                    factory
                        .bootstrap(Path::new(state), provider, bridges.as_ref())
                        .await
                }
                .await;
                match initialized {
                    Ok(connection) => {
                        transport = Some(connection);
                        Response::Ready {}
                    }
                    Err(code) => Response::Error { code: code.into() },
                }
            }
            Command::Initialize { .. } => Response::Error {
                code: "transport_already_initialized".into(),
            },
            Command::Reset {} => {
                transport = None;
                Response::Ready {}
            }
            Command::Send { request } | Command::SendOnce { request } => match &transport {
                Some(connection) => match connection
                    .transmit(request, matches!(&command, Command::SendOnce { .. }))
                    .await
                {
                    Ok(text) => Response::Answer { text },
                    Err(code) => Response::Error { code: code.into() },
                },
                None => Response::Error {
                    code: "transport_not_initialized".into(),
                },
            },
        };
        let envelope = key.seal(sequence, &response)?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| "invalid_egress_response")?);
        // Never replay: the provider may already have received the request.
        let _ = nw_ipc::write_frame(&mut stream, &bytes, MAX_WIRE * 5).await;
    }
}
