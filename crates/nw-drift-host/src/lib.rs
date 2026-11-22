//! Framed stdin/stdout relay; no generic RPC or endpoint is accepted from browser data.
pub async fn relay<R: std::io::Read, W: std::io::Write>(
    endpoint: &nw_ipc::Endpoint,
    input: &mut R,
    output: &mut W,
) -> std::io::Result<()> {
    while let Some(request) = nw_bridge::read_native(input)? {
        let id = request.id;
        let reply = nw_bridge::call(endpoint, request)
            .await
            .unwrap_or(nw_bridge::Reply {
                version: nw_proto::SCHEMA_VERSION,
                id,
                result: nw_bridge::Result::Error {
                    code: nw_bridge::ErrorCode::WorkspaceLocked,
                },
            });
        nw_bridge::write_native(output, &reply)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use nw_bridge::{Command, Request, Result as Reply};
    struct Core;
    impl nw_bridge::Handler for Core {
        async fn handle(&self, command: Command) -> Reply {
            match command {
                Command::Status {} => Reply::Status {
                    paused: false,
                    mode: nw_bridge::Mode::Assisted,
                    ai_web_automation: false,
                },
                _ => Reply::Tasks { tasks: vec![] },
            }
        }
    }
    #[tokio::test]
    async fn browser_stdio_roundtrip_contains_only_cover_reply() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let value = format!("nymwrap-stdio-test-{}", std::process::id());
        #[cfg(unix)]
        let value = directory
            .path()
            .join("private/cover.sock")
            .to_string_lossy()
            .into_owned();
        let _keep = directory;
        let endpoint = nw_ipc::Endpoint::new(value, nw_proto::Lane::Cover).unwrap();
        let listener = nw_ipc::Listener::bind(endpoint.clone()).unwrap();
        let server = tokio::spawn(nw_bridge::serve(listener, Core));
        let request = Request {
            version: 1,
            id: 9,
            command: Command::Status {},
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let mut input = (bytes.len() as u32).to_le_bytes().to_vec();
        input.extend(bytes);
        let mut output = vec![];
        super::relay(&endpoint, &mut input.as_slice(), &mut output)
            .await
            .unwrap();
        let length = u32::from_le_bytes(output[..4].try_into().unwrap()) as usize;
        assert_eq!(length, output.len() - 4);
        let reply: nw_bridge::Reply = serde_json::from_slice(&output[4..]).unwrap();
        assert_eq!(reply.id, 9);
        assert!(matches!(reply.result, Reply::Status { .. }));
        server.abort();
        let _ = server.await;
    }
}
