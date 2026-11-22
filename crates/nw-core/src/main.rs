use nw_core::{PreviewInput, PreviewSecret};
use std::io::{self, Read};
use zeroize::Zeroizing;
fn stdin_bounded(limit: usize) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut bytes = Zeroizing::new(Vec::new());
    io::stdin()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input_too_large".into());
    }
    Ok(bytes)
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    nw_platform::harden_process()?;
    #[cfg(target_os = "linux")]
    nw_platform::deny_remote_sockets()?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let command = args.first().and_then(|s| s.to_str()).unwrap_or("status");
    let value = match command {
        "status" => serde_json::to_value(nw_core::status())?,
        "paths" => serde_json::to_value(nw_core::config::Paths::discover()?)?,
        "rpc" => {
            let bytes = stdin_bounded(16 * 1024 * 1024)?;
            let command: nw_core::service::Command =
                serde_json::from_slice(&bytes).map_err(|_| "invalid_input")?;
            let runtime = tokio::runtime::Runtime::new()?;
            let reply =
                runtime.block_on(nw_core::service::Client::current_user()?.request(command))?;
            reply.into_json()?
        }
        "demo" => {
            let preview = nw_core::preview(PreviewInput {
                text: "Я Синтетик Тестов, напиши на demo@example.test про садоводство.".into(),
                secrets: vec![PreviewSecret {
                    kind: nw_shield::SecretKind::Person,
                    value: "Синтетик Тестов".into(),
                    local_only: false,
                }],
            })?;
            let ring = nw_vault::KeyRing::new()?;
            let blob = ring.seal(nw_vault::Domain::Vault, b"SYNTHETIC_ONLY")?;
            serde_json::json!({"shield":preview,"encrypted_blob_bytes":blob.len(),"data_written":false,"note":"Synthetic offline demonstration; no local model or network used."})
        }
        "shield" => {
            let bytes = stdin_bounded(nw_proto::MAX_FRAME_BYTES)?;
            let input: PreviewInput =
                serde_json::from_slice(&bytes).map_err(|_| "invalid_input")?;
            serde_json::to_value(nw_core::preview(input)?)?
        }
        "audit" => {
            let format = match args.get(1).and_then(|s| s.to_str()).unwrap_or("takeout") {
                "takeout" => nw_audit::Format::Takeout,
                "chatgpt" => nw_audit::Format::Chatgpt,
                "claude" => nw_audit::Format::Claude,
                "gemini" => nw_audit::Format::Gemini,
                "browser" => nw_audit::Format::BrowserJson,
                "chrome" => nw_audit::Format::ChromeSqlite,
                "firefox" => nw_audit::Format::FirefoxSqlite,
                "safari" => nw_audit::Format::SafariSqlite,
                _ => return Err("unsupported_import_format".into()),
            };
            let bytes = stdin_bounded(nw_audit::MAX_IMPORT_BYTES)?;
            let runtime = tokio::runtime::Runtime::new()?;
            serde_json::to_value(runtime.block_on(nw_core::audit_offline(&bytes, format))?)?
        }
        "purge-template" => {
            serde_json::json!({"template":nw_purge::deletion_template(),"sent":false})
        }
        "run" => {
            if args.get(1).and_then(|s| s.to_str()) != Some("--") {
                return Err("usage: nymwrap run -- /absolute/program [args]".into());
            }
            let program = args.get(2).ok_or("missing_program")?;
            let paths = nw_core::config::Paths::discover()?;
            let code = nw_sandbox::run_agent(
                &std::env::current_dir()?,
                std::path::Path::new(program),
                &args[3..],
                std::path::Path::new(&paths.api),
            )?;
            std::process::exit(code);
        }
        "help" | "--help" | "-h" => {
            println!(
                "nymwrap status | rpc < command.json | demo | shield < input.json | audit [takeout|chatgpt|claude|gemini|browser|chrome|firefox|safari] < export | purge-template | run -- /absolute/program [args]\nRPC connects to the private nymwrapd daemon. Secrets are accepted on stdin, never command arguments."
            );
            return Ok(());
        }
        _ => return Err("unknown_command".into()),
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("nymwrap: {error}");
        std::process::exit(1);
    }
}
