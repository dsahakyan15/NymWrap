use nw_net::wire::SessionKey;
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
    let mut parent = nw_platform::inherited_stdin_pipe()?;
    parent.read_exact(&mut *bytes)?;
    let key = SessionKey::new(*bytes)?;
    bytes.zeroize();
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = parent.read(&mut [0]);
        let _ = tx.send(());
    });
    let listener = nw_ipc::Listener::bind(endpoint)?;
    tokio::select! {
        result = nw_netd::server::serve(listener, key) => result?,
        _ = &mut rx => {},
        _ = tokio::signal::ctrl_c() => {},
    }
    Ok(())
}
