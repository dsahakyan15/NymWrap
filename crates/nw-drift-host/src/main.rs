//! Browser native messaging host. Stdout is reserved exclusively for framed replies.
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("cover_native_host_stopped");
        std::process::exit(1);
    }
}
async fn run() -> std::io::Result<()> {
    nw_platform::harden_process()?;
    let endpoint = nw_bridge::endpoint().map_err(std::io::Error::other)?;
    let (mut input, mut output) = (std::io::stdin().lock(), std::io::stdout().lock());
    nw_drift_host::relay(&endpoint, &mut input, &mut output).await
}
