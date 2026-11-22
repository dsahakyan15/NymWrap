//! One import per process, anonymous pipes only, no filenames or model tools.
use std::io::{Read, Write};
use zeroize::Zeroizing;
fn run() -> Result<(), Box<dyn std::error::Error>> {
    nw_platform::harden_process()?;
    #[cfg(target_os = "linux")]
    nw_platform::confine_import_worker()?;
    let mut input = std::io::stdin().lock();
    let mut size = [0; 4];
    input.read_exact(&mut size)?;
    let size = u32::from_le_bytes(size) as usize;
    if size == 0 || size > nw_audit::MAX_IMPORT_BYTES + 4096 {
        return Err("invalid_import_frame".into());
    }
    let mut bytes = Zeroizing::new(vec![0; size]);
    input.read_exact(&mut bytes)?;
    let newline = bytes
        .iter()
        .position(|b| *b == b'\n')
        .filter(|n| *n < 128)
        .ok_or("invalid_import_frame")?;
    let format: nw_audit::Format =
        serde_json::from_slice(&bytes[..newline]).map_err(|_| "invalid_import_format")?;
    let response = match nw_audit::import(&bytes[newline + 1..], format) {
        Ok(summary) => serde_json::json!({"summary":summary}),
        Err(error) => serde_json::json!({"error":error.to_string()}),
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&response)?);
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("invalid_import_result".into());
    }
    let mut output = std::io::stdout().lock();
    output.write_all(&(bytes.len() as u32).to_le_bytes())?;
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("import_worker_failed");
        std::process::exit(1);
    }
}
