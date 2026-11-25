#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use {
    std::io::{Read, Write},
    zeroize::Zeroizing,
};
fn main() {
    if run().is_err() {
        eprintln!("probe_failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    nw_platform::harden_process().map_err(|_| "probe_hardening_failed")?;
    #[cfg(windows)]
    if !nw_platform::is_appcontainer().map_err(|_| "probe_sandbox_unavailable")? {
        return Err("probe_sandbox_required");
    }
    #[cfg(target_os = "linux")]
    nw_platform::deny_remote_sockets().map_err(|_| "probe_sandbox_unavailable")?;
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err("probe_sandbox_unavailable")
    }
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.first().is_none_or(|a| a != "--stdio") || !matches!(args.len(), 1 | 3) {
            return Err("invalid_probe_arguments");
        }
        let git = if args.len() == 3 {
            #[cfg(windows)]
            {
                if args[1] != "--git-handle" {
                    return Err("invalid_probe_arguments");
                }
                Some(
                    nw_platform::inherited_read_file(
                        args[2].parse().map_err(|_| "invalid_probe_arguments")?,
                    )
                    .map_err(|_| "probe_git_unavailable")?,
                )
            }
            #[cfg(target_os = "linux")]
            {
                if args[1] != "--git" || args[2] != "/run/probe/gitconfig" {
                    return Err("invalid_probe_arguments");
                }
                Some(std::fs::File::open(&args[2]).map_err(|_| "probe_git_unavailable")?)
            }
            #[cfg(target_os = "macos")]
            {
                if args[1] != "--git-fd" {
                    return Err("invalid_probe_arguments");
                }
                Some(
                    nw_platform::inherited_probe_file(
                        args[2].parse().map_err(|_| "invalid_probe_arguments")?,
                    )
                    .map_err(|_| "probe_git_unavailable")?,
                )
            }
        } else {
            None
        };
        #[cfg(target_os = "macos")]
        nw_platform::confine_device_probe(git.as_ref()).map_err(|_| "probe_sandbox_unavailable")?;
        let mut input = std::io::stdin().lock();
        let mut header = [0u8; 4];
        input
            .read_exact(&mut header)
            .map_err(|_| "invalid_probe_request")?;
        let len = u32::from_le_bytes(header) as usize;
        if len == 0 || len > nw_probe::MAX_FRAME {
            return Err("invalid_probe_request");
        }
        let mut bytes = Zeroizing::new(vec![0u8; len]);
        input
            .read_exact(&mut bytes)
            .map_err(|_| "invalid_probe_request")?;
        let mut extra = [0u8; 1];
        if input
            .read(&mut extra)
            .map_err(|_| "invalid_probe_request")?
            != 0
        {
            return Err("invalid_probe_request");
        }
        let hints = serde_json::from_slice::<nw_probe::Hints>(&bytes)
            .map_err(|_| "invalid_probe_request")?;
        let report = nw_probe::collect(&hints, git)?;
        let payload =
            Zeroizing::new(serde_json::to_vec(&report).map_err(|_| "invalid_probe_result")?);
        if payload.len() > nw_probe::MAX_FRAME {
            return Err("probe_capacity_exceeded");
        }
        let mut output = std::io::stdout().lock();
        output
            .write_all(&(payload.len() as u32).to_le_bytes())
            .and_then(|()| output.write_all(&payload))
            .and_then(|()| output.flush())
            .map_err(|_| "probe_output_failed")?;
        Ok(())
    }
}
