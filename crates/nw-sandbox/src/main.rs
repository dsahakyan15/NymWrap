//! Explicit macOS coordinator interface. Does not silently wrap desktop launches.
#[cfg(target_os = "macos")]
fn launch() -> Result<(), nw_sandbox::SandboxError> {
    use nw_sandbox::{
        SandboxError,
        macos::{Lane, Process, Profile},
    };
    use std::{ffi::OsString, os::unix::process::CommandExt, path::PathBuf};
    let mut args = std::env::args_os().skip(1);
    let mut process = None;
    let mut lane = None;
    let mut container = None;
    let mut reads = Vec::<PathBuf>::new();
    let mut sockets = Vec::<PathBuf>::new();
    loop {
        let flag = args.next().ok_or(SandboxError::InvalidPath)?;
        if flag == "--" {
            break;
        }
        let value = args.next().ok_or(SandboxError::InvalidPath)?;
        match flag.to_str() {
            Some("--process") if process.is_none() => {
                process = Some(match value.to_str() {
                    Some("nymwrapd") => Process::Core,
                    Some("nw-api") => Process::Api,
                    Some("nw-llmd") => Process::Llmd,
                    Some("nw-netd") => Process::Netd,
                    Some("nw-drift-host") => Process::DriftHost,
                    Some("nw-audit-worker") => Process::Audit,
                    Some("ui") => Process::Ui,
                    _ => return Err(SandboxError::InvalidPath),
                });
            }
            Some("--lane") if lane.is_none() => {
                lane = Some(match value.to_str() {
                    Some("shadow") => Lane::Shadow,
                    Some("cover") => Lane::Cover,
                    _ => return Err(SandboxError::InvalidPath),
                });
            }
            Some("--container") if container.is_none() => container = Some(PathBuf::from(value)),
            Some("--read-only") => reads.push(PathBuf::from(value)),
            Some("--socket") => sockets.push(PathBuf::from(value)),
            _ => return Err(SandboxError::InvalidPath),
        }
    }
    let program = PathBuf::from(args.next().ok_or(SandboxError::InvalidPath)?);
    let args: Vec<OsString> = args.collect();
    let reads: Vec<_> = reads.iter().map(PathBuf::as_path).collect();
    let sockets: Vec<_> = sockets.iter().map(PathBuf::as_path).collect();
    nw_platform::harden_process().map_err(|_| SandboxError::Launch)?;
    let mut command = Profile {
        process: process.ok_or(SandboxError::InvalidPath)?,
        lane: lane.ok_or(SandboxError::InvalidPath)?,
        container: container.as_deref(),
        read_only: &reads,
        sockets: &sockets,
    }
    .command(&program, &args)?;
    // exec keeps coordinator PID and inherited IPC pipes. On any error there is
    // no retry via the original executable, even when sandbox-exec is absent.
    let _error = command.exec();
    Err(SandboxError::Launch)
}

fn main() {
    #[cfg(target_os = "macos")]
    let result = launch();
    #[cfg(not(target_os = "macos"))]
    let result: Result<(), nw_sandbox::SandboxError> = Err(nw_sandbox::SandboxError::Unsupported);
    if result.is_err() {
        eprintln!("sandbox_launch_failed");
        std::process::exit(1);
    }
}
