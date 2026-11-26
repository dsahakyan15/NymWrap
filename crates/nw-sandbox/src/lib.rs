//! OS sandbox launchers. Unsupported mechanisms fail instead of launching unconfined.
#[cfg(target_os = "macos")]
pub mod macos;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};
use thiserror::Error;
#[derive(Debug, Error, Eq, PartialEq)]
pub enum SandboxError {
    #[error("sandbox_not_available_use_linux")]
    Unsupported,
    #[error("invalid_sandbox_path")]
    InvalidPath,
    #[error("sandbox_launch_failed")]
    Launch,
    #[error("private_api_socket_required")]
    Api,
}
#[cfg(windows)]
pub fn parser_exchange(
    program: &Path,
    input: zeroize::Zeroizing<Vec<u8>>,
) -> Result<nw_platform::SandboxOutput, SandboxError> {
    nw_platform::appcontainer_exchange(
        program,
        &[],
        input,
        4 * 1024 * 1024 + 4,
        std::time::Duration::from_secs(30),
    )
    .map_err(|_| SandboxError::Launch)
}
/// Probe has no network capabilities. Git is an inherited read-only regular file.
#[cfg(windows)]
pub fn probe_exchange(
    program: &Path,
    git: Option<&std::fs::File>,
    input: zeroize::Zeroizing<Vec<u8>>,
) -> Result<nw_platform::SandboxOutput, SandboxError> {
    let files: Vec<_> = git.map(|f| ("git", f)).into_iter().collect();
    let args: Vec<OsString> = if git.is_some() {
        vec![
            "--stdio".into(),
            "--git-handle".into(),
            "@handle:git".into(),
        ]
    } else {
        vec!["--stdio".into()]
    };
    nw_platform::appcontainer_probe_exchange(program, &args, &files, input)
        .map_err(|_| SandboxError::Launch)
}
/// Dedicated trusted inventory worker: host identifiers are intentionally visible,
/// but no home directory, service socket or IP socket is available. The worker
/// installs seccomp before reading its input; NETLINK_ROUTE remains read-only to
/// this unprivileged, cap-free process so local addresses can be inventoried.
#[cfg(target_os = "linux")]
pub fn probe_command(program: &Path, git: Option<&std::fs::File>) -> Result<Command, SandboxError> {
    let program = program
        .canonicalize()
        .map_err(|_| SandboxError::InvalidPath)?;
    if !program.is_file() {
        return Err(SandboxError::InvalidPath);
    }
    let bwrap = ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or(SandboxError::Unsupported)?;
    let mut command = Command::new(bwrap);
    command
        .env_clear()
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-cgroup",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--uid",
        ])
        .arg(nw_platform::current_user_id().map_err(|_| SandboxError::Launch)?)
        .arg("--gid")
        .arg(nw_platform::current_group_id())
        .args(["--ro-bind", "/usr", "/usr"]);
    for path in [
        "/bin",
        "/lib",
        "/lib64",
        "/etc/passwd",
        "/etc/group",
        "/etc/machine-id",
        "/etc/localtime",
        "/etc/timezone",
        "/sys",
    ] {
        if Path::new(path).exists() {
            command.args(["--ro-bind", path, path]);
        }
    }
    let wifi = "/etc/NetworkManager/system-connections";
    if std::fs::read_dir(wifi).is_ok() {
        command.args(["--ro-bind", wifi, wifi]);
    }
    command.args([
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/run/probe",
    ]);
    nw_platform::sandbox_data_files(
        &mut command,
        &[(
            "/etc/nsswitch.conf",
            b"passwd: files\ngroup: files\nhosts: files\n",
        )],
    )
    .map_err(|_| SandboxError::Launch)?;
    if let Some(file) = git {
        nw_platform::sandbox_read_files(&mut command, &[("/run/probe/gitconfig", file)])
            .map_err(|_| SandboxError::Launch)?;
    }
    command
        .arg("--ro-bind")
        .arg(program)
        .args(["/worker", "--chdir", "/tmp", "--", "/worker", "--stdio"]);
    if git.is_some() {
        command.args(["--git", "/run/probe/gitconfig"]);
    }
    Ok(command)
}
#[cfg(target_os = "macos")]
pub fn probe_command(program: &Path, git: Option<&std::fs::File>) -> Result<Command, SandboxError> {
    nw_platform::macos_probe_command(program, git).map_err(|_| SandboxError::Launch)
}
pub fn offline_command(
    workdir: &Path,
    program: &Path,
    args: &[OsString],
) -> Result<Command, SandboxError> {
    confined_command(workdir, program, args, None)
}
/// Give the agent exactly the shadow HTTP socket, never the core RPC or model socket.
pub fn agent_command(
    workdir: &Path,
    program: &Path,
    args: &[OsString],
    api: &Path,
) -> Result<Command, SandboxError> {
    confined_command(workdir, program, args, Some(api))
}
fn confined_command(
    workdir: &Path,
    program: &Path,
    args: &[OsString],
    api: Option<&Path>,
) -> Result<Command, SandboxError> {
    if !cfg!(target_os = "linux") {
        return Err(SandboxError::Unsupported);
    }
    let root = workdir
        .canonicalize()
        .map_err(|_| SandboxError::InvalidPath)?;
    let executable = program
        .canonicalize()
        .map_err(|_| SandboxError::InvalidPath)?;
    if root == Path::new("/") || !root.is_dir() || !executable.is_file() {
        return Err(SandboxError::InvalidPath);
    }
    let bwrap = ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .ok_or(SandboxError::Unsupported)?;
    let inside = if let Ok(relative) = executable.strip_prefix(&root) {
        Path::new("/work").join(relative)
    } else if executable.starts_with("/usr/") {
        executable
    } else {
        return Err(SandboxError::InvalidPath);
    };
    let mut cmd = Command::new(bwrap);
    cmd.env_clear();
    if let Some(api) = api {
        if !api.is_absolute() {
            return Err(SandboxError::Api);
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let metadata = std::fs::symlink_metadata(api).map_err(|_| SandboxError::Api)?;
            if api.file_name().is_none_or(|n| n != "api.sock")
                || !metadata.file_type().is_socket()
                || metadata.mode() & 0o077 != 0
                || metadata.uid().to_string()
                    != nw_platform::current_user_id().map_err(|_| SandboxError::Api)?
            {
                return Err(SandboxError::Api);
            }
        }
        cmd.env("NYMWRAP_API_SOCKET", "/run/nymwrap/api.sock")
            .env("OPENAI_BASE_URL", "http://localhost/v1")
            .env("OPENAI_API_KEY", "local");
    }
    cmd.args([
        "--unshare-all",
        "--hostname",
        "localhost",
        "--uid",
        "1000",
        "--gid",
        "1000",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    for path in ["/bin", "/lib", "/lib64"] {
        if Path::new(path).exists() {
            cmd.args(["--ro-bind", path, path]);
        }
    }
    cmd.args([
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/run", "--bind",
    ])
    .arg(&root)
    .args(["/work", "--chdir", "/work"]);
    if let Some(api) = api {
        cmd.args(["--dir", "/run/nymwrap", "--ro-bind"])
            .arg(api)
            .arg("/run/nymwrap/api.sock");
    }
    normalize_environment(&mut cmd)?;
    cmd.arg("--").arg(inside).args(args);
    Ok(cmd)
}
pub fn run_offline(workdir: &Path, program: &Path, args: &[OsString]) -> Result<i32, SandboxError> {
    let status = offline_command(workdir, program, args)?
        .status()
        .map_err(|_| SandboxError::Launch)?;
    Ok(status.code().unwrap_or(1))
}
pub fn run_agent(
    workdir: &Path,
    program: &Path,
    args: &[OsString],
    api: &Path,
) -> Result<i32, SandboxError> {
    let status = agent_command(workdir, program, args, api)?
        .status()
        .map_err(|_| SandboxError::Launch)?;
    Ok(status.code().unwrap_or(1))
}
/// Parser worker: no writable host paths, no home, no network namespace access.
pub fn isolated_worker(program: &Path) -> Result<Command, SandboxError> {
    if !cfg!(target_os = "linux") {
        return Err(SandboxError::Unsupported);
    }
    let program = program
        .canonicalize()
        .map_err(|_| SandboxError::InvalidPath)?;
    if !program.is_file() {
        return Err(SandboxError::InvalidPath);
    }
    let bwrap = ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or(SandboxError::Unsupported)?;
    let mut command = Command::new(bwrap);
    command.env_clear();
    command.args([
        "--unshare-all",
        "--hostname",
        "localhost",
        "--uid",
        "1000",
        "--gid",
        "1000",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    for path in ["/bin", "/lib", "/lib64"] {
        if Path::new(path).exists() {
            command.args(["--ro-bind", path, path]);
        }
    }
    command
        .args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(program)
        .args(["/worker", "--chdir", "/tmp"]);
    normalize_environment(&mut command)?;
    command.args(["--", "/worker"]);
    Ok(command)
}
fn normalize_environment(command: &mut Command) -> Result<(), SandboxError> {
    // Also use bwrap --setenv: callers may clear the launcher's environment later.
    for (name, value) in [
        ("PATH", "/usr/bin:/bin"),
        ("HOME", "/home/user"),
        ("USER", "user"),
        ("LOGNAME", "user"),
        ("HOSTNAME", "localhost"),
        ("TZ", "UTC"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("GIT_CONFIG_GLOBAL", "/home/user/.gitconfig"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
    ] {
        command.env(name, value).args(["--setenv", name, value]);
    }
    command.args(["--dir", "/etc", "--dir", "/home/user"]);
    #[cfg(target_os = "linux")]
    {
        // Minimal TZif v1 UTC: no transitions, one UTC type and four abbreviation bytes.
        let mut utc = [0u8; 54];
        utc[..4].copy_from_slice(b"TZif");
        utc[39] = 1;
        utc[43] = 4;
        utc[50..].copy_from_slice(b"UTC\0");
        nw_platform::sandbox_data_files(
            command,
            &[
                ("/etc/passwd", b"user:x:1000:1000:user:/home/user:/bin/sh\n"),
                ("/etc/group", b"user:x:1000:\n"),
                ("/etc/machine-id", b"00000000000000000000000000000001\n"),
                ("/etc/hostname", b"localhost\n"),
                ("/etc/hosts", b"127.0.0.1 localhost\n::1 localhost\n"),
                (
                    "/etc/nsswitch.conf",
                    b"passwd: files\ngroup: files\nhosts: files\n",
                ),
                ("/etc/timezone", b"UTC\n"),
                ("/etc/localtime", &utc),
                (
                    "/home/user/.gitconfig",
                    b"[user]\n\tname = user\n\temail = user@localhost\n",
                ),
            ],
        )
        .map_err(|_| SandboxError::Launch)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn never_runs_unconfined_on_unsupported_platform() {
        if !cfg!(target_os = "linux") {
            assert_eq!(
                offline_command(Path::new("."), Path::new("dummy"), &[]).err(),
                Some(SandboxError::Unsupported)
            );
        }
    }
}
