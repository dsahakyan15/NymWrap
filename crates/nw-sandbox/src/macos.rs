//! Deny-default Seatbelt launcher without an Apple Developer identity (ADR 0094).
//! The trusted coordinator chooses one lane, one private container and exact IPC
//! endpoints. No entitlement, shell, caller-supplied SBPL or unsandboxed retry.
use crate::SandboxError;
pub use nw_platform::verify_runtime_sysctl_policy;
use std::{ffi::OsString, os::unix::fs::MetadataExt, path::Path, process::Command};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    Shadow,
    Cover,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Process {
    Core,
    Api,
    Llmd,
    Netd,
    DriftHost,
    Audit,
    Ui,
}
impl Process {
    pub fn permits(self, lane: Lane) -> bool {
        match self {
            Self::Core | Self::Ui => true,
            Self::DriftHost => lane == Lane::Cover,
            Self::Api | Self::Llmd | Self::Netd | Self::Audit => lane == Lane::Shadow,
        }
    }
}

/// All paths are trusted launch configuration, never model output. Containers
/// must be distinct, non-nested, per-process/per-lane directories. Inherited
/// stdin/stdout are IPC only; the coordinator must not pass open secret files or
/// network descriptors. UNIX sockets still require the usual nw-ipc peer checks.
pub struct Profile<'a> {
    pub process: Process,
    pub lane: Lane,
    pub container: Option<&'a Path>,
    pub read_only: &'a [&'a Path],
    pub sockets: &'a [&'a Path],
}

fn existing_path(path: &Path) -> Result<std::path::PathBuf, SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::InvalidPath);
    }
    let canonical = path.canonicalize().map_err(|_| SandboxError::InvalidPath)?;
    // Do not turn aliases or traversal into additional authority. In particular,
    // /var aliases must be canonicalized by the trusted caller before launch.
    if canonical != path
        || path
            .to_str()
            .is_none_or(|s| s.chars().any(char::is_control))
    {
        return Err(SandboxError::InvalidPath);
    }
    Ok(canonical)
}

impl Profile<'_> {
    pub fn command(&self, program: &Path, args: &[OsString]) -> Result<Command, SandboxError> {
        if !self.process.permits(self.lane)
            || self.read_only.len() > 16
            || self.sockets.len() > 16
            || (!self.read_only.is_empty()
                && !matches!(self.process, Process::Llmd | Process::Audit))
        {
            return Err(SandboxError::InvalidPath);
        }
        let executable = existing_path(program)?;
        if !executable.is_file() {
            return Err(SandboxError::InvalidPath);
        }
        let mut profile = include_str!("../profiles/macos/common.sb").to_owned();
        profile.push_str(if self.process == Process::Netd {
            include_str!("../profiles/macos/netd.sb")
        } else {
            include_str!("../profiles/macos/offline.sb")
        });
        let mut parameters = vec![OsString::from(format!("PROGRAM={}", executable.display()))];
        let container = self.container.map(existing_path).transpose()?;
        if let Some(root) = &container {
            let metadata = root.metadata().map_err(|_| SandboxError::InvalidPath)?;
            if !metadata.is_dir()
                || metadata.mode() & 0o077 != 0
                || metadata.uid().to_string()
                    != nw_platform::current_user_id().map_err(|_| SandboxError::Launch)?
                || root.parent().is_none()
            {
                return Err(SandboxError::InvalidPath);
            }
            // The entire user profile, system trees and their ancestors must
            // never become a container, even if someone chmod'ed them to 0700.
            for forbidden in ["/Users", "/System", "/Library", "/usr", "/private", "/dev"] {
                if Path::new(forbidden).starts_with(root) {
                    return Err(SandboxError::InvalidPath);
                }
            }
            if std::env::var_os("HOME").is_some_and(|home| {
                Path::new(&home)
                    .canonicalize()
                    .is_ok_and(|home| home.starts_with(root))
            }) {
                return Err(SandboxError::InvalidPath);
            }
            parameters.push(format!("CONTAINER={}", root.display()).into());
            profile
                .push_str("\n(allow file-read-data file-write* (subpath (param \"CONTAINER\")))\n");
            // Services can create their own private UNIX endpoint, never an IP
            // listener or an endpoint in another process/lane's directory.
            profile.push_str("(allow network-bind network-inbound (local unix-socket (subpath (param \"CONTAINER\"))))\n");
        }
        for (index, file) in self.read_only.iter().enumerate() {
            let file = existing_path(file)?;
            if !file.is_file() {
                return Err(SandboxError::InvalidPath);
            }
            parameters.push(format!("READ_{index}={}", file.display()).into());
            profile.push_str(&format!(
                "\n(allow file-read-data (literal (param \"READ_{index}\")))\n(deny file-write* (literal (param \"READ_{index}\")))\n"
            ));
        }
        for (index, socket) in self.sockets.iter().enumerate() {
            use std::os::unix::fs::FileTypeExt;
            let socket = existing_path(socket)?;
            let metadata = socket.metadata().map_err(|_| SandboxError::Api)?;
            if !metadata.file_type().is_socket()
                || metadata.mode() & 0o077 != 0
                || metadata.uid().to_string()
                    != nw_platform::current_user_id().map_err(|_| SandboxError::Launch)?
            {
                return Err(SandboxError::Api);
            }
            parameters.push(format!("SOCKET_{index}={}", socket.display()).into());
            profile.push_str(&format!(
                "\n(allow network-outbound (remote unix-socket (literal (param \"SOCKET_{index}\"))))\n"
            ));
        }
        if container.is_some() || !self.sockets.is_empty() {
            profile.push_str("\n(allow system-socket (socket-domain AF_UNIX))\n");
        }
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .env_clear()
            .current_dir(container.as_deref().unwrap_or(Path::new("/")));
        for (key, value) in [
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/nonexistent"),
            ("USER", "user"),
            ("LOGNAME", "user"),
            ("TZ", "UTC"),
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C.UTF-8"),
        ] {
            command.env(key, value);
        }
        command.arg("-p").arg(profile);
        for parameter in parameters {
            command.arg("-D").arg(parameter);
        }
        command.arg("--").arg(executable).args(args);
        Ok(command)
    }
}
