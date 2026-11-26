//! Repository-owned leaf-daemon profiles. No caller-supplied sandbox switches.
use crate::SandboxError;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::{ffi::OsString, path::PathBuf, process::ExitStatus};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Api,
    Model,
    DriftHost,
}
impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Model => "model",
            Self::DriftHost => "drift_host",
        }
    }
    pub fn lane(self) -> &'static str {
        if self == Self::DriftHost {
            "cover"
        } else {
            "shadow"
        }
    }
}

/// A leaf gets only its private listener directory, explicit upstream sockets
/// and read-only files. It never receives the complete application data root.
pub struct Launch {
    pub profile: Profile,
    pub binary: PathBuf,
    pub arguments: Vec<OsString>,
    pub listener: Option<PathBuf>,
    pub upstream: Vec<PathBuf>,
    pub files: Vec<(String, PathBuf)>,
    pub environment: Vec<(OsString, OsString)>,
}

pub enum Input {
    Ordinary(tokio::process::ChildStdin),
    #[cfg(windows)]
    Native(tokio::fs::File),
}
impl AsyncWrite for Input {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Ordinary(v) => std::pin::Pin::new(v).poll_write(cx, bytes),
            #[cfg(windows)]
            Self::Native(v) => std::pin::Pin::new(v).poll_write(cx, bytes),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Ordinary(v) => std::pin::Pin::new(v).poll_flush(cx),
            #[cfg(windows)]
            Self::Native(v) => std::pin::Pin::new(v).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Ordinary(v) => std::pin::Pin::new(v).poll_shutdown(cx),
            #[cfg(windows)]
            Self::Native(v) => std::pin::Pin::new(v).poll_shutdown(cx),
        }
    }
}
pub struct Child {
    inner: Inner,
    pub stdin: Option<Input>,
    pub stdout: Option<Output>,
}
pub enum Output {
    Ordinary(tokio::process::ChildStdout),
    #[cfg(windows)]
    Native(tokio::fs::File),
}
impl AsyncRead for Output {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Ordinary(v) => std::pin::Pin::new(v).poll_read(cx, buffer),
            #[cfg(windows)]
            Self::Native(v) => std::pin::Pin::new(v).poll_read(cx, buffer),
        }
    }
}
enum Inner {
    Ordinary(tokio::process::Child),
    #[cfg(target_os = "linux")]
    Bubblewrap {
        monitor: tokio::process::Child,
        identity: nw_platform::SandboxIdentity,
        _status: tokio::io::BufReader<tokio::io::Take<tokio::net::UnixStream>>,
    },
    #[cfg(windows)]
    Native(nw_platform::AppContainerProcess),
}
impl Child {
    /// Retain the existing trusted coordinator until the key/launch broker exists.
    pub fn coordinator(mut child: tokio::process::Child) -> Self {
        let stdin = child.stdin.take().map(Input::Ordinary);
        let stdout = child.stdout.take().map(Output::Ordinary);
        Self {
            inner: Inner::Ordinary(child),
            stdin,
            stdout,
        }
    }
    pub fn id(&self) -> Option<u32> {
        match &self.inner {
            Inner::Ordinary(v) => v.id(),
            #[cfg(target_os = "linux")]
            Inner::Bubblewrap { identity, .. } => Some(identity.pid()),
            #[cfg(windows)]
            Inner::Native(v) => Some(v.id()),
        }
    }
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        match &mut self.inner {
            Inner::Ordinary(v) => v.try_wait(),
            #[cfg(target_os = "linux")]
            Inner::Bubblewrap {
                monitor, identity, ..
            } => {
                let status = monitor.try_wait()?;
                if status.is_none() && !identity.alive()? {
                    return Err(std::io::Error::other("sandbox_payload_stopped"));
                }
                Ok(status)
            }
            #[cfg(windows)]
            Inner::Native(v) => v.try_wait(),
        }
    }
    pub fn start_kill(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            Inner::Ordinary(v) => v.start_kill(),
            #[cfg(target_os = "linux")]
            Inner::Bubblewrap { monitor, .. } => monitor.start_kill(),
            #[cfg(windows)]
            Inner::Native(v) => v.kill(),
        }
    }
    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match &mut self.inner {
            Inner::Ordinary(v) => v.wait().await,
            #[cfg(target_os = "linux")]
            Inner::Bubblewrap { monitor, .. } => monitor.wait().await,
            #[cfg(windows)]
            Inner::Native(v) => loop {
                if let Some(status) = v.try_wait()? {
                    break Ok(status);
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            },
        }
    }
}

impl Launch {
    pub async fn spawn(self) -> Result<Child, SandboxError> {
        let profiles: serde_json::Value =
            serde_json::from_str(include_str!("../profiles/daemons.json"))
                .map_err(|_| SandboxError::Launch)?;
        let policy = &profiles[self.profile.name()];
        if policy["lane"] != self.profile.lane()
            || policy["network"] != false
            || policy["children"] != false
        {
            return Err(SandboxError::Launch);
        }
        let labels = policy["file_labels"]
            .as_array()
            .ok_or(SandboxError::Launch)?;
        let upstream = policy["upstream_sockets"]
            .as_u64()
            .ok_or(SandboxError::Launch)?;
        if self.upstream.len() as u64 > upstream
            || self.listener.is_some() && policy["listener"] != true
            || self.files.iter().enumerate().any(|(i, (label, _))| {
                !labels.iter().any(|allowed| allowed == label)
                    || self.files[..i].iter().any(|(prior, _)| prior == label)
            })
        {
            return Err(SandboxError::InvalidPath);
        }
        if !self.binary.is_absolute()
            || !self.binary.is_file()
            || self.arguments.len() > 64
            || self.files.len() > 4
            || self.upstream.len() > 4
        {
            return Err(SandboxError::InvalidPath);
        }
        for (name, value) in &self.environment {
            if !["LOCALAPPDATA", "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "HOME"]
                .iter()
                .any(|allowed| name == allowed)
                || !std::path::Path::new(value).is_absolute()
            {
                return Err(SandboxError::InvalidPath);
            }
        }
        for (label, path) in &self.files {
            let meta = std::fs::symlink_metadata(path).map_err(|_| SandboxError::InvalidPath)?;
            if !path.is_absolute()
                || !meta.is_file()
                || meta.is_symlink()
                || label.is_empty()
                || label.len() > 32
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_')
            {
                return Err(SandboxError::InvalidPath);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & 0x400 != 0 {
                    return Err(SandboxError::InvalidPath);
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            self.spawn_linux().await
        }
        #[cfg(windows)]
        {
            self.spawn_windows()
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            Err(SandboxError::Unsupported)
        }
    }
}

/// Irreversible second stage, before the runtime or any untrusted input.
pub fn seal() -> Result<(), SandboxError> {
    #[cfg(target_os = "linux")]
    {
        if std::fs::read("/run/nymwrap/leaf-profile").ok().as_deref() != Some(b"nw-leaf-v1") {
            return Err(SandboxError::Launch);
        }
        nw_platform::confine_leaf_daemon().map_err(|_| SandboxError::Launch)
    }
    #[cfg(windows)]
    {
        nw_platform::verify_lpac_boundary().map_err(|_| SandboxError::Launch)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(SandboxError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
impl Launch {
    async fn spawn_linux(self) -> Result<Child, SandboxError> {
        use std::{
            os::unix::fs::{FileTypeExt, MetadataExt},
            process::Stdio,
        };
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};
        let bwrap = ["/usr/bin/bwrap", "/bin/bwrap"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .ok_or(SandboxError::Unsupported)?;
        let binary = self
            .binary
            .canonicalize()
            .map_err(|_| SandboxError::InvalidPath)?;
        let mut command = std::process::Command::new(bwrap);
        // Keep the host PID namespace for authenticated SO_PEERCRED with core.
        // /proc is absent; seccomp denies process inspection and child creation.
        command
            .env_clear()
            .args([
                "--unshare-user",
                "--unshare-net",
                "--unshare-ipc",
                "--unshare-uts",
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
            .args(["--hostname", "localhost", "--ro-bind", "/usr", "/usr"]);
        for path in ["/bin", "/lib", "/lib64"] {
            if Path::new(path).exists() {
                command.args(["--ro-bind", path, path]);
            }
        }
        command
            .args([
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--dir",
                "/run/nymwrap",
                "--chdir",
                "/tmp",
                "--ro-bind",
            ])
            .arg(binary)
            .arg("/daemon");
        for socket in &self.upstream {
            let meta = std::fs::symlink_metadata(socket).map_err(|_| SandboxError::Api)?;
            if !socket.is_absolute()
                || !meta.file_type().is_socket()
                || meta.mode() & 0o077 != 0
                || meta.uid().to_string()
                    != nw_platform::current_user_id().map_err(|_| SandboxError::Launch)?
            {
                return Err(SandboxError::Api);
            }
            command.arg("--ro-bind").arg(socket).arg(socket);
        }
        if let Some(listener) = &self.listener {
            let parent = listener.parent().ok_or(SandboxError::Api)?;
            nw_platform::create_private_directory_all(parent).map_err(|_| SandboxError::Launch)?;
            // Mount a dedicated directory containing this leaf's listener only.
            if std::fs::read_dir(parent)
                .map_err(|_| SandboxError::Api)?
                .next()
                .is_some()
            {
                return Err(SandboxError::Api);
            }
            command.arg("--bind").arg(parent).arg(parent);
        }
        for (label, path) in &self.files {
            if label.is_empty()
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_')
            {
                return Err(SandboxError::InvalidPath);
            }
            let path = path.canonicalize().map_err(|_| SandboxError::InvalidPath)?;
            if !path.is_file() {
                return Err(SandboxError::InvalidPath);
            }
            command
                .arg("--ro-bind")
                .arg(path)
                .arg(format!("/run/nymwrap/{label}"));
        }
        super::normalize_environment(&mut command)?;
        nw_platform::sandbox_data_files(
            &mut command,
            &[("/run/nymwrap/leaf-profile", b"nw-leaf-v1")],
        )
        .map_err(|_| SandboxError::Launch)?;
        for (name, value) in &self.environment {
            command
                .env(name, value)
                .arg("--setenv")
                .arg(name)
                .arg(value);
        }
        nw_platform::sandbox_leaf_filter(&mut command).map_err(|_| SandboxError::Launch)?;
        let status =
            nw_platform::sandbox_status_stream(&mut command).map_err(|_| SandboxError::Launch)?;
        command
            .args(["--", "/daemon"])
            .args(self.arguments.iter().map(|arg| {
                arg.to_str()
                    .and_then(|s| s.strip_prefix("@file:"))
                    .map(|label| OsString::from(format!("/run/nymwrap/{label}")))
                    .unwrap_or_else(|| arg.clone())
            }));
        let mut command = tokio::process::Command::from(command);
        let mut monitor = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| SandboxError::Launch)?;
        let stdin = monitor.stdin.take().map(Input::Ordinary);
        let stdout = monitor.stdout.take().map(Output::Ordinary);
        let status = tokio::net::UnixStream::from_std(status).map_err(|_| SandboxError::Launch)?;
        let mut line = String::new();
        let mut status = tokio::io::BufReader::new(status.take(4097));
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            status.read_line(&mut line),
        )
        .await
        .map_err(|_| SandboxError::Launch)?
        .map_err(|_| SandboxError::Launch)?;
        if count == 0 || count > 4096 || !line.ends_with('\n') {
            return Err(SandboxError::Launch);
        }
        let info: serde_json::Value =
            serde_json::from_str(&line).map_err(|_| SandboxError::Launch)?;
        let pid = info["child-pid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(SandboxError::Launch)?;
        let identity =
            nw_platform::SandboxIdentity::pin(pid, monitor.id().ok_or(SandboxError::Launch)?)
                .map_err(|_| SandboxError::Launch)?;
        Ok(Child {
            inner: Inner::Bubblewrap {
                monitor,
                identity,
                _status: status,
            },
            stdin,
            stdout,
        })
    }
}

#[cfg(windows)]
impl Launch {
    fn spawn_windows(self) -> Result<Child, SandboxError> {
        let endpoints: Vec<_> = self
            .listener
            .iter()
            .chain(self.upstream.iter())
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        let mut process = nw_platform::appcontainer_daemon(
            &self.binary,
            &self.arguments,
            &self.files,
            &endpoints,
            &self.environment,
            self.listener.as_ref().and_then(|p| p.to_str()),
        )
        .map_err(|_| SandboxError::Launch)?;
        let stdin = process
            .stdin
            .take()
            .map(tokio::fs::File::from_std)
            .map(Input::Native);
        let stdout = process
            .stdout
            .take()
            .map(tokio::fs::File::from_std)
            .map(Output::Native);
        Ok(Child {
            inner: Inner::Native(process),
            stdin,
            stdout,
        })
    }
}
