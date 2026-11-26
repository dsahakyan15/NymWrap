//! Private local IPC, bounded framing, and a lane fixed by the listener.
pub use interprocess::local_socket::tokio::Stream as LocalStream;
use interprocess::local_socket::{
    self as local, ListenerOptions,
    prelude::*,
    tokio::{Stream, prelude::*},
};
use nw_proto::{Lane, MAX_FRAME_BYTES};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
#[cfg(unix)]
use std::path::Path;
use std::{io, time::Duration};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// Different configured data roots must never share a Windows pipe namespace.
/// In particular, a synthetic test instance cannot bind the user's live pipes.
#[cfg(windows)]
pub fn user_namespace() -> Result<String, IpcError> {
    use sha2::{Digest, Sha256};
    use std::{
        os::windows::ffi::OsStrExt,
        path::{Component, PathBuf},
    };
    let root = PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or(IpcError::Endpoint)?);
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(IpcError::Endpoint);
    }
    let user = nw_platform::current_user_id().map_err(|_| IpcError::Peer)?;
    let mut hash = Sha256::new();
    hash.update(b"nymwrap-user-data-root-v1\0");
    hash.update((user.len() as u64).to_le_bytes());
    hash.update(user.as_bytes());
    for code in root.as_os_str().encode_wide() {
        if code == 0 {
            return Err(IpcError::Endpoint);
        }
        hash.update(code.to_le_bytes());
    }
    Ok(format!("{:x}", hash.finalize())[..24].to_owned())
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("invalid_ipc_endpoint")]
    Endpoint,
    #[error("ipc_unavailable")]
    Io,
    #[error("ipc_wrong_peer")]
    Peer,
    #[error("ipc_wrong_lane")]
    Lane,
    #[error("invalid_ipc_frame")]
    Frame,
    #[error("ipc_timeout")]
    Timeout,
}
#[derive(Clone)]
pub struct Endpoint {
    value: String,
    lane: Lane,
    #[cfg(windows)]
    sandboxed: bool,
}
impl Endpoint {
    pub fn new(value: String, lane: Lane) -> Result<Self, IpcError> {
        #[cfg(windows)]
        {
            let name = value.strip_prefix(r"\\.\pipe\").unwrap_or(&value);
            let name = name.strip_prefix(r"LOCAL\").unwrap_or(name);
            if !name.starts_with("nymwrap-")
                || name.len() > 180
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                return Err(IpcError::Endpoint);
            }
            Ok(Self {
                value: name.to_owned(),
                lane,
                sandboxed: name.ends_with("-api") || name.ends_with("-llm"),
            })
        }
        #[cfg(unix)]
        {
            if !Path::new(&value).is_absolute()
                || value.len() > 100
                || value.as_bytes().contains(&0)
            {
                return Err(IpcError::Endpoint);
            }
            Ok(Self { value, lane })
        }
    }
    pub fn lane(&self) -> Lane {
        self.lane
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    pub fn sandboxed(mut self) -> Self {
        #[cfg(windows)]
        {
            self.sandboxed = true;
        }
        #[cfg(not(windows))]
        {
            let _ = &mut self;
        }
        self
    }
    fn name(&self, _server: bool) -> Result<local::Name<'_>, IpcError> {
        #[cfg(windows)]
        {
            let name = if self.sandboxed {
                if _server {
                    format!(r"LOCAL\{}", self.value)
                } else {
                    nw_platform::appcontainer_pipe_address(&self.value)
                        .map_err(|_| IpcError::Endpoint)?
                }
            } else {
                self.value.clone()
            };
            name.to_ns_name::<local::GenericNamespaced>()
                .map_err(|_| IpcError::Endpoint)
        }
        #[cfg(unix)]
        {
            self.value
                .as_str()
                .to_fs_name::<local::GenericFilePath>()
                .map_err(|_| IpcError::Endpoint)
        }
    }
    pub async fn connect(&self) -> Result<Stream, IpcError> {
        let stream =
            tokio::time::timeout(Duration::from_secs(5), Stream::connect(self.name(false)?))
                .await
                .map_err(|_| IpcError::Timeout)?
                .map_err(|_| IpcError::Io)?;
        authenticate(&stream)?;
        Ok(stream)
    }
}
pub struct Listener {
    inner: local::tokio::Listener,
    endpoint: Endpoint,
}
impl axum::serve::Listener for Listener {
    type Io = Stream;
    type Addr = ();
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match Listener::accept(self).await {
                Ok(stream) => return (stream, ()),
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }
    fn local_addr(&self) -> io::Result<()> {
        Ok(())
    }
}
impl Listener {
    pub fn bind(endpoint: Endpoint) -> Result<Self, IpcError> {
        #[cfg(unix)]
        {
            use std::{
                fs,
                os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
            };
            let parent = Path::new(&endpoint.value)
                .parent()
                .ok_or(IpcError::Endpoint)?;
            match fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
            {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(IpcError::Io),
            }
            let meta = fs::symlink_metadata(parent).map_err(|_| IpcError::Io)?;
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.permissions().mode() & 0o077 != 0
                || meta.uid().to_string()
                    != nw_platform::current_user_id().map_err(|_| IpcError::Peer)?
            {
                return Err(IpcError::Peer);
            }
        }
        let options = ListenerOptions::new()
            .name(endpoint.name(true)?)
            .try_overwrite(false);
        #[cfg(windows)]
        let options = {
            use interprocess::os::windows::{
                local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor,
            };
            let sid = nw_platform::current_user_id().map_err(|_| IpcError::Peer)?;
            let capability =
                nw_platform::appcontainer_pipe_acl(endpoint.value()).map_err(|_| IpcError::Peer)?;
            let sddl = widestring::U16CString::from_str(format!(
                "O:{sid}D:P(D;;GA;;;NU)(A;;GA;;;{sid}){capability}S:(ML;;NW;;;LW)"
            ))
            .map_err(|_| IpcError::Peer)?;
            options.security_descriptor(
                SecurityDescriptor::deserialize(&sddl).map_err(|_| IpcError::Peer)?,
            )
        };
        #[cfg(target_os = "linux")]
        let options = {
            use interprocess::os::unix::local_socket::ListenerOptionsExt;
            options.mode(0o600)
        };
        let inner = options.create_tokio().map_err(|_| IpcError::Io)?;
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&endpoint.value, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| IpcError::Io)?;
        }
        Ok(Self { inner, endpoint })
    }
    pub fn lane(&self) -> Lane {
        self.endpoint.lane
    }
    pub async fn accept(&self) -> Result<Stream, IpcError> {
        let stream = self.inner.accept().await.map_err(|_| IpcError::Io)?;
        authenticate(&stream)?;
        Ok(stream)
    }
}
fn authenticate(stream: &Stream) -> Result<(), IpcError> {
    let expected = nw_platform::current_user_id().map_err(|_| IpcError::Peer)?;
    #[cfg(unix)]
    {
        if stream
            .peer_creds()
            .map_err(|_| IpcError::Peer)?
            .euid()
            .map(|id| id.to_string())
            .as_deref()
            != Some(expected.as_str())
        {
            return Err(IpcError::Peer);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        let Stream::NamedPipe(pipe) = stream;
        if nw_platform::kernel_object_owner(pipe.as_handle()).map_err(|_| IpcError::Peer)?
            != expected
        {
            return Err(IpcError::Peer);
        }
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet<T> {
    pub version: u16,
    pub lane: Lane,
    pub request_id: u64,
    pub body: T,
}
pub fn peer_image(stream: &LocalStream) -> Result<std::path::PathBuf, IpcError> {
    nw_platform::process_image(peer_process(stream)?)
        .and_then(std::fs::canonicalize)
        .map_err(|_| IpcError::Peer)
}
pub fn peer_process(stream: &LocalStream) -> Result<u32, IpcError> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd;
        let Stream::UdSocket(socket) = stream;
        nw_platform::local_peer_process(socket.inner().as_fd()).map_err(|_| IpcError::Peer)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let pid = stream
            .peer_creds()
            .map_err(|_| IpcError::Peer)?
            .pid()
            .ok_or(IpcError::Peer)?;
        #[cfg(unix)]
        let pid = u32::try_from(pid).map_err(|_| IpcError::Peer)?;
        if pid == 0 {
            return Err(IpcError::Peer);
        }
        Ok(pid)
    }
}
impl<T> Packet<T> {
    pub fn new(lane: Lane, request_id: u64, body: T) -> Self {
        Self {
            version: nw_proto::SCHEMA_VERSION,
            lane,
            request_id,
            body,
        }
    }
}
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    read_frame_timeout(reader, limit, Duration::from_secs(120)).await
}
pub async fn read_frame_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let op = async {
        let length = reader.read_u32_le().await.map_err(|_| IpcError::Io)? as usize;
        if length == 0 || length > limit || length > 16 * 1024 * 1024 {
            return Err(IpcError::Frame);
        }
        let mut bytes = Zeroizing::new(vec![0u8; length]);
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(|_| IpcError::Io)?;
        Ok(bytes)
    };
    tokio::time::timeout(timeout, op)
        .await
        .map_err(|_| IpcError::Timeout)?
}
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    limit: usize,
) -> Result<(), IpcError> {
    if bytes.is_empty() || bytes.len() > limit || bytes.len() > 16 * 1024 * 1024 {
        return Err(IpcError::Frame);
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        writer
            .write_u32_le(bytes.len() as u32)
            .await
            .map_err(|_| IpcError::Io)?;
        writer.write_all(bytes).await.map_err(|_| IpcError::Io)?;
        writer.flush().await.map_err(|_| IpcError::Io)
    })
    .await
    .map_err(|_| IpcError::Timeout)?
}
pub async fn read_packet<T: DeserializeOwned, R: AsyncRead + Unpin>(
    reader: &mut R,
    lane: Lane,
) -> Result<Packet<T>, IpcError> {
    let bytes = read_frame(reader, MAX_FRAME_BYTES).await?;
    let packet: Packet<T> = serde_json::from_slice(&bytes).map_err(|_| IpcError::Frame)?;
    if packet.version != nw_proto::SCHEMA_VERSION {
        return Err(IpcError::Frame);
    }
    if packet.lane != lane {
        return Err(IpcError::Lane);
    }
    Ok(packet)
}
pub async fn write_packet<T: Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &Packet<T>,
    lane: Lane,
) -> Result<(), IpcError> {
    if packet.lane != lane {
        return Err(IpcError::Lane);
    }
    let bytes = Zeroizing::new(serde_json::to_vec(packet).map_err(|_| IpcError::Frame)?);
    write_frame(writer, &bytes, MAX_FRAME_BYTES).await
}

#[cfg(test)]
#[path = "../../../tests/leak/src/ipc_identity.rs"]
mod identity_tests;
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn private_roundtrip_rejects_foreign_lane_and_oversize() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let value = directory
            .path()
            .join("private/ipc.sock")
            .to_str()
            .unwrap()
            .to_owned();
        #[cfg(windows)]
        let value = format!(
            "nymwrap-test-{}-{}",
            std::process::id(),
            directory.path().file_name().unwrap().to_str().unwrap()
        );
        let endpoint = Endpoint::new(value, Lane::Shadow).unwrap();
        let listener = Listener::bind(endpoint.clone()).unwrap();
        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let packet: Packet<String> = read_packet(&mut stream, Lane::Shadow).await.unwrap();
            write_packet(&mut stream, &packet, Lane::Shadow)
                .await
                .unwrap();
        });
        let mut stream = endpoint.connect().await.unwrap();
        write_packet(
            &mut stream,
            &Packet::new(Lane::Shadow, 17, "synthetic"),
            Lane::Shadow,
        )
        .await
        .unwrap();
        assert!(matches!(
            read_packet::<String, _>(&mut stream, Lane::Cover).await,
            Err(IpcError::Lane)
        ));
        server.await.unwrap();
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_u32_le(u32::MAX).await.unwrap();
        assert!(matches!(
            read_frame(&mut b, MAX_FRAME_BYTES).await,
            Err(IpcError::Frame)
        ));
    }
}
