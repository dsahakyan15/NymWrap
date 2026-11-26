//! Ephemeral authority belongs to a process instance, never a filename or uid.
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use nw_platform::LockedKey;
use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretBox};
use std::{io::Read, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, sync::oneshot};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"NWRPC\0\x01\0";
const BOOTSTRAP_BYTES: usize = 45;
pub(super) const HANDSHAKE: Duration = Duration::from_secs(2);
pub(super) const CHALLENGE_BYTES: usize = 32;
const WIRE_OVERHEAD: usize = 24 + 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcRole {
    Control,
    Api,
}
impl RpcRole {
    fn byte(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Api => 1,
        }
    }
    pub(super) fn permits(self, command: &super::Command) -> bool {
        use super::Command;
        self == Self::Control
            || matches!(
                command,
                Command::SubmitRemoteJob { .. }
                    | Command::LoadRemoteJob { .. }
                    | Command::CancelRemoteJob { .. }
                    | Command::Chat { .. }
                    | Command::RemoteChat { .. }
                    | Command::Embeddings { .. }
            )
    }
}
pub(super) struct Key(LockedKey);
impl Key {
    fn from_bytes(mut bytes: [u8; 32]) -> Result<Arc<Self>, String> {
        let key = LockedKey::new(SecretBox::new(Box::new(bytes)));
        bytes.zeroize();
        key.map(|key| Arc::new(Self(key)))
            .map_err(|_| "memory_lock_failed".into())
    }
    pub(super) fn random() -> Result<Arc<Self>, String> {
        let mut bytes = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(&mut *bytes);
        Self::from_bytes(*bytes)
    }
    fn aad(role: RpcRole, challenge: &[u8; CHALLENGE_BYTES], reply: bool) -> Vec<u8> {
        let mut aad = b"nymwrap-core-shadow-rpc-v1".to_vec();
        aad.extend_from_slice(&[role.byte(), u8::from(reply)]);
        aad.extend_from_slice(challenge);
        aad
    }
    pub(super) fn seal(
        &self,
        role: RpcRole,
        challenge: &[u8; CHALLENGE_BYTES],
        reply: bool,
        plaintext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        if plaintext.is_empty() || plaintext.len() > super::FRAME_LIMIT - WIRE_OVERHEAD {
            return Err("invalid_core_request".into());
        }
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = XChaCha20Poly1305::new(self.0.expose_secret().into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &Self::aad(role, challenge, reply),
                },
            )
            .map_err(|_| "ipc_authentication_failed")?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(24 + ciphertext.len()));
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        Ok(bytes)
    }
    pub(super) fn open(
        &self,
        role: RpcRole,
        challenge: &[u8; CHALLENGE_BYTES],
        reply: bool,
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        if bytes.len() <= WIRE_OVERHEAD || bytes.len() > super::FRAME_LIMIT {
            return Err("ipc_authentication_failed".into());
        }
        XChaCha20Poly1305::new(self.0.expose_secret().into())
            .decrypt(
                XNonce::from_slice(&bytes[..24]),
                Payload {
                    msg: &bytes[24..],
                    aad: &Self::aad(role, challenge, reply),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| "ipc_authentication_failed".into())
    }
    pub(super) async fn deliver(
        &self,
        writer: &mut (impl tokio::io::AsyncWrite + Unpin),
        role: RpcRole,
    ) -> Result<(), String> {
        let mut bytes = Zeroizing::new([0; BOOTSTRAP_BYTES]);
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = role.byte();
        bytes[9..13].copy_from_slice(&std::process::id().to_le_bytes());
        bytes[13..].copy_from_slice(self.0.expose_secret());
        tokio::time::timeout(HANDSHAKE, async {
            writer.write_all(&*bytes).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| "ipc_timeout")?
        .map_err(|_| "ipc_bootstrap_failed".into())
    }
}

#[derive(Clone)]
pub(super) struct Grant {
    pub(super) key: Arc<Key>,
    pub(super) pid: u32,
    pub(super) role: RpcRole,
}
#[derive(Default)]
pub(super) struct Access {
    pub(super) grants: Vec<Grant>,
}
impl Access {
    pub(super) fn for_peer(&self, pid: u32) -> Option<Grant> {
        let mut matches = self
            .grants
            .iter()
            .filter(|grant| grant.pid == pid && pid != 0);
        let grant = matches.next()?.clone();
        matches.next().is_none().then_some(grant)
    }
}

/// The only production authority input is a dedicated inherited anonymous pipe.
/// The parent chooses a fresh key for every child; no session key is reattached.
pub struct ParentSession {
    pub(super) grant: Grant,
    pub parent_closed: oneshot::Receiver<()>,
}
impl ParentSession {
    pub async fn read(role: RpcRole) -> Result<Self, String> {
        let (bootstrap_tx, bootstrap_rx) = oneshot::channel();
        let (closed_tx, parent_closed) = oneshot::channel();
        // std's stdin can block after async cancellation. This dedicated thread
        // is not a runtime worker and cannot keep a failed bootstrap alive.
        std::thread::spawn(move || {
            let mut stdin = match nw_platform::inherited_stdin_pipe() {
                Ok(pipe) => pipe,
                Err(error) => {
                    let _ = bootstrap_tx.send(Err(error));
                    return;
                }
            };
            let mut bytes = Zeroizing::new([0; BOOTSTRAP_BYTES]);
            let result = stdin.read_exact(&mut *bytes).map(|()| bytes);
            if bootstrap_tx.send(result).is_err() {
                return;
            }
            let _ = stdin.read(&mut [0; 1]);
            let _ = closed_tx.send(());
        });
        let bytes = tokio::time::timeout(Duration::from_secs(5), bootstrap_rx)
            .await
            .map_err(|_| "ipc_bootstrap_timeout")?
            .map_err(|_| "ipc_bootstrap_failed")?
            .map_err(|_| "ipc_bootstrap_failed")?;
        if &bytes[..8] != MAGIC || bytes[8] != role.byte() {
            return Err("ipc_bootstrap_failed".into());
        }
        let pid = u32::from_le_bytes(
            bytes[9..13]
                .try_into()
                .map_err(|_| "ipc_bootstrap_failed")?,
        );
        if pid == 0 || pid == std::process::id() {
            return Err("ipc_bootstrap_failed".into());
        }
        let key = Key::from_bytes(bytes[13..].try_into().map_err(|_| "ipc_bootstrap_failed")?)?;
        Ok(Self {
            grant: Grant { key, pid, role },
            parent_closed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_bind_role_direction_challenge_key_and_content() {
        let key = Key::random().unwrap();
        let other = Key::random().unwrap();
        let challenge = [17; 32];
        let value = b"SYNTHETIC_RPC_AUTH_CANARY";
        let mut frame = key
            .seal(RpcRole::Control, &challenge, false, value)
            .unwrap();
        assert!(!frame.windows(value.len()).any(|bytes| bytes == value));
        assert_eq!(
            &*key
                .open(RpcRole::Control, &challenge, false, &frame)
                .unwrap(),
            value
        );
        assert!(key.open(RpcRole::Api, &challenge, false, &frame).is_err());
        assert!(
            key.open(RpcRole::Control, &challenge, true, &frame)
                .is_err()
        );
        assert!(
            key.open(RpcRole::Control, &[18; 32], false, &frame)
                .is_err()
        );
        assert!(
            other
                .open(RpcRole::Control, &challenge, false, &frame)
                .is_err()
        );
        frame[24] ^= 1;
        assert!(
            key.open(RpcRole::Control, &challenge, false, &frame)
                .is_err()
        );
        for bytes in [&[][..], &[0; 24][..], &[0; WIRE_OVERHEAD][..]] {
            assert!(
                key.open(RpcRole::Control, &challenge, false, bytes)
                    .is_err()
            );
        }
    }
}
