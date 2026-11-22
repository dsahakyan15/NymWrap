//! Authenticated, domain-separated encrypted blobs. Keys never serialize implicitly.
pub mod os_secret;
pub mod store;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use nw_platform::LockedKey;
use nw_proto::Lane;
use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"NWRAP\0\0\x01";
pub const MAX_BLOB: usize = 16 * 1024 * 1024;

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    ShadowHistory,
    Vault,
    Persona,
    CoverLog,
    Imports,
    Metrics,
}
impl Domain {
    pub const ALL: [Self; 6] = [
        Self::ShadowHistory,
        Self::Vault,
        Self::Persona,
        Self::CoverLog,
        Self::Imports,
        Self::Metrics,
    ];
    pub fn lane(self) -> Lane {
        if self == Self::CoverLog {
            Lane::Cover
        } else {
            Lane::Shadow
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::ShadowHistory => "shadow_history",
            Self::Vault => "vault",
            Self::Persona => "persona",
            Self::CoverLog => "cover_log",
            Self::Imports => "imports",
            Self::Metrics => "metrics",
        }
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("authentication_failed")]
    Authentication,
    #[error("invalid_ciphertext")]
    Invalid,
    #[error("domain_key_unavailable")]
    KeyUnavailable,
    #[error("vault_io_error")]
    Io,
    #[error("blob_too_large")]
    TooLarge,
    #[error("key_derivation_failed")]
    Kdf,
    #[error("os_secret_unavailable")]
    OsSecret,
    #[error("store_locked")]
    Locked,
    #[error("store_already_exists")]
    Exists,
    #[error("invalid_record")]
    Record,
    #[error("sqlcipher_unavailable")]
    Cipher,
    #[error("key_cleanup_required")]
    Cleanup,
    #[error("commit_durability_uncertain")]
    CommitUncertain,
    #[error("key_memory_lock_failed")]
    MemoryLock,
}

pub struct MasterKey(LockedKey);
impl MasterKey {
    pub fn random() -> Result<Self, VaultError> {
        let mut bytes = Box::new([0u8; 32]);
        OsRng.fill_bytes(bytes.as_mut_slice());
        Ok(Self(
            LockedKey::new(SecretBox::new(bytes)).map_err(|_| VaultError::MemoryLock)?,
        ))
    }
    /// os_secret must come from an OS credential store, not from a configuration file.
    pub fn derive(
        password: &SecretString,
        os_secret: &LockedKey,
        salt: &[u8; 16],
    ) -> Result<Self, VaultError> {
        Self::derive_for_profile(password, os_secret, salt, true)
    }
    fn derive_for_profile(
        password: &SecretString,
        os_secret: &LockedKey,
        salt: &[u8; 16],
        required: bool,
    ) -> Result<Self, VaultError> {
        if (required || !password.expose_secret().is_empty()) && password.expose_secret().len() < 12
            || password.expose_secret().len() > 1024
        {
            return Err(VaultError::Kdf);
        }
        let mut material = Zeroizing::new(Vec::with_capacity(password.expose_secret().len() + 32));
        material.extend_from_slice(password.expose_secret().as_bytes());
        material.extend_from_slice(os_secret.expose_secret());
        let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| VaultError::Kdf)?;
        let mut output = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(&material, salt, output.as_mut_slice())
            .map_err(|_| VaultError::Kdf)?;
        Ok(Self(
            LockedKey::new(SecretBox::new(Box::new(*output)))
                .map_err(|_| VaultError::MemoryLock)?,
        ))
    }
}

pub struct KeyRing {
    keys: BTreeMap<Domain, LockedKey>,
}
impl KeyRing {
    pub fn new() -> Result<Self, VaultError> {
        let keys = Domain::ALL
            .into_iter()
            .map(|domain| {
                let key = MasterKey::random()?.0;
                Ok((domain, key))
            })
            .collect::<Result<_, VaultError>>()?;
        Ok(Self { keys })
    }
    pub fn seal(&self, domain: Domain, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let key = self.keys.get(&domain).ok_or(VaultError::KeyUnavailable)?;
        encrypt(key, domain.name().as_bytes(), plaintext)
    }
    pub fn open(
        &self,
        domain: Domain,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let key = self.keys.get(&domain).ok_or(VaultError::KeyUnavailable)?;
        decrypt(key, domain.name().as_bytes(), ciphertext)
    }
    pub fn shred(&mut self, domain: Domain) {
        self.keys.remove(&domain);
    }
    pub fn shred_all(&mut self) {
        self.keys.clear();
    }
    /// The caller must replace every persisted wrapped keyring when shredding a domain.
    pub fn wrap(&self, master: &MasterKey) -> Result<Vec<u8>, VaultError> {
        let mut bytes = Zeroizing::new(Vec::new());
        for (i, domain) in Domain::ALL.iter().enumerate() {
            if let Some(key) = self.keys.get(domain) {
                bytes.push(i as u8);
                bytes.extend_from_slice(key.expose_secret());
            }
        }
        encrypt(&master.0, b"keyring-v1", &bytes)
    }
    pub fn unwrap(master: &MasterKey, ciphertext: &[u8]) -> Result<Self, VaultError> {
        let bytes = decrypt(&master.0, b"keyring-v1", ciphertext)?;
        if bytes.len() % 33 != 0 || bytes.len() > 198 {
            return Err(VaultError::Invalid);
        }
        let mut keys = BTreeMap::new();
        for chunk in bytes.as_chunks::<33>().0 {
            let domain = *Domain::ALL
                .get(chunk[0] as usize)
                .ok_or(VaultError::Invalid)?;
            let mut key = Box::new([0; 32]);
            key.copy_from_slice(&chunk[1..]);
            if keys
                .insert(
                    domain,
                    LockedKey::new(SecretBox::new(key)).map_err(|_| VaultError::MemoryLock)?,
                )
                .is_some()
            {
                return Err(VaultError::Invalid);
            }
        }
        Ok(Self { keys })
    }
    pub fn write(&self, domain: Domain, path: &Path, plaintext: &[u8]) -> Result<(), VaultError> {
        write_ciphertext_new(path, &self.seal(domain, plaintext)?)
    }
    pub fn read(&self, domain: Domain, path: &Path) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut file = fs::File::open(path)
            .map_err(|_| VaultError::Io)?
            .take((MAX_BLOB + 49) as u64);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| VaultError::Io)?;
        self.open(domain, &bytes)
    }
}

fn encrypt(key: &LockedKey, domain: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    if plaintext.len() > MAX_BLOB {
        return Err(VaultError::TooLarge);
    }
    let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut aad = MAGIC.to_vec();
    aad.extend_from_slice(domain);
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Authentication)?;
    let mut bytes = Vec::with_capacity(32 + encrypted.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&encrypted);
    Ok(bytes)
}
fn decrypt(key: &LockedKey, domain: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if bytes.len() < 48 || bytes.len() > MAX_BLOB + 48 || &bytes[..8] != MAGIC {
        return Err(VaultError::Invalid);
    }
    let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
    let mut aad = MAGIC.to_vec();
    aad.extend_from_slice(domain);
    cipher
        .decrypt(
            XNonce::from_slice(&bytes[8..32]),
            Payload {
                msg: &bytes[32..],
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Authentication)
}

/// Refuse overwrite and symlinks. Only authenticated ciphertext is ever written.
pub fn write_ciphertext_new(path: &Path, ciphertext: &[u8]) -> Result<(), VaultError> {
    if ciphertext.len() < 48 || ciphertext.len() > MAX_BLOB + 48 || &ciphertext[..8] != MAGIC {
        return Err(VaultError::Invalid);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| VaultError::Io)?;
    file.write_all(ciphertext)
        .and_then(|_| file.sync_all())
        .map_err(|_| VaultError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn files_are_ciphertext_authenticated_and_keys_are_separate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.nwenc");
        let mut ring = KeyRing::new().unwrap();
        let secret = b"SYNTHETIC_PRIVATE_HISTORY_58103";
        ring.write(Domain::ShadowHistory, &path, secret).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
        assert_eq!(&**ring.read(Domain::ShadowHistory, &path).unwrap(), secret);
        assert!(ring.open(Domain::CoverLog, &bytes).is_err());
        let mut tampered = bytes.clone();
        tampered[35] ^= 1;
        assert!(ring.open(Domain::ShadowHistory, &tampered).is_err());
        let master = MasterKey::random().unwrap();
        let wrapped = ring.wrap(&master).unwrap();
        assert!(KeyRing::unwrap(&MasterKey::random().unwrap(), &wrapped).is_err());
        assert_eq!(
            &**KeyRing::unwrap(&master, &wrapped)
                .unwrap()
                .open(Domain::ShadowHistory, &bytes)
                .unwrap(),
            secret
        );
        ring.shred(Domain::ShadowHistory);
        let recovered = KeyRing::unwrap(&master, &ring.wrap(&master).unwrap()).unwrap();
        assert!(recovered.open(Domain::ShadowHistory, &bytes).is_err());
        assert!(ring.write(Domain::Vault, &path, secret).is_err());
    }
}
