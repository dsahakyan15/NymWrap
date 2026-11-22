//! OS credentials are the only persistence backend for root secrets.
use crate::VaultError;
use nw_platform::LockedKey;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

pub trait SecretStore: Send + Sync {
    fn put(&self, id: &str, value: &LockedKey) -> Result<(), VaultError>;
    fn get(&self, id: &str) -> Result<LockedKey, VaultError>;
    fn remove(&self, id: &str) -> Result<(), VaultError>;
}
pub struct OsSecretStore;
fn entry(id: &str) -> Result<keyring::Entry, VaultError> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(VaultError::Invalid);
    }
    keyring::Entry::new("NymWrap.v1", id).map_err(|_| VaultError::OsSecret)
}
impl SecretStore for OsSecretStore {
    fn put(&self, id: &str, value: &LockedKey) -> Result<(), VaultError> {
        let entry = entry(id)?;
        match entry.get_secret() {
            Err(keyring::Error::NoEntry) => {}
            _ => return Err(VaultError::OsSecret),
        }
        entry
            .set_secret(value.expose_secret())
            .map_err(|_| VaultError::OsSecret)
    }
    fn get(&self, id: &str) -> Result<LockedKey, VaultError> {
        let bytes = Zeroizing::new(entry(id)?.get_secret().map_err(|_| VaultError::OsSecret)?);
        if bytes.len() != 32 {
            return Err(VaultError::Invalid);
        }
        let mut key = Box::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        LockedKey::new(SecretBox::new(key)).map_err(|_| VaultError::MemoryLock)
    }
    fn remove(&self, id: &str) -> Result<(), VaultError> {
        match entry(id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(VaultError::OsSecret),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, rngs::OsRng};
    #[test]
    #[ignore = "requires an available unlocked OS credential store"]
    fn actual_os_secret_roundtrip() {
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let key = LockedKey::new(SecretBox::new(Box::new([73u8; 32]))).unwrap();
        let provider = OsSecretStore;
        provider.put(&id, &key).unwrap();
        let result = provider.get(&id);
        provider.remove(&id).unwrap();
        assert_eq!(result.unwrap().expose_secret(), key.expose_secret());
        assert!(provider.get(&id).is_err());
    }
}
