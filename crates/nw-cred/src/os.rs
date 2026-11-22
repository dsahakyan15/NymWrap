//! Provider tokens are stored only in the OS credential store, never config files.
use crate::CredentialError;
use nw_platform::LockedString;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;
pub trait ProviderSecrets: Send + Sync {
    fn put(&self, id: &str, key: &LockedString) -> Result<(), CredentialError>;
    fn get(&self, id: &str) -> Result<LockedString, CredentialError>;
    fn remove(&self, id: &str) -> Result<(), CredentialError>;
}
pub struct OsProviderSecrets;
pub fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn entry(id: &str) -> Result<keyring::Entry, CredentialError> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CredentialError::Invalid);
    }
    keyring::Entry::new("NymWrap.provider.v1", id).map_err(|_| CredentialError::Store)
}
pub fn validate(key: &str) -> Result<(), CredentialError> {
    if key.len() < 8 || key.len() > 4096 || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(CredentialError::Invalid);
    }
    Ok(())
}
impl ProviderSecrets for OsProviderSecrets {
    fn put(&self, id: &str, key: &LockedString) -> Result<(), CredentialError> {
        validate(key.expose_secret())?;
        let target = entry(id)?;
        if !matches!(target.get_secret(), Err(keyring::Error::NoEntry)) {
            return Err(CredentialError::Store);
        }
        target
            .set_secret(key.expose_secret().as_bytes())
            .map_err(|_| CredentialError::Store)
    }
    fn get(&self, id: &str) -> Result<LockedString, CredentialError> {
        let bytes = Zeroizing::new(
            entry(id)?
                .get_secret()
                .map_err(|_| CredentialError::Store)?,
        );
        let text = std::str::from_utf8(&bytes).map_err(|_| CredentialError::Invalid)?;
        validate(text)?;
        LockedString::new(SecretString::from(text.to_owned()))
            .map_err(|_| CredentialError::MemoryLock)
    }
    fn remove(&self, id: &str) -> Result<(), CredentialError> {
        match entry(id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(CredentialError::Store),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_cannot_inject_http_headers() {
        for value in ["", "short", "synthetic\r\nCookie:bad", "synthetic token"] {
            assert!(validate(value).is_err());
        }
        assert!(validate("synthetic-token_only").is_ok());
    }
    #[test]
    #[ignore = "requires an unlocked OS credential store; writes a synthetic token only"]
    fn actual_provider_credential_roundtrip() {
        let id = random_id();
        let store = OsProviderSecrets;
        let key = LockedString::new(SecretString::from("synthetic-provider-token-only")).unwrap();
        store.put(&id, &key).unwrap();
        let result = store.get(&id);
        store.remove(&id).unwrap();
        assert_eq!(result.unwrap().expose_secret(), key.expose_secret());
    }
}
