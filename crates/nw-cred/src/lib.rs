//! One credential lease per conversation; exhausted pools never silently reuse keys.
use nw_platform::LockedString;
use secrecy::{ExposeSecret, SecretString};
pub mod os;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CredentialError {
    #[error("credential_memory_lock_failed")]
    MemoryLock,
    #[error("credential_store_unavailable")]
    Store,
    #[error("credential_pool_exhausted")]
    Exhausted,
    #[error("invalid_conversation")]
    Invalid,
    #[error("zkapi_unavailable")]
    Unavailable,
}
pub trait CredentialProvider {
    fn acquire(&mut self, conversation: &str) -> Result<&LockedString, CredentialError>;
    fn release(&mut self, conversation: &str);
}
pub struct KeyPool {
    available: VecDeque<LockedString>,
    leased: BTreeMap<String, LockedString>,
    retired: BTreeSet<String>,
}
impl KeyPool {
    pub fn new(keys: Vec<SecretString>) -> Result<Self, CredentialError> {
        let mut unique = BTreeSet::new();
        if keys.len() > 1000
            || keys.iter().any(|k| {
                k.expose_secret().len() < 8
                    || k.expose_secret().len() > 4096
                    || !unique.insert(k.expose_secret())
            })
        {
            return Err(CredentialError::Invalid);
        }
        Ok(Self {
            available: keys
                .into_iter()
                .map(|key| LockedString::new(key).map_err(|_| CredentialError::MemoryLock))
                .collect::<Result<_, _>>()?,
            leased: BTreeMap::new(),
            retired: BTreeSet::new(),
        })
    }
}
impl CredentialProvider for KeyPool {
    fn acquire(&mut self, conversation: &str) -> Result<&LockedString, CredentialError> {
        if conversation.is_empty()
            || conversation.len() > 128
            || self.retired.contains(conversation)
        {
            return Err(CredentialError::Invalid);
        }
        if !self.leased.contains_key(conversation) {
            let key = self
                .available
                .pop_front()
                .ok_or(CredentialError::Exhausted)?;
            self.leased.insert(conversation.to_owned(), key);
        }
        self.leased
            .get(conversation)
            .ok_or(CredentialError::Exhausted)
    }
    fn release(&mut self, conversation: &str) {
        if self.leased.remove(conversation).is_some() {
            self.retired.insert(conversation.to_owned());
        }
    }
}
#[cfg(feature = "experimental-zkapi")]
pub fn experimental_zkapi_status() -> Result<(), CredentialError> {
    Err(CredentialError::Unavailable)
}
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    #[test]
    fn keys_are_bound_and_never_recycled_across_conversations() {
        let mut pool = KeyPool::new(vec![
            SecretString::from("synthetic-key-a"),
            SecretString::from("synthetic-key-b"),
        ])
        .unwrap();
        assert_eq!(
            pool.acquire("a").unwrap().expose_secret(),
            "synthetic-key-a"
        );
        assert_eq!(
            pool.acquire("a").unwrap().expose_secret(),
            "synthetic-key-a"
        );
        assert_eq!(
            pool.acquire("b").unwrap().expose_secret(),
            "synthetic-key-b"
        );
        pool.release("a");
        assert!(pool.acquire("c").is_err());
        assert!(pool.acquire("a").is_err());
        assert!(
            KeyPool::new(vec![
                SecretString::from("synthetic-duplicate"),
                SecretString::from("synthetic-duplicate")
            ])
            .is_err()
        );
    }
}
