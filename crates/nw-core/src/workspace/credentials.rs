use super::{Domain, Workspace, WorkspaceError, now};
use nw_cred::os::ProviderSecrets;
use nw_platform::LockedString;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum State {
    Pending {},
    Available {},
    Leased { conversation: String },
    Retired { conversation: Option<String> },
    Deleted { conversation: Option<String> },
}
impl State {
    fn conversation(&self) -> Option<&str> {
        match self {
            Self::Leased { conversation } => Some(conversation),
            Self::Retired { conversation } | Self::Deleted { conversation } => {
                conversation.as_deref()
            }
            _ => None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    fingerprint: String,
    state: State,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    entries: Vec<Entry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialInfo {
    pub id: String,
    pub state: String,
}
fn identifier(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}
impl Workspace {
    pub fn has_provider_key(
        &mut self,
        conversation: &str,
        secrets: &dyn ProviderSecrets,
    ) -> Result<bool, WorkspaceError> {
        Ok(self.recover_credentials(secrets)?.entries.iter().any(|e| {
            matches!(e.state, State::Available {})
                || matches!(&e.state,State::Leased{conversation:c}if c==conversation)
        }))
    }
    fn credential_catalog(&mut self) -> Result<Catalog, WorkspaceError> {
        let catalog: Catalog = self
            .store
            .get_json(Domain::Vault, "provider-keys")?
            .unwrap_or_default();
        let mut ids = std::collections::BTreeSet::new();
        let mut hashes = std::collections::BTreeSet::new();
        let mut conversations = std::collections::BTreeSet::new();
        if catalog.entries.len() > 50_000
            || catalog.entries.iter().any(|e| {
                !identifier(&e.id, 64)
                    || !identifier(&e.fingerprint, 64)
                    || !ids.insert(&e.id)
                    || !hashes.insert(&e.fingerprint)
                    || e.state
                        .conversation()
                        .is_some_and(|c| !identifier(c, 32) || !conversations.insert(c))
            })
        {
            return Err(WorkspaceError::Invalid);
        }
        Ok(catalog)
    }
    fn save_credentials(&mut self, catalog: &Catalog) -> Result<(), WorkspaceError> {
        self.store
            .put_json(Domain::Vault, "provider-keys", catalog, now())?;
        Ok(())
    }
    fn recover_credentials(
        &mut self,
        secrets: &dyn ProviderSecrets,
    ) -> Result<Catalog, WorkspaceError> {
        let mut catalog = self.credential_catalog()?;
        let mut changed = false;
        for entry in &mut catalog.entries {
            if matches!(entry.state, State::Pending {} | State::Retired { .. }) {
                secrets.remove(&entry.id)?;
                entry.state = State::Deleted {
                    conversation: entry.state.conversation().map(str::to_owned),
                };
                changed = true;
            }
        }
        if changed {
            self.save_credentials(&catalog)?;
        }
        Ok(catalog)
    }
    pub fn provider_keys(
        &mut self,
        secrets: &dyn ProviderSecrets,
    ) -> Result<Vec<CredentialInfo>, WorkspaceError> {
        Ok(self
            .recover_credentials(secrets)?
            .entries
            .into_iter()
            .filter(|e| !matches!(e.state, State::Deleted { .. }))
            .map(|e| CredentialInfo {
                id: e.id,
                state: match e.state {
                    State::Available {} => "available",
                    State::Leased { .. } => "leased",
                    _ => "retired",
                }
                .into(),
            })
            .collect())
    }
    pub fn add_provider_key(
        &mut self,
        key: SecretString,
        secrets: &dyn ProviderSecrets,
    ) -> Result<String, WorkspaceError> {
        nw_cred::os::validate(key.expose_secret())?;
        let key = LockedString::new(key).map_err(|_| nw_cred::CredentialError::MemoryLock)?;
        let mut catalog = self.recover_credentials(secrets)?;
        let fingerprint = format!("{:x}", Sha256::digest(key.expose_secret().as_bytes()));
        if catalog.entries.len() >= 50_000
            || catalog
                .entries
                .iter()
                .filter(|e| !matches!(e.state, State::Deleted { .. }))
                .count()
                >= 1000
            || catalog.entries.iter().any(|e| e.fingerprint == fingerprint)
        {
            return Err(WorkspaceError::Policy);
        }
        let id = nw_cred::os::random_id();
        catalog.entries.push(Entry {
            id: id.clone(),
            fingerprint,
            state: State::Pending {},
        });
        self.save_credentials(&catalog)?; // durable staging precedes the OS secret.
        secrets.put(&id, &key)?;
        catalog
            .entries
            .last_mut()
            .ok_or(WorkspaceError::Invalid)?
            .state = State::Available {};
        self.save_credentials(&catalog)?;
        Ok(id)
    }
    pub fn acquire_provider_key(
        &mut self,
        conversation: &str,
        secrets: &dyn ProviderSecrets,
    ) -> Result<LockedString, WorkspaceError> {
        if !identifier(conversation, 32) {
            return Err(WorkspaceError::Invalid);
        }
        let mut catalog = self.recover_credentials(secrets)?;
        if catalog.entries.iter().any(|e| {
            matches!(e.state, State::Deleted { .. } | State::Retired { .. })
                && e.state.conversation() == Some(conversation)
        }) {
            return Err(WorkspaceError::Policy);
        }
        let index = catalog
            .entries
            .iter()
            .position(|e| matches!(&e.state,State::Leased{conversation:c}if c==conversation))
            .or_else(|| {
                catalog
                    .entries
                    .iter()
                    .position(|e| matches!(e.state, State::Available {}))
            })
            .ok_or(nw_cred::CredentialError::Exhausted)?;
        let entry = &mut catalog.entries[index];
        entry.state = State::Leased {
            conversation: conversation.into(),
        };
        let id = entry.id.clone();
        self.save_credentials(&catalog)?; // never recycle after an uncertain send.
        Ok(secrets.get(&id)?)
    }
    pub(crate) fn consume_provider_key(
        &mut self,
        conversation: &str,
        secrets: &dyn ProviderSecrets,
    ) -> Result<LockedString, WorkspaceError> {
        let key = self.acquire_provider_key(conversation, secrets)?;
        let id = self
            .credential_catalog()?
            .entries
            .into_iter()
            .find(|e| matches!(&e.state, State::Leased { conversation: c } if c == conversation))
            .ok_or(WorkspaceError::Invalid)?
            .id;
        // Persist the tombstone and delete the OS copy before a one-shot send.
        self.retire_provider_key(&id, secrets)?;
        Ok(key)
    }
    pub fn retire_provider_key(
        &mut self,
        id: &str,
        secrets: &dyn ProviderSecrets,
    ) -> Result<(), WorkspaceError> {
        let mut catalog = self.recover_credentials(secrets)?;
        let entry = catalog
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(WorkspaceError::Invalid)?;
        entry.state = State::Retired {
            conversation: entry.state.conversation().map(str::to_owned),
        };
        self.save_credentials(&catalog)?;
        self.recover_credentials(secrets)?;
        Ok(())
    }
    pub(super) fn clear_provider_keys(
        &mut self,
        secrets: &dyn ProviderSecrets,
    ) -> Result<(), WorkspaceError> {
        let mut catalog = self.credential_catalog()?;
        if catalog.entries.is_empty() {
            return Ok(());
        }
        for entry in &mut catalog.entries {
            if !matches!(entry.state, State::Deleted { .. }) {
                entry.state = State::Retired {
                    conversation: entry.state.conversation().map(str::to_owned),
                };
            }
        }
        self.save_credentials(&catalog)?;
        self.recover_credentials(secrets)?;
        Ok(())
    }
}
