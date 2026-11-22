//! SQLCipher domain stores with OS-rooted keys and crash-recoverable key rotation.
use crate::{
    Domain, KeyRing, MAX_BLOB, MasterKey, VaultError, decrypt, encrypt, os_secret::SecretStore,
};
use nw_proto::Profile;
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const ROOT_MAGIC: &[u8; 8] = b"NWROOT01";
const ROOT_FILE: &str = "root.nwenc";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u16,
    profile: Profile,
    keyring: Vec<u8>,
    retired: Vec<String>,
    reset: Vec<Domain>,
}

pub struct Store {
    root: PathBuf,
    provider: Arc<dyn SecretStore>,
    keys: KeyRing,
    master: MasterKey,
    password: SecretString,
    credential_id: String,
    salt: [u8; 16],
    profile: Profile,
    connections: BTreeMap<Domain, Connection>,
    retired: Vec<String>,
    reset: Vec<Domain>,
    _lock: File,
}
fn random_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn forbidden_file(path: &Path) -> Result<(), VaultError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & 0x400 != 0 {
                    return Err(VaultError::Io);
                }
            }
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(VaultError::Io);
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(VaultError::Io),
    }
}
fn prepare(root: &Path) -> Result<(PathBuf, File), VaultError> {
    if !root.is_absolute() {
        return Err(VaultError::Io);
    }
    if !root.exists() {
        #[cfg(windows)]
        nw_platform::create_private_directory_all(root).map_err(|_| VaultError::Io)?;
        #[cfg(unix)]
        {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(root).map_err(|_| VaultError::Io)?;
        }
    }
    let meta = fs::symlink_metadata(root).map_err(|_| VaultError::Io)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(VaultError::Io);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(VaultError::Io);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(VaultError::Io);
        }
    }
    let root = root.canonicalize().map_err(|_| VaultError::Io)?;
    for entry in fs::read_dir(&root).map_err(|_| VaultError::Io)? {
        let name = entry.map_err(|_| VaultError::Io)?.file_name();
        let name = name.to_str().ok_or(VaultError::Io)?;
        let known = name == ROOT_FILE
            || name == "store.lock"
            || Domain::ALL.iter().any(|d| {
                [".db", ".db-wal", ".db-shm", ".db-journal"]
                    .iter()
                    .any(|s| name == format!("{}{s}", d.name()))
            })
            || name
                .strip_prefix(".root-")
                .and_then(|s| s.strip_suffix(".nwenc"))
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
        if !known {
            return Err(VaultError::Io);
        }
    }
    #[cfg(windows)]
    nw_platform::private_directory(&root).map_err(|_| VaultError::Io)?;
    let lock_path = root.join("store.lock");
    forbidden_file(&lock_path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(&lock_path).map_err(|_| VaultError::Io)?;
    lock.try_lock().map_err(|_| VaultError::Locked)?;
    Ok((root, lock))
}
fn atomic_write(root: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let target = root.join(ROOT_FILE);
    forbidden_file(&target)?;
    let temporary = root.join(format!(".root-{}.nwenc", random_id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary).map_err(|_| VaultError::Io)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| VaultError::Io)?;
        drop(file);
        fs::rename(&temporary, &target).map_err(|_| VaultError::Io)?;
        #[cfg(unix)]
        File::open(root)
            .and_then(|d| d.sync_all())
            .map_err(|_| VaultError::CommitUncertain)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
impl Store {
    pub fn create(
        root: &Path,
        password: SecretString,
        profile: Profile,
        provider: Arc<dyn SecretStore>,
    ) -> Result<Self, VaultError> {
        let (root, lock) = prepare(root)?;
        if root
            .join(ROOT_FILE)
            .try_exists()
            .map_err(|_| VaultError::Io)?
        {
            return Err(VaultError::Exists);
        }
        // Never key an existing orphan DB with unrelated new keys.
        if Domain::ALL
            .iter()
            .any(|d| root.join(format!("{}.db", d.name())).exists())
        {
            return Err(VaultError::Exists);
        }
        let credential_id = random_id();
        let os_key = MasterKey::random()?.0;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let master =
            MasterKey::derive_for_profile(&password, &os_key, &salt, profile != Profile::Standard)?;
        let keys = KeyRing::new()?;
        provider.put(&credential_id, &os_key)?;
        let store = Self {
            root,
            provider,
            keys,
            master,
            password,
            credential_id,
            salt,
            profile,
            connections: BTreeMap::new(),
            retired: vec![],
            reset: vec![],
            _lock: lock,
        };
        if let Err(e) = store.commit() {
            if !matches!(e, VaultError::CommitUncertain) {
                let _ = store.provider.remove(&store.credential_id);
            }
            return Err(e);
        }
        Ok(store)
    }
    pub fn open(
        root: &Path,
        password: SecretString,
        provider: Arc<dyn SecretStore>,
    ) -> Result<Self, VaultError> {
        let (root, lock) = prepare(root)?;
        let path = root.join(ROOT_FILE);
        forbidden_file(&path)?;
        let mut bytes = Vec::new();
        File::open(&path)
            .map_err(|_| VaultError::Io)?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| VaultError::Io)?;
        if bytes.len() < 8 + 16 + 64 + 48 || bytes.len() > 16384 || &bytes[..8] != ROOT_MAGIC {
            return Err(VaultError::Invalid);
        }
        let salt: [u8; 16] = bytes[8..24].try_into().map_err(|_| VaultError::Invalid)?;
        let credential_id = std::str::from_utf8(&bytes[24..88])
            .map_err(|_| VaultError::Invalid)?
            .to_owned();
        if !credential_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(VaultError::Invalid);
        }
        let os_key = provider.get(&credential_id)?;
        let master = MasterKey::derive_for_profile(&password, &os_key, &salt, false)?;
        let clear = decrypt(&master.0, b"store-root-v1", &bytes[88..])?;
        let state: State = serde_json::from_slice(&clear).map_err(|_| VaultError::Invalid)?;
        if state.version != 1
            || state.retired.len() > 32
            || state.reset.len() > 6
            || state.retired.iter().any(|id| {
                id.len() != 64 || id == &credential_id || !id.bytes().all(|b| b.is_ascii_hexdigit())
            })
        {
            return Err(VaultError::Invalid);
        }
        if state.profile != Profile::Standard && password.expose_secret().len() < 12 {
            return Err(VaultError::Kdf);
        }
        let keys = KeyRing::unwrap(&master, &state.keyring)?;
        let mut store = Self {
            root,
            provider,
            keys,
            master,
            password,
            credential_id,
            salt,
            profile: state.profile,
            connections: BTreeMap::new(),
            retired: state.retired,
            reset: state.reset,
            _lock: lock,
        };
        store.finish_cleanup()?;
        Ok(store)
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    fn commit(&self) -> Result<(), VaultError> {
        let state = State {
            version: 1,
            profile: self.profile,
            keyring: self.keys.wrap(&self.master)?,
            retired: self.retired.clone(),
            reset: self.reset.clone(),
        };
        let clear = Zeroizing::new(serde_json::to_vec(&state).map_err(|_| VaultError::Invalid)?);
        let encrypted = encrypt(&self.master.0, b"store-root-v1", &clear)?;
        let mut bytes = ROOT_MAGIC.to_vec();
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(self.credential_id.as_bytes());
        bytes.extend_from_slice(&encrypted);
        atomic_write(&self.root, &bytes)
    }
    fn connection(&mut self, domain: Domain) -> Result<&mut Connection, VaultError> {
        if !self.retired.is_empty() || !self.reset.is_empty() {
            return Err(VaultError::Cleanup);
        }
        if !self.connections.contains_key(&domain) {
            let path = self.root.join(format!("{}.db", domain.name()));
            forbidden_file(&path)?;
            let key = self
                .keys
                .keys
                .get(&domain)
                .ok_or(VaultError::KeyUnavailable)?;
            let conn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|_| VaultError::Io)?;
            conn.key(None::<&str>, key.expose_secret(), false)
                .map_err(|_| VaultError::Authentication)?;
            let version: String = conn
                .pragma_query_one(None, "cipher_version")
                .map_err(|_| VaultError::Cipher)?;
            if version.is_empty() {
                return Err(VaultError::Cipher);
            }
            conn.execute_batch("PRAGMA cipher_memory_security=ON; PRAGMA temp_store=MEMORY; PRAGMA trusted_schema=OFF; PRAGMA secure_delete=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL, updated INTEGER NOT NULL) STRICT;").map_err(|_|VaultError::Authentication)?;
            let _previous = conn
                .set_limit(
                    rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
                    (MAX_BLOB + 1024) as i32,
                )
                .map_err(|_| VaultError::Io)?;
            self.connections.insert(domain, conn);
        }
        self.connections.get_mut(&domain).ok_or(VaultError::Io)
    }
    fn id(id: &str) -> Result<(), VaultError> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
        {
            return Err(VaultError::Record);
        }
        Ok(())
    }
    pub fn put(
        &mut self,
        domain: Domain,
        id: &str,
        bytes: &[u8],
        now: u64,
    ) -> Result<(), VaultError> {
        Self::id(id)?;
        let timestamp = i64::try_from(now).map_err(|_| VaultError::Record)?;
        let cipher = self.keys.seal(domain, bytes)?;
        self.connection(domain)?.execute("INSERT INTO records(id,body,updated) VALUES (?1,?2,?3) ON CONFLICT(id) DO UPDATE SET body=excluded.body, updated=excluded.updated",params![id,cipher,timestamp]).map_err(|_|VaultError::Io)?;
        Ok(())
    }
    pub fn get(
        &mut self,
        domain: Domain,
        id: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        Self::id(id)?;
        let value: Option<Vec<u8>> = self
            .connection(domain)?
            .query_row("SELECT body FROM records WHERE id=?1", params![id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|_| VaultError::Io)?;
        value
            .map(|bytes| self.keys.open(domain, &bytes))
            .transpose()
    }
    pub fn put_json<T: Serialize>(
        &mut self,
        domain: Domain,
        id: &str,
        value: &T,
        now: u64,
    ) -> Result<(), VaultError> {
        let clear = Zeroizing::new(serde_json::to_vec(value).map_err(|_| VaultError::Record)?);
        self.put(domain, id, &clear, now)
    }
    pub fn get_json<T: DeserializeOwned>(
        &mut self,
        domain: Domain,
        id: &str,
    ) -> Result<Option<T>, VaultError> {
        self.get(domain, id)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| VaultError::Record))
            .transpose()
    }
    pub fn remove(&mut self, domain: Domain, id: &str) -> Result<(), VaultError> {
        Self::id(id)?;
        self.connection(domain)?
            .execute("DELETE FROM records WHERE id=?1", [id])
            .map_err(|_| VaultError::Io)?;
        Ok(())
    }
    pub fn expire(&mut self, domain: Domain, before: u64) -> Result<usize, VaultError> {
        let timestamp = i64::try_from(before).map_err(|_| VaultError::Record)?;
        self.connection(domain)?
            .execute("DELETE FROM records WHERE updated<?1", [timestamp])
            .map_err(|_| VaultError::Io)
    }
    pub fn ids(&mut self, domain: Domain) -> Result<Vec<String>, VaultError> {
        let mut statement = self
            .connection(domain)?
            .prepare("SELECT id FROM records ORDER BY id LIMIT 50001")
            .map_err(|_| VaultError::Io)?;
        let ids = statement
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|_| VaultError::Io)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| VaultError::Io)?;
        if ids.len() > 50_000 {
            return Err(VaultError::TooLarge);
        }
        Ok(ids)
    }
    pub fn recent_ids(
        &mut self,
        domain: Domain,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<String>, VaultError> {
        Self::id(prefix)?;
        if limit == 0 || limit > 1000 {
            return Err(VaultError::Record);
        }
        let mut statement = self
            .connection(domain)?
            .prepare(
                "SELECT id FROM records WHERE substr(id,1,?1)=?2 ORDER BY updated DESC,id LIMIT ?3",
            )
            .map_err(|_| VaultError::Io)?;
        statement
            .query_map(params![prefix.len() as i64, prefix, limit as i64], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| VaultError::Io)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| VaultError::Io)
    }
    pub fn shred_domain(&mut self, domain: Domain) -> Result<(), VaultError> {
        self.finish_cleanup()?;
        self.connections.clear();
        let previous_keys = self.keys.wrap(&self.master)?;
        let replacement = MasterKey::random()?.0;
        let previous = self.keys.keys.insert(domain, replacement);
        self.reset = vec![domain];
        if let Err(e) = self.rotate_root() {
            if !matches!(e, VaultError::CommitUncertain) {
                self.keys = KeyRing::unwrap(&self.master, &previous_keys)?;
                self.reset.clear();
            }
            drop(previous);
            return Err(e);
        }
        drop(previous);
        self.finish_cleanup()
    }
    fn rotate_root(&mut self) -> Result<(), VaultError> {
        let new_id = random_id();
        let new_secret = MasterKey::random()?.0;
        let mut new_salt = [0u8; 16];
        OsRng.fill_bytes(&mut new_salt);
        let new_master = MasterKey::derive_for_profile(
            &self.password,
            &new_secret,
            &new_salt,
            self.profile != Profile::Standard,
        )?;
        self.provider.put(&new_id, &new_secret)?;
        let old_id = std::mem::replace(&mut self.credential_id, new_id);
        let old_salt = std::mem::replace(&mut self.salt, new_salt);
        let old_master = std::mem::replace(&mut self.master, new_master);
        self.retired.push(old_id.clone());
        if let Err(e) = self.commit() {
            if matches!(e, VaultError::CommitUncertain) {
                return Err(e);
            }
            let failed_id = std::mem::replace(&mut self.credential_id, old_id);
            self.salt = old_salt;
            self.master = old_master;
            self.retired.pop();
            let _ = self.provider.remove(&failed_id);
            return Err(e);
        }
        Ok(())
    }
    fn finish_cleanup(&mut self) -> Result<(), VaultError> {
        if self.retired.is_empty() && self.reset.is_empty() {
            return Ok(());
        }
        for id in &self.retired {
            self.provider.remove(id).map_err(|_| VaultError::Cleanup)?;
        }
        for domain in &self.reset {
            for suffix in [".db", ".db-wal", ".db-shm", ".db-journal"] {
                let path = self.root.join(format!("{}{suffix}", domain.name()));
                forbidden_file(&path)?;
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(VaultError::Cleanup),
                }
            }
        }
        let retired = std::mem::take(&mut self.retired);
        let reset = std::mem::take(&mut self.reset);
        if let Err(e) = self.commit() {
            self.retired = retired;
            self.reset = reset;
            return Err(e);
        }
        Ok(())
    }
    pub fn destroy(mut self) -> Result<(), VaultError> {
        self.connections.clear();
        self.finish_cleanup()?;
        self.provider.remove(&self.credential_id)?;
        self.keys.shred_all();
        for domain in Domain::ALL {
            for suffix in [".db", ".db-wal", ".db-shm", ".db-journal"] {
                let path = self.root.join(format!("{}{suffix}", domain.name()));
                forbidden_file(&path)?;
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(VaultError::Cleanup),
                }
            }
        }
        fs::remove_file(self.root.join(ROOT_FILE)).map_err(|_| VaultError::Cleanup)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Memory(Mutex<BTreeMap<String, nw_platform::LockedKey>>);
    impl SecretStore for Memory {
        fn put(&self, id: &str, key: &nw_platform::LockedKey) -> Result<(), VaultError> {
            self.0
                .lock()
                .unwrap()
                .insert(id.into(), key.copy().map_err(|_| VaultError::MemoryLock)?);
            Ok(())
        }
        fn get(&self, id: &str) -> Result<nw_platform::LockedKey, VaultError> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .map(|k| k.copy().map_err(|_| VaultError::MemoryLock))
                .transpose()?
                .ok_or(VaultError::OsSecret)
        }
        fn remove(&self, id: &str) -> Result<(), VaultError> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }
    }
    #[test]
    fn persists_reopens_expires_and_shreds_without_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store");
        let backend = Arc::new(Memory::default());
        let password = || SecretString::from("synthetic password 4819");
        let mut store = Store::create(&path, password(), Profile::Strict, backend.clone()).unwrap();
        let secret = b"SYNTHETIC_PERSISTED_PRIVATE_CANARY_81037";
        store
            .put(Domain::ShadowHistory, "conversation-a", secret, 100)
            .unwrap();
        store
            .put(
                Domain::CoverLog,
                "progress",
                b"synthetic cover progress",
                100,
            )
            .unwrap();
        let old_root = fs::read(path.join(ROOT_FILE)).unwrap();
        assert!(Store::open(&path, password(), backend.clone()).is_err());
        drop(store);
        assert!(
            Store::open(
                &path,
                SecretString::from("wrong password 0921"),
                backend.clone()
            )
            .is_err()
        );
        let mut store = Store::open(&path, password(), backend.clone()).unwrap();
        assert_eq!(
            &**store
                .get(Domain::ShadowHistory, "conversation-a")
                .unwrap()
                .unwrap(),
            secret
        );
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == "store.lock" {
                assert_eq!(entry.metadata().unwrap().len(), 0);
                continue;
            }
            let bytes = fs::read(entry.path()).unwrap();
            assert!(!bytes.windows(secret.len()).any(|b| b == secret));
        }
        let raw = Connection::open(path.join("shadow_history.db")).unwrap();
        assert!(
            raw.query_row("SELECT count(*) FROM records", [], |r| r.get::<_, i64>(0))
                .is_err()
        );
        drop(raw);
        store.shred_domain(Domain::ShadowHistory).unwrap();
        assert!(
            store
                .get(Domain::ShadowHistory, "conversation-a")
                .unwrap()
                .is_none()
        );
        assert!(store.get(Domain::CoverLog, "progress").unwrap().is_some());
        assert_eq!(store.expire(Domain::CoverLog, 101).unwrap(), 1);
        drop(store);
        let new_root = fs::read(path.join(ROOT_FILE)).unwrap();
        fs::write(path.join(ROOT_FILE), old_root).unwrap();
        assert!(Store::open(&path, password(), backend.clone()).is_err());
        fs::write(path.join(ROOT_FILE), new_root).unwrap();
        Store::open(&path, password(), backend.clone())
            .unwrap()
            .destroy()
            .unwrap();
        assert!(Store::open(&path, password(), backend).is_err());
    }
}
