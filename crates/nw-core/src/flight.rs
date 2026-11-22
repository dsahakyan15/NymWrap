//! Short synchronous reservation bookkeeping; never holds a guard across await.
use crate::CoreError;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;
#[derive(Clone, Default)]
pub(super) struct Flights {
    entries: Arc<Mutex<BTreeMap<String, Arc<watch::Sender<bool>>>>>,
}
pub(super) struct Flight {
    owner: Flights,
    id: String,
    cancel: Arc<watch::Sender<bool>>,
}
impl Flights {
    pub fn active(&self, id: &str) -> Result<bool, CoreError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| CoreError::Session)?
            .contains_key(id))
    }
    pub fn len(&self) -> Result<usize, CoreError> {
        Ok(self.entries.lock().map_err(|_| CoreError::Session)?.len())
    }
    pub fn begin(&self, id: &str) -> Result<Flight, CoreError> {
        let mut entries = self.entries.lock().map_err(|_| CoreError::Session)?;
        if entries.contains_key(id) {
            return Err(CoreError::Busy);
        }
        if entries.len() >= 128 {
            return Err(CoreError::Limit);
        }
        let cancel = Arc::new(watch::channel(false).0);
        entries.insert(id.into(), cancel.clone());
        Ok(Flight {
            owner: self.clone(),
            id: id.into(),
            cancel,
        })
    }
    pub fn cancel(&self, id: &str) {
        if let Ok(entries) = self.entries.lock()
            && let Some(cancel) = entries.get(id)
        {
            cancel.send_replace(true);
        }
    }
}
impl Flight {
    pub fn belongs_to(&self, owner: &Flights) -> bool {
        Arc::ptr_eq(&self.owner.entries, &owner.entries)
    }
    pub async fn cancelled(&self) {
        let mut changes = self.cancel.subscribe();
        let _ = changes.wait_for(|cancelled| *cancelled).await;
    }
    pub fn valid(&self) -> bool {
        !*self.cancel.borrow()
    }
}
impl Drop for Flight {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.owner.entries.lock()
            && entries
                .get(&self.id)
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.cancel))
        {
            entries.remove(&self.id);
        }
    }
}
