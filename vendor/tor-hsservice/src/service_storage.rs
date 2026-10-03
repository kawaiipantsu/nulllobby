//! Per-service persistence policy. Ephemeral services keep their live state in
//! the existing manager structs and never restore it in another process.
use serde::{Serialize, de::DeserializeOwned};
use tor_persist::{slug::TryIntoSlug, state_dir};

/// A filesystem instance, or a fresh service with no persistent state.
pub(crate) struct Instance(pub(crate) Option<state_dir::InstanceStateHandle>);
impl Instance {
    /// Obtain state storage without creating files for an ephemeral service.
    pub(crate) fn storage_handle<T>(
        &self,
        key: &(impl TryIntoSlug + ?Sized),
    ) -> state_dir::Result<Storage<T>> {
        Ok(Storage(self.0.as_ref().map(|s| s.storage_handle(key)).transpose()?))
    }
    /// Obtain a replay directory only for a persistent service.
    pub(crate) fn raw_subdir(
        &self,
        key: &(impl TryIntoSlug + ?Sized),
    ) -> state_dir::Result<Option<state_dir::InstanceRawSubdir>> {
        self.0.as_ref().map(|s| s.raw_subdir(key)).transpose()
    }
}

/// Persistence only; authoritative live state remains in the service managers.
pub(crate) struct Storage<T>(Option<state_dir::StorageHandle<T>>);
impl<T: Serialize + DeserializeOwned> Storage<T> {
    /// Ephemeral services always start fresh.
    pub(crate) fn load(&self) -> state_dir::Result<Option<T>> {
        self.0.as_ref().map_or(Ok(None), |s| s.load())
    }
    /// Skip persistence for an ephemeral service, without discarding live state.
    pub(crate) fn store(&mut self, value: &T) -> state_dir::Result<()> {
        self.0.as_mut().map_or(Ok(()), |s| s.store(value))
    }
}
impl<T> From<state_dir::StorageHandle<T>> for Storage<T> {
    fn from(value: state_dir::StorageHandle<T>) -> Self {
        Self(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ephemeral_storage_has_no_filesystem_handle() {
        let instance = Instance(None);
        let mut store = instance.storage_handle::<Vec<u8>>("state").unwrap();
        assert!(store.0.is_none());
        store.store(&vec![42; 32]).unwrap();
        assert!(store.load().unwrap().is_none());
        assert!(instance.raw_subdir("replays").unwrap().is_none());
    }
}
