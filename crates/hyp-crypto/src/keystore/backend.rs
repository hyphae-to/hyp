//! Backend dispatch for SecretStore; index and file cleanup ordering stays with the store.
use super::*;

type Read = fn(&SecretStore, &str, &str) -> Result<Option<Zeroizing<String>>, CryptoError>;
type Write = fn(&SecretStore, &str, &str, &str) -> Result<String, CryptoError>;
type Delete = fn(&SecretStore, &str, &str) -> Result<bool, CryptoError>;
type List = fn(&SecretStore, &str) -> Result<Vec<String>, CryptoError>;

pub(super) trait Backend: Sync {
    fn write(
        &self,
        store: &SecretStore,
        name: &str,
        value: &str,
    ) -> Result<(String, Option<String>), CryptoError>;
    fn read(
        &self,
        store: &SecretStore,
        name: &str,
        recorded: Option<&str>,
    ) -> Result<Zeroizing<String>, CryptoError>;
    fn delete(
        &self,
        store: &SecretStore,
        name: &str,
        recorded: Option<&str>,
    ) -> Result<bool, CryptoError>;
    fn indexed_metadata(
        &self,
        store: &SecretStore,
        name: &str,
        recorded: Option<&str>,
    ) -> Result<Option<SecretMetadata>, CryptoError>;
    fn discover(
        &self,
        _store: &SecretStore,
        _by_name: &mut BTreeMap<String, SecretMetadata>,
    ) -> Result<(), CryptoError> {
        Ok(())
    }
}

struct FileBackend;
impl Backend for FileBackend {
    fn write(
        &self,
        store: &SecretStore,
        name: &str,
        value: &str,
    ) -> Result<(String, Option<String>), CryptoError> {
        Ok((store.write_file_secret(name, value)?, None))
    }
    fn read(
        &self,
        store: &SecretStore,
        name: &str,
        _recorded: Option<&str>,
    ) -> Result<Zeroizing<String>, CryptoError> {
        store.read_file_secret(name)
    }
    fn delete(
        &self,
        _store: &SecretStore,
        _name: &str,
        _recorded: Option<&str>,
    ) -> Result<bool, CryptoError> {
        // The store removes file secrets after the indexed backend deletion step.
        Ok(false)
    }
    fn indexed_metadata(
        &self,
        store: &SecretStore,
        name: &str,
        _recorded: Option<&str>,
    ) -> Result<Option<SecretMetadata>, CryptoError> {
        let path = store.secret_file_path(name)?;
        if !path.exists() {
            return Ok(None);
        }
        let (mode_ok, bytes) = match check_private_owner_and_mode(&path, false) {
            Ok(size) => (true, Some(size)),
            Err(_) => (
                false,
                fs::symlink_metadata(&path)
                    .ok()
                    .map(|metadata| metadata.len()),
            ),
        };
        Ok(Some(SecretMetadata {
            name: name.to_string(),
            backend: SecretBackend::File,
            location: path.display().to_string(),
            mode_ok,
            bytes,
        }))
    }
}

struct ExternalBackend {
    kind: SecretBackend,
    resolve: fn(&SecretStore) -> Result<String, CryptoError>,
    validate: fn(&str) -> Result<(), CryptoError>,
    metadata_default: fn(&SecretStore) -> &str,
    location_suffix: &'static str,
    write: Write,
    read: Read,
    delete: Delete,
    list: Option<List>,
}

impl ExternalBackend {
    fn scope(&self, store: &SecretStore, recorded: Option<&str>) -> Result<String, CryptoError> {
        match recorded {
            Some(scope) => {
                (self.validate)(scope)?;
                Ok(scope.to_string())
            }
            None => (self.resolve)(store),
        }
    }
    fn metadata(&self, name: &str, scope: &str) -> SecretMetadata {
        SecretMetadata {
            name: name.to_string(),
            backend: self.kind,
            location: format!(
                "{}:{scope}/{}{name}",
                self.kind.as_str(),
                self.location_suffix
            ),
            mode_ok: true,
            bytes: None,
        }
    }
}

impl Backend for ExternalBackend {
    fn write(
        &self,
        store: &SecretStore,
        name: &str,
        value: &str,
    ) -> Result<(String, Option<String>), CryptoError> {
        let scope = self.scope(store, None)?;
        let location = (self.write)(store, name, value, &scope)?;
        let _ = fs::remove_file(store.secret_file_path(name)?);
        Ok((location, Some(scope)))
    }
    fn read(
        &self,
        store: &SecretStore,
        name: &str,
        recorded: Option<&str>,
    ) -> Result<Zeroizing<String>, CryptoError> {
        let scope = self.scope(store, recorded)?;
        (self.read)(store, name, &scope)?
            .ok_or_else(|| CryptoError::SecretNotFound(name.to_string()))
    }
    fn delete(
        &self,
        store: &SecretStore,
        name: &str,
        recorded: Option<&str>,
    ) -> Result<bool, CryptoError> {
        let scope = self.scope(store, recorded)?;
        (self.delete)(store, name, &scope)
    }
    fn indexed_metadata(
        &self,
        store: &SecretStore,
        name: &str,
        recorded: Option<&str>,
    ) -> Result<Option<SecretMetadata>, CryptoError> {
        // Listing keeps its existing unvalidated recorded/default scope policy.
        Ok(Some(self.metadata(
            name,
            recorded.unwrap_or_else(|| (self.metadata_default)(store)),
        )))
    }
    fn discover(
        &self,
        store: &SecretStore,
        by_name: &mut BTreeMap<String, SecretMetadata>,
    ) -> Result<(), CryptoError> {
        let Some(list) = self.list else {
            return Ok(());
        };
        let scope = self.scope(store, None)?;
        for name in list(store, &scope)? {
            by_name
                .entry(name.clone())
                .or_insert_with(|| self.metadata(&name, &scope));
        }
        Ok(())
    }
}

pub(super) fn for_kind(kind: SecretBackend) -> &'static dyn Backend {
    match kind {
        SecretBackend::File => &FileBackend,
        SecretBackend::Keychain => &ExternalBackend {
            kind: SecretBackend::Keychain,
            resolve: |store| Ok(store.service.clone()),
            validate: |_| Ok(()),
            metadata_default: |store| &store.service,
            location_suffix: "",
            write: |store, name, value, _scope| store.write_mac_keychain(name, value),
            read: SecretStore::read_mac_keychain,
            delete: |store, name, scope| Ok(store.delete_mac_keychain(name, scope)),
            list: None,
        },
        SecretBackend::SecretService => &ExternalBackend {
            kind: SecretBackend::SecretService,
            resolve: |store| Ok(store.service.clone()),
            validate: |_| Ok(()),
            metadata_default: |store| &store.service,
            location_suffix: "",
            write: |store, name, value, _scope| store.write_linux_secret_service(name, value),
            read: SecretStore::read_linux_secret_service,
            delete: |store, name, scope| Ok(store.delete_linux_secret_service(name, scope)),
            list: None,
        },
        SecretBackend::OnePassword => &ExternalBackend {
            kind: SecretBackend::OnePassword,
            resolve: SecretStore::resolved_op_vault,
            validate: validate_onepassword_vault,
            metadata_default: |_| DEFAULT_OP_VAULT,
            location_suffix: "hyphae/",
            write: SecretStore::write_onepassword,
            read: SecretStore::read_onepassword,
            delete: SecretStore::delete_onepassword,
            list: Some(SecretStore::list_onepassword),
        },
        SecretBackend::LastPass => &ExternalBackend {
            kind: SecretBackend::LastPass,
            resolve: SecretStore::resolved_lpass_prefix,
            validate: validate_lastpass_prefix,
            metadata_default: |_| DEFAULT_LPASS_PREFIX,
            location_suffix: "",
            write: SecretStore::write_lastpass,
            read: SecretStore::read_lastpass,
            delete: SecretStore::delete_lastpass,
            list: Some(SecretStore::list_lastpass),
        },
        SecretBackend::Pass => &ExternalBackend {
            kind: SecretBackend::Pass,
            resolve: SecretStore::resolved_pass_prefix,
            validate: validate_pass_prefix,
            metadata_default: |_| DEFAULT_PASS_PREFIX,
            location_suffix: "",
            write: SecretStore::write_pass,
            read: SecretStore::read_pass,
            delete: SecretStore::delete_pass,
            list: Some(SecretStore::list_pass_metadata),
        },
    }
}
