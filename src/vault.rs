//! The encrypted vault file and the in-memory data model.
//!
//! Layout (envelope encryption):
//!   * A random 256-bit vault key encrypts the entries.
//!   * The vault key is stored several times, each copy sealed by a different "slot":
//!       - password slot: key derived from the master password with Argon2id
//!       - backup slot (optional): the same, from a separate backup password
//!       - Windows Hello slot (optional): key derived from a signature made by a
//!         TPM-backed Windows Hello key that never leaves this PC
//!   * Nothing in the file is readable without one of those secrets.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, CryptoError, KdfParams, SALT_LEN, Sealed, SecretKey, b64};

const FORMAT_NAME: &str = "LocalVault";
const FORMAT_VERSION: u32 = 1;
const AAD_PASSWORD_SLOT: &[u8] = b"LocalVault v1 password slot";
const AAD_BACKUP_SLOT: &[u8] = b"LocalVault v1 backup slot";
const AAD_HELLO_SLOT: &[u8] = b"LocalVault v1 windows hello slot";
const AAD_DATA: &[u8] = b"LocalVault v1 data";
const HELLO_KEY_LABEL: &[u8] = b"LocalVault v1 windows hello key";

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Format(String),
    WrongPassword,
    HelloKeyMismatch,
    Crypto(CryptoError),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "Could not read or write the vault file: {e}"),
            VaultError::Format(e) => write!(f, "The vault file is damaged or not a LocalVault file ({e})."),
            VaultError::WrongPassword => write!(f, "That password is not correct."),
            VaultError::HelloKeyMismatch => {
                write!(f, "Windows Hello could not open this vault. Unlock with your master password and set up Windows Hello again in Settings.")
            }
            VaultError::Crypto(e) => write!(f, "Encryption error: {e}"),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        VaultError::Crypto(e)
    }
}

// ---------------------------------------------------------------------------
// On-disk format
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordSlot {
    pub kdf: KdfParams,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    pub wrapped_key: Sealed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloSlot {
    /// Name of the Windows Hello key credential on this PC.
    pub credential_name: String,
    /// Random data that Windows Hello signs; the signature becomes the key.
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
    pub wrapped_key: Sealed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultFile {
    pub format: String,
    pub version: u32,
    #[serde(with = "b64")]
    pub vault_id: Vec<u8>,
    pub password_slot: PasswordSlot,
    /// Absent in vaults created before backup passwords existed.
    #[serde(default)]
    pub backup_slot: Option<PasswordSlot>,
    pub hello_slot: Option<HelloSlot>,
    pub data: Sealed,
}

impl VaultFile {
    pub fn load(path: &Path) -> Result<VaultFile, VaultError> {
        let bytes = fs::read(path)?;
        let file: VaultFile = serde_json::from_slice(&bytes).map_err(|e| VaultError::Format(e.to_string()))?;
        if file.format != FORMAT_NAME {
            return Err(VaultError::Format("unknown format name".into()));
        }
        if file.version != FORMAT_VERSION {
            return Err(VaultError::Format(format!("unsupported version {}", file.version)));
        }
        Ok(file)
    }

    pub fn vault_id_hex(&self) -> String {
        self.vault_id.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn aad(&self, label: &[u8]) -> Vec<u8> {
        let mut aad = label.to_vec();
        aad.extend_from_slice(&self.vault_id);
        aad
    }
}

/// Writes to a temporary file first, then swaps it in, so a crash or power
/// cut never leaves a half-written vault. The previous version is kept as
/// `<name>.bak` (it is just as encrypted as the vault itself).
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if path.exists() {
        fs::copy(path, path.with_extension("bak"))?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Decrypted data
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    pub name: String,
    pub value: String,
    /// Secret fields are hidden until the user chooses Show.
    pub secret: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub website: String,
    pub notes: String,
    pub fields: Vec<Field>,
    pub created: u64,
    pub modified: u64,
}

impl Entry {
    /// A new login with the two fields almost every account needs.
    pub fn new_login() -> Result<Entry, VaultError> {
        let id: String = crypto::random_bytes::<8>()?.iter().map(|b| format!("{b:02x}")).collect();
        let now = unix_now();
        Ok(Entry {
            id,
            title: String::new(),
            website: String::new(),
            notes: String::new(),
            fields: vec![
                Field { name: "Username".into(), value: String::new(), secret: false },
                Field { name: "Password".into(), value: String::new(), secret: true },
            ],
            created: now,
            modified: now,
        })
    }

    /// The first non-secret field with a value, shown under the title in lists.
    pub fn subtitle(&self) -> &str {
        self.fields.iter().find(|f| !f.secret && !f.value.is_empty()).map(|f| f.value.as_str()).unwrap_or("")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    pub entries: Vec<Entry>,
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Unlocked vault
// ---------------------------------------------------------------------------

pub struct UnlockedVault {
    path: PathBuf,
    file: VaultFile,
    key: SecretKey,
    pub data: VaultData,
    /// True when this session was opened with the backup password, so the
    /// master password can be replaced without knowing the old one.
    pub opened_with_backup: bool,
}

fn make_password_slot(file_aad: &[u8], key: &SecretKey, password: &str, kdf: KdfParams) -> Result<PasswordSlot, VaultError> {
    let salt = crypto::random_bytes::<SALT_LEN>()?;
    let kek = crypto::derive_key(password.as_bytes(), &salt, kdf)?;
    let wrapped_key = crypto::wrap_key(&kek, key, file_aad)?;
    Ok(PasswordSlot { kdf, salt: salt.to_vec(), wrapped_key })
}

impl UnlockedVault {
    /// Creates a brand new, empty vault protected by `password`.
    pub fn create(path: &Path, password: &str, kdf: KdfParams) -> Result<UnlockedVault, VaultError> {
        let key = crypto::random_key()?;
        let vault_id = crypto::random_bytes::<16>()?.to_vec();
        let placeholder = Sealed { nonce: Vec::new(), ciphertext: Vec::new() };
        let mut file = VaultFile {
            format: FORMAT_NAME.into(),
            version: FORMAT_VERSION,
            vault_id,
            password_slot: PasswordSlot { kdf, salt: Vec::new(), wrapped_key: placeholder.clone() },
            backup_slot: None,
            hello_slot: None,
            data: placeholder,
        };
        file.password_slot = make_password_slot(&file.aad(AAD_PASSWORD_SLOT), &key, password, kdf)?;
        let mut vault = UnlockedVault { path: path.to_path_buf(), file, key, data: VaultData::default(), opened_with_backup: false };
        vault.save()?;
        Ok(vault)
    }

    pub fn unlock_with_password(path: &Path, password: &str) -> Result<UnlockedVault, VaultError> {
        let file = VaultFile::load(path)?;
        let slot = &file.password_slot;
        let kek = crypto::derive_key(password.as_bytes(), &slot.salt, slot.kdf)?;
        if let Ok(key) = crypto::unwrap_key(&kek, &slot.wrapped_key, &file.aad(AAD_PASSWORD_SLOT)) {
            return Self::open_with_key(path, file, key);
        }
        let slot = file.backup_slot.as_ref().ok_or(VaultError::WrongPassword)?;
        let kek = crypto::derive_key(password.as_bytes(), &slot.salt, slot.kdf)?;
        let key = crypto::unwrap_key(&kek, &slot.wrapped_key, &file.aad(AAD_BACKUP_SLOT)).map_err(|_| VaultError::WrongPassword)?;
        let mut vault = Self::open_with_key(path, file, key)?;
        vault.opened_with_backup = true;
        Ok(vault)
    }

    /// `signature` is what Windows Hello returned for the slot's challenge.
    pub fn unlock_with_hello_signature(path: &Path, file: VaultFile, signature: &[u8]) -> Result<UnlockedVault, VaultError> {
        let slot = file.hello_slot.as_ref().ok_or(VaultError::HelloKeyMismatch)?;
        let kek = crypto::key_from_material(HELLO_KEY_LABEL, signature);
        let key = crypto::unwrap_key(&kek, &slot.wrapped_key, &file.aad(AAD_HELLO_SLOT)).map_err(|_| VaultError::HelloKeyMismatch)?;
        Self::open_with_key(path, file, key)
    }

    fn open_with_key(path: &Path, file: VaultFile, key: SecretKey) -> Result<UnlockedVault, VaultError> {
        let plain = crypto::open(&key, &file.data, &file.aad(AAD_DATA)).map_err(|_| VaultError::Format("vault data failed authentication".into()))?;
        let data: VaultData = serde_json::from_slice(&plain).map_err(|e| VaultError::Format(e.to_string()))?;
        Ok(UnlockedVault { path: path.to_path_buf(), file, key, data, opened_with_backup: false })
    }

    pub fn save(&mut self) -> Result<(), VaultError> {
        let plain = Zeroizing::new(serde_json::to_vec(&self.data).map_err(|e| VaultError::Format(e.to_string()))?);
        self.file.data = crypto::seal(&self.key, &plain, &self.file.aad(AAD_DATA))?;
        let bytes = serde_json::to_vec_pretty(&self.file).map_err(|e| VaultError::Format(e.to_string()))?;
        write_atomically(&self.path, &bytes)
    }

    #[cfg(test)]
    pub fn verify_password(&self, password: &str) -> bool {
        let slot = &self.file.password_slot;
        match crypto::derive_key(password.as_bytes(), &slot.salt, slot.kdf) {
            Ok(kek) => crypto::unwrap_key(&kek, &slot.wrapped_key, &self.file.aad(AAD_PASSWORD_SLOT)).is_ok(),
            Err(_) => false,
        }
    }

    /// Re-protects the vault key with a new master password. The entries keep
    /// the same key, so the Windows Hello slot stays valid.
    #[cfg(test)]
    pub fn change_password(&mut self, new_password: &str, kdf: KdfParams) -> Result<(), VaultError> {
        self.file.password_slot = make_password_slot(&self.file.aad(AAD_PASSWORD_SLOT), &self.key, new_password, kdf)?;
        self.save()
    }

    /// Salt and cost settings of the current password slot, so the slow key
    /// derivation can run on a worker thread.
    pub fn password_kdf_inputs(&self) -> (Vec<u8>, KdfParams) {
        (self.file.password_slot.salt.clone(), self.file.password_slot.kdf)
    }

    /// Checks a key derived (elsewhere) from a candidate current password.
    pub fn password_key_matches(&self, kek: &SecretKey) -> bool {
        crypto::unwrap_key(kek, &self.file.password_slot.wrapped_key, &self.file.aad(AAD_PASSWORD_SLOT)).is_ok()
    }

    /// Installs a new password slot from a key derived (elsewhere) with `salt` and `kdf`.
    pub fn set_password_key(&mut self, salt: Vec<u8>, kdf: KdfParams, kek: &SecretKey) -> Result<(), VaultError> {
        let wrapped_key = crypto::wrap_key(kek, &self.key, &self.file.aad(AAD_PASSWORD_SLOT))?;
        self.file.password_slot = PasswordSlot { kdf, salt, wrapped_key };
        self.opened_with_backup = false;
        self.save()
    }

    /// Installs or replaces the backup slot from a key derived (elsewhere) with `salt` and `kdf`.
    pub fn set_backup_key(&mut self, salt: Vec<u8>, kdf: KdfParams, kek: &SecretKey) -> Result<(), VaultError> {
        let wrapped_key = crypto::wrap_key(kek, &self.key, &self.file.aad(AAD_BACKUP_SLOT))?;
        self.file.backup_slot = Some(PasswordSlot { kdf, salt, wrapped_key });
        self.save()
    }

    pub fn remove_backup(&mut self) -> Result<(), VaultError> {
        self.file.backup_slot = None;
        self.save()
    }

    pub fn has_backup(&self) -> bool {
        self.file.backup_slot.is_some()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn hello_slot(&self) -> Option<&HelloSlot> {
        self.file.hello_slot.as_ref()
    }

    pub fn vault_id_hex(&self) -> String {
        self.file.vault_id_hex()
    }

    pub fn enable_hello(&mut self, credential_name: String, challenge: Vec<u8>, signature: &[u8]) -> Result<(), VaultError> {
        let kek = crypto::key_from_material(HELLO_KEY_LABEL, signature);
        let wrapped_key = crypto::wrap_key(&kek, &self.key, &self.file.aad(AAD_HELLO_SLOT))?;
        self.file.hello_slot = Some(HelloSlot { credential_name, challenge, wrapped_key });
        self.save()
    }

    pub fn disable_hello(&mut self) -> Result<Option<String>, VaultError> {
        let name = self.file.hello_slot.take().map(|s| s.credential_name);
        self.save()?;
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        (dir, path)
    }

    fn sample_entry(title: &str, password: &str) -> Entry {
        let mut e = Entry::new_login().unwrap();
        e.title = title.into();
        e.fields[0].value = "jake@example.com".into();
        e.fields[1].value = password.into();
        e.fields.push(Field { name: "PIN".into(), value: "4321".into(), secret: true });
        e
    }

    #[test]
    fn create_save_and_unlock() {
        let (_d, path) = temp_vault();
        let mut v = UnlockedVault::create(&path, "correct horse", KdfParams::TEST).unwrap();
        v.data.entries.push(sample_entry("Bank", "s3cr3t-Pa55"));
        v.save().unwrap();

        let v2 = UnlockedVault::unlock_with_password(&path, "correct horse").unwrap();
        assert_eq!(v2.data.entries.len(), 1);
        assert_eq!(v2.data.entries[0].fields[1].value, "s3cr3t-Pa55");
        assert_eq!(v2.data.entries[0].fields[2].name, "PIN");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (_d, path) = temp_vault();
        UnlockedVault::create(&path, "correct horse", KdfParams::TEST).unwrap();
        assert!(matches!(UnlockedVault::unlock_with_password(&path, "wrong"), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn file_contains_no_plaintext() {
        let (_d, path) = temp_vault();
        let mut v = UnlockedVault::create(&path, "correct horse", KdfParams::TEST).unwrap();
        v.data.entries.push(sample_entry("MyBankAccount", "UniqueSecretValue123"));
        v.save().unwrap();
        let raw = String::from_utf8_lossy(&fs::read(&path).unwrap()).to_string();
        for needle in ["MyBankAccount", "UniqueSecretValue123", "jake@example.com", "Username", "PIN"] {
            assert!(!raw.contains(needle), "plaintext {needle} leaked into the file");
        }
    }

    #[test]
    fn tampered_file_is_rejected() {
        let (_d, path) = temp_vault();
        let mut v = UnlockedVault::create(&path, "pw", KdfParams::TEST).unwrap();
        v.data.entries.push(sample_entry("A", "B"));
        v.save().unwrap();
        let mut file = VaultFile::load(&path).unwrap();
        file.data.ciphertext[3] ^= 0x40;
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(matches!(UnlockedVault::unlock_with_password(&path, "pw"), Err(VaultError::Format(_))));
    }

    #[test]
    fn change_password_keeps_data_and_hello() {
        let (_d, path) = temp_vault();
        let mut v = UnlockedVault::create(&path, "old", KdfParams::TEST).unwrap();
        v.data.entries.push(sample_entry("Mail", "m"));
        v.enable_hello("cred".into(), vec![1, 2, 3], b"fake signature").unwrap();
        v.change_password("new", KdfParams::TEST).unwrap();

        assert!(UnlockedVault::unlock_with_password(&path, "old").is_err());
        let v2 = UnlockedVault::unlock_with_password(&path, "new").unwrap();
        assert_eq!(v2.data.entries[0].title, "Mail");
        let file = VaultFile::load(&path).unwrap();
        assert!(UnlockedVault::unlock_with_hello_signature(&path, file, b"fake signature").is_ok());
    }

    #[test]
    fn hello_slot_needs_the_exact_signature() {
        let (_d, path) = temp_vault();
        let mut v = UnlockedVault::create(&path, "pw", KdfParams::TEST).unwrap();
        v.enable_hello("cred".into(), vec![9; 32], b"signature A").unwrap();

        let file = VaultFile::load(&path).unwrap();
        assert!(matches!(
            UnlockedVault::unlock_with_hello_signature(&path, file.clone(), b"signature B"),
            Err(VaultError::HelloKeyMismatch)
        ));
        assert!(UnlockedVault::unlock_with_hello_signature(&path, file, b"signature A").is_ok());

        let mut v = UnlockedVault::unlock_with_password(&path, "pw").unwrap();
        assert_eq!(v.disable_hello().unwrap().as_deref(), Some("cred"));
        let file = VaultFile::load(&path).unwrap();
        assert!(file.hello_slot.is_none());
    }

    #[test]
    fn saving_twice_replaces_file_and_keeps_backup() {
        let (_d, path) = temp_vault();
        let mut v = UnlockedVault::create(&path, "pw", KdfParams::TEST).unwrap();
        v.data.entries.push(sample_entry("One", "1"));
        v.save().unwrap();
        v.data.entries.push(sample_entry("Two", "2"));
        v.save().unwrap();
        assert!(path.with_extension("bak").exists());
        assert!(!path.with_extension("tmp").exists());
        let v2 = UnlockedVault::unlock_with_password(&path, "pw").unwrap();
        assert_eq!(v2.data.entries.len(), 2);
    }

    #[test]
    fn password_change_via_derived_keys() {
        let (_d, path) = temp_vault();
        let mut v = UnlockedVault::create(&path, "old", KdfParams::TEST).unwrap();
        let (salt, kdf) = v.password_kdf_inputs();
        assert!(v.password_key_matches(&crypto::derive_key(b"old", &salt, kdf).unwrap()));
        assert!(!v.password_key_matches(&crypto::derive_key(b"bad", &salt, kdf).unwrap()));

        let new_salt = crypto::random_bytes::<SALT_LEN>().unwrap().to_vec();
        let kek = crypto::derive_key(b"new", &new_salt, KdfParams::TEST).unwrap();
        v.set_password_key(new_salt, KdfParams::TEST, &kek).unwrap();
        assert!(UnlockedVault::unlock_with_password(&path, "new").is_ok());
        assert!(UnlockedVault::unlock_with_password(&path, "old").is_err());
    }

    fn add_backup(v: &mut UnlockedVault, password: &[u8]) {
        let salt = crypto::random_bytes::<SALT_LEN>().unwrap().to_vec();
        let kek = crypto::derive_key(password, &salt, KdfParams::TEST).unwrap();
        v.set_backup_key(salt, KdfParams::TEST, &kek).unwrap();
    }

    #[test]
    fn backup_password_opens_and_resets_master() {
        let (_d, path) = temp_vault();
        let mut v = UnlockedVault::create(&path, "master", KdfParams::TEST).unwrap();
        v.data.entries.push(sample_entry("Mail", "m"));
        add_backup(&mut v, b"backup");

        assert!(!UnlockedVault::unlock_with_password(&path, "master").unwrap().opened_with_backup);
        assert!(matches!(UnlockedVault::unlock_with_password(&path, "wrong"), Err(VaultError::WrongPassword)));

        let mut v = UnlockedVault::unlock_with_password(&path, "backup").unwrap();
        assert!(v.opened_with_backup);
        assert_eq!(v.data.entries[0].title, "Mail");

        // The unused current password may be empty when resetting.
        let (salt, kdf) = v.password_kdf_inputs();
        crypto::derive_key(b"", &salt, kdf).unwrap();
        let new_salt = crypto::random_bytes::<SALT_LEN>().unwrap().to_vec();
        let kek = crypto::derive_key(b"new master", &new_salt, KdfParams::TEST).unwrap();
        v.set_password_key(new_salt, KdfParams::TEST, &kek).unwrap();
        assert!(!v.opened_with_backup);

        assert!(UnlockedVault::unlock_with_password(&path, "master").is_err());
        assert!(UnlockedVault::unlock_with_password(&path, "new master").is_ok());
        assert!(UnlockedVault::unlock_with_password(&path, "backup").is_ok());
    }

    #[test]
    fn removed_backup_stops_working() {
        let (_d, path) = temp_vault();
        let mut v = UnlockedVault::create(&path, "master", KdfParams::TEST).unwrap();
        add_backup(&mut v, b"backup");
        v.remove_backup().unwrap();
        assert!(!v.has_backup());
        assert!(matches!(UnlockedVault::unlock_with_password(&path, "backup"), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn older_vault_without_backup_slot_still_opens() {
        let (_d, path) = temp_vault();
        UnlockedVault::create(&path, "master", KdfParams::TEST).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        json.as_object_mut().unwrap().remove("backup_slot");
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(UnlockedVault::unlock_with_password(&path, "master").is_ok());
    }

    #[test]
    fn verify_password_works() {
        let (_d, path) = temp_vault();
        let v = UnlockedVault::create(&path, "pw", KdfParams::TEST).unwrap();
        assert!(v.verify_password("pw"));
        assert!(!v.verify_password("nope"));
    }

    #[test]
    fn two_vaults_with_same_password_differ() {
        let (_d, path) = temp_vault();
        let (_d2, path2) = temp_vault();
        UnlockedVault::create(&path, "pw", KdfParams::TEST).unwrap();
        UnlockedVault::create(&path2, "pw", KdfParams::TEST).unwrap();
        let a = VaultFile::load(&path).unwrap();
        let b = VaultFile::load(&path2).unwrap();
        assert_ne!(a.password_slot.salt, b.password_slot.salt);
        assert_ne!(a.password_slot.wrapped_key.ciphertext, b.password_slot.wrapped_key.ciphertext);
    }
}
