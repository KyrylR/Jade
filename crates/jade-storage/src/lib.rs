#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use zeroize::Zeroize;

pub const NVS_KEY_NAME_MAX_SIZE: usize = 16;
pub const MAX_KEY_NAME_LEN: usize = NVS_KEY_NAME_MAX_SIZE - 1;
pub const DEFAULT_PIN_RETRIES: u8 = 3;
pub const BLE_ENABLED: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageNamespace {
    Default,
    Multisig,
    Descriptor,
    Otp,
    HotpCounters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    NotFound,
    InvalidKey,
    ValueTooLarge,
    CapacityExceeded,
    BackendFailure,
}

pub type StorageResult<T> = Result<T, StorageError>;

pub trait StorageBackend {
    fn get(&self, namespace: StorageNamespace, key: &str, out: &mut Vec<u8>) -> StorageResult<()>;
    fn set(&mut self, namespace: StorageNamespace, key: &str, value: &[u8]) -> StorageResult<()>;
    fn erase(&mut self, namespace: StorageNamespace, key: &str) -> StorageResult<()>;
    fn list(&self, namespace: StorageNamespace, out: &mut Vec<String>) -> StorageResult<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageLimits {
    pub max_value_len: usize,
    pub max_records_per_namespace: usize,
}

impl StorageLimits {
    pub const ESP32_NVS_DEFAULT: Self = Self {
        max_value_len: 401 * 1024,
        max_records_per_namespace: 64,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageRecord<'a> {
    PinPrivateKey,
    EncryptedBlob,
    PinCounter,
    ReplayCounter,
    KeyFlags,
    WalletErasePin,
    PinserverUrlA,
    PinserverUrlB,
    PinserverPubkey,
    PinserverCertificate,
    NetworkRestriction,
    IdleTimeout,
    Brightness,
    GuiFlags,
    BleFlags,
    QrFlags,
    MultisigRegistration { name: &'a str },
    DescriptorRegistration { name: &'a str },
    OtpData { name: &'a str },
    OtpHotpCounter { name: &'a str },
}

impl<'a> StorageRecord<'a> {
    pub fn namespace(self) -> StorageNamespace {
        match self {
            Self::MultisigRegistration { .. } => StorageNamespace::Multisig,
            Self::DescriptorRegistration { .. } => StorageNamespace::Descriptor,
            Self::OtpData { .. } => StorageNamespace::Otp,
            Self::OtpHotpCounter { .. } => StorageNamespace::HotpCounters,
            _ => StorageNamespace::Default,
        }
    }

    pub fn key(self) -> &'a str {
        match self {
            Self::PinPrivateKey => "pin_privatekey",
            Self::EncryptedBlob => "blob",
            Self::PinCounter => "pin_counter",
            Self::ReplayCounter => "replay_counter",
            Self::KeyFlags => "key_flags",
            Self::WalletErasePin => "wallet_erase",
            Self::PinserverUrlA => "urlA",
            Self::PinserverUrlB => "urlB",
            Self::PinserverPubkey => "pinserver_pub",
            Self::PinserverCertificate => "pinserver_cert",
            Self::NetworkRestriction => "network_type",
            Self::IdleTimeout => "idle_timeout",
            Self::Brightness => "brightness",
            Self::GuiFlags => "gui_flags",
            Self::BleFlags => "ble_flags",
            Self::QrFlags => "qr_flags",
            Self::MultisigRegistration { name }
            | Self::DescriptorRegistration { name }
            | Self::OtpData { name }
            | Self::OtpHotpCounter { name } => name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JadeStorage<B> {
    backend: B,
    limits: StorageLimits,
}

impl<B: StorageBackend> JadeStorage<B> {
    pub fn new(backend: B, limits: StorageLimits) -> Self {
        Self { backend, limits }
    }

    pub fn into_inner(self) -> B {
        self.backend
    }

    pub fn get_record(&self, record: StorageRecord<'_>, out: &mut Vec<u8>) -> StorageResult<()> {
        validate_record(record)?;
        self.backend.get(record.namespace(), record.key(), out)
    }

    pub fn set_record(&mut self, record: StorageRecord<'_>, value: &[u8]) -> StorageResult<()> {
        validate_record(record)?;
        if value.len() > self.limits.max_value_len {
            return Err(StorageError::ValueTooLarge);
        }
        self.backend.set(record.namespace(), record.key(), value)
    }

    pub fn erase_record(&mut self, record: StorageRecord<'_>) -> StorageResult<()> {
        validate_record(record)?;
        self.backend.erase(record.namespace(), record.key())
    }

    pub fn list_names(
        &self,
        namespace: StorageNamespace,
        out: &mut Vec<String>,
    ) -> StorageResult<()> {
        self.backend.list(namespace, out)
    }

    pub fn count(&self, namespace: StorageNamespace) -> StorageResult<usize> {
        let mut names = Vec::new();
        self.backend.list(namespace, &mut names)?;
        Ok(names.len())
    }

    pub fn set_encrypted_blob(&mut self, encrypted: &[u8]) -> StorageResult<()> {
        self.restore_pin_counter()?;
        self.set_record(StorageRecord::EncryptedBlob, encrypted)
    }

    pub fn get_encrypted_blob(&self, out: &mut Vec<u8>) -> StorageResult<()> {
        self.get_record(StorageRecord::EncryptedBlob, out)
    }

    pub fn erase_encrypted_blob(&mut self) -> StorageResult<()> {
        let _ = self.erase_record(StorageRecord::PinCounter);
        self.erase_record(StorageRecord::EncryptedBlob)
    }

    pub fn decrement_pin_counter(&mut self) -> StorageResult<()> {
        let counter = self.pin_counter();
        if counter == 0 || counter > DEFAULT_PIN_RETRIES {
            let _ = self.erase_encrypted_blob();
            return Err(StorageError::BackendFailure);
        }

        let next = counter - 1;
        if self.set_record(StorageRecord::PinCounter, &[next]).is_err() {
            let _ = self.erase_encrypted_blob();
            return Err(StorageError::BackendFailure);
        }
        Ok(())
    }

    pub fn restore_pin_counter(&mut self) -> StorageResult<()> {
        self.set_record(StorageRecord::PinCounter, &[DEFAULT_PIN_RETRIES])
    }

    pub fn pin_counter(&self) -> u8 {
        let mut value = Vec::new();
        match self.get_record(StorageRecord::PinCounter, &mut value) {
            Ok(()) if value.len() == 1 => value[0],
            _ => 0,
        }
    }

    pub fn next_replay_counter(&mut self) -> StorageResult<u32> {
        let current = self.u32_or_default(StorageRecord::ReplayCounter, 0)?;
        let next = current.checked_add(1).ok_or(StorageError::ValueTooLarge)?;
        self.set_u32(StorageRecord::ReplayCounter, next)?;
        Ok(current)
    }

    pub fn set_pinserver_details(
        &mut self,
        url_a: &str,
        url_b: &str,
        pubkey: Option<&[u8]>,
    ) -> StorageResult<()> {
        self.set_record(StorageRecord::PinserverUrlA, url_a.as_bytes())?;
        self.set_record(StorageRecord::PinserverUrlB, url_b.as_bytes())?;
        if let Some(pubkey) = pubkey {
            self.set_record(StorageRecord::PinserverPubkey, pubkey)?;
        }
        let _ = self.erase_record(StorageRecord::PinPrivateKey);
        Ok(())
    }

    pub fn erase_pinserver_details(&mut self) -> StorageResult<()> {
        let _ = self.erase_record(StorageRecord::PinserverUrlA);
        let _ = self.erase_record(StorageRecord::PinserverUrlB);
        let _ = self.erase_record(StorageRecord::PinserverPubkey);
        let _ = self.erase_record(StorageRecord::PinPrivateKey);
        Ok(())
    }

    pub fn set_u8(&mut self, record: StorageRecord<'_>, value: u8) -> StorageResult<()> {
        self.set_record(record, &[value])
    }

    pub fn u8_or_default(&self, record: StorageRecord<'_>, default: u8) -> u8 {
        let mut value = Vec::new();
        match self.get_record(record, &mut value) {
            Ok(()) if value.len() == 1 => value[0],
            _ => default,
        }
    }

    pub fn set_u16(&mut self, record: StorageRecord<'_>, value: u16) -> StorageResult<()> {
        self.set_record(record, &value.to_le_bytes())
    }

    pub fn u16_or_default(&self, record: StorageRecord<'_>, default: u16) -> StorageResult<u16> {
        let mut value = Vec::new();
        match self.get_record(record, &mut value) {
            Ok(()) if value.len() == 2 => Ok(u16::from_le_bytes([value[0], value[1]])),
            Ok(()) => Err(StorageError::BackendFailure),
            Err(StorageError::NotFound) => Ok(default),
            Err(err) => Err(err),
        }
    }

    pub fn set_u32(&mut self, record: StorageRecord<'_>, value: u32) -> StorageResult<()> {
        self.set_record(record, &value.to_le_bytes())
    }

    pub fn u32_or_default(&self, record: StorageRecord<'_>, default: u32) -> StorageResult<u32> {
        let mut value = Vec::new();
        match self.get_record(record, &mut value) {
            Ok(()) if value.len() == 4 => {
                Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
            }
            Ok(()) if value.len() == 2 && record == StorageRecord::QrFlags => {
                Ok(u16::from_le_bytes([value[0], value[1]]) as u32)
            }
            Ok(()) => Err(StorageError::BackendFailure),
            Err(StorageError::NotFound) => Ok(default),
            Err(err) => Err(err),
        }
    }

    pub fn set_u64(&mut self, record: StorageRecord<'_>, value: u64) -> StorageResult<()> {
        self.set_record(record, &value.to_le_bytes())
    }

    pub fn u64_or_default(&self, record: StorageRecord<'_>, default: u64) -> StorageResult<u64> {
        let mut value = Vec::new();
        match self.get_record(record, &mut value) {
            Ok(()) if value.len() == 8 => Ok(u64::from_le_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ])),
            Ok(()) => Err(StorageError::BackendFailure),
            Err(StorageError::NotFound) => Ok(default),
            Err(err) => Err(err),
        }
    }

    pub fn set_multisig_registration(&mut self, name: &str, value: &[u8]) -> StorageResult<()> {
        self.ensure_namespace_capacity(StorageNamespace::Multisig, name)?;
        self.set_record(StorageRecord::MultisigRegistration { name }, value)
    }

    pub fn set_descriptor_registration(&mut self, name: &str, value: &[u8]) -> StorageResult<()> {
        self.ensure_namespace_capacity(StorageNamespace::Descriptor, name)?;
        self.set_record(StorageRecord::DescriptorRegistration { name }, value)
    }

    pub fn set_otp_data(&mut self, name: &str, value: &[u8]) -> StorageResult<()> {
        self.ensure_namespace_capacity(StorageNamespace::Otp, name)?;
        self.set_record(StorageRecord::OtpData { name }, value)
    }

    pub fn set_otp_hotp_counter(&mut self, name: &str, counter: u64) -> StorageResult<()> {
        self.set_u64(StorageRecord::OtpHotpCounter { name }, counter)
    }

    pub fn otp_hotp_counter(&self, name: &str) -> StorageResult<u64> {
        self.u64_or_default(StorageRecord::OtpHotpCounter { name }, 0)
    }

    pub fn erase_otp(&mut self, name: &str) -> StorageResult<()> {
        let _ = self.erase_record(StorageRecord::OtpHotpCounter { name });
        self.erase_record(StorageRecord::OtpData { name })
    }

    fn ensure_namespace_capacity(
        &self,
        namespace: StorageNamespace,
        incoming_name: &str,
    ) -> StorageResult<()> {
        let mut names = Vec::new();
        self.backend.list(namespace, &mut names)?;
        if names.iter().any(|name| name == incoming_name) {
            return Ok(());
        }
        if names.len() >= self.limits.max_records_per_namespace {
            return Err(StorageError::CapacityExceeded);
        }
        Ok(())
    }
}

pub fn key_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_KEY_NAME_LEN
        && name.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

pub fn make_key_name_valid(name: &str) -> StorageResult<String> {
    if name.is_empty() {
        return Err(StorageError::InvalidKey);
    }

    let mut out = String::new();
    for ch in name.chars().take(MAX_KEY_NAME_LEN) {
        if ch.is_ascii_graphic() {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        return Err(StorageError::InvalidKey);
    }
    Ok(out)
}

fn validate_record(record: StorageRecord<'_>) -> StorageResult<()> {
    if key_name_valid(record.key()) {
        Ok(())
    } else {
        Err(StorageError::InvalidKey)
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryStorage {
    records: Vec<MemoryRecord>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    fn find_index(&self, namespace: StorageNamespace, key: &str) -> Option<usize> {
        self.records
            .iter()
            .position(|record| record.namespace == namespace && record.key == key)
    }
}

impl Drop for MemoryStorage {
    fn drop(&mut self) {
        for record in &mut self.records {
            record.value.zeroize();
        }
    }
}

impl StorageBackend for MemoryStorage {
    fn get(&self, namespace: StorageNamespace, key: &str, out: &mut Vec<u8>) -> StorageResult<()> {
        let index = self
            .find_index(namespace, key)
            .ok_or(StorageError::NotFound)?;
        out.clear();
        out.extend_from_slice(&self.records[index].value);
        Ok(())
    }

    fn set(&mut self, namespace: StorageNamespace, key: &str, value: &[u8]) -> StorageResult<()> {
        match self.find_index(namespace, key) {
            Some(index) => {
                self.records[index].value.zeroize();
                self.records[index].value.clear();
                self.records[index].value.extend_from_slice(value);
            }
            None => self.records.push(MemoryRecord {
                namespace,
                key: String::from(key),
                value: value.to_vec(),
            }),
        }
        Ok(())
    }

    fn erase(&mut self, namespace: StorageNamespace, key: &str) -> StorageResult<()> {
        let index = self
            .find_index(namespace, key)
            .ok_or(StorageError::NotFound)?;
        let mut record = self.records.remove(index);
        record.value.zeroize();
        Ok(())
    }

    fn list(&self, namespace: StorageNamespace, out: &mut Vec<String>) -> StorageResult<()> {
        out.clear();
        out.extend(
            self.records
                .iter()
                .filter(|record| record.namespace == namespace)
                .map(|record| record.key.clone()),
        );
        out.sort();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MemoryRecord {
    namespace: StorageNamespace,
    key: String,
    value: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn key_names_follow_jade_nvs_constraints() {
        assert!(key_name_valid("wallet-1"));
        assert!(key_name_valid("123456789012345"));
        assert!(!key_name_valid(""));
        assert!(!key_name_valid("has space"));
        assert!(!key_name_valid("1234567890123456"));

        assert_eq!(make_key_name_valid("bad name\n").unwrap(), "bad_name_");
        assert_eq!(
            make_key_name_valid("123456789012345678").unwrap(),
            "123456789012345"
        );
    }

    #[test]
    fn memory_backend_sets_gets_lists_and_erases_records() {
        let mut storage = JadeStorage::new(
            MemoryStorage::new(),
            StorageLimits {
                max_value_len: 32,
                max_records_per_namespace: 4,
            },
        );

        storage
            .set_multisig_registration("wallet-a", b"record-a")
            .unwrap();
        storage
            .set_descriptor_registration("desc-a", b"record-d")
            .unwrap();

        let mut value = Vec::new();
        storage
            .get_record(
                StorageRecord::MultisigRegistration { name: "wallet-a" },
                &mut value,
            )
            .unwrap();
        assert_eq!(value, b"record-a");

        let mut names = Vec::new();
        storage
            .list_names(StorageNamespace::Multisig, &mut names)
            .unwrap();
        assert_eq!(names, vec![String::from("wallet-a")]);

        storage
            .erase_record(StorageRecord::MultisigRegistration { name: "wallet-a" })
            .unwrap();
        assert_eq!(storage.count(StorageNamespace::Multisig).unwrap(), 0);
    }

    #[test]
    fn wallet_blob_restores_and_erases_pin_counter() {
        let mut storage = JadeStorage::new(MemoryStorage::new(), StorageLimits::ESP32_NVS_DEFAULT);

        storage.set_encrypted_blob(b"encrypted").unwrap();
        assert_eq!(storage.pin_counter(), DEFAULT_PIN_RETRIES);

        storage.decrement_pin_counter().unwrap();
        assert_eq!(storage.pin_counter(), DEFAULT_PIN_RETRIES - 1);

        storage.erase_encrypted_blob().unwrap();
        assert_eq!(storage.pin_counter(), 0);
    }

    #[test]
    fn replay_and_otp_counters_match_incrementing_storage_semantics() {
        let mut storage = JadeStorage::new(MemoryStorage::new(), StorageLimits::ESP32_NVS_DEFAULT);

        assert_eq!(storage.next_replay_counter().unwrap(), 0);
        assert_eq!(storage.next_replay_counter().unwrap(), 1);

        storage.set_otp_data("otp-a", b"otpauth://totp/a").unwrap();
        storage.set_otp_hotp_counter("otp-a", 41).unwrap();
        assert_eq!(storage.otp_hotp_counter("otp-a").unwrap(), 41);

        storage.erase_otp("otp-a").unwrap();
        assert_eq!(storage.otp_hotp_counter("otp-a").unwrap(), 0);
        assert_eq!(storage.count(StorageNamespace::Otp).unwrap(), 0);
    }

    #[test]
    fn settings_and_pinserver_records_are_typed_helpers() {
        let mut storage = JadeStorage::new(MemoryStorage::new(), StorageLimits::ESP32_NVS_DEFAULT);

        storage
            .set_u8(StorageRecord::BleFlags, BLE_ENABLED)
            .unwrap();
        storage.set_u16(StorageRecord::IdleTimeout, 120).unwrap();
        storage
            .set_u32(StorageRecord::QrFlags, 0x1234_5678)
            .unwrap();
        storage
            .set_pinserver_details("https://a.example", "https://b.example", Some(&[1, 2, 3]))
            .unwrap();

        assert_eq!(
            storage.u8_or_default(StorageRecord::BleFlags, 0),
            BLE_ENABLED
        );
        assert_eq!(
            storage
                .u16_or_default(StorageRecord::IdleTimeout, 0)
                .unwrap(),
            120
        );
        assert_eq!(
            storage.u32_or_default(StorageRecord::QrFlags, 0).unwrap(),
            0x1234_5678
        );

        let mut pubkey = Vec::new();
        storage
            .get_record(StorageRecord::PinserverPubkey, &mut pubkey)
            .unwrap();
        assert_eq!(pubkey, [1, 2, 3]);

        storage.erase_pinserver_details().unwrap();
        assert_eq!(
            storage.get_record(StorageRecord::PinserverPubkey, &mut pubkey),
            Err(StorageError::NotFound)
        );
    }
}
