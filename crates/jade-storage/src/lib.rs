#![no_std]

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::str;

use zeroize::Zeroize;

pub const NVS_KEY_NAME_MAX_SIZE: usize = 16;
pub const MAX_KEY_NAME_LEN: usize = NVS_KEY_NAME_MAX_SIZE - 1;
pub const DEFAULT_PIN_RETRIES: u8 = 3;
pub const BLE_ENABLED: u8 = 0x01;
pub const HMAC_SHA256_LEN: usize = 32;
pub const BIP32_SERIALIZED_LEN: usize = 78;
pub const MAX_ALLOWED_SIGNERS: usize = 15;
pub const MAX_PATH_LEN: usize = 16;
pub const MULTISIG_MASTER_BLINDING_KEY_SIZE: usize = 32;

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
    AuthenticationFailed,
    InvalidRecord,
    BackendFailure,
}

pub type StorageResult<T> = Result<T, StorageError>;

pub trait StorageBackend {
    fn get(&self, namespace: StorageNamespace, key: &str, out: &mut Vec<u8>) -> StorageResult<()>;
    fn set(&mut self, namespace: StorageNamespace, key: &str, value: &[u8]) -> StorageResult<()>;
    fn erase(&mut self, namespace: StorageNamespace, key: &str) -> StorageResult<()>;
    fn list(&self, namespace: StorageNamespace, out: &mut Vec<String>) -> StorageResult<()>;
}

pub trait RecordAuthenticator {
    fn verify_record(&self, payload: &[u8], tag: &[u8; HMAC_SHA256_LEN]) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorSummary {
    pub descriptor_type: u8,
    pub descriptor_len: u16,
    pub num_datavalues: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorDetails {
    pub descriptor_type: u8,
    pub descriptor: String,
    pub datavalues: Vec<DescriptorDataValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorDataValue {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultisigSummary {
    pub variant: MultisigVariant,
    pub sorted: bool,
    pub threshold: u8,
    pub num_signers: u8,
    pub master_blinding_key: Option<[u8; MULTISIG_MASTER_BLINDING_KEY_SIZE]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigDetails {
    pub summary: MultisigSummary,
    pub signers: Option<Vec<MultisigSignerDetails>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigSignerDetails {
    pub fingerprint: [u8; 4],
    pub derivation: Vec<u32>,
    pub xpub: [u8; BIP32_SERIALIZED_LEN],
    pub path: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MultisigVariant {
    P2wsh = 4,
    P2sh = 5,
    P2wshP2sh = 6,
}

impl MultisigVariant {
    pub fn from_storage(value: u8) -> StorageResult<Self> {
        match value {
            4 => Ok(Self::P2wsh),
            5 => Ok(Self::P2sh),
            6 => Ok(Self::P2wshP2sh),
            _ => Err(StorageError::InvalidRecord),
        }
    }

    pub fn as_v1_str(self) -> &'static str {
        match self {
            Self::P2wsh => "wsh(multi(k))",
            Self::P2sh => "sh(multi(k))",
            Self::P2wshP2sh => "sh(wsh(multi(k)))",
        }
    }
}

pub fn parse_descriptor_summary(
    record: &[u8],
    authenticator: &impl RecordAuthenticator,
) -> StorageResult<DescriptorSummary> {
    let details = parse_descriptor_details(record, authenticator)?;

    Ok(DescriptorSummary {
        descriptor_type: details.descriptor_type,
        descriptor_len: details.descriptor.len() as u16,
        num_datavalues: details.datavalues.len() as u8,
    })
}

pub fn parse_descriptor_details(
    record: &[u8],
    authenticator: &impl RecordAuthenticator,
) -> StorageResult<DescriptorDetails> {
    let payload = authenticated_payload(record, authenticator)?;
    let mut reader = RecordReader::new(payload);

    let version = reader.u8()?;
    if version > 0 {
        return Err(StorageError::InvalidRecord);
    }

    let descriptor_type = reader.u8()?;
    let descriptor_len = reader.u16_le()?;
    let descriptor = str::from_utf8(reader.take(descriptor_len as usize)?)
        .map_err(|_| StorageError::InvalidRecord)?
        .to_string();

    let num_datavalues = reader.u8()?;
    if num_datavalues as usize > MAX_ALLOWED_SIGNERS {
        return Err(StorageError::InvalidRecord);
    }

    let mut datavalues = Vec::with_capacity(num_datavalues as usize);
    for _ in 0..num_datavalues {
        let key_len = reader.u16_le()? as usize;
        let key = str::from_utf8(reader.take(key_len)?)
            .map_err(|_| StorageError::InvalidRecord)?
            .to_string();
        let value_len = reader.u16_le()? as usize;
        let value = str::from_utf8(reader.take(value_len)?)
            .map_err(|_| StorageError::InvalidRecord)?
            .to_string();
        datavalues.push(DescriptorDataValue { key, value });
    }
    reader.finish()?;

    Ok(DescriptorDetails {
        descriptor_type,
        descriptor,
        datavalues,
    })
}

pub fn parse_multisig_summary(
    record: &[u8],
    authenticator: &impl RecordAuthenticator,
) -> StorageResult<MultisigSummary> {
    parse_multisig_details(record, authenticator).map(|details| details.summary)
}

pub fn parse_multisig_details(
    record: &[u8],
    authenticator: &impl RecordAuthenticator,
) -> StorageResult<MultisigDetails> {
    let payload = authenticated_payload(record, authenticator)?;
    let mut reader = RecordReader::new(payload);

    let version = reader.u8()?;
    if version > 3 {
        return Err(StorageError::InvalidRecord);
    }

    let variant = MultisigVariant::from_storage(reader.u8()?)?;
    let sorted = if version > 0 {
        reader.u8()? != 0
    } else {
        false
    };
    let threshold = reader.u8()?;

    let master_blinding_key = if version > 1 {
        let key_len = reader.u8()? as usize;
        match key_len {
            0 => None,
            MULTISIG_MASTER_BLINDING_KEY_SIZE => Some(reader.array32()?),
            _ => return Err(StorageError::InvalidRecord),
        }
    } else {
        None
    };

    let (num_signers, signers) = if version < 3 {
        let remaining_len = reader.remaining().len();
        let num_signers = parse_legacy_multisig_signer_count(reader.remaining())?;
        reader.skip(remaining_len)?;
        (num_signers, None)
    } else {
        let signers = parse_current_multisig_signers(&mut reader)?;
        (signers.len() as u8, Some(signers))
    };
    if threshold == 0 || threshold > num_signers {
        return Err(StorageError::InvalidRecord);
    }
    reader.finish()?;

    Ok(MultisigDetails {
        summary: MultisigSummary {
            variant,
            sorted,
            threshold,
            num_signers,
            master_blinding_key,
        },
        signers,
    })
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

    pub fn debug_clean_reset(&mut self) -> StorageResult<()> {
        for record in [
            StorageRecord::EncryptedBlob,
            StorageRecord::PinCounter,
            StorageRecord::NetworkRestriction,
            StorageRecord::PinserverUrlA,
            StorageRecord::PinserverUrlB,
            StorageRecord::PinserverPubkey,
            StorageRecord::PinserverCertificate,
            StorageRecord::PinPrivateKey,
        ] {
            self.erase_optional_record(record)?;
        }

        self.erase_namespace(StorageNamespace::Multisig)?;
        self.erase_namespace(StorageNamespace::Descriptor)?;
        self.erase_namespace(StorageNamespace::Otp)?;
        self.erase_namespace(StorageNamespace::HotpCounters)?;
        Ok(())
    }

    fn erase_optional_record(&mut self, record: StorageRecord<'_>) -> StorageResult<()> {
        match self.erase_record(record) {
            Ok(()) | Err(StorageError::NotFound) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn erase_namespace(&mut self, namespace: StorageNamespace) -> StorageResult<()> {
        let mut names = Vec::new();
        self.list_names(namespace, &mut names)?;
        for name in names {
            let record = match namespace {
                StorageNamespace::Multisig => StorageRecord::MultisigRegistration { name: &name },
                StorageNamespace::Descriptor => {
                    StorageRecord::DescriptorRegistration { name: &name }
                }
                StorageNamespace::Otp => StorageRecord::OtpData { name: &name },
                StorageNamespace::HotpCounters => StorageRecord::OtpHotpCounter { name: &name },
                StorageNamespace::Default => continue,
            };
            self.erase_optional_record(record)?;
        }
        Ok(())
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

fn authenticated_payload<'a>(
    record: &'a [u8],
    authenticator: &impl RecordAuthenticator,
) -> StorageResult<&'a [u8]> {
    if record.len() <= HMAC_SHA256_LEN {
        return Err(StorageError::InvalidRecord);
    }
    let payload_len = record.len() - HMAC_SHA256_LEN;
    let (payload, tag) = record.split_at(payload_len);
    let tag: &[u8; HMAC_SHA256_LEN] = tag.try_into().map_err(|_| StorageError::InvalidRecord)?;
    if authenticator.verify_record(payload, tag) {
        Ok(payload)
    } else {
        Err(StorageError::AuthenticationFailed)
    }
}

fn parse_legacy_multisig_signer_count(signer_bytes: &[u8]) -> StorageResult<u8> {
    let num_signers = signer_bytes.len() / BIP32_SERIALIZED_LEN;
    if num_signers == 0
        || num_signers > MAX_ALLOWED_SIGNERS
        || num_signers * BIP32_SERIALIZED_LEN != signer_bytes.len()
    {
        return Err(StorageError::InvalidRecord);
    }
    Ok(num_signers as u8)
}

fn parse_current_multisig_signers(
    reader: &mut RecordReader<'_>,
) -> StorageResult<Vec<MultisigSignerDetails>> {
    let num_signers = reader.u8()?;
    if num_signers == 0 || num_signers as usize > MAX_ALLOWED_SIGNERS {
        return Err(StorageError::InvalidRecord);
    }

    let mut signers = Vec::with_capacity(num_signers as usize);
    for _ in 0..num_signers {
        let fingerprint = reader.array4()?;

        let derivation_len = reader.u8()? as usize;
        if derivation_len > MAX_PATH_LEN {
            return Err(StorageError::InvalidRecord);
        }
        let derivation = reader.u32_vec(derivation_len)?;

        let xpub = reader.array78()?;

        let path_len = reader.u8()? as usize;
        if path_len > MAX_PATH_LEN {
            return Err(StorageError::InvalidRecord);
        }
        let path = reader.u32_vec(path_len)?;

        signers.push(MultisigSignerDetails {
            fingerprint,
            derivation,
            xpub,
            path,
        });
    }

    Ok(signers)
}

#[derive(Debug, Clone, Copy)]
struct RecordReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> RecordReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.cursor..]
    }

    fn u8(&mut self) -> StorageResult<u8> {
        let value = *self
            .bytes
            .get(self.cursor)
            .ok_or(StorageError::InvalidRecord)?;
        self.cursor += 1;
        Ok(value)
    }

    fn u16_le(&mut self) -> StorageResult<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32_le(&mut self) -> StorageResult<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u32_vec(&mut self, len: usize) -> StorageResult<Vec<u32>> {
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(self.u32_le()?);
        }
        Ok(values)
    }

    fn array4(&mut self) -> StorageResult<[u8; 4]> {
        self.take(4)?
            .try_into()
            .map_err(|_| StorageError::InvalidRecord)
    }

    fn array32(&mut self) -> StorageResult<[u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| StorageError::InvalidRecord)
    }

    fn array78(&mut self) -> StorageResult<[u8; BIP32_SERIALIZED_LEN]> {
        self.take(BIP32_SERIALIZED_LEN)?
            .try_into()
            .map_err(|_| StorageError::InvalidRecord)
    }

    fn skip(&mut self, len: usize) -> StorageResult<()> {
        self.take(len).map(|_| ())
    }

    fn take(&mut self, len: usize) -> StorageResult<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(StorageError::InvalidRecord)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(StorageError::InvalidRecord)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn finish(self) -> StorageResult<()> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(StorageError::InvalidRecord)
        }
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

    #[derive(Debug, Clone, Copy)]
    struct TestAuthenticator;

    impl RecordAuthenticator for TestAuthenticator {
        fn verify_record(&self, _payload: &[u8], tag: &[u8; HMAC_SHA256_LEN]) -> bool {
            tag == &[0xa5; HMAC_SHA256_LEN]
        }
    }

    fn authenticated_record(mut payload: Vec<u8>) -> Vec<u8> {
        payload.extend_from_slice(&[0xa5; HMAC_SHA256_LEN]);
        payload
    }

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
    fn parses_authenticated_descriptor_summary_records() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0, 2]);
        payload.extend_from_slice(&3u16.to_le_bytes());
        payload.extend_from_slice(b"wsh");
        payload.push(2);
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(b"k");
        payload.extend_from_slice(&5u16.to_le_bytes());
        payload.extend_from_slice(b"value");
        payload.extend_from_slice(&4u16.to_le_bytes());
        payload.extend_from_slice(b"xpub");
        payload.extend_from_slice(&3u16.to_le_bytes());
        payload.extend_from_slice(b"abc");

        let record = authenticated_record(payload);
        let summary = parse_descriptor_summary(&record, &TestAuthenticator).unwrap();

        assert_eq!(
            summary,
            DescriptorSummary {
                descriptor_type: 2,
                descriptor_len: 3,
                num_datavalues: 2,
            }
        );

        let details = parse_descriptor_details(&record, &TestAuthenticator).unwrap();
        assert_eq!(details.descriptor, "wsh");
        assert_eq!(
            details.datavalues,
            vec![
                DescriptorDataValue {
                    key: "k".to_string(),
                    value: "value".to_string(),
                },
                DescriptorDataValue {
                    key: "xpub".to_string(),
                    value: "abc".to_string(),
                },
            ]
        );
    }

    #[test]
    fn parses_authenticated_current_multisig_summary_records() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[3, MultisigVariant::P2wsh as u8, 1, 2]);
        payload.push(MULTISIG_MASTER_BLINDING_KEY_SIZE as u8);
        payload.extend_from_slice(&[0x11; MULTISIG_MASTER_BLINDING_KEY_SIZE]);
        payload.push(3);
        for signer in 0..3u8 {
            payload.extend_from_slice(&[signer; 4]);
            payload.push(1);
            payload.extend_from_slice(&(48u32 | 0x8000_0000).to_le_bytes());
            payload.extend_from_slice(&[0; BIP32_SERIALIZED_LEN]);
            payload.push(2);
            payload.extend_from_slice(&0u32.to_le_bytes());
            payload.extend_from_slice(&(signer as u32).to_le_bytes());
        }

        let record = authenticated_record(payload);
        let summary = parse_multisig_summary(&record, &TestAuthenticator).unwrap();

        assert_eq!(summary.variant.as_v1_str(), "wsh(multi(k))");
        assert!(summary.sorted);
        assert_eq!(summary.threshold, 2);
        assert_eq!(summary.num_signers, 3);
        assert_eq!(
            summary.master_blinding_key,
            Some([0x11; MULTISIG_MASTER_BLINDING_KEY_SIZE])
        );

        let details = parse_multisig_details(&record, &TestAuthenticator).unwrap();
        let signers = details.signers.unwrap();
        assert_eq!(signers.len(), 3);
        assert_eq!(signers[0].fingerprint, [0; 4]);
        assert_eq!(signers[0].derivation, vec![48u32 | 0x8000_0000]);
        assert_eq!(signers[0].xpub, [0; BIP32_SERIALIZED_LEN]);
        assert_eq!(signers[0].path, vec![0, 0]);
        assert_eq!(signers[2].fingerprint, [2; 4]);
        assert_eq!(signers[2].path, vec![0, 2]);
    }

    #[test]
    fn parses_authenticated_legacy_multisig_summary_records() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[2, MultisigVariant::P2wshP2sh as u8, 0, 1, 0]);
        payload.extend_from_slice(&[0; BIP32_SERIALIZED_LEN * 2]);

        let record = authenticated_record(payload);
        let summary = parse_multisig_summary(&record, &TestAuthenticator).unwrap();

        assert_eq!(summary.variant.as_v1_str(), "sh(wsh(multi(k)))");
        assert!(!summary.sorted);
        assert_eq!(summary.threshold, 1);
        assert_eq!(summary.num_signers, 2);
        assert_eq!(summary.master_blinding_key, None);

        let details = parse_multisig_details(&record, &TestAuthenticator).unwrap();
        assert_eq!(details.summary, summary);
        assert_eq!(details.signers, None);
    }

    #[test]
    fn rejects_records_without_valid_authentication() {
        let mut record = vec![0, 2, 0, 0, 0, 0];
        record.extend_from_slice(&[0; HMAC_SHA256_LEN]);

        assert_eq!(
            parse_descriptor_summary(&record, &TestAuthenticator),
            Err(StorageError::AuthenticationFailed)
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
    fn debug_clean_reset_erases_wallet_pinserver_and_registration_records() {
        let mut storage = JadeStorage::new(MemoryStorage::new(), StorageLimits::ESP32_NVS_DEFAULT);
        storage
            .set_record(StorageRecord::EncryptedBlob, b"blob")
            .unwrap();
        storage.set_u16(StorageRecord::PinCounter, 2).unwrap();
        storage
            .set_record(StorageRecord::PinserverUrlA, b"https://a")
            .unwrap();
        storage
            .set_record(StorageRecord::PinserverCertificate, b"cert")
            .unwrap();
        storage
            .set_multisig_registration("wallet-a", b"multisig")
            .unwrap();
        storage
            .set_descriptor_registration("desc-a", b"descriptor")
            .unwrap();
        storage.set_otp_data("otp-a", b"otp").unwrap();
        storage.set_otp_hotp_counter("otp-a", 9).unwrap();

        storage.debug_clean_reset().unwrap();

        let mut out = Vec::new();
        assert_eq!(
            storage.get_record(StorageRecord::EncryptedBlob, &mut out),
            Err(StorageError::NotFound)
        );
        assert_eq!(
            storage.get_record(StorageRecord::PinserverCertificate, &mut out),
            Err(StorageError::NotFound)
        );
        assert_eq!(storage.count(StorageNamespace::Multisig).unwrap(), 0);
        assert_eq!(storage.count(StorageNamespace::Descriptor).unwrap(), 0);
        assert_eq!(storage.count(StorageNamespace::Otp).unwrap(), 0);
        assert_eq!(storage.count(StorageNamespace::HotpCounters).unwrap(), 0);
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
