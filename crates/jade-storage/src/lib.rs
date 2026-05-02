#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageNamespace {
    Keychain,
    Multisig,
    Descriptor,
    Otp,
    Pinserver,
    Settings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    NotFound,
    InvalidKey,
    ValueTooLarge,
    BackendFailure,
}

pub trait StorageBackend {
    fn get(
        &self,
        namespace: StorageNamespace,
        key: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), StorageError>;
    fn set(
        &mut self,
        namespace: StorageNamespace,
        key: &str,
        value: &[u8],
    ) -> Result<(), StorageError>;
    fn erase(&mut self, namespace: StorageNamespace, key: &str) -> Result<(), StorageError>;
    fn list(&self, namespace: StorageNamespace, out: &mut Vec<String>) -> Result<(), StorageError>;
}
