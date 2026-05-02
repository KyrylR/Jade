#![no_std]

extern crate alloc;

use alloc::borrow::Cow;
use minicbor::{Decode, Encode};

pub const MAX_ID_LEN: usize = 16;
pub const MAX_METHOD_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    InvalidRequest = -32600,
    UnknownMethod = -32601,
    BadParameters = -32602,
    InternalError = -32603,
    UserCancelled = -32000,
    ProtocolError = -32001,
    HardwareLocked = -32002,
    NetworkMismatch = -32003,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodClass {
    Immediate,
    PreAuth,
    Debug,
    Authenticated,
    Continuation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParityStatus {
    MustParity,
    AdapterOnly,
    Deferred,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSpec {
    pub name: &'static str,
    pub class: MethodClass,
    pub parity: ParityStatus,
}

pub const METHOD_SPECS: &[MethodSpec] = &[
    MethodSpec {
        name: "ping",
        class: MethodClass::Immediate,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_version_info",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "add_entropy",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "set_epoch",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "logout",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "register_attestation",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "sign_attestation",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "update_pinserver",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "auth_user",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "cancel",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "ota",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "ota_delta",
        class: MethodClass::PreAuth,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "register_otp",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_otp_code",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_xpub",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_registered_multisigs",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_registered_multisig",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "register_multisig",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_registered_descriptors",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_registered_descriptor",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "register_descriptor",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_receive_address",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_identity_pubkey",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_identity_shared_key",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "sign_identity",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "sign_message",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "sign_psbt",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "sign_tx",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "sign_liquid_tx",
        class: MethodClass::Authenticated,
        parity: ParityStatus::Deferred,
    },
    MethodSpec {
        name: "get_commitments",
        class: MethodClass::Authenticated,
        parity: ParityStatus::Deferred,
    },
    MethodSpec {
        name: "get_blinding_factor",
        class: MethodClass::Authenticated,
        parity: ParityStatus::Deferred,
    },
    MethodSpec {
        name: "get_master_blinding_key",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_blinding_key",
        class: MethodClass::Authenticated,
        parity: ParityStatus::Deferred,
    },
    MethodSpec {
        name: "get_shared_nonce",
        class: MethodClass::Authenticated,
        parity: ParityStatus::Deferred,
    },
    MethodSpec {
        name: "get_bip85_pubkey",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "sign_bip85_digests",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "show_bip85_bip39_entropy",
        class: MethodClass::Authenticated,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_bip85_bip39_entropy",
        class: MethodClass::Debug,
        parity: ParityStatus::AdapterOnly,
    },
    MethodSpec {
        name: "get_bip85_rsa_entropy",
        class: MethodClass::Debug,
        parity: ParityStatus::AdapterOnly,
    },
    MethodSpec {
        name: "debug_selfcheck",
        class: MethodClass::Debug,
        parity: ParityStatus::AdapterOnly,
    },
    MethodSpec {
        name: "debug_clean_reset",
        class: MethodClass::Debug,
        parity: ParityStatus::AdapterOnly,
    },
    MethodSpec {
        name: "debug_set_mnemonic",
        class: MethodClass::Debug,
        parity: ParityStatus::AdapterOnly,
    },
    MethodSpec {
        name: "debug_handshake",
        class: MethodClass::Debug,
        parity: ParityStatus::AdapterOnly,
    },
    MethodSpec {
        name: "debug_scan_qr",
        class: MethodClass::Debug,
        parity: ParityStatus::AdapterOnly,
    },
    MethodSpec {
        name: "debug_capture_image_data",
        class: MethodClass::Debug,
        parity: ParityStatus::AdapterOnly,
    },
    MethodSpec {
        name: "ota_data",
        class: MethodClass::Continuation,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "ota_complete",
        class: MethodClass::Continuation,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "tx_input",
        class: MethodClass::Continuation,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_extended_data",
        class: MethodClass::Continuation,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "get_signature",
        class: MethodClass::Continuation,
        parity: ParityStatus::MustParity,
    },
    MethodSpec {
        name: "pin",
        class: MethodClass::Continuation,
        parity: ParityStatus::MustParity,
    },
];

pub fn method_spec(method: &str) -> Option<&'static MethodSpec> {
    METHOD_SPECS.iter().find(|spec| spec.name == method)
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Request<'a> {
    #[n(0)]
    pub id: Cow<'a, str>,
    #[n(1)]
    pub method: Cow<'a, str>,
}

impl<'a> Request<'a> {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_id(&self.id)?;
        validate_method(&self.method)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ErrorResponse<'a> {
    #[n(0)]
    pub id: Cow<'a, str>,
    #[n(1)]
    pub code: i32,
    #[n(2)]
    pub message: Cow<'a, str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    EmptyId,
    IdTooLong,
    EmptyMethod,
    MethodTooLong,
    UnknownMethod,
}

pub fn validate_id(id: &str) -> Result<(), ValidationError> {
    if id.is_empty() {
        return Err(ValidationError::EmptyId);
    }
    if id.len() > MAX_ID_LEN {
        return Err(ValidationError::IdTooLong);
    }
    Ok(())
}

pub fn validate_method(method: &str) -> Result<(), ValidationError> {
    if method.is_empty() {
        return Err(ValidationError::EmptyMethod);
    }
    if method.len() > MAX_METHOD_LEN {
        return Err(ValidationError::MethodTooLong);
    }
    if method_spec(method).is_none() {
        return Err(ValidationError::UnknownMethod);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_catalog_methods_fit_v1_wire_limits() {
        for spec in METHOD_SPECS {
            assert!(
                spec.name.len() <= MAX_METHOD_LEN,
                "method too long: {}",
                spec.name
            );
        }
    }

    #[test]
    fn known_methods_are_classified() {
        assert_eq!(method_spec("ping").unwrap().class, MethodClass::Immediate);
        assert_eq!(
            method_spec("sign_psbt").unwrap().parity,
            ParityStatus::MustParity
        );
        assert_eq!(
            method_spec("sign_liquid_tx").unwrap().parity,
            ParityStatus::Deferred
        );
    }
}
