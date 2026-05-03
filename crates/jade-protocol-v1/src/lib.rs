#![no_std]

extern crate alloc;

use alloc::{borrow::Cow, string::String, vec::Vec};
use minicbor::{data::Type, Decoder, Encoder};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub id: Cow<'a, str>,
    pub method: Cow<'a, str>,
    pub params: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_id(&self.id)?;
        validate_method(&self.method)
    }

    pub fn params(&self) -> Option<Params<'a>> {
        self.params.map(Params)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResponse<'a> {
    pub id: Cow<'a, str>,
    pub code: i32,
    pub message: Cow<'a, str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultMapEntry<'a> {
    pub key: &'a str,
    pub value: V1Value<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V1Value<'a> {
    Bool(bool),
    U64(u64),
    Text(&'a str),
    Bytes(&'a [u8]),
    Map(&'a [ResultMapEntry<'a>]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedResultMapEntry {
    pub key: String,
    pub value: OwnedV1Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedV1Value {
    Bool(bool),
    U64(u64),
    Text(String),
    Bytes(Vec<u8>),
    Map(Vec<OwnedResultMapEntry>),
    Array(Vec<OwnedV1Value>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params<'a>(&'a [u8]);

impl<'a> Params<'a> {
    pub fn raw(self) -> &'a [u8] {
        self.0
    }

    pub fn bool(self, field: &str) -> Result<Option<bool>, ValidationError> {
        self.find_field(field, |decoder| {
            decoder.bool().map_err(ValidationError::from)
        })
    }

    pub fn u64(self, field: &str) -> Result<Option<u64>, ValidationError> {
        self.find_field(field, |decoder| {
            decoder.u64().map_err(ValidationError::from)
        })
    }

    pub fn str(self, field: &str) -> Result<Option<&'a str>, ValidationError> {
        self.find_field(field, |decoder| {
            decoder.str().map_err(ValidationError::from)
        })
    }

    pub fn bytes(self, field: &str) -> Result<Option<&'a [u8]>, ValidationError> {
        self.find_field(field, |decoder| {
            decoder.bytes().map_err(ValidationError::from)
        })
    }

    pub fn contains(self, field: &str) -> Result<bool, ValidationError> {
        let mut decoder = Decoder::new(self.0);
        let Some(len) = decoder.map()? else {
            return Err(ValidationError::MalformedCbor);
        };

        for _ in 0..len {
            match decoder.datatype()? {
                Type::String => {
                    let key = decoder.str()?;
                    if key == field {
                        return Ok(true);
                    }
                    decoder.skip()?;
                }
                _ => {
                    decoder.skip()?;
                    decoder.skip()?;
                }
            }
        }

        Ok(false)
    }

    pub fn u32_array(
        self,
        field: &str,
        max_len: usize,
    ) -> Result<Option<Vec<u32>>, ValidationError> {
        self.find_field(field, |decoder| {
            let Some(len) = decoder.array()? else {
                return Err(ValidationError::MalformedCbor);
            };
            if len as usize > max_len {
                return Err(ValidationError::ArrayTooLong);
            }

            let mut values = Vec::with_capacity(len as usize);
            for _ in 0..len {
                values.push(decoder.u32()?);
            }
            Ok(values)
        })
    }

    fn find_field<T>(
        self,
        field: &str,
        decode: impl FnOnce(&mut Decoder<'a>) -> Result<T, ValidationError>,
    ) -> Result<Option<T>, ValidationError> {
        let mut decoder = Decoder::new(self.0);
        let Some(len) = decoder.map()? else {
            return Err(ValidationError::MalformedCbor);
        };

        let mut decode = Some(decode);
        for _ in 0..len {
            match decoder.datatype()? {
                Type::String => {
                    let key = decoder.str()?;
                    if key == field {
                        return decode.take().expect("decode closure used once")(&mut decoder)
                            .map(Some);
                    }
                    decoder.skip()?;
                }
                _ => {
                    decoder.skip()?;
                    decoder.skip()?;
                }
            }
        }

        Ok(None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    EmptyId,
    IdTooLong,
    EmptyMethod,
    MethodTooLong,
    UnknownMethod,
    MalformedCbor,
    TrailingData,
    MissingId,
    MissingMethod,
    ArrayTooLong,
}

impl From<minicbor::decode::Error> for ValidationError {
    fn from(_: minicbor::decode::Error) -> Self {
        Self::MalformedCbor
    }
}

pub fn decode_request(input: &[u8]) -> Result<Request<'_>, ValidationError> {
    let mut decoder = Decoder::new(input);
    let Some(len) = decoder.map()? else {
        return Err(ValidationError::MalformedCbor);
    };

    let mut id = None;
    let mut method = None;
    let mut params = None;

    for _ in 0..len {
        match decoder.datatype()? {
            Type::String => {
                let key = decoder.str()?;
                match key {
                    "id" if id.is_none() => id = Some(decoder.str()?),
                    "method" if method.is_none() => method = Some(decoder.str()?),
                    "params" if params.is_none() => {
                        let start = decoder.position();
                        decoder.skip()?;
                        params = Some(&input[start..decoder.position()]);
                    }
                    _ => decoder.skip()?,
                }
            }
            _ => {
                decoder.skip()?;
                decoder.skip()?;
            }
        }
    }

    if decoder.position() != input.len() {
        return Err(ValidationError::TrailingData);
    }

    let request = Request {
        id: Cow::Borrowed(id.ok_or(ValidationError::MissingId)?),
        method: Cow::Borrowed(method.ok_or(ValidationError::MissingMethod)?),
        params,
    };
    request.validate()?;
    Ok(request)
}

pub fn encode_error_response(response: &ErrorResponse<'_>) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(2)
        .and_then(|e| e.str("id"))
        .and_then(|e| e.str(&response.id))
        .and_then(|e| e.str("error"))
        .and_then(|e| e.map(2))
        .and_then(|e| e.str("code"))
        .and_then(|e| e.i32(response.code))
        .and_then(|e| e.str("message"))
        .and_then(|e| e.str(&response.message))
        .expect("Vec-backed CBOR encoding is infallible");
    output
}

pub fn encode_error_with_data_response(response: &ErrorResponse<'_>, data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(2)
        .and_then(|e| e.str("id"))
        .and_then(|e| e.str(&response.id))
        .and_then(|e| e.str("error"))
        .and_then(|e| e.map(3))
        .and_then(|e| e.str("code"))
        .and_then(|e| e.i32(response.code))
        .and_then(|e| e.str("message"))
        .and_then(|e| e.str(&response.message))
        .and_then(|e| e.str("data"))
        .and_then(|e| e.bytes(data))
        .expect("Vec-backed CBOR encoding is infallible");
    output
}

pub fn encode_uint_result(id: &str, result: u64) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(2)
        .and_then(|e| e.str("id"))
        .and_then(|e| e.str(id))
        .and_then(|e| e.str("result"))
        .and_then(|e| e.u64(result))
        .expect("Vec-backed CBOR encoding is infallible");
    output
}

pub fn encode_bool_result(id: &str, result: bool) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(2)
        .and_then(|e| e.str("id"))
        .and_then(|e| e.str(id))
        .and_then(|e| e.str("result"))
        .and_then(|e| e.bool(result))
        .expect("Vec-backed CBOR encoding is infallible");
    output
}

pub fn encode_bytes_result(id: &str, result: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(2)
        .and_then(|e| e.str("id"))
        .and_then(|e| e.str(id))
        .and_then(|e| e.str("result"))
        .and_then(|e| e.bytes(result))
        .expect("Vec-backed CBOR encoding is infallible");
    output
}

pub fn encode_bytes_sequence_result(id: &str, seqnum: u64, seqlen: u64, result: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(4)
        .and_then(|e| e.str("id"))
        .and_then(|e| e.str(id))
        .and_then(|e| e.str("seqnum"))
        .and_then(|e| e.u64(seqnum))
        .and_then(|e| e.str("seqlen"))
        .and_then(|e| e.u64(seqlen))
        .and_then(|e| e.str("result"))
        .and_then(|e| e.bytes(result))
        .expect("Vec-backed CBOR encoding is infallible");
    output
}

pub fn encode_text_result(id: &str, result: &str) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(2)
        .and_then(|e| e.str("id"))
        .and_then(|e| e.str(id))
        .and_then(|e| e.str("result"))
        .and_then(|e| e.str(result))
        .expect("Vec-backed CBOR encoding is infallible");
    output
}

pub fn encode_map_result(id: &str, entries: &[ResultMapEntry<'_>]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(2)
        .and_then(|e| e.str("id"))
        .and_then(|e| e.str(id))
        .and_then(|e| e.str("result"))
        .and_then(|e| e.map(entries.len() as u64))
        .expect("Vec-backed CBOR encoding is infallible");

    for entry in entries {
        encode_borrowed_entry(&mut encoder, entry);
    }
    output
}

pub fn encode_owned_map_result(id: &str, entries: &[OwnedResultMapEntry]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(2)
        .and_then(|e| e.str("id"))
        .and_then(|e| e.str(id))
        .and_then(|e| e.str("result"))
        .and_then(|e| e.map(entries.len() as u64))
        .expect("Vec-backed CBOR encoding is infallible");

    for entry in entries {
        encode_owned_entry(&mut encoder, entry);
    }
    output
}

fn encode_borrowed_entry(encoder: &mut Encoder<&mut Vec<u8>>, entry: &ResultMapEntry<'_>) {
    encoder
        .str(entry.key)
        .expect("Vec-backed CBOR encoding is infallible");
    match entry.value {
        V1Value::Bool(value) => encoder
            .bool(value)
            .expect("Vec-backed CBOR encoding is infallible"),
        V1Value::U64(value) => encoder
            .u64(value)
            .expect("Vec-backed CBOR encoding is infallible"),
        V1Value::Text(value) => encoder
            .str(value)
            .expect("Vec-backed CBOR encoding is infallible"),
        V1Value::Bytes(value) => encoder
            .bytes(value)
            .expect("Vec-backed CBOR encoding is infallible"),
        V1Value::Map(entries) => {
            encoder
                .map(entries.len() as u64)
                .expect("Vec-backed CBOR encoding is infallible");
            for entry in entries {
                encode_borrowed_entry(encoder, entry);
            }
            encoder
        }
    };
}

fn encode_owned_entry(encoder: &mut Encoder<&mut Vec<u8>>, entry: &OwnedResultMapEntry) {
    encoder
        .str(&entry.key)
        .expect("Vec-backed CBOR encoding is infallible");
    match &entry.value {
        OwnedV1Value::Bool(value) => encoder
            .bool(*value)
            .expect("Vec-backed CBOR encoding is infallible"),
        OwnedV1Value::U64(value) => encoder
            .u64(*value)
            .expect("Vec-backed CBOR encoding is infallible"),
        OwnedV1Value::Text(value) => encoder
            .str(value)
            .expect("Vec-backed CBOR encoding is infallible"),
        OwnedV1Value::Bytes(value) => encoder
            .bytes(value)
            .expect("Vec-backed CBOR encoding is infallible"),
        OwnedV1Value::Map(entries) => {
            encoder
                .map(entries.len() as u64)
                .expect("Vec-backed CBOR encoding is infallible");
            for entry in entries {
                encode_owned_entry(encoder, entry);
            }
            encoder
        }
        OwnedV1Value::Array(values) => {
            encoder
                .array(values.len() as u64)
                .expect("Vec-backed CBOR encoding is infallible");
            for value in values {
                encode_owned_value(encoder, value);
            }
            encoder
        }
    };
}

fn encode_owned_value(encoder: &mut Encoder<&mut Vec<u8>>, value: &OwnedV1Value) {
    match value {
        OwnedV1Value::Bool(value) => encoder
            .bool(*value)
            .expect("Vec-backed CBOR encoding is infallible"),
        OwnedV1Value::U64(value) => encoder
            .u64(*value)
            .expect("Vec-backed CBOR encoding is infallible"),
        OwnedV1Value::Text(value) => encoder
            .str(value)
            .expect("Vec-backed CBOR encoding is infallible"),
        OwnedV1Value::Bytes(value) => encoder
            .bytes(value)
            .expect("Vec-backed CBOR encoding is infallible"),
        OwnedV1Value::Map(entries) => {
            encoder
                .map(entries.len() as u64)
                .expect("Vec-backed CBOR encoding is infallible");
            for entry in entries {
                encode_owned_entry(encoder, entry);
            }
            encoder
        }
        OwnedV1Value::Array(values) => {
            encoder
                .array(values.len() as u64)
                .expect("Vec-backed CBOR encoding is infallible");
            for value in values {
                encode_owned_value(encoder, value);
            }
            encoder
        }
    };
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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

    #[test]
    fn decodes_real_v1_string_keyed_request() {
        let bytes = [
            0xa2, 0x62, b'i', b'd', 0x61, b'1', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x64,
            b'p', b'i', b'n', b'g',
        ];

        let request = decode_request(&bytes).unwrap();

        assert_eq!(request.id, "1");
        assert_eq!(request.method, "ping");
        assert!(request.params.is_none());
    }

    #[test]
    fn preserves_raw_params_slice() {
        let bytes = [
            0xa3, 0x62, b'i', b'd', 0x61, b'1', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x64,
            b'p', b'i', b'n', b'g', 0x66, b'p', b'a', b'r', b'a', b'm', b's', 0xa1, 0x6b, b'n',
            b'o', b'n', b'b', b'l', b'o', b'c', b'k', b'i', b'n', b'g', 0xf5,
        ];

        let request = decode_request(&bytes).unwrap();

        assert_eq!(
            request.params.unwrap(),
            &[0xa1, 0x6b, b'n', b'o', b'n', b'b', b'l', b'o', b'c', b'k', b'i', b'n', b'g', 0xf5]
        );
        assert_eq!(
            request.params().unwrap().bool("nonblocking"),
            Ok(Some(true))
        );
    }

    #[test]
    fn reads_typed_params_fields() {
        let params = Params(&[
            0xa4, 0x65, b'e', b'p', b'o', b'c', b'h', 0x1a, 0x65, 0x53, 0xf1, 0x00, 0x67, b'n',
            b'e', b't', b'w', b'o', b'r', b'k', 0x67, b't', b'e', b's', b't', b'n', b'e', b't',
            0x66, b'b', b'i', b'n', b'a', b'r', b'y', 0x42, 0xab, 0xcd, 0x64, b'f', b'l', b'a',
            b'g', 0xf4,
        ]);

        assert_eq!(params.u64("epoch"), Ok(Some(1_700_000_000)));
        assert_eq!(params.str("network"), Ok(Some("testnet")));
        assert_eq!(params.bytes("binary"), Ok(Some(&[0xab, 0xcd][..])));
        assert_eq!(params.bool("flag"), Ok(Some(false)));
        assert_eq!(params.u64("missing"), Ok(None));
        assert_eq!(params.contains("epoch"), Ok(true));
        assert_eq!(params.contains("missing"), Ok(false));
    }

    #[test]
    fn reads_bounded_u32_path_arrays() {
        let params = Params(&[
            0xa1, 0x64, b'p', b'a', b't', b'h', 0x83, 0x1a, 0x80, 0x00, 0x00, 0x54, 0x1a, 0x80,
            0x00, 0x00, 0x00, 0x00,
        ]);

        assert_eq!(
            params.u32_array("path", 3),
            Ok(Some(vec![0x8000_0054, 0x8000_0000, 0]))
        );
        assert_eq!(
            params.u32_array("path", 2),
            Err(ValidationError::ArrayTooLong)
        );
    }

    #[test]
    fn rejects_trailing_data() {
        let bytes = [
            0xa2, 0x62, b'i', b'd', 0x61, b'1', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x64,
            b'p', b'i', b'n', b'g', 0x00,
        ];

        assert_eq!(decode_request(&bytes), Err(ValidationError::TrailingData));
    }

    #[test]
    fn decodes_unknown_method_for_adapter_error_parity() {
        let bytes = [
            0xa2, 0x62, b'i', b'd', 0x61, b'1', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x6c,
            b'n', b'o', b't', b'_', b'a', b'_', b'm', b'e', b't', b'h', b'o', b'd',
        ];

        let request = decode_request(&bytes).unwrap();

        assert_eq!(request.id, "1");
        assert_eq!(request.method, "not_a_method");
        assert!(method_spec(&request.method).is_none());
    }

    #[test]
    fn encodes_v1_error_shape() {
        let response = ErrorResponse {
            id: Cow::Borrowed("1"),
            code: ErrorCode::UnknownMethod as i32,
            message: Cow::Borrowed("Unknown method"),
        };

        assert_eq!(
            encode_error_response(&response),
            [
                0xa2, 0x62, b'i', b'd', 0x61, b'1', 0x65, b'e', b'r', b'r', b'o', b'r', 0xa2, 0x64,
                b'c', b'o', b'd', b'e', 0x39, 0x7f, 0x58, 0x67, b'm', b'e', b's', b's', b'a', b'g',
                b'e', 0x6e, b'U', b'n', b'k', b'n', b'o', b'w', b'n', b' ', b'm', b'e', b't', b'h',
                b'o', b'd',
            ]
        );
    }

    #[test]
    fn encodes_v1_ping_result_shape() {
        assert_eq!(
            encode_uint_result("1", 0),
            [0xa2, 0x62, b'i', b'd', 0x61, b'1', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0x00,]
        );
    }

    #[test]
    fn encodes_v1_bytes_result_shape() {
        assert_eq!(
            encode_bytes_result("b", &[1, 2, 3]),
            [
                0xa2, 0x62, b'i', b'd', 0x61, b'b', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0x43,
                1, 2, 3,
            ]
        );
    }

    #[test]
    fn encodes_v1_bytes_sequence_result_shape() {
        assert_eq!(
            encode_bytes_sequence_result("b", 2, 3, &[4, 5]),
            [
                0xa4, 0x62, b'i', b'd', 0x61, b'b', 0x66, b's', b'e', b'q', b'n', b'u', b'm', 0x02,
                0x66, b's', b'e', b'q', b'l', b'e', b'n', 0x03, 0x66, b'r', b'e', b's', b'u', b'l',
                b't', 0x42, 4, 5,
            ]
        );
    }

    #[test]
    fn encodes_v1_text_result_shape() {
        assert_eq!(
            encode_text_result("x", "xpub"),
            [
                0xa2, 0x62, b'i', b'd', 0x61, b'x', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0x64,
                b'x', b'p', b'u', b'b',
            ]
        );
    }

    #[test]
    fn encodes_v1_map_result_shape() {
        let encoded = encode_map_result(
            "v",
            &[
                ResultMapEntry {
                    key: "JADE_STATE",
                    value: V1Value::Text("UNINIT"),
                },
                ResultMapEntry {
                    key: "JADE_HAS_PIN",
                    value: V1Value::Bool(false),
                },
            ],
        );

        assert_eq!(
            encoded,
            [
                0xa2, 0x62, b'i', b'd', 0x61, b'v', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0xa2,
                0x6a, b'J', b'A', b'D', b'E', b'_', b'S', b'T', b'A', b'T', b'E', 0x66, b'U', b'N',
                b'I', b'N', b'I', b'T', 0x6c, b'J', b'A', b'D', b'E', b'_', b'H', b'A', b'S', b'_',
                b'P', b'I', b'N', 0xf4,
            ]
        );
    }

    #[test]
    fn encodes_owned_nested_map_results() {
        let encoded = encode_owned_map_result(
            "w",
            &[OwnedResultMapEntry {
                key: String::from("wallet-a"),
                value: OwnedV1Value::Map(vec![
                    OwnedResultMapEntry {
                        key: String::from("threshold"),
                        value: OwnedV1Value::U64(2),
                    },
                    OwnedResultMapEntry {
                        key: String::from("sorted"),
                        value: OwnedV1Value::Bool(true),
                    },
                ]),
            }],
        );

        let mut decoder = Decoder::new(&encoded);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "w");
        assert_eq!(decoder.str().unwrap(), "result");
        assert_eq!(decoder.map().unwrap(), Some(1));
        assert_eq!(decoder.str().unwrap(), "wallet-a");
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "threshold");
        assert_eq!(decoder.u64().unwrap(), 2);
        assert_eq!(decoder.str().unwrap(), "sorted");
        assert!(decoder.bool().unwrap());
    }

    #[test]
    fn encodes_owned_array_results() {
        let encoded = encode_owned_map_result(
            "w",
            &[OwnedResultMapEntry {
                key: String::from("signers"),
                value: OwnedV1Value::Array(vec![
                    OwnedV1Value::Map(vec![OwnedResultMapEntry {
                        key: String::from("path"),
                        value: OwnedV1Value::Array(vec![
                            OwnedV1Value::U64(1),
                            OwnedV1Value::U64(2),
                        ]),
                    }]),
                    OwnedV1Value::Map(vec![OwnedResultMapEntry {
                        key: String::from("path"),
                        value: OwnedV1Value::Array(vec![]),
                    }]),
                ]),
            }],
        );

        let mut decoder = Decoder::new(&encoded);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "w");
        assert_eq!(decoder.str().unwrap(), "result");
        assert_eq!(decoder.map().unwrap(), Some(1));
        assert_eq!(decoder.str().unwrap(), "signers");
        assert_eq!(decoder.array().unwrap(), Some(2));
        assert_eq!(decoder.map().unwrap(), Some(1));
        assert_eq!(decoder.str().unwrap(), "path");
        assert_eq!(decoder.array().unwrap(), Some(2));
        assert_eq!(decoder.u64().unwrap(), 1);
        assert_eq!(decoder.u64().unwrap(), 2);
        assert_eq!(decoder.map().unwrap(), Some(1));
        assert_eq!(decoder.str().unwrap(), "path");
        assert_eq!(decoder.array().unwrap(), Some(0));
    }
}
