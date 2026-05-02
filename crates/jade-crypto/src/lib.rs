#![no_std]

extern crate alloc;

use zeroize::Zeroize;

use sha2::Digest;

pub const SHA256_LEN: usize = 32;
pub const SHA512_LEN: usize = 64;
pub const EC_PRIVATE_KEY_LEN: usize = 32;
pub const EC_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
pub const OTP_MAX_NAME_LEN: usize = 16;
pub const OTP_MAX_URI_LEN: usize = 256;
pub const OTP_MAX_TOKEN_LEN: usize = 12;
pub const OTP_MAX_RECORDS: usize = 16;
pub const BITCOIN_MESSAGE_MAX_LEN: usize = 64 * 1024 - 64;

pub trait SecretKeyMaterial: Zeroize {
    fn expose_secret_bytes(&self) -> &[u8];
}

pub trait Secp256k1Backend {
    type Error;

    fn verify_public_key(&self, public_key: &[u8]) -> Result<(), Self::Error>;
    fn derive_public_key(
        &self,
        secret_key: &[u8],
    ) -> Result<[u8; EC_PUBLIC_KEY_COMPRESSED_LEN], Self::Error>;
    fn sign_ecdsa_low_r(
        &self,
        digest32: &[u8; SHA256_LEN],
        path: &[u32],
    ) -> Result<alloc::vec::Vec<u8>, Self::Error>;
    fn sign_bip340(
        &self,
        digest32: &[u8; SHA256_LEN],
        path: &[u32],
    ) -> Result<[u8; 64], Self::Error>;
}

pub trait P256Backend {
    type Error;

    fn sign_identity(
        &self,
        digest32: &[u8; SHA256_LEN],
        key_index: u32,
    ) -> Result<[u8; 65], Self::Error>;
    fn ecdh_identity(
        &self,
        peer_public_key: &[u8],
        key_index: u32,
    ) -> Result<[u8; SHA256_LEN], Self::Error>;
}

pub trait Bip85RsaCompatibility {
    type Error;

    fn derive_public_key_pem(
        &self,
        key_bits: usize,
        index: usize,
    ) -> Result<alloc::string::String, Self::Error>;
    fn sign_digest(
        &self,
        key_bits: usize,
        index: usize,
        digest: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindingFactorKind {
    Asset,
    Value,
    AssetAndValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindingFactorBytes {
    bytes: [u8; SHA256_LEN * 2],
    len: usize,
}

impl BlindingFactorBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpubPrefix {
    Main,
    Test,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Main,
    Test,
    Regtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidNetwork {
    Main,
    Test,
    Regtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinglesigScriptVariant {
    Pkh,
    Wpkh,
    ShWpkh,
    Tr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultisigScriptVariant {
    P2wsh,
    P2sh,
    P2wshP2sh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKeyType {
    Slip13,
    Slip17,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySignature {
    pub pubkey: [u8; 65],
    pub signature: [u8; 65],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip85EncryptedEntropy {
    pub pubkey: [u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
    pub encrypted: alloc::vec::Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Hotp { counter: u64 },
    Totp { period: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpUri<'a> {
    pub kind: OtpKind,
    pub algorithm: OtpAlgorithm,
    pub digits: u8,
    pub secret: &'a str,
    pub label: &'a str,
    pub issuer: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    InvalidUri,
    InvalidSecret,
    TokenTooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtEnvelope {
    Bitcoin,
    Liquid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtScanError {
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtSignError {
    Invalid,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxSignError {
    Invalid,
    Unsupported,
}

pub fn psbt_envelope(bytes: &[u8]) -> Option<PsbtEnvelope> {
    if bytes.starts_with(b"psbt\xff") {
        Some(PsbtEnvelope::Bitcoin)
    } else if bytes.starts_with(b"pset\xff") {
        Some(PsbtEnvelope::Liquid)
    } else {
        None
    }
}

pub fn psbt_needs_wallet_signature(
    bytes: &[u8],
    wallet_fingerprint: &[u8; 4],
) -> Result<bool, PsbtScanError> {
    let envelope = psbt_envelope(bytes).ok_or(PsbtScanError::Invalid)?;
    let mut pos = 5;
    let counts = scan_psbt_global_map(bytes, &mut pos, envelope)?;
    let input_count = counts.input_count.ok_or(PsbtScanError::Invalid)?;
    let output_count = counts.output_count.ok_or(PsbtScanError::Invalid)?;

    for _ in 0..input_count {
        if scan_psbt_input_map(bytes, &mut pos, wallet_fingerprint)? {
            return Ok(true);
        }
    }
    for _ in 0..output_count {
        skip_psbt_map(bytes, &mut pos)?;
    }

    if pos == bytes.len() {
        Ok(false)
    } else {
        Err(PsbtScanError::Invalid)
    }
}

#[derive(Default)]
struct PsbtCounts {
    input_count: Option<usize>,
    output_count: Option<usize>,
}

fn scan_psbt_global_map(
    bytes: &[u8],
    pos: &mut usize,
    envelope: PsbtEnvelope,
) -> Result<PsbtCounts, PsbtScanError> {
    let mut counts = PsbtCounts::default();

    loop {
        let key = read_psbt_key(bytes, pos)?;
        if key.is_empty() {
            return Ok(counts);
        }
        let value = read_psbt_value(bytes, pos)?;
        match key[0] {
            0x00 if envelope == PsbtEnvelope::Bitcoin => {
                if let Some((inputs, outputs)) = bitcoin_tx_counts(value) {
                    counts.input_count = Some(inputs);
                    counts.output_count = Some(outputs);
                } else {
                    return Err(PsbtScanError::Invalid);
                }
            }
            0x04 => {
                counts.input_count = Some(read_single_compact_size_value(value)?);
            }
            0x05 => {
                counts.output_count = Some(read_single_compact_size_value(value)?);
            }
            _ => {}
        }
    }
}

fn scan_psbt_input_map(
    bytes: &[u8],
    pos: &mut usize,
    wallet_fingerprint: &[u8; 4],
) -> Result<bool, PsbtScanError> {
    let mut signed_pubkeys: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::new();
    let mut wallet_pubkeys: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::new();

    loop {
        let key = read_psbt_key(bytes, pos)?;
        if key.is_empty() {
            return Ok(wallet_pubkeys
                .iter()
                .any(|pubkey| !signed_pubkeys.iter().any(|signed| signed == pubkey)));
        }
        let value = read_psbt_value(bytes, pos)?;
        match key[0] {
            // PSBT_IN_PARTIAL_SIG. Key data is the signed public key.
            0x02 => signed_pubkeys.push(&key[1..]),
            // PSBT_IN_BIP32_DERIVATION. Value starts with the 4-byte master fingerprint.
            0x06 if value.get(..4) == Some(wallet_fingerprint) => {
                wallet_pubkeys.push(&key[1..]);
            }
            // PSBT_IN_TAP_BIP32_DERIVATION. Taproot signing is a separate milestone,
            // so any matching taproot derivation must stay on the explicit signing path.
            0x16 if tap_derivation_matches_fingerprint(value, wallet_fingerprint) => {
                return Ok(true);
            }
            _ => {}
        }
    }
}

fn skip_psbt_map(bytes: &[u8], pos: &mut usize) -> Result<(), PsbtScanError> {
    loop {
        let key = read_psbt_key(bytes, pos)?;
        if key.is_empty() {
            return Ok(());
        }
        let _ = read_psbt_value(bytes, pos)?;
    }
}

fn read_psbt_key<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], PsbtScanError> {
    let len = read_compact_size(bytes, pos)?;
    read_exact(bytes, pos, len)
}

fn read_psbt_value<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], PsbtScanError> {
    let len = read_compact_size(bytes, pos)?;
    read_exact(bytes, pos, len)
}

fn read_single_compact_size_value(value: &[u8]) -> Result<usize, PsbtScanError> {
    let mut pos = 0;
    let parsed = read_compact_size(value, &mut pos)?;
    if pos == value.len() {
        Ok(parsed)
    } else {
        Err(PsbtScanError::Invalid)
    }
}

fn read_compact_size(bytes: &[u8], pos: &mut usize) -> Result<usize, PsbtScanError> {
    let tag = *read_exact(bytes, pos, 1)?
        .first()
        .ok_or(PsbtScanError::Invalid)?;
    match tag {
        0x00..=0xfc => Ok(tag as usize),
        0xfd => {
            let raw = read_exact(bytes, pos, 2)?;
            Ok(u16::from_le_bytes(raw.try_into().expect("fixed compact size")) as usize)
        }
        0xfe => {
            let raw = read_exact(bytes, pos, 4)?;
            Ok(u32::from_le_bytes(raw.try_into().expect("fixed compact size")) as usize)
        }
        0xff => {
            let raw = read_exact(bytes, pos, 8)?;
            let value = u64::from_le_bytes(raw.try_into().expect("fixed compact size"));
            value.try_into().map_err(|_| PsbtScanError::Invalid)
        }
    }
}

fn read_exact<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], PsbtScanError> {
    let end = pos.checked_add(len).ok_or(PsbtScanError::Invalid)?;
    if end > bytes.len() {
        return Err(PsbtScanError::Invalid);
    }
    let value = &bytes[*pos..end];
    *pos = end;
    Ok(value)
}

fn bitcoin_tx_counts(tx: &[u8]) -> Option<(usize, usize)> {
    let mut pos = 0;
    read_exact_opt(tx, &mut pos, 4)?;
    let input_count = read_compact_size_opt(tx, &mut pos)?;
    for _ in 0..input_count {
        read_exact_opt(tx, &mut pos, 36)?;
        let script_len = read_compact_size_opt(tx, &mut pos)?;
        read_exact_opt(tx, &mut pos, script_len)?;
        read_exact_opt(tx, &mut pos, 4)?;
    }
    let output_count = read_compact_size_opt(tx, &mut pos)?;
    for _ in 0..output_count {
        read_exact_opt(tx, &mut pos, 8)?;
        let script_len = read_compact_size_opt(tx, &mut pos)?;
        read_exact_opt(tx, &mut pos, script_len)?;
    }
    read_exact_opt(tx, &mut pos, 4)?;
    (pos == tx.len()).then_some((input_count, output_count))
}

fn read_compact_size_opt(bytes: &[u8], pos: &mut usize) -> Option<usize> {
    read_compact_size(bytes, pos).ok()
}

fn read_exact_opt<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Option<&'a [u8]> {
    read_exact(bytes, pos, len).ok()
}

fn tap_derivation_matches_fingerprint(value: &[u8], wallet_fingerprint: &[u8; 4]) -> bool {
    let mut pos = 0;
    let Some(leaf_hashes) = read_compact_size_opt(value, &mut pos) else {
        return false;
    };
    let Some(skip_len) = leaf_hashes.checked_mul(SHA256_LEN) else {
        return false;
    };
    if read_exact_opt(value, &mut pos, skip_len).is_none() {
        return false;
    }
    value.get(pos..pos + 4) == Some(wallet_fingerprint)
}

impl<'a> OtpUri<'a> {
    pub fn parse(uri: &'a str) -> Result<Self, OtpError> {
        const PREFIX: &str = "otpauth://";

        if uri.len() >= OTP_MAX_URI_LEN
            || !uri.starts_with(PREFIX)
            || uri.as_bytes().contains(&b'#')
        {
            return Err(OtpError::InvalidUri);
        }

        let rest = &uri[PREFIX.len()..];
        let (kind_str, rest) = split_once(rest, b'/').ok_or(OtpError::InvalidUri)?;
        let (label, query) = split_once(rest, b'?').ok_or(OtpError::InvalidUri)?;
        if query.is_empty() {
            return Err(OtpError::InvalidUri);
        }

        let secret = query_arg(query, "secret").ok_or(OtpError::InvalidUri)?;
        if secret.is_empty() {
            return Err(OtpError::InvalidUri);
        }

        let digits = match query_arg(query, "digits") {
            Some(value) if value.len() == 1 => match value.as_bytes()[0] {
                b'6' => 6,
                b'8' => 8,
                _ => return Err(OtpError::InvalidUri),
            },
            Some(_) => return Err(OtpError::InvalidUri),
            None => 6,
        };

        let algorithm = match query_arg(query, "algorithm") {
            Some("SHA1") | None => OtpAlgorithm::Sha1,
            Some("SHA256") => OtpAlgorithm::Sha256,
            Some("SHA512") => OtpAlgorithm::Sha512,
            Some(_) => return Err(OtpError::InvalidUri),
        };

        let kind = match kind_str {
            "hotp" => {
                let counter = query_arg(query, "counter")
                    .and_then(parse_decimal_u64)
                    .ok_or(OtpError::InvalidUri)?;
                OtpKind::Hotp { counter }
            }
            "totp" => {
                let period = match query_arg(query, "period") {
                    Some(value) => {
                        let value = parse_decimal_u64(value).ok_or(OtpError::InvalidUri)?;
                        if value == 0 || value > u8::MAX as u64 {
                            return Err(OtpError::InvalidUri);
                        }
                        value as u8
                    }
                    None => 30,
                };
                OtpKind::Totp { period }
            }
            _ => return Err(OtpError::InvalidUri),
        };

        let parsed = Self {
            kind,
            algorithm,
            digits,
            secret,
            label,
            issuer: query_arg(query, "issuer"),
        };
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn initial_hotp_counter(&self) -> Option<u64> {
        match self.kind {
            OtpKind::Hotp { counter } => Some(counter),
            OtpKind::Totp { .. } => None,
        }
    }

    pub fn counter_for_value(&self, value: u64) -> u64 {
        match self.kind {
            OtpKind::Hotp { .. } => value,
            OtpKind::Totp { period } => value / period as u64,
        }
    }

    pub fn auth_code(&self, value: u64) -> Result<alloc::string::String, OtpError> {
        let counter = self.counter_for_value(value);
        let secret = base32_to_bytes(self.secret)?;
        let hmac = match self.algorithm {
            OtpAlgorithm::Sha1 => hmac_sha1(&secret, counter),
            OtpAlgorithm::Sha256 => {
                let padded = padded_secret(secret, 32)?;
                hmac_sha256(&padded, counter)
            }
            OtpAlgorithm::Sha512 => {
                let padded = padded_secret(secret, 64)?;
                hmac_sha512(&padded, counter)
            }
        };

        let code = truncate_otp(&hmac, self.digits)?;
        Ok(format_otp_code(code, self.digits))
    }

    fn validate(&self) -> Result<(), OtpError> {
        if self.secret.is_empty()
            || !matches!(self.kind, OtpKind::Hotp { .. } | OtpKind::Totp { .. })
            || !matches!(self.digits, 6 | 8)
        {
            return Err(OtpError::InvalidUri);
        }
        if matches!(self.kind, OtpKind::Totp { period: 0 }) {
            return Err(OtpError::InvalidUri);
        }
        Ok(())
    }
}

fn split_once(value: &str, byte: u8) -> Option<(&str, &str)> {
    let index = value.as_bytes().iter().position(|item| *item == byte)?;
    Some((&value[..index], &value[index + 1..]))
}

fn query_arg<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for field in query.split('&') {
        let (candidate, value) = split_once(field, b'=')?;
        if candidate.eq_ignore_ascii_case(key) {
            return Some(value);
        }
    }
    None
}

fn parse_decimal_u64(value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }

    value.bytes().try_fold(0u64, |acc, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        acc.checked_mul(10)?.checked_add((byte - b'0') as u64)
    })
}

fn base32_to_bytes(value: &str) -> Result<alloc::vec::Vec<u8>, OtpError> {
    if value.is_empty() {
        return Err(OtpError::InvalidSecret);
    }

    let mut out = alloc::vec::Vec::with_capacity(value.len() * 5 / 8);
    let mut tmp = 0u32;
    let mut num_bits = 0u8;
    for byte in value.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            b'=' => break,
            _ => return Err(OtpError::InvalidSecret),
        } as u32;

        tmp = (tmp << 5) | value;
        num_bits += 5;
        if num_bits >= 8 {
            num_bits -= 8;
            out.push((tmp >> num_bits) as u8);
        }
    }

    if out.is_empty() {
        return Err(OtpError::InvalidSecret);
    }
    Ok(out)
}

fn padded_secret(
    mut secret: alloc::vec::Vec<u8>,
    min_size: usize,
) -> Result<alloc::vec::Vec<u8>, OtpError> {
    if secret.is_empty() {
        return Err(OtpError::InvalidSecret);
    }

    let original_len = secret.len();
    while secret.len() < min_size {
        let copy_len = core::cmp::min(min_size - secret.len(), original_len);
        for index in 0..copy_len {
            secret.push(secret[index]);
        }
    }
    Ok(secret)
}

fn hmac_sha1(secret: &[u8], counter: u64) -> alloc::vec::Vec<u8> {
    type HmacSha1 = hmac::Hmac<sha1::Sha1>;

    let mut mac = <HmacSha1 as hmac::digest::KeyInit>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    hmac::Mac::update(&mut mac, &counter.to_be_bytes());
    hmac::Mac::finalize(mac).into_bytes().to_vec()
}

fn hmac_sha256(secret: &[u8], counter: u64) -> alloc::vec::Vec<u8> {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    hmac::Mac::update(&mut mac, &counter.to_be_bytes());
    hmac::Mac::finalize(mac).into_bytes().to_vec()
}

fn hmac_sha512(secret: &[u8], counter: u64) -> alloc::vec::Vec<u8> {
    type HmacSha512 = hmac::Hmac<sha2::Sha512>;

    let mut mac = <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    hmac::Mac::update(&mut mac, &counter.to_be_bytes());
    hmac::Mac::finalize(mac).into_bytes().to_vec()
}

fn truncate_otp(hmac: &[u8], digits: u8) -> Result<u32, OtpError> {
    if hmac.is_empty() {
        return Err(OtpError::InvalidSecret);
    }
    let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
    if offset + 4 > hmac.len() {
        return Err(OtpError::InvalidSecret);
    }

    let full_code = ((hmac[offset] as u32 & 0x7f) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | hmac[offset + 3] as u32;
    let modulo = match digits {
        6 => 1_000_000,
        8 => 100_000_000,
        _ => return Err(OtpError::TokenTooLong),
    };
    Ok(full_code % modulo)
}

fn format_otp_code(code: u32, digits: u8) -> alloc::string::String {
    use alloc::format;

    match digits {
        6 => format!("{code:06}"),
        8 => format!("{code:08}"),
        _ => format!("{code}"),
    }
}

pub fn bitcoin_message_hash(message: &[u8]) -> Option<[u8; SHA256_LEN]> {
    if message.is_empty() || message.len() > BITCOIN_MESSAGE_MAX_LEN {
        return None;
    }

    let varint_len = if message.len() < 0xfd { 1 } else { 3 };
    let mut formatted = alloc::vec::Vec::with_capacity(25 + varint_len + message.len());
    formatted.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
    if message.len() < 0xfd {
        formatted.push(message.len() as u8);
    } else {
        formatted.push(0xfd);
        formatted.push((message.len() & 0xff) as u8);
        formatted.push((message.len() >> 8) as u8);
    }
    formatted.extend_from_slice(message);

    let first = sha2::Sha256::digest(&formatted);
    sha2::Sha256::digest(first).as_slice().try_into().ok()
}

fn base64_encode(bytes: &[u8]) -> alloc::string::String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = alloc::string::String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn slip77_master_unblinding_key_from_seed(seed: &[u8]) -> Option<[u8; SHA512_LEN]> {
    if !matches!(seed.len(), 16 | 32 | 64) {
        return None;
    }

    type HmacSha512 = hmac::Hmac<sha2::Sha512>;

    let mut root_mac =
        <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(b"Symmetric key seed").ok()?;
    hmac::Mac::update(&mut root_mac, seed);
    let root = hmac::Mac::finalize(root_mac).into_bytes();

    let mut child_mac =
        <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(&root[..SHA512_LEN / 2]).ok()?;
    hmac::Mac::update(&mut child_mac, b"\x00SLIP-0077");
    hmac::Mac::finalize(child_mac)
        .into_bytes()
        .as_slice()
        .try_into()
        .ok()
}

#[cfg(feature = "pure-rust-curves")]
pub mod pure_rust {
    use super::{
        Bip85EncryptedEntropy, BitcoinNetwork, BlindingFactorBytes, BlindingFactorKind,
        IdentityKeyType, LiquidNetwork, MultisigScriptVariant, PsbtEnvelope, PsbtSignError,
        SinglesigScriptVariant, TxSignError, XpubPrefix, EC_PRIVATE_KEY_LEN,
        EC_PUBLIC_KEY_COMPRESSED_LEN, SHA256_LEN, SHA512_LEN,
    };
    use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
    use aes::{Aes256, Block};
    use alloc::string::String;
    use alloc::vec::Vec;
    use bech32::{ByteIterExt, Fe32IterExt};
    use hmac::{Hmac, KeyInit, Mac};
    pub use k256;
    use k256::ecdsa::hazmat::{bits2field, SignPrimitive};
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey as K256SigningKey;
    use k256::elliptic_curve::{bigint::U256, ops::Reduce, sec1::ToEncodedPoint};
    use k256::schnorr::SigningKey as K256SchnorrSigningKey;
    use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey};
    pub use p256;
    use p256::{
        ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey},
        FieldBytes as P256FieldBytes, ProjectivePoint as P256ProjectivePoint,
        PublicKey as P256PublicKey, Scalar as P256Scalar, SecretKey as P256SecretKey,
    };
    use sha2::{Digest, Sha256, Sha512};

    type HmacSha256 = Hmac<Sha256>;
    type HmacSha512 = Hmac<Sha512>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BitcoinTxSignInput<'a> {
        pub tx_input_index: usize,
        pub path: &'a [u32],
        pub script_code: &'a [u8],
        pub sighash: u32,
        pub is_witness: bool,
        pub satoshi: Option<u64>,
    }

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum Blech32 {}

    impl bech32::Checksum for Blech32 {
        type MidstateRepr = u64;
        const CHECKSUM_LENGTH: usize = 12;
        const GENERATOR_SH: [u64; 5] = [
            0x7d52fba40bd886,
            0x5e8dbf1a03950c,
            0x1c3a3c74072a18,
            0x385d72fa0e5139,
            0x7093e5a608865b,
        ];
        const TARGET_RESIDUE: u64 = 1;
        const CODE_LENGTH: usize = 1024;
    }

    pub fn sign_bitcoin_message_from_seed(
        seed: &[u8],
        path: &[u32],
        message: &[u8],
    ) -> Option<String> {
        if path.is_empty() {
            return None;
        }

        let message_hash = super::bitcoin_message_hash(message)?;
        let mut derivation_path = bip32::DerivationPath::default();
        for value in path {
            let hardened = value & bip32::ChildNumber::HARDENED_FLAG != 0;
            let child =
                bip32::ChildNumber::new(value & !bip32::ChildNumber::HARDENED_FLAG, hardened)
                    .ok()?;
            derivation_path.push(child);
        }
        let private_key = bip32::XPrv::derive_from_path(seed, &derivation_path).ok()?;
        let signing_key = K256SigningKey::from_slice(private_key.to_bytes().as_ref()).ok()?;
        let (signature, recid) = signing_key.sign_prehash_recoverable(&message_hash).ok()?;

        let mut recoverable = [0u8; 65];
        recoverable[0] = 27 + recid.to_byte() + 4;
        recoverable[1..].copy_from_slice(signature.to_bytes().as_ref());
        Some(super::base64_encode(&recoverable))
    }

    pub fn sign_bitcoin_psbt_singlesig_from_seed(
        psbt: &[u8],
        seed: &[u8],
        wallet_fingerprint: &[u8; 4],
    ) -> Result<Option<Vec<u8>>, PsbtSignError> {
        if super::psbt_envelope(psbt) != Some(PsbtEnvelope::Bitcoin) {
            return Err(PsbtSignError::Invalid);
        }

        let mut pos = 5;
        let global = parsed_psbt_map(psbt, &mut pos)?;
        let unsigned_tx_view = global
            .single_value(0x00)
            .map(|tx| bitcoin_unsigned_tx_view(tx).ok_or(PsbtSignError::Invalid))
            .transpose()?;
        let (tx_version, lock_time, input_count, output_count) =
            if let Some(view) = &unsigned_tx_view {
                (
                    view.version,
                    view.lock_time,
                    view.inputs.len(),
                    view.outputs.len(),
                )
            } else {
                let tx_version = global
                    .single_value(0x02)
                    .and_then(le_u32)
                    .ok_or(PsbtSignError::Unsupported)?;
                let lock_time = global.single_value(0x03).and_then(le_u32).unwrap_or(0);
                let input_count = global
                    .single_value(0x04)
                    .and_then(compact_size_value)
                    .ok_or(PsbtSignError::Unsupported)?;
                let output_count = global
                    .single_value(0x05)
                    .and_then(compact_size_value)
                    .ok_or(PsbtSignError::Unsupported)?;
                (tx_version, lock_time, input_count, output_count)
            };

        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(parsed_psbt_map(psbt, &mut pos)?);
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(parsed_psbt_map(psbt, &mut pos)?);
        }
        if pos != psbt.len() {
            return Err(PsbtSignError::Invalid);
        }

        let mut tx_outputs = Vec::with_capacity(outputs.len());
        if let Some(view) = &unsigned_tx_view {
            tx_outputs.extend_from_slice(&view.outputs);
        } else {
            for output in &outputs {
                let amount = output
                    .single_value(0x03)
                    .and_then(le_u64)
                    .ok_or(PsbtSignError::Unsupported)?;
                let script = output
                    .single_value(0x04)
                    .ok_or(PsbtSignError::Unsupported)?;
                tx_outputs.push(TxOutputView { amount, script });
            }
        }

        let mut tx_inputs = Vec::with_capacity(inputs.len());
        let mut prev_outputs = Vec::with_capacity(inputs.len());
        if let Some(view) = &unsigned_tx_view {
            tx_inputs.extend_from_slice(&view.inputs);
            for (input, tx_input) in inputs.iter().zip(&view.inputs) {
                let prev_tx = input.single_value(0x00);
                if let Some(prev_tx) = prev_tx {
                    if bitcoin_transaction_txid(prev_tx).as_ref() != Some(tx_input.prev_txid) {
                        return Err(PsbtSignError::Invalid);
                    }
                }
                let prev_output = previous_output(input, prev_tx, tx_input.prev_vout as usize)
                    .ok_or(PsbtSignError::Invalid)?;
                prev_outputs.push(prev_output);
            }
        } else {
            for input in &inputs {
                let prev_tx = input.single_value(0x00);
                let prev_txid = input
                    .single_value(0x0e)
                    .and_then(|value| <&[u8; SHA256_LEN]>::try_from(value).ok())
                    .ok_or(PsbtSignError::Unsupported)?;
                let prev_vout = input
                    .single_value(0x0f)
                    .and_then(le_u32)
                    .ok_or(PsbtSignError::Unsupported)?;
                let sequence = input
                    .single_value(0x10)
                    .and_then(le_u32)
                    .unwrap_or(u32::MAX);
                if let Some(prev_tx) = prev_tx {
                    if bitcoin_transaction_txid(prev_tx).as_ref() != Some(prev_txid) {
                        return Err(PsbtSignError::Invalid);
                    }
                }
                let prev_output = previous_output(input, prev_tx, prev_vout as usize)
                    .ok_or(PsbtSignError::Invalid)?;
                tx_inputs.push(TxInputView {
                    prev_txid,
                    prev_vout,
                    sequence,
                });
                prev_outputs.push(prev_output);
            }
        }

        let sighash_tx = SighashTx {
            version: tx_version,
            lock_time,
            inputs: &tx_inputs,
            outputs: &tx_outputs,
        };
        let mut signatures = Vec::new();
        for (index, input) in inputs.iter().enumerate() {
            let explicit_sighash = input.single_value(0x03).and_then(le_u32);
            let prev_output = prev_outputs[index];

            let mut signed_pubkeys = Vec::new();
            let mut wallet_candidates = Vec::new();
            let mut tap_key_signed = false;
            let mut tap_candidates = Vec::new();
            for entry in &input.entries {
                match entry.key.first().copied() {
                    Some(0x13) if entry.key.len() == 1 => tap_key_signed = true,
                    Some(0x02) => signed_pubkeys.push(&entry.key[1..]),
                    Some(0x06)
                        if entry.value.get(..4) == Some(wallet_fingerprint)
                            && compressed_pubkey_len(&entry.key[1..]) =>
                    {
                        wallet_candidates.push((&entry.key[1..], &entry.value[4..]));
                    }
                    Some(0x16)
                        if entry.key.len() == 1 + SHA256_LEN
                            && super::tap_derivation_matches_fingerprint(
                                entry.value,
                                wallet_fingerprint,
                            ) =>
                    {
                        tap_candidates.push((&entry.key[1..], entry.value));
                    }
                    _ => {}
                }
            }

            for (pubkey, path_bytes) in wallet_candidates {
                if signed_pubkeys.iter().any(|signed| signed == &pubkey) {
                    continue;
                }
                let path = parse_psbt_derivation_path(path_bytes)?;
                let derived_pubkey =
                    public_key_from_seed_path(seed, &path).ok_or(PsbtSignError::Unsupported)?;
                if derived_pubkey.as_slice() != pubkey {
                    continue;
                }
                let sighash = explicit_sighash.unwrap_or(1);
                if sighash != 1 {
                    return Err(PsbtSignError::Unsupported);
                }
                let digest = singlesig_sighash(input, pubkey, prev_output, &sighash_tx, index)?;
                let signature = sign_digest_der_from_seed(seed, &path, &digest, sighash as u8)
                    .ok_or(PsbtSignError::Unsupported)?;
                signatures.push(PsbtSignature {
                    input_index: index,
                    key: psbt_key_with_data(0x02, pubkey),
                    signature,
                });
            }

            if !tap_key_signed {
                for (xonly_pubkey, derivation_value) in tap_candidates {
                    let path = parse_tap_derivation_path(derivation_value, wallet_fingerprint)?;
                    let derived_pubkey =
                        public_key_from_seed_path(seed, &path).ok_or(PsbtSignError::Unsupported)?;
                    if &derived_pubkey[1..] != xonly_pubkey {
                        continue;
                    }
                    let output_key = taproot_keyspend_output_key(&derived_pubkey)
                        .ok_or(PsbtSignError::Unsupported)?;
                    if p2tr_script_pubkey(&output_key) != prev_output.script {
                        return Err(PsbtSignError::Unsupported);
                    }
                    let sighash = explicit_sighash.unwrap_or(0);
                    if !matches!(sighash, 0 | 1) {
                        return Err(PsbtSignError::Unsupported);
                    }
                    let digest =
                        taproot_key_spend_sighash(&sighash_tx, &prev_outputs, index, sighash as u8);
                    let signature =
                        sign_taproot_key_spend_from_seed(seed, &path, &digest, sighash as u8)
                            .ok_or(PsbtSignError::Unsupported)?;
                    signatures.push(PsbtSignature {
                        input_index: index,
                        key: alloc::vec![0x13],
                        signature,
                    });
                }
            }
        }

        if signatures.is_empty() {
            return Ok(None);
        }

        Ok(Some(insert_psbt_partial_signatures(
            psbt,
            &inputs,
            &signatures,
        )?))
    }

    pub fn bitcoin_tx_input_count(txn: &[u8]) -> Result<usize, TxSignError> {
        bitcoin_transaction_view(txn)
            .map(|tx| tx.inputs.len())
            .ok_or(TxSignError::Invalid)
    }

    pub fn bitcoin_prevout_amount(
        txn: &[u8],
        tx_input_index: usize,
        input_tx: &[u8],
    ) -> Result<u64, TxSignError> {
        let tx = bitcoin_transaction_view(txn).ok_or(TxSignError::Invalid)?;
        let input = tx.inputs.get(tx_input_index).ok_or(TxSignError::Invalid)?;
        let input_txid = bitcoin_transaction_txid(input_tx).ok_or(TxSignError::Invalid)?;
        if &input_txid != input.prev_txid {
            return Err(TxSignError::Invalid);
        }
        let prev_output =
            bitcoin_tx_output(input_tx, input.prev_vout as usize).ok_or(TxSignError::Invalid)?;
        Ok(prev_output.amount)
    }

    pub fn sign_bitcoin_tx_from_seed(
        txn: &[u8],
        seed: &[u8],
        signing_inputs: &[BitcoinTxSignInput<'_>],
    ) -> Result<Vec<Vec<u8>>, TxSignError> {
        let tx = bitcoin_transaction_view(txn).ok_or(TxSignError::Invalid)?;
        let sighash_tx = SighashTx {
            version: tx.version,
            lock_time: tx.lock_time,
            inputs: &tx.inputs,
            outputs: &tx.outputs,
        };
        let prev_outputs = if signing_inputs
            .iter()
            .any(|input| input.sighash == 0 || is_p2tr_script_pubkey(input.script_code))
        {
            Some(taproot_prev_outputs(&sighash_tx, signing_inputs)?)
        } else {
            None
        };
        let mut signatures = Vec::with_capacity(signing_inputs.len());
        for signing_input in signing_inputs {
            if signing_input.path.is_empty()
                || signing_input.script_code.is_empty()
                || signing_input.tx_input_index >= sighash_tx.inputs.len()
            {
                return Err(TxSignError::Invalid);
            }

            if is_p2tr_script_pubkey(signing_input.script_code) {
                if !matches!(signing_input.sighash, 0 | 1) {
                    return Err(TxSignError::Unsupported);
                }
                let public_key = public_key_from_seed_path(seed, signing_input.path)
                    .ok_or(TxSignError::Unsupported)?;
                let output_key =
                    taproot_keyspend_output_key(&public_key).ok_or(TxSignError::Unsupported)?;
                if p2tr_script_pubkey(&output_key) != signing_input.script_code {
                    return Err(TxSignError::Unsupported);
                }
                let digest = taproot_key_spend_sighash(
                    &sighash_tx,
                    prev_outputs.as_deref().ok_or(TxSignError::Invalid)?,
                    signing_input.tx_input_index,
                    signing_input.sighash as u8,
                );
                let signature = sign_taproot_key_spend_from_seed(
                    seed,
                    signing_input.path,
                    &digest,
                    signing_input.sighash as u8,
                )
                .ok_or(TxSignError::Unsupported)?;
                signatures.push(signature);
                continue;
            }

            if signing_input.sighash != 1 {
                return Err(TxSignError::Unsupported);
            }
            let digest = if signing_input.is_witness {
                let amount = signing_input.satoshi.ok_or(TxSignError::Invalid)?;
                segwit_v0_sighash_all(
                    sighash_tx.version,
                    sighash_tx.lock_time,
                    sighash_tx.inputs,
                    sighash_tx.outputs,
                    signing_input.tx_input_index,
                    signing_input.script_code,
                    amount,
                )
            } else {
                legacy_sighash_all(
                    sighash_tx.version,
                    sighash_tx.lock_time,
                    sighash_tx.inputs,
                    sighash_tx.outputs,
                    signing_input.tx_input_index,
                    signing_input.script_code,
                )
            };
            let signature = sign_digest_der_from_seed(
                seed,
                signing_input.path,
                &digest,
                signing_input.sighash as u8,
            )
            .ok_or(TxSignError::Unsupported)?;
            signatures.push(signature);
        }

        Ok(signatures)
    }

    fn taproot_prev_outputs<'a>(
        tx: &SighashTx<'_, '_>,
        signing_inputs: &'a [BitcoinTxSignInput<'a>],
    ) -> Result<Vec<TxOutputView<'a>>, TxSignError> {
        if signing_inputs.len() != tx.inputs.len() {
            return Err(TxSignError::Unsupported);
        }
        let mut prev_outputs = Vec::with_capacity(tx.inputs.len());
        for (index, signing_input) in signing_inputs.iter().enumerate() {
            if signing_input.tx_input_index != index
                || !is_p2tr_script_pubkey(signing_input.script_code)
            {
                return Err(TxSignError::Unsupported);
            }
            prev_outputs.push(TxOutputView {
                amount: signing_input.satoshi.ok_or(TxSignError::Invalid)?,
                script: signing_input.script_code,
            });
        }
        Ok(prev_outputs)
    }

    struct PsbtEntry<'a> {
        key: &'a [u8],
        value: &'a [u8],
        end: usize,
    }

    struct ParsedPsbtMap<'a> {
        entries: Vec<PsbtEntry<'a>>,
        content_start: usize,
        end: usize,
    }

    impl<'a> ParsedPsbtMap<'a> {
        fn single_value(&self, key_type: u8) -> Option<&'a [u8]> {
            self.entries
                .iter()
                .find(|entry| entry.key.len() == 1 && entry.key[0] == key_type)
                .map(|entry| entry.value)
        }
    }

    struct BitcoinTxView<'a> {
        version: u32,
        lock_time: u32,
        inputs: Vec<TxInputView<'a>>,
        outputs: Vec<TxOutputView<'a>>,
    }

    #[derive(Clone, Copy)]
    struct TxInputView<'a> {
        prev_txid: &'a [u8; SHA256_LEN],
        prev_vout: u32,
        sequence: u32,
    }

    #[derive(Clone, Copy)]
    struct TxOutputView<'a> {
        amount: u64,
        script: &'a [u8],
    }

    struct PsbtSignature {
        input_index: usize,
        key: Vec<u8>,
        signature: Vec<u8>,
    }

    struct SighashTx<'tx, 'data> {
        version: u32,
        lock_time: u32,
        inputs: &'tx [TxInputView<'data>],
        outputs: &'tx [TxOutputView<'data>],
    }

    fn parsed_psbt_map<'a>(
        bytes: &'a [u8],
        pos: &mut usize,
    ) -> Result<ParsedPsbtMap<'a>, PsbtSignError> {
        let content_start = *pos;
        let mut entries = Vec::new();
        loop {
            let key_len = read_compact_size_sign(bytes, pos)?;
            if key_len == 0 {
                return Ok(ParsedPsbtMap {
                    entries,
                    content_start,
                    end: *pos,
                });
            }
            let key = read_exact_sign(bytes, pos, key_len)?;
            if key.is_empty() {
                return Err(PsbtSignError::Invalid);
            }
            let value_len = read_compact_size_sign(bytes, pos)?;
            let value = read_exact_sign(bytes, pos, value_len)?;
            entries.push(PsbtEntry {
                key,
                value,
                end: *pos,
            });
        }
    }

    fn read_compact_size_sign(bytes: &[u8], pos: &mut usize) -> Result<usize, PsbtSignError> {
        super::read_compact_size(bytes, pos).map_err(|_| PsbtSignError::Invalid)
    }

    fn read_exact_sign<'a>(
        bytes: &'a [u8],
        pos: &mut usize,
        len: usize,
    ) -> Result<&'a [u8], PsbtSignError> {
        super::read_exact(bytes, pos, len).map_err(|_| PsbtSignError::Invalid)
    }

    fn compact_size_value(value: &[u8]) -> Option<usize> {
        let mut pos = 0;
        let parsed = read_compact_size_sign(value, &mut pos).ok()?;
        (pos == value.len()).then_some(parsed)
    }

    fn le_u32(value: &[u8]) -> Option<u32> {
        Some(u32::from_le_bytes(value.try_into().ok()?))
    }

    fn le_u64(value: &[u8]) -> Option<u64> {
        Some(u64::from_le_bytes(value.try_into().ok()?))
    }

    fn compressed_pubkey_len(value: &[u8]) -> bool {
        value.len() == EC_PUBLIC_KEY_COMPRESSED_LEN && matches!(value[0], 0x02 | 0x03)
    }

    fn parse_psbt_derivation_path(value: &[u8]) -> Result<Vec<u32>, PsbtSignError> {
        if value.len() % 4 != 0 {
            return Err(PsbtSignError::Invalid);
        }
        let mut path = Vec::with_capacity(value.len() / 4);
        for chunk in value.chunks_exact(4) {
            path.push(u32::from_le_bytes(
                chunk.try_into().expect("fixed path component"),
            ));
        }
        Ok(path)
    }

    fn parse_tap_derivation_path(
        value: &[u8],
        wallet_fingerprint: &[u8; 4],
    ) -> Result<Vec<u32>, PsbtSignError> {
        let mut pos = 0;
        let leaf_hash_count = read_compact_size_sign(value, &mut pos)?;
        let skip_len = leaf_hash_count
            .checked_mul(SHA256_LEN)
            .ok_or(PsbtSignError::Invalid)?;
        read_exact_sign(value, &mut pos, skip_len)?;
        if value.get(pos..pos + 4) != Some(wallet_fingerprint) {
            return Err(PsbtSignError::Unsupported);
        }
        pos += 4;
        parse_psbt_derivation_path(&value[pos..])
    }

    fn double_sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
        let first = Sha256::digest(bytes);
        Sha256::digest(first).into()
    }

    fn previous_output<'a>(
        input: &'a ParsedPsbtMap<'a>,
        prev_tx: Option<&'a [u8]>,
        output_index: usize,
    ) -> Option<TxOutputView<'a>> {
        input
            .single_value(0x01)
            .and_then(bitcoin_tx_output_from_bytes)
            .or_else(|| bitcoin_tx_output(prev_tx?, output_index))
    }

    fn bitcoin_tx_output_from_bytes(value: &[u8]) -> Option<TxOutputView<'_>> {
        let mut pos = 0;
        let amount = le_u64(super::read_exact_opt(value, &mut pos, 8)?)?;
        let script_len = super::read_compact_size_opt(value, &mut pos)?;
        let script = super::read_exact_opt(value, &mut pos, script_len)?;
        (pos == value.len()).then_some(TxOutputView { amount, script })
    }

    fn bitcoin_unsigned_tx_view(tx: &[u8]) -> Option<BitcoinTxView<'_>> {
        let mut pos = 0;
        let version = le_u32(super::read_exact_opt(tx, &mut pos, 4)?)?;
        let input_count = super::read_compact_size_opt(tx, &mut pos)?;
        if input_count == 0 {
            return None;
        }

        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let prev_txid =
                <&[u8; SHA256_LEN]>::try_from(super::read_exact_opt(tx, &mut pos, SHA256_LEN)?)
                    .ok()?;
            let prev_vout = le_u32(super::read_exact_opt(tx, &mut pos, 4)?)?;
            let script_len = super::read_compact_size_opt(tx, &mut pos)?;
            if script_len != 0 {
                return None;
            }
            super::read_exact_opt(tx, &mut pos, script_len)?;
            let sequence = le_u32(super::read_exact_opt(tx, &mut pos, 4)?)?;
            inputs.push(TxInputView {
                prev_txid,
                prev_vout,
                sequence,
            });
        }

        let output_count = super::read_compact_size_opt(tx, &mut pos)?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let amount = le_u64(super::read_exact_opt(tx, &mut pos, 8)?)?;
            let script_len = super::read_compact_size_opt(tx, &mut pos)?;
            let script = super::read_exact_opt(tx, &mut pos, script_len)?;
            outputs.push(TxOutputView { amount, script });
        }
        let lock_time = le_u32(super::read_exact_opt(tx, &mut pos, 4)?)?;

        (pos == tx.len()).then_some(BitcoinTxView {
            version,
            lock_time,
            inputs,
            outputs,
        })
    }

    fn bitcoin_transaction_view(tx: &[u8]) -> Option<BitcoinTxView<'_>> {
        let mut pos = 0;
        let version = le_u32(super::read_exact_opt(tx, &mut pos, 4)?)?;
        let has_witness = match tx.get(pos).copied() {
            Some(0) => {
                pos += 1;
                if super::read_exact_opt(tx, &mut pos, 1)? != [1] {
                    return None;
                }
                true
            }
            Some(_) => false,
            None => return None,
        };
        let input_count = super::read_compact_size_opt(tx, &mut pos)?;
        if input_count == 0 {
            return None;
        }

        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let prev_txid =
                <&[u8; SHA256_LEN]>::try_from(super::read_exact_opt(tx, &mut pos, SHA256_LEN)?)
                    .ok()?;
            let prev_vout = le_u32(super::read_exact_opt(tx, &mut pos, 4)?)?;
            let script_len = super::read_compact_size_opt(tx, &mut pos)?;
            super::read_exact_opt(tx, &mut pos, script_len)?;
            let sequence = le_u32(super::read_exact_opt(tx, &mut pos, 4)?)?;
            inputs.push(TxInputView {
                prev_txid,
                prev_vout,
                sequence,
            });
        }

        let output_count = super::read_compact_size_opt(tx, &mut pos)?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let amount = le_u64(super::read_exact_opt(tx, &mut pos, 8)?)?;
            let script_len = super::read_compact_size_opt(tx, &mut pos)?;
            let script = super::read_exact_opt(tx, &mut pos, script_len)?;
            outputs.push(TxOutputView { amount, script });
        }

        if has_witness {
            for _ in 0..input_count {
                let item_count = super::read_compact_size_opt(tx, &mut pos)?;
                for _ in 0..item_count {
                    let item_len = super::read_compact_size_opt(tx, &mut pos)?;
                    super::read_exact_opt(tx, &mut pos, item_len)?;
                }
            }
        }

        let lock_time = le_u32(super::read_exact_opt(tx, &mut pos, 4)?)?;
        (pos == tx.len()).then_some(BitcoinTxView {
            version,
            lock_time,
            inputs,
            outputs,
        })
    }

    fn bitcoin_transaction_txid(tx: &[u8]) -> Option<[u8; SHA256_LEN]> {
        let mut pos = 0;
        let mut stripped = Vec::new();
        stripped.extend_from_slice(super::read_exact_opt(tx, &mut pos, 4)?);
        let has_witness = match tx.get(pos).copied() {
            Some(0) => {
                pos += 1;
                if super::read_exact_opt(tx, &mut pos, 1)? != [1] {
                    return None;
                }
                true
            }
            Some(_) => false,
            None => return None,
        };

        let (input_count, input_count_bytes) = read_compact_size_with_bytes(tx, &mut pos)?;
        if input_count == 0 {
            return None;
        }
        stripped.extend_from_slice(input_count_bytes);
        for _ in 0..input_count {
            stripped.extend_from_slice(super::read_exact_opt(tx, &mut pos, 36)?);
            let (script_len, script_len_bytes) = read_compact_size_with_bytes(tx, &mut pos)?;
            stripped.extend_from_slice(script_len_bytes);
            stripped.extend_from_slice(super::read_exact_opt(tx, &mut pos, script_len)?);
            stripped.extend_from_slice(super::read_exact_opt(tx, &mut pos, 4)?);
        }

        let (output_count, output_count_bytes) = read_compact_size_with_bytes(tx, &mut pos)?;
        stripped.extend_from_slice(output_count_bytes);
        for _ in 0..output_count {
            stripped.extend_from_slice(super::read_exact_opt(tx, &mut pos, 8)?);
            let (script_len, script_len_bytes) = read_compact_size_with_bytes(tx, &mut pos)?;
            stripped.extend_from_slice(script_len_bytes);
            stripped.extend_from_slice(super::read_exact_opt(tx, &mut pos, script_len)?);
        }

        if has_witness {
            for _ in 0..input_count {
                let item_count = super::read_compact_size_opt(tx, &mut pos)?;
                for _ in 0..item_count {
                    let item_len = super::read_compact_size_opt(tx, &mut pos)?;
                    super::read_exact_opt(tx, &mut pos, item_len)?;
                }
            }
        }

        stripped.extend_from_slice(super::read_exact_opt(tx, &mut pos, 4)?);
        (pos == tx.len()).then(|| double_sha256(&stripped))
    }

    fn bitcoin_tx_output(tx: &[u8], output_index: usize) -> Option<TxOutputView<'_>> {
        bitcoin_transaction_view(tx)?
            .outputs
            .get(output_index)
            .copied()
    }

    fn read_compact_size_with_bytes<'a>(
        bytes: &'a [u8],
        pos: &mut usize,
    ) -> Option<(usize, &'a [u8])> {
        let start = *pos;
        let value = super::read_compact_size_opt(bytes, pos)?;
        Some((value, &bytes[start..*pos]))
    }

    fn singlesig_sighash(
        input: &ParsedPsbtMap<'_>,
        pubkey: &[u8],
        prev_output: TxOutputView<'_>,
        tx: &SighashTx<'_, '_>,
        signing_input: usize,
    ) -> Result<[u8; SHA256_LEN], PsbtSignError> {
        let pubkey_hash = hash160(pubkey);
        let p2pkh_script = p2pkh_script_pubkey(&pubkey_hash);
        if p2pkh_script == prev_output.script {
            return Ok(legacy_sighash_all(
                tx.version,
                tx.lock_time,
                tx.inputs,
                tx.outputs,
                signing_input,
                prev_output.script,
            ));
        }

        let witness_script = witness_v0_script_pubkey(&pubkey_hash);
        if witness_script == prev_output.script {
            return Ok(segwit_v0_sighash_all(
                tx.version,
                tx.lock_time,
                tx.inputs,
                tx.outputs,
                signing_input,
                &p2pkh_script,
                prev_output.amount,
            ));
        }

        if input.single_value(0x04) == Some(witness_script.as_slice())
            && p2sh_script_pubkey(&hash160(&witness_script)) == prev_output.script
        {
            return Ok(segwit_v0_sighash_all(
                tx.version,
                tx.lock_time,
                tx.inputs,
                tx.outputs,
                signing_input,
                &p2pkh_script,
                prev_output.amount,
            ));
        }

        if let Some(witness_script) = input.single_value(0x05) {
            if script_contains_pubkey(witness_script, pubkey) {
                let witness_script_hash = Sha256::digest(witness_script);
                let witness_program = witness_v0_script_pubkey(witness_script_hash.as_ref());
                if witness_program == prev_output.script
                    || (input.single_value(0x04) == Some(witness_program.as_slice())
                        && p2sh_script_pubkey(&hash160(&witness_program)) == prev_output.script)
                {
                    return Ok(segwit_v0_sighash_all(
                        tx.version,
                        tx.lock_time,
                        tx.inputs,
                        tx.outputs,
                        signing_input,
                        witness_script,
                        prev_output.amount,
                    ));
                }
            }
        }

        if let Some(redeem_script) = input.single_value(0x04) {
            if script_contains_pubkey(redeem_script, pubkey)
                && p2sh_script_pubkey(&hash160(redeem_script)) == prev_output.script
            {
                return Ok(legacy_sighash_all(
                    tx.version,
                    tx.lock_time,
                    tx.inputs,
                    tx.outputs,
                    signing_input,
                    redeem_script,
                ));
            }
        }

        Err(PsbtSignError::Unsupported)
    }

    fn script_contains_pubkey(script: &[u8], pubkey: &[u8]) -> bool {
        pubkey.len() == EC_PUBLIC_KEY_COMPRESSED_LEN
            && script
                .windows(1 + EC_PUBLIC_KEY_COMPRESSED_LEN)
                .any(|window| {
                    window[0] == EC_PUBLIC_KEY_COMPRESSED_LEN as u8 && &window[1..] == pubkey
                })
    }

    fn p2tr_script_pubkey(output_key: &[u8; SHA256_LEN]) -> Vec<u8> {
        let mut script = Vec::with_capacity(34);
        script.extend_from_slice(&[0x51, 0x20]);
        script.extend_from_slice(output_key);
        script
    }

    fn is_p2tr_script_pubkey(script: &[u8]) -> bool {
        script.len() == 2 + SHA256_LEN && script[0] == 0x51 && script[1] == SHA256_LEN as u8
    }

    fn legacy_sighash_all(
        tx_version: u32,
        lock_time: u32,
        inputs: &[TxInputView<'_>],
        outputs: &[TxOutputView<'_>],
        signing_input: usize,
        script_code: &[u8],
    ) -> [u8; SHA256_LEN] {
        let mut tx = Vec::new();
        tx.extend_from_slice(&tx_version.to_le_bytes());
        push_compact_size(&mut tx, inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            tx.extend_from_slice(input.prev_txid);
            tx.extend_from_slice(&input.prev_vout.to_le_bytes());
            if index == signing_input {
                push_compact_size(&mut tx, script_code.len());
                tx.extend_from_slice(script_code);
            } else {
                tx.push(0);
            }
            tx.extend_from_slice(&input.sequence.to_le_bytes());
        }
        push_compact_size(&mut tx, outputs.len());
        for output in outputs {
            tx.extend_from_slice(&output.amount.to_le_bytes());
            push_compact_size(&mut tx, output.script.len());
            tx.extend_from_slice(output.script);
        }
        tx.extend_from_slice(&lock_time.to_le_bytes());
        tx.extend_from_slice(&1u32.to_le_bytes());
        double_sha256(&tx)
    }

    fn segwit_v0_sighash_all(
        tx_version: u32,
        lock_time: u32,
        inputs: &[TxInputView<'_>],
        outputs: &[TxOutputView<'_>],
        signing_input: usize,
        script_code: &[u8],
        amount: u64,
    ) -> [u8; SHA256_LEN] {
        let mut prevouts = Vec::new();
        let mut sequences = Vec::new();
        for input in inputs {
            prevouts.extend_from_slice(input.prev_txid);
            prevouts.extend_from_slice(&input.prev_vout.to_le_bytes());
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }

        let input = &inputs[signing_input];
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&tx_version.to_le_bytes());
        preimage.extend_from_slice(&double_sha256(&prevouts));
        preimage.extend_from_slice(&double_sha256(&sequences));
        preimage.extend_from_slice(input.prev_txid);
        preimage.extend_from_slice(&input.prev_vout.to_le_bytes());
        push_compact_size(&mut preimage, script_code.len());
        preimage.extend_from_slice(script_code);
        preimage.extend_from_slice(&amount.to_le_bytes());
        preimage.extend_from_slice(&input.sequence.to_le_bytes());
        preimage.extend_from_slice(&serialized_outputs_hash(outputs));
        preimage.extend_from_slice(&lock_time.to_le_bytes());
        preimage.extend_from_slice(&1u32.to_le_bytes());
        double_sha256(&preimage)
    }

    fn serialized_outputs_hash(outputs: &[TxOutputView<'_>]) -> [u8; SHA256_LEN] {
        let mut serialized = Vec::new();
        for output in outputs {
            serialized.extend_from_slice(&output.amount.to_le_bytes());
            push_compact_size(&mut serialized, output.script.len());
            serialized.extend_from_slice(output.script);
        }
        double_sha256(&serialized)
    }

    fn taproot_key_spend_sighash(
        tx: &SighashTx<'_, '_>,
        prev_outputs: &[TxOutputView<'_>],
        signing_input: usize,
        sighash_type: u8,
    ) -> [u8; SHA256_LEN] {
        let mut prevouts = Vec::new();
        let mut amounts = Vec::new();
        let mut script_pubkeys = Vec::new();
        let mut sequences = Vec::new();
        for (input, prev_output) in tx.inputs.iter().zip(prev_outputs) {
            prevouts.extend_from_slice(input.prev_txid);
            prevouts.extend_from_slice(&input.prev_vout.to_le_bytes());
            amounts.extend_from_slice(&prev_output.amount.to_le_bytes());
            push_compact_size(&mut script_pubkeys, prev_output.script.len());
            script_pubkeys.extend_from_slice(prev_output.script);
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }

        let mut preimage = Vec::new();
        preimage.push(0);
        preimage.push(sighash_type);
        preimage.extend_from_slice(&tx.version.to_le_bytes());
        preimage.extend_from_slice(&tx.lock_time.to_le_bytes());
        preimage.extend_from_slice(&Sha256::digest(&prevouts));
        preimage.extend_from_slice(&Sha256::digest(&amounts));
        preimage.extend_from_slice(&Sha256::digest(&script_pubkeys));
        preimage.extend_from_slice(&Sha256::digest(&sequences));
        preimage.extend_from_slice(&taproot_serialized_outputs_hash(tx.outputs));
        preimage.push(0);
        preimage.extend_from_slice(&(signing_input as u32).to_le_bytes());
        tagged_hash(b"TapSighash", &preimage)
    }

    fn taproot_serialized_outputs_hash(outputs: &[TxOutputView<'_>]) -> [u8; SHA256_LEN] {
        let mut serialized = Vec::new();
        for output in outputs {
            serialized.extend_from_slice(&output.amount.to_le_bytes());
            push_compact_size(&mut serialized, output.script.len());
            serialized.extend_from_slice(output.script);
        }
        Sha256::digest(&serialized).into()
    }

    fn sign_digest_der_from_seed(
        seed: &[u8],
        path: &[u32],
        digest: &[u8; SHA256_LEN],
        sighash_type: u8,
    ) -> Option<Vec<u8>> {
        let mut derivation_path = bip32::DerivationPath::default();
        for value in path {
            let hardened = value & bip32::ChildNumber::HARDENED_FLAG != 0;
            let child =
                bip32::ChildNumber::new(value & !bip32::ChildNumber::HARDENED_FLAG, hardened)
                    .ok()?;
            derivation_path.push(child);
        }
        let private_key = bip32::XPrv::derive_from_path(seed, &derivation_path).ok()?;
        let secret = SecretKey::from_slice(private_key.to_bytes().as_ref()).ok()?;
        let secret_scalar = *secret.to_nonzero_scalar().as_ref();
        let z = bits2field::<k256::Secp256k1>(digest).ok()?;

        let mut counter = 0u32;
        let mut extra_entropy = [0u8; 32];
        loop {
            let ad = if counter == 0 {
                &[][..]
            } else {
                &extra_entropy[..]
            };
            let (signature, _) = secret_scalar
                .try_sign_prehashed_rfc6979::<k256::sha2::Sha256>(&z, ad)
                .ok()?;
            let signature = signature.normalize_s().unwrap_or(signature);
            let raw = signature.to_bytes();
            if raw[0] < 0x80 {
                let der = signature.to_der();
                let mut output = der.as_bytes().to_vec();
                output.push(sighash_type);
                return Some(output);
            }

            counter = counter.checked_add(1)?;
            extra_entropy = [0u8; 32];
            extra_entropy[..4].copy_from_slice(&counter.to_le_bytes());
        }
    }

    fn sign_taproot_key_spend_from_seed(
        seed: &[u8],
        path: &[u32],
        digest: &[u8; SHA256_LEN],
        sighash_type: u8,
    ) -> Option<Vec<u8>> {
        let private_key = private_key_from_seed_path(seed, path)?;
        let public_key = public_key_from_private_key(&private_key)?;
        let secret = SecretKey::from_slice(&private_key).ok()?;
        let mut scalar = *secret.to_nonzero_scalar().as_ref();
        if public_key[0] == 0x03 {
            scalar = -scalar;
        }

        let mut xonly = [0u8; SHA256_LEN];
        xonly.copy_from_slice(&public_key[1..]);
        let tweak_hash = tagged_hash(b"TapTweak", &xonly);
        let tweak_bytes: FieldBytes = tweak_hash.into();
        let tweak = <Scalar as Reduce<U256>>::reduce_bytes(&tweak_bytes);
        let tweaked = scalar + tweak;
        if bool::from(tweaked.is_zero()) {
            return None;
        }

        let signing_key = K256SchnorrSigningKey::from_bytes(&tweaked.to_bytes()).ok()?;
        let signature = signing_key.sign_prehash(digest).ok()?;
        let mut output = signature.to_bytes().to_vec();
        if sighash_type != 0 {
            output.push(sighash_type);
        }
        Some(output)
    }

    fn insert_psbt_partial_signatures(
        psbt: &[u8],
        inputs: &[ParsedPsbtMap<'_>],
        signatures: &[PsbtSignature],
    ) -> Result<Vec<u8>, PsbtSignError> {
        let extra_len: usize = signatures
            .iter()
            .map(|signature| {
                compact_size_len(signature.key.len())
                    + signature.key.len()
                    + compact_size_len(signature.signature.len())
                    + signature.signature.len()
            })
            .sum();
        let mut output = Vec::with_capacity(psbt.len() + extra_len);
        let mut cursor = 0;

        for (input_index, input) in inputs.iter().enumerate() {
            let mut matching = signatures
                .iter()
                .filter(|signature| signature.input_index == input_index)
                .peekable();
            if matching.peek().is_none() {
                continue;
            }

            let insert_offset = input
                .entries
                .iter()
                .filter(|entry| matches!(entry.key.first().copied(), Some(0x00 | 0x01 | 0x03)))
                .map(|entry| entry.end)
                .next_back()
                .unwrap_or(input.content_start);
            if insert_offset < cursor || insert_offset > input.end || insert_offset > psbt.len() {
                return Err(PsbtSignError::Invalid);
            }

            output.extend_from_slice(&psbt[cursor..insert_offset]);
            for signature in matching {
                push_compact_size(&mut output, signature.key.len());
                output.extend_from_slice(&signature.key);
                push_compact_size(&mut output, signature.signature.len());
                output.extend_from_slice(&signature.signature);
            }
            cursor = insert_offset;
        }

        output.extend_from_slice(&psbt[cursor..]);
        Ok(output)
    }

    fn push_compact_size(output: &mut Vec<u8>, value: usize) {
        match value {
            0x00..=0xfc => output.push(value as u8),
            0xfd..=0xffff => {
                output.push(0xfd);
                output.extend_from_slice(&(value as u16).to_le_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                output.push(0xfe);
                output.extend_from_slice(&(value as u32).to_le_bytes());
            }
            _ => {
                output.push(0xff);
                output.extend_from_slice(&(value as u64).to_le_bytes());
            }
        }
    }

    fn compact_size_len(value: usize) -> usize {
        match value {
            0x00..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        }
    }

    fn psbt_key_with_data(key_type: u8, key_data: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + key_data.len());
        key.push(key_type);
        key.extend_from_slice(key_data);
        key
    }

    pub fn xpub_from_seed(seed: &[u8], path: &[u32], prefix: XpubPrefix) -> Option<String> {
        let mut derivation_path = bip32::DerivationPath::default();
        for value in path {
            let hardened = value & bip32::ChildNumber::HARDENED_FLAG != 0;
            let child =
                bip32::ChildNumber::new(value & !bip32::ChildNumber::HARDENED_FLAG, hardened)
                    .ok()?;
            derivation_path.push(child);
        }

        let private_key = bip32::XPrv::derive_from_path(seed, &derivation_path).ok()?;
        let prefix = match prefix {
            XpubPrefix::Main => bip32::Prefix::XPUB,
            XpubPrefix::Test => bip32::Prefix::TPUB,
        };
        Some(private_key.public_key().to_string(prefix))
    }

    pub fn public_key_from_seed_path(
        seed: &[u8],
        path: &[u32],
    ) -> Option<[u8; EC_PUBLIC_KEY_COMPRESSED_LEN]> {
        let mut derivation_path = bip32::DerivationPath::default();
        for value in path {
            let hardened = value & bip32::ChildNumber::HARDENED_FLAG != 0;
            let child =
                bip32::ChildNumber::new(value & !bip32::ChildNumber::HARDENED_FLAG, hardened)
                    .ok()?;
            derivation_path.push(child);
        }

        let private_key = bip32::XPrv::derive_from_path(seed, &derivation_path).ok()?;
        Some(private_key.public_key().to_bytes())
    }

    fn private_key_from_seed_path(seed: &[u8], path: &[u32]) -> Option<[u8; EC_PRIVATE_KEY_LEN]> {
        let mut derivation_path = bip32::DerivationPath::default();
        for value in path {
            let hardened = value & bip32::ChildNumber::HARDENED_FLAG != 0;
            let child =
                bip32::ChildNumber::new(value & !bip32::ChildNumber::HARDENED_FLAG, hardened)
                    .ok()?;
            derivation_path.push(child);
        }

        let private_key = bip32::XPrv::derive_from_path(seed, &derivation_path).ok()?;
        private_key.to_bytes().as_ref().try_into().ok()
    }

    pub fn public_key_from_serialized_xpub_path(
        xpub: &[u8; 78],
        path: &[u32],
    ) -> Option<[u8; EC_PUBLIC_KEY_COMPRESSED_LEN]> {
        let mut xpub = serialized_xpub(xpub)?;
        for value in path {
            if value & bip32::ChildNumber::HARDENED_FLAG != 0 {
                return None;
            }
            let child = bip32::ChildNumber::new(*value, false).ok()?;
            xpub = xpub.derive_child(child).ok()?;
        }

        Some(xpub.to_bytes())
    }

    pub fn bitcoin_multisig_address_from_xpubs(
        xpubs: &[[u8; 78]],
        paths: &[Vec<u32>],
        network: BitcoinNetwork,
        variant: MultisigScriptVariant,
        sorted: bool,
        threshold: u8,
    ) -> Option<String> {
        if xpubs.len() != paths.len() {
            return None;
        }

        let mut pubkeys = Vec::with_capacity(xpubs.len());
        for (xpub, path) in xpubs.iter().zip(paths.iter()) {
            pubkeys.push(public_key_from_serialized_xpub_path(xpub, path)?);
        }

        bitcoin_multisig_address_from_pubkeys(&pubkeys, network, variant, sorted, threshold)
    }

    pub fn bitcoin_multisig_address_from_pubkeys(
        pubkeys: &[[u8; EC_PUBLIC_KEY_COMPRESSED_LEN]],
        network: BitcoinNetwork,
        variant: MultisigScriptVariant,
        sorted: bool,
        threshold: u8,
    ) -> Option<String> {
        let multisig_script = multisig_script(pubkeys, sorted, threshold)?;
        match variant {
            MultisigScriptVariant::P2wsh => {
                let script_hash = Sha256::digest(&multisig_script);
                bech32::segwit::encode_v0(segwit_hrp(network), script_hash.as_ref()).ok()
            }
            MultisigScriptVariant::P2sh => {
                let script_hash = hash160(&multisig_script);
                p2sh_address(network, &script_hash)
            }
            MultisigScriptVariant::P2wshP2sh => {
                let witness_script_hash = Sha256::digest(&multisig_script);
                let mut witness_program = [0u8; 34];
                witness_program[1] = SHA256_LEN as u8;
                witness_program[2..].copy_from_slice(witness_script_hash.as_ref());
                let script_hash = hash160(&witness_program);
                p2sh_address(network, &script_hash)
            }
        }
    }

    pub fn liquid_unconfidential_multisig_address_from_xpubs(
        xpubs: &[[u8; 78]],
        paths: &[Vec<u32>],
        network: LiquidNetwork,
        variant: MultisigScriptVariant,
        sorted: bool,
        threshold: u8,
    ) -> Option<String> {
        if xpubs.len() != paths.len() {
            return None;
        }

        let mut pubkeys = Vec::with_capacity(xpubs.len());
        for (xpub, path) in xpubs.iter().zip(paths.iter()) {
            pubkeys.push(public_key_from_serialized_xpub_path(xpub, path)?);
        }

        liquid_unconfidential_multisig_address_from_pubkeys(
            &pubkeys, network, variant, sorted, threshold,
        )
    }

    pub fn liquid_confidential_multisig_address_from_xpubs(
        xpubs: &[[u8; 78]],
        paths: &[Vec<u32>],
        network: LiquidNetwork,
        variant: MultisigScriptVariant,
        sorted: bool,
        threshold: u8,
        master_unblinding_key: &[u8; SHA512_LEN],
    ) -> Option<String> {
        if xpubs.len() != paths.len() {
            return None;
        }

        let mut pubkeys = Vec::with_capacity(xpubs.len());
        for (xpub, path) in xpubs.iter().zip(paths.iter()) {
            pubkeys.push(public_key_from_serialized_xpub_path(xpub, path)?);
        }

        liquid_confidential_multisig_address_from_pubkeys(
            &pubkeys,
            network,
            variant,
            sorted,
            threshold,
            master_unblinding_key,
        )
    }

    pub fn liquid_unconfidential_multisig_address_from_pubkeys(
        pubkeys: &[[u8; EC_PUBLIC_KEY_COMPRESSED_LEN]],
        network: LiquidNetwork,
        variant: MultisigScriptVariant,
        sorted: bool,
        threshold: u8,
    ) -> Option<String> {
        let multisig_script = multisig_script(pubkeys, sorted, threshold)?;
        match variant {
            MultisigScriptVariant::P2wsh => {
                let script_hash = Sha256::digest(&multisig_script);
                bech32::segwit::encode_v0(liquid_segwit_hrp(network), script_hash.as_ref()).ok()
            }
            MultisigScriptVariant::P2sh => {
                let script_hash = hash160(&multisig_script);
                liquid_p2sh_address(network, &script_hash)
            }
            MultisigScriptVariant::P2wshP2sh => {
                let witness_script_hash = Sha256::digest(&multisig_script);
                let mut witness_program = [0u8; 34];
                witness_program[1] = SHA256_LEN as u8;
                witness_program[2..].copy_from_slice(witness_script_hash.as_ref());
                let script_hash = hash160(&witness_program);
                liquid_p2sh_address(network, &script_hash)
            }
        }
    }

    pub fn liquid_confidential_multisig_address_from_pubkeys(
        pubkeys: &[[u8; EC_PUBLIC_KEY_COMPRESSED_LEN]],
        network: LiquidNetwork,
        variant: MultisigScriptVariant,
        sorted: bool,
        threshold: u8,
        master_unblinding_key: &[u8; SHA512_LEN],
    ) -> Option<String> {
        let multisig_script = multisig_script(pubkeys, sorted, threshold)?;
        match variant {
            MultisigScriptVariant::P2wsh => {
                let script_hash = Sha256::digest(&multisig_script);
                let script_pubkey = witness_v0_script_pubkey(script_hash.as_ref());
                let blinding_public_key =
                    blinding_public_key_for_script(master_unblinding_key, &script_pubkey)?;
                liquid_confidential_segwit_address(
                    network,
                    script_hash.as_ref(),
                    &blinding_public_key,
                )
            }
            MultisigScriptVariant::P2sh => {
                let script_hash = hash160(&multisig_script);
                let script_pubkey = p2sh_script_pubkey(&script_hash);
                let blinding_public_key =
                    blinding_public_key_for_script(master_unblinding_key, &script_pubkey)?;
                liquid_confidential_base58_address(
                    liquid_blinded_prefix(network),
                    liquid_p2sh_prefix(network),
                    &script_hash,
                    &blinding_public_key,
                )
            }
            MultisigScriptVariant::P2wshP2sh => {
                let witness_script_hash = Sha256::digest(&multisig_script);
                let witness_program = witness_v0_script_pubkey(witness_script_hash.as_ref());
                let script_hash = hash160(&witness_program);
                let script_pubkey = p2sh_script_pubkey(&script_hash);
                let blinding_public_key =
                    blinding_public_key_for_script(master_unblinding_key, &script_pubkey)?;
                liquid_confidential_base58_address(
                    liquid_blinded_prefix(network),
                    liquid_p2sh_prefix(network),
                    &script_hash,
                    &blinding_public_key,
                )
            }
        }
    }

    pub fn bitcoin_wsh_address_from_script(
        script: &[u8],
        network: BitcoinNetwork,
    ) -> Option<String> {
        let script_hash = Sha256::digest(script);
        bech32::segwit::encode_v0(segwit_hrp(network), script_hash.as_ref()).ok()
    }

    pub fn hash160_digest(bytes: &[u8]) -> [u8; 20] {
        hash160(bytes)
    }

    pub fn bip85_bip39_entropy_from_seed(
        seed: &[u8],
        nwords: usize,
        index: u32,
    ) -> Option<Vec<u8>> {
        let entropy_len = match nwords {
            12 => 16,
            24 => 32,
            _ => return None,
        };
        if index > 0x7fff_ffff {
            return None;
        }

        let path = [
            bip32::ChildNumber::HARDENED_FLAG | 83_696_968,
            bip32::ChildNumber::HARDENED_FLAG | 39,
            bip32::ChildNumber::HARDENED_FLAG,
            bip32::ChildNumber::HARDENED_FLAG | nwords as u32,
            bip32::ChildNumber::HARDENED_FLAG | index,
        ];
        let mut derivation_path = bip32::DerivationPath::default();
        for value in path {
            let child =
                bip32::ChildNumber::new(value & !bip32::ChildNumber::HARDENED_FLAG, true).ok()?;
            derivation_path.push(child);
        }

        let private_key = bip32::XPrv::derive_from_path(seed, &derivation_path).ok()?;
        let mut mac = HmacSha512::new_from_slice(b"bip-entropy-from-k").ok()?;
        mac.update(private_key.to_bytes().as_ref());
        Some(mac.finalize().into_bytes()[..entropy_len].to_vec())
    }

    pub fn bip85_bip39_encrypted_entropy_from_seed(
        seed: &[u8],
        nwords: usize,
        index: u32,
        host_pubkey: &[u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
        ephemeral_private_key: &[u8; EC_PRIVATE_KEY_LEN],
        iv: &[u8; 16],
    ) -> Option<Bip85EncryptedEntropy> {
        let entropy = bip85_bip39_entropy_from_seed(seed, nwords, index)?;
        bip85_encrypted_entropy(
            &entropy,
            b"bip85_bip39_entropy",
            host_pubkey,
            ephemeral_private_key,
            iv,
        )
    }

    pub fn bip85_rsa_entropy_from_seed(
        seed: &[u8],
        key_bits: u32,
        index: u32,
    ) -> Option<[u8; SHA512_LEN]> {
        if key_bits > 0x7fff_ffff || index > 0x7fff_ffff {
            return None;
        }

        let path = [
            bip32::ChildNumber::HARDENED_FLAG | 83_696_968,
            bip32::ChildNumber::HARDENED_FLAG | 828_365,
            bip32::ChildNumber::HARDENED_FLAG | key_bits,
            bip32::ChildNumber::HARDENED_FLAG | index,
        ];
        let mut derivation_path = bip32::DerivationPath::default();
        for value in path {
            let child =
                bip32::ChildNumber::new(value & !bip32::ChildNumber::HARDENED_FLAG, true).ok()?;
            derivation_path.push(child);
        }

        let private_key = bip32::XPrv::derive_from_path(seed, &derivation_path).ok()?;
        let mut mac = HmacSha512::new_from_slice(b"bip-entropy-from-k").ok()?;
        mac.update(private_key.to_bytes().as_ref());
        mac.finalize().into_bytes().as_slice().try_into().ok()
    }

    pub fn bip85_rsa_encrypted_entropy_from_seed(
        seed: &[u8],
        key_bits: u32,
        index: u32,
        host_pubkey: &[u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
        ephemeral_private_key: &[u8; EC_PRIVATE_KEY_LEN],
        iv: &[u8; 16],
    ) -> Option<Bip85EncryptedEntropy> {
        let entropy = bip85_rsa_entropy_from_seed(seed, key_bits, index)?;
        bip85_encrypted_entropy(
            &entropy,
            b"bip85_rsa_entropy",
            host_pubkey,
            ephemeral_private_key,
            iv,
        )
    }

    fn bip85_encrypted_entropy(
        entropy: &[u8],
        label: &[u8],
        host_pubkey: &[u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
        ephemeral_private_key: &[u8; EC_PRIVATE_KEY_LEN],
        iv: &[u8; 16],
    ) -> Option<Bip85EncryptedEntropy> {
        let ephemeral_pubkey = public_key_from_private_key(ephemeral_private_key)?;
        let encrypted = wally_aes_cbc_with_ecdh_key_encrypt(
            ephemeral_private_key,
            iv,
            entropy,
            host_pubkey,
            label,
        )?;

        Some(Bip85EncryptedEntropy {
            pubkey: ephemeral_pubkey,
            encrypted,
        })
    }

    pub fn identity_public_key_from_seed(
        seed: &[u8],
        identity: &str,
        index: u32,
        key_type: IdentityKeyType,
    ) -> Option<[u8; 65]> {
        let private_key = identity_private_key_from_seed(seed, identity, index, key_type)?;
        let secret = P256SecretKey::from_slice(&private_key).ok()?;
        let public_key = secret.public_key();
        public_key
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .ok()
    }

    pub fn sign_identity_from_seed(
        seed: &[u8],
        identity: &str,
        index: u32,
        challenge: &[u8],
    ) -> Option<super::IdentitySignature> {
        if challenge.is_empty() {
            return None;
        }

        let private_key =
            identity_private_key_from_seed(seed, identity, index, IdentityKeyType::Slip13)?;
        let secret = P256SecretKey::from_slice(&private_key).ok()?;
        let public_key = secret.public_key();
        let pubkey = public_key
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .ok()?;

        let signing_key = P256SigningKey::from_slice(&private_key).ok()?;
        let ssh_challenge_hash;
        let prehash = if identity.starts_with("ssh://") {
            ssh_challenge_hash = Sha256::digest(challenge);
            ssh_challenge_hash.as_ref()
        } else {
            challenge
        };
        let signature: P256Signature = signing_key.sign_prehash(prehash).ok()?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature_bytes = signature.to_bytes();
        let mut output_signature = [0u8; 65];
        output_signature[1..].copy_from_slice(signature_bytes.as_ref());

        Some(super::IdentitySignature {
            pubkey,
            signature: output_signature,
        })
    }

    pub fn identity_shared_key_from_seed(
        seed: &[u8],
        identity: &str,
        index: u32,
        their_pubkey: &[u8; 65],
    ) -> Option<[u8; SHA256_LEN]> {
        let private_key =
            identity_private_key_from_seed(seed, identity, index, IdentityKeyType::Slip17)?;
        let secret = P256SecretKey::from_slice(&private_key).ok()?;
        let peer = P256PublicKey::from_sec1_bytes(their_pubkey).ok()?;
        let shared_point = (P256ProjectivePoint::from(*peer.as_affine())
            * secret.to_nonzero_scalar().as_ref())
        .to_affine();
        let encoded = shared_point.to_encoded_point(false);
        encoded.as_bytes()[1..1 + SHA256_LEN].try_into().ok()
    }

    pub fn bitcoin_singlesig_address_from_seed(
        seed: &[u8],
        path: &[u32],
        network: BitcoinNetwork,
        variant: SinglesigScriptVariant,
    ) -> Option<String> {
        let public_key = public_key_from_seed_path(seed, path)?;
        let pubkey_hash = hash160(&public_key);
        match variant {
            SinglesigScriptVariant::Pkh => {
                let mut payload = Vec::with_capacity(21);
                payload.push(match network {
                    BitcoinNetwork::Main => 0x00,
                    BitcoinNetwork::Test | BitcoinNetwork::Regtest => 0x6f,
                });
                payload.extend_from_slice(&pubkey_hash);
                Some(base58ck::encode_check(&payload))
            }
            SinglesigScriptVariant::Wpkh => {
                bech32::segwit::encode_v0(segwit_hrp(network), &pubkey_hash).ok()
            }
            SinglesigScriptVariant::ShWpkh => {
                let mut redeem_script = [0u8; 22];
                redeem_script[1] = 0x14;
                redeem_script[2..].copy_from_slice(&pubkey_hash);
                let script_hash = hash160(&redeem_script);

                let mut payload = Vec::with_capacity(21);
                payload.push(match network {
                    BitcoinNetwork::Main => 0x05,
                    BitcoinNetwork::Test | BitcoinNetwork::Regtest => 0xc4,
                });
                payload.extend_from_slice(&script_hash);
                Some(base58ck::encode_check(&payload))
            }
            SinglesigScriptVariant::Tr => {
                let output_key = taproot_keyspend_output_key(&public_key)?;
                bech32::segwit::encode_v1(segwit_hrp(network), &output_key).ok()
            }
        }
    }

    pub fn liquid_unconfidential_singlesig_address_from_seed(
        seed: &[u8],
        path: &[u32],
        network: LiquidNetwork,
        variant: SinglesigScriptVariant,
    ) -> Option<String> {
        let public_key = public_key_from_seed_path(seed, path)?;
        let pubkey_hash = hash160(&public_key);
        match variant {
            SinglesigScriptVariant::Pkh => {
                let mut payload = Vec::with_capacity(21);
                payload.push(match network {
                    LiquidNetwork::Main => 57,
                    LiquidNetwork::Test => 36,
                    LiquidNetwork::Regtest => 235,
                });
                payload.extend_from_slice(&pubkey_hash);
                Some(base58ck::encode_check(&payload))
            }
            SinglesigScriptVariant::Wpkh => {
                bech32::segwit::encode_v0(liquid_segwit_hrp(network), &pubkey_hash).ok()
            }
            SinglesigScriptVariant::ShWpkh => {
                let mut redeem_script = [0u8; 22];
                redeem_script[1] = 0x14;
                redeem_script[2..].copy_from_slice(&pubkey_hash);
                let script_hash = hash160(&redeem_script);

                let mut payload = Vec::with_capacity(21);
                payload.push(match network {
                    LiquidNetwork::Main => 39,
                    LiquidNetwork::Test => 19,
                    LiquidNetwork::Regtest => 75,
                });
                payload.extend_from_slice(&script_hash);
                Some(base58ck::encode_check(&payload))
            }
            SinglesigScriptVariant::Tr => None,
        }
    }

    pub fn liquid_confidential_singlesig_address_from_seed(
        seed: &[u8],
        path: &[u32],
        network: LiquidNetwork,
        variant: SinglesigScriptVariant,
        master_unblinding_key: &[u8; SHA512_LEN],
    ) -> Option<String> {
        let public_key = public_key_from_seed_path(seed, path)?;
        let pubkey_hash = hash160(&public_key);
        match variant {
            SinglesigScriptVariant::Pkh => {
                let script_pubkey = p2pkh_script_pubkey(&pubkey_hash);
                let blinding_public_key =
                    blinding_public_key_for_script(master_unblinding_key, &script_pubkey)?;
                liquid_confidential_base58_address(
                    liquid_blinded_prefix(network),
                    liquid_p2pkh_prefix(network),
                    &pubkey_hash,
                    &blinding_public_key,
                )
            }
            SinglesigScriptVariant::Wpkh => {
                let script_pubkey = witness_v0_script_pubkey(&pubkey_hash);
                let blinding_public_key =
                    blinding_public_key_for_script(master_unblinding_key, &script_pubkey)?;
                liquid_confidential_segwit_address(network, &pubkey_hash, &blinding_public_key)
            }
            SinglesigScriptVariant::ShWpkh => {
                let mut redeem_script = [0u8; 22];
                redeem_script[1] = 0x14;
                redeem_script[2..].copy_from_slice(&pubkey_hash);
                let script_hash = hash160(&redeem_script);
                let script_pubkey = p2sh_script_pubkey(&script_hash);
                let blinding_public_key =
                    blinding_public_key_for_script(master_unblinding_key, &script_pubkey)?;
                liquid_confidential_base58_address(
                    liquid_blinded_prefix(network),
                    liquid_p2sh_prefix(network),
                    &script_hash,
                    &blinding_public_key,
                )
            }
            SinglesigScriptVariant::Tr => None,
        }
    }

    pub fn slip77_blinding_private_key(
        master_unblinding_key: &[u8; 64],
        script: &[u8],
    ) -> Option<[u8; EC_PRIVATE_KEY_LEN]> {
        if script.is_empty() {
            return None;
        }

        let mut mac = HmacSha256::new_from_slice(&master_unblinding_key[32..64]).ok()?;
        mac.update(script);
        let bytes = mac.finalize().into_bytes();
        let key: [u8; EC_PRIVATE_KEY_LEN] = bytes.as_slice().try_into().ok()?;
        k256::SecretKey::from_slice(&key).ok()?;
        Some(key)
    }

    pub fn public_key_from_private_key(
        private_key: &[u8; EC_PRIVATE_KEY_LEN],
    ) -> Option<[u8; EC_PUBLIC_KEY_COMPRESSED_LEN]> {
        let secret = k256::SecretKey::from_slice(private_key).ok()?;
        let public_key = secret.public_key();
        public_key.to_encoded_point(true).as_bytes().try_into().ok()
    }

    pub fn ecdh_nonce_hash(
        private_key: &[u8; EC_PRIVATE_KEY_LEN],
        peer_public_key: &[u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
    ) -> Option<[u8; SHA256_LEN]> {
        let secret = SecretKey::from_slice(private_key).ok()?;
        let peer = PublicKey::from_sec1_bytes(peer_public_key).ok()?;
        let shared_point = (ProjectivePoint::from(*peer.as_affine())
            * secret.to_nonzero_scalar().as_ref())
        .to_affine();
        let shared_point = shared_point.to_encoded_point(true);

        let ecdh_hash = Sha256::digest(shared_point.as_bytes());
        let nonce_hash = Sha256::digest(ecdh_hash.as_slice());
        nonce_hash.as_slice().try_into().ok()
    }

    pub fn deterministic_blinding_factor(
        master_unblinding_key: &[u8; 64],
        hash_prevouts: &[u8; SHA256_LEN],
        output_index: u32,
        kind: BlindingFactorKind,
    ) -> Option<BlindingFactorBytes> {
        let mut mac = HmacSha256::new_from_slice(&master_unblinding_key[32..64]).ok()?;
        mac.update(hash_prevouts);
        let base = mac.finalize().into_bytes();

        let mut output = BlindingFactorBytes {
            bytes: [0; SHA256_LEN * 2],
            len: 0,
        };
        let mut message = [0u8, b'B', b'F', 0, 0, 0, 0];
        message[3..7].copy_from_slice(&output_index.to_be_bytes());

        if matches!(
            kind,
            BlindingFactorKind::Asset | BlindingFactorKind::AssetAndValue
        ) {
            message[0] = b'A';
            let mut mac = HmacSha256::new_from_slice(base.as_slice()).ok()?;
            mac.update(&message);
            output.bytes[output.len..output.len + SHA256_LEN]
                .copy_from_slice(mac.finalize().into_bytes().as_slice());
            output.len += SHA256_LEN;
        }

        if matches!(
            kind,
            BlindingFactorKind::Value | BlindingFactorKind::AssetAndValue
        ) {
            message[0] = b'V';
            let mut mac = HmacSha256::new_from_slice(base.as_slice()).ok()?;
            mac.update(&message);
            output.bytes[output.len..output.len + SHA256_LEN]
                .copy_from_slice(mac.finalize().into_bytes().as_slice());
            output.len += SHA256_LEN;
        }

        Some(output)
    }

    fn hash160(bytes: &[u8]) -> [u8; 20] {
        let sha = Sha256::digest(bytes);
        let ripemd = <ripemd::Ripemd160 as ripemd::Digest>::digest(sha.as_slice());
        let mut output = [0u8; 20];
        output.copy_from_slice(&ripemd);
        output
    }

    fn p2sh_address(network: BitcoinNetwork, script_hash: &[u8; 20]) -> Option<String> {
        let mut payload = Vec::with_capacity(21);
        payload.push(match network {
            BitcoinNetwork::Main => 0x05,
            BitcoinNetwork::Test | BitcoinNetwork::Regtest => 0xc4,
        });
        payload.extend_from_slice(script_hash);
        Some(base58ck::encode_check(&payload))
    }

    fn liquid_p2sh_address(network: LiquidNetwork, script_hash: &[u8; 20]) -> Option<String> {
        let mut payload = Vec::with_capacity(21);
        payload.push(liquid_p2sh_prefix(network));
        payload.extend_from_slice(script_hash);
        Some(base58ck::encode_check(&payload))
    }

    fn liquid_confidential_base58_address(
        confidential_prefix: u8,
        unconfidential_prefix: u8,
        hash: &[u8; 20],
        blinding_public_key: &[u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
    ) -> Option<String> {
        let mut payload = Vec::with_capacity(55);
        payload.push(confidential_prefix);
        payload.push(unconfidential_prefix);
        payload.extend_from_slice(blinding_public_key);
        payload.extend_from_slice(hash);
        Some(base58ck::encode_check(&payload))
    }

    fn liquid_confidential_segwit_address(
        network: LiquidNetwork,
        witness_program: &[u8],
        blinding_public_key: &[u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
    ) -> Option<String> {
        let hrp = liquid_blech32_hrp(network);
        let byte_iter = blinding_public_key
            .iter()
            .copied()
            .chain(witness_program.iter().copied());
        let chars = byte_iter
            .bytes_to_fes()
            .with_checksum::<Blech32>(&hrp)
            .with_witness_version(bech32::Fe32::Q)
            .chars();

        let mut output = String::new();
        output.extend(chars);
        Some(output)
    }

    fn blinding_public_key_for_script(
        master_unblinding_key: &[u8; SHA512_LEN],
        script_pubkey: &[u8],
    ) -> Option<[u8; EC_PUBLIC_KEY_COMPRESSED_LEN]> {
        let private_key = slip77_blinding_private_key(master_unblinding_key, script_pubkey)?;
        public_key_from_private_key(&private_key)
    }

    fn p2pkh_script_pubkey(hash: &[u8; 20]) -> Vec<u8> {
        let mut script = Vec::with_capacity(25);
        script.extend_from_slice(&[0x76, 0xa9, 0x14]);
        script.extend_from_slice(hash);
        script.extend_from_slice(&[0x88, 0xac]);
        script
    }

    fn p2sh_script_pubkey(hash: &[u8; 20]) -> Vec<u8> {
        let mut script = Vec::with_capacity(23);
        script.extend_from_slice(&[0xa9, 0x14]);
        script.extend_from_slice(hash);
        script.push(0x87);
        script
    }

    fn witness_v0_script_pubkey(program: &[u8]) -> Vec<u8> {
        let mut script = Vec::with_capacity(2 + program.len());
        script.push(0x00);
        script.push(program.len() as u8);
        script.extend_from_slice(program);
        script
    }

    fn liquid_p2pkh_prefix(network: LiquidNetwork) -> u8 {
        match network {
            LiquidNetwork::Main => 57,
            LiquidNetwork::Test => 36,
            LiquidNetwork::Regtest => 235,
        }
    }

    fn liquid_p2sh_prefix(network: LiquidNetwork) -> u8 {
        match network {
            LiquidNetwork::Main => 39,
            LiquidNetwork::Test => 19,
            LiquidNetwork::Regtest => 75,
        }
    }

    fn liquid_blinded_prefix(network: LiquidNetwork) -> u8 {
        match network {
            LiquidNetwork::Main => 12,
            LiquidNetwork::Test => 23,
            LiquidNetwork::Regtest => 4,
        }
    }

    fn multisig_script(
        pubkeys: &[[u8; EC_PUBLIC_KEY_COMPRESSED_LEN]],
        sorted: bool,
        threshold: u8,
    ) -> Option<Vec<u8>> {
        if pubkeys.is_empty()
            || pubkeys.len() > 16
            || threshold == 0
            || threshold as usize > pubkeys.len()
            || threshold > 16
        {
            return None;
        }

        let mut pubkeys = pubkeys.to_vec();
        for pubkey in &pubkeys {
            k256::PublicKey::from_sec1_bytes(pubkey).ok()?;
        }
        if sorted {
            pubkeys.sort();
        }

        let pubkey_count = pubkeys.len() as u8;
        let mut script = Vec::with_capacity(1 + pubkeys.len() * 34 + 2);
        script.push(op_n(threshold)?);
        for pubkey in pubkeys {
            script.push(EC_PUBLIC_KEY_COMPRESSED_LEN as u8);
            script.extend_from_slice(&pubkey);
        }
        script.push(op_n(pubkey_count)?);
        script.push(0xae);
        Some(script)
    }

    fn op_n(value: u8) -> Option<u8> {
        match value {
            1..=16 => Some(0x50 + value),
            _ => None,
        }
    }

    fn serialized_xpub(bytes: &[u8; 78]) -> Option<bip32::XPub> {
        let prefix = bip32::Prefix::from_bytes(bytes[..4].try_into().ok()?).ok()?;
        let attrs = bip32::ExtendedKeyAttrs {
            depth: bytes[4],
            parent_fingerprint: bytes[5..9].try_into().ok()?,
            child_number: bip32::ChildNumber::from_bytes(bytes[9..13].try_into().ok()?),
            chain_code: bytes[13..45].try_into().ok()?,
        };
        let key_bytes = bytes[45..78].try_into().ok()?;
        let extended = bip32::ExtendedKey {
            prefix,
            attrs,
            key_bytes,
        };
        bip32::XPub::try_from(extended).ok()
    }

    fn segwit_hrp(network: BitcoinNetwork) -> bech32::Hrp {
        match network {
            BitcoinNetwork::Main => bech32::hrp::BC,
            BitcoinNetwork::Test => bech32::hrp::TB,
            BitcoinNetwork::Regtest => bech32::hrp::BCRT,
        }
    }

    fn liquid_segwit_hrp(network: LiquidNetwork) -> bech32::Hrp {
        match network {
            LiquidNetwork::Main => bech32::Hrp::parse_unchecked("ex"),
            LiquidNetwork::Test => bech32::Hrp::parse_unchecked("tex"),
            LiquidNetwork::Regtest => bech32::Hrp::parse_unchecked("ert"),
        }
    }

    fn liquid_blech32_hrp(network: LiquidNetwork) -> bech32::Hrp {
        match network {
            LiquidNetwork::Main => bech32::Hrp::parse_unchecked("lq"),
            LiquidNetwork::Test => bech32::Hrp::parse_unchecked("tlq"),
            LiquidNetwork::Regtest => bech32::Hrp::parse_unchecked("el"),
        }
    }

    fn identity_private_key_from_seed(
        seed: &[u8],
        identity: &str,
        index: u32,
        key_type: IdentityKeyType,
    ) -> Option<[u8; EC_PRIVATE_KEY_LEN]> {
        if identity.is_empty() || index > 0x7fff_ffff {
            return None;
        }

        let mut root_mac = HmacSha512::new_from_slice(b"Nist256p1 seed").ok()?;
        root_mac.update(seed);
        let root = root_mac.finalize().into_bytes();
        let mut private_key = [0u8; EC_PRIVATE_KEY_LEN];
        let mut chain_code = [0u8; EC_PRIVATE_KEY_LEN];
        private_key.copy_from_slice(&root[..EC_PRIVATE_KEY_LEN]);
        chain_code.copy_from_slice(&root[EC_PRIVATE_KEY_LEN..]);

        for child_index in identity_path(identity, index, key_type) {
            let mut mac = HmacSha512::new_from_slice(&chain_code).ok()?;
            mac.update(&[0]);
            mac.update(&private_key);
            mac.update(&child_index.to_be_bytes());
            let digest = mac.finalize().into_bytes();

            let parent_scalar =
                <P256Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&private_key));
            let tweak_scalar = <P256Scalar as Reduce<U256>>::reduce(U256::from_be_slice(
                &digest[..EC_PRIVATE_KEY_LEN],
            ));
            let child_scalar = parent_scalar + tweak_scalar;
            let child_bytes: P256FieldBytes = child_scalar.to_bytes();
            private_key.copy_from_slice(&child_bytes);
            chain_code.copy_from_slice(&digest[EC_PRIVATE_KEY_LEN..]);
        }

        P256SecretKey::from_slice(&private_key).ok()?;
        Some(private_key)
    }

    fn identity_path(identity: &str, index: u32, key_type: IdentityKeyType) -> [u32; 5] {
        let mut hasher = Sha256::new();
        hasher.update(index.to_le_bytes());
        hasher.update(identity.as_bytes());
        let identity_hash = hasher.finalize();
        let prefix = match key_type {
            IdentityKeyType::Slip13 => 13,
            IdentityKeyType::Slip17 => 17,
        };

        [
            bip32::ChildNumber::HARDENED_FLAG | prefix,
            bip32::ChildNumber::HARDENED_FLAG
                | u32::from_le_bytes(identity_hash[0..4].try_into().expect("slice length")),
            bip32::ChildNumber::HARDENED_FLAG
                | u32::from_le_bytes(identity_hash[4..8].try_into().expect("slice length")),
            bip32::ChildNumber::HARDENED_FLAG
                | u32::from_le_bytes(identity_hash[8..12].try_into().expect("slice length")),
            bip32::ChildNumber::HARDENED_FLAG
                | u32::from_le_bytes(identity_hash[12..16].try_into().expect("slice length")),
        ]
    }

    pub(crate) fn taproot_keyspend_output_key(
        public_key: &[u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
    ) -> Option<[u8; SHA256_LEN]> {
        let mut even_internal_key = [0u8; EC_PUBLIC_KEY_COMPRESSED_LEN];
        even_internal_key[0] = 0x02;
        even_internal_key[1..].copy_from_slice(&public_key[1..]);

        let internal_public_key = PublicKey::from_sec1_bytes(&even_internal_key).ok()?;
        let internal_point = ProjectivePoint::from(*internal_public_key.as_affine());
        let tweak_hash = tagged_hash(b"TapTweak", &public_key[1..]);
        let tweak_bytes: FieldBytes = tweak_hash.into();
        let tweak = <Scalar as Reduce<U256>>::reduce_bytes(&tweak_bytes);
        let output_point = (internal_point + ProjectivePoint::GENERATOR * tweak).to_affine();
        if bool::from(
            k256::elliptic_curve::group::prime::PrimeCurveAffine::is_identity(&output_point),
        ) {
            return None;
        }

        let encoded = output_point.to_encoded_point(true);
        encoded.as_bytes()[1..].try_into().ok()
    }

    fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; SHA256_LEN] {
        let tag_hash = Sha256::digest(tag);
        let digest = Sha256::new()
            .chain_update(tag_hash.as_slice())
            .chain_update(tag_hash.as_slice())
            .chain_update(message)
            .finalize();
        let mut output = [0u8; SHA256_LEN];
        output.copy_from_slice(&digest);
        output
    }

    fn wally_aes_cbc_with_ecdh_key_encrypt(
        private_key: &[u8; EC_PRIVATE_KEY_LEN],
        iv: &[u8; 16],
        payload: &[u8],
        peer_public_key: &[u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
        label: &[u8],
    ) -> Option<Vec<u8>> {
        if payload.is_empty() || label.is_empty() {
            return None;
        }

        let secret = secp256k1_ecdh_secret(private_key, peer_public_key)?;
        let mut mac = HmacSha512::new_from_slice(&secret).ok()?;
        mac.update(label);
        let keys = mac.finalize().into_bytes();
        let enc_key = &keys[..32];
        let hmac_key = &keys[32..64];

        let cipher = Aes256::new_from_slice(enc_key).ok()?;
        let mut previous = *iv;
        let mut output = Vec::with_capacity(16 + ((payload.len() / 16) + 1) * 16 + 32);
        output.extend_from_slice(iv);

        let full_blocks = payload.len() / 16;
        for block_index in 0..full_blocks {
            let mut xored = [0u8; 16];
            xored.copy_from_slice(&payload[block_index * 16..block_index * 16 + 16]);
            for (byte, previous_byte) in xored.iter_mut().zip(previous) {
                *byte ^= previous_byte;
            }
            let mut block = Block::default();
            block.copy_from_slice(&xored);
            cipher.encrypt_block(&mut block);
            previous.copy_from_slice(&block);
            output.extend_from_slice(&block);
        }

        let remainder = payload.len() % 16;
        let padding = (16 - remainder) as u8;
        let mut final_block = [padding; 16];
        final_block[..remainder].copy_from_slice(&payload[full_blocks * 16..]);
        for (byte, previous_byte) in final_block.iter_mut().zip(previous) {
            *byte ^= previous_byte;
        }
        let mut block = Block::default();
        block.copy_from_slice(&final_block);
        cipher.encrypt_block(&mut block);
        output.extend_from_slice(&block);

        let mut hmac = HmacSha256::new_from_slice(hmac_key).ok()?;
        hmac.update(&output);
        output.extend_from_slice(&hmac.finalize().into_bytes());
        Some(output)
    }

    fn secp256k1_ecdh_secret(
        private_key: &[u8; EC_PRIVATE_KEY_LEN],
        peer_public_key: &[u8; EC_PUBLIC_KEY_COMPRESSED_LEN],
    ) -> Option<[u8; SHA256_LEN]> {
        let secret = SecretKey::from_slice(private_key).ok()?;
        let peer = PublicKey::from_sec1_bytes(peer_public_key).ok()?;
        let shared_point = (ProjectivePoint::from(*peer.as_affine())
            * secret.to_nonzero_scalar().as_ref())
        .to_affine()
        .to_encoded_point(true);
        Sha256::digest(shared_point.as_bytes())
            .as_slice()
            .try_into()
            .ok()
    }
}

#[cfg(test)]
mod otp_tests {
    use super::*;

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        let otp = OtpUri::parse(
            "otpauth://hotp/ACME%20Co:john.doe@email.com\
             ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&counter=0",
        )
        .unwrap();

        for (counter, expected) in [
            (0, "755224"),
            (1, "287082"),
            (2, "359152"),
            (3, "969429"),
            (4, "338314"),
            (5, "254676"),
            (6, "287922"),
            (7, "162583"),
            (8, "399871"),
            (9, "520489"),
        ] {
            assert_eq!(otp.auth_code(counter).unwrap(), expected);
        }
    }

    #[test]
    fn totp_matches_rfc6238_vectors_for_supported_hashes() {
        let timestamps = [
            59,
            1_111_111_109,
            1_111_111_111,
            1_234_567_890,
            2_000_000_000,
            20_000_000_000,
        ];

        for (algorithm, expected) in [
            (
                "SHA1",
                [
                    "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
                ],
            ),
            (
                "SHA256",
                [
                    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
                ],
            ),
            (
                "SHA512",
                [
                    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
                ],
            ),
        ] {
            let uri = alloc::format!(
                "otpauth://totp/ACME%20Co:john.doe@email.com\
                 ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&digits=8&algorithm={algorithm}"
            );
            let otp = OtpUri::parse(&uri).unwrap();
            for (timestamp, expected) in timestamps.iter().zip(expected) {
                assert_eq!(otp.auth_code(*timestamp).unwrap(), expected, "{algorithm}");
            }
        }
    }

    #[test]
    fn totp_short_secret_padding_matches_jade_vectors() {
        let sha1 =
            OtpUri::parse("otpauth://totp/ACM?secret=VMR466AB62ZBOKHE&digits=6&algorithm=SHA1")
                .unwrap();
        assert_eq!(sha1.auth_code(0).unwrap(), "538532");
        assert_eq!(sha1.auth_code(1_426_847_216).unwrap(), "543160");

        let short_sha1 = OtpUri::parse("otpauth://totp/Foo?secret=VM").unwrap();
        assert_eq!(short_sha1.auth_code(1_659_641_526).unwrap(), "468828");
        assert_eq!(short_sha1.auth_code(1_659_641_674).unwrap(), "550073");
        assert_eq!(short_sha1.auth_code(1_659_641_710).unwrap(), "222948");
    }

    #[test]
    fn otp_uri_rejects_jade_bad_parameter_cases() {
        for uri in [
            "otpauth://hotp/Foo?secret=GEZDGNBVGY3TQOJQ",
            "otpauth://hotp/Foo?secret=GEZDGNBVGY3TQOJQ&counter=",
            "otpauth://hotp/Foo?secret=GEZDGNBVGY3TQOJQ&counter=18446744073709551616",
            "otpauth://hotp/Foo?secret=GEZDGNBVGY3TQOJQ&counter=abc",
            "otpauth://totp/Foo?secret=GEZDGNBVGY3TQOJQ&digits=",
            "otpauth://totp/Foo?secret=GEZDGNBVGY3TQOJQ&digits=7",
            "otpauth://totp/Foo?secret=GEZDGNBVGY3TQOJQ&period=",
            "otpauth://totp/Foo?secret=GEZDGNBVGY3TQOJQ&period=256",
        ] {
            assert_eq!(OtpUri::parse(uri), Err(OtpError::InvalidUri), "{uri}");
        }
    }
}

#[cfg(all(test, feature = "pure-rust-curves"))]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn slip77_master_unblinding_key_from_seed_matches_wally_symmetric_derivation() {
        assert_eq!(
            slip77_master_unblinding_key_from_seed(&[0u8; SHA512_LEN]).unwrap(),
            [
                0x19, 0x9d, 0x6a, 0xdf, 0x6b, 0xe1, 0x4d, 0x06, 0x66, 0x36, 0xaf, 0xae, 0x63, 0xb6,
                0xa1, 0x69, 0xb2, 0x5a, 0xda, 0xb0, 0x6e, 0xf5, 0xbe, 0xbe, 0x1f, 0x65, 0x87, 0x57,
                0x35, 0x38, 0x9a, 0x52, 0x4b, 0x4c, 0xa9, 0x49, 0x22, 0x1f, 0x7c, 0xdf, 0x23, 0xad,
                0x07, 0x39, 0x90, 0xc1, 0xc9, 0x68, 0x57, 0x8b, 0xad, 0xa6, 0x21, 0x85, 0xf9, 0xe5,
                0x52, 0xd1, 0x9f, 0x05, 0x89, 0xa1, 0xd6, 0x33,
            ]
        );
        assert_eq!(slip77_master_unblinding_key_from_seed(&[0u8; 31]), None);
    }

    #[test]
    fn derives_compressed_public_key_from_private_key_one() {
        let mut private_key = [0u8; EC_PRIVATE_KEY_LEN];
        private_key[EC_PRIVATE_KEY_LEN - 1] = 1;

        assert_eq!(
            pure_rust::public_key_from_private_key(&private_key).unwrap(),
            [
                0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
                0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
                0x5b, 0x16, 0xf8, 0x17, 0x98,
            ]
        );
    }

    #[test]
    fn slip77_rejects_empty_scripts() {
        assert_eq!(
            pure_rust::slip77_blinding_private_key(&[0x11; 64], &[]),
            None
        );
    }

    #[test]
    fn xpub_from_seed_matches_bip32_vector_and_test_prefix() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        assert_eq!(
            pure_rust::xpub_from_seed(&seed, &[], XpubPrefix::Main).unwrap(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
        assert_eq!(
            pure_rust::xpub_from_seed(&seed, &[0x8000_0000], XpubPrefix::Main).unwrap(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        );
        assert!(
            pure_rust::xpub_from_seed(&seed, &[0x8000_0000], XpubPrefix::Test)
                .unwrap()
                .starts_with("tpub")
        );
    }

    #[test]
    fn bitcoin_message_signatures_match_jade_fixtures() {
        let seed = decode_hex_64(
            "f1d56befd46eddfc31cda129dc76cd4a2b41d2cf86f10a5ccf0787617afa3869\
             967aab0224742ccc002056747ea09b68598ddf79c027c37a7c3ec923004593da",
        );

        for (path, message, expected) in [
            (
                &[0u32][..],
                "Jade is cool",
                "IHd2/Y65d1P7Gq6I6gTDoRql9eEsFEh7B8RtAJm+g+AdHuxT5hbMKN28Jlotxfp0LO3WLxPlJh61BQYPYL1uikw=",
            ),
            (
                &[2_147_483_651, 2_147_483_648][..],
                "The above path initially failed with Jade, this proves it now works.",
                "IKS4r0mTB21NqFv57yxphyD69zBT2yMXVXmseLJh9mZGB8qoMeeK8bAmcplMRvWAY9DuXmbqEIcQsDZRhRhFLAU=",
            ),
        ] {
            assert_eq!(
                pure_rust::sign_bitcoin_message_from_seed(&seed, path, message.as_bytes())
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn bitcoin_singlesig_addresses_match_bip32_vector_child() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let path = [0x8000_0000];

        assert_eq!(
            pure_rust::bitcoin_singlesig_address_from_seed(
                &seed,
                &path,
                BitcoinNetwork::Main,
                SinglesigScriptVariant::Pkh,
            )
            .unwrap(),
            "19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh"
        );
        assert_eq!(
            pure_rust::bitcoin_singlesig_address_from_seed(
                &seed,
                &path,
                BitcoinNetwork::Main,
                SinglesigScriptVariant::Wpkh,
            )
            .unwrap(),
            "bc1qtsdavj8dyw49l4gt554jg47pr60gpf48ww2ens"
        );
        assert_eq!(
            pure_rust::bitcoin_singlesig_address_from_seed(
                &seed,
                &path,
                BitcoinNetwork::Main,
                SinglesigScriptVariant::ShWpkh,
            )
            .unwrap(),
            "3AbBmNbPDSzeZKHywDrH3h5v2rL8xGfT7e"
        );
        assert_eq!(
            pure_rust::bitcoin_singlesig_address_from_seed(
                &seed,
                &path,
                BitcoinNetwork::Regtest,
                SinglesigScriptVariant::Wpkh,
            )
            .unwrap(),
            "bcrt1qtsdavj8dyw49l4gt554jg47pr60gpf48xpg8l2"
        );
    }

    #[test]
    fn liquid_unconfidential_singlesig_address_matches_jade_vector() {
        let seed =
            decode_hex_32("b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c");
        let path = [0x8000_0000, 0x8000_0000, 0x8000_0009];

        assert_eq!(
            pure_rust::liquid_unconfidential_singlesig_address_from_seed(
                &seed,
                &path,
                LiquidNetwork::Regtest,
                SinglesigScriptVariant::Pkh,
            )
            .unwrap(),
            "2dafKNiCKbRum9S1u5BYqTByZT5R9zSqcWy"
        );
    }

    #[test]
    fn liquid_confidential_singlesig_addresses_match_jade_vectors() {
        let seed =
            decode_hex_32("b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c");
        let master_unblinding_key = slip77_master_unblinding_key_from_seed(&seed).unwrap();

        for (variant, index, expected) in [
            (
                SinglesigScriptVariant::ShWpkh,
                1,
                "AzpnFQq17AnWm4gvL2oHLRucFawmq8VWFyaxfPX3EgrihEdwDXWmb1QmA7QrRu5RCy3wDtSe8h9WxKbQ",
            ),
            (
                SinglesigScriptVariant::Wpkh,
                2,
                "el1qqwud2rtjxwgfxc9wrey504mtjqujrmzsc442zway65gkuj2f0mm4xfv8h3sqfz223jxjrj307zyqln2dywxmsvpvs9x2tvufj",
            ),
            (
                SinglesigScriptVariant::Pkh,
                3,
                "CTEuAWMSL94hM2PbTzoe8TGLjyVkkSgdPFas7eUMouiGk5Q2SfzadGnGduPwvoVK1ZpthykJup8A8Eh2",
            ),
            (
                SinglesigScriptVariant::Pkh,
                9,
                "CTEjtdpkvj7mrGtgMTrmDfSnH9DdN9Rzi2tzsxsFNujSU8qhYzNnQaWx24j5hX8iWcaZgTZJ6Y3sedLi",
            ),
        ] {
            let path = [0x8000_0000, 0x8000_0000, 0x8000_0000 | index];
            assert_eq!(
                pure_rust::liquid_confidential_singlesig_address_from_seed(
                    &seed,
                    &path,
                    LiquidNetwork::Regtest,
                    variant,
                    &master_unblinding_key,
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn liquid_confidential_multisig_address_matches_jade_fixture() {
        let mut master_unblinding_key = [0u8; SHA512_LEN];
        master_unblinding_key[32..].copy_from_slice(&decode_hex_32(
            "afacc503637e85da661ca1706c4ea147f1407868c48d8f92dd339ac272293cdc",
        ));
        let xpubs = [
            decode_xpub(
                "tpubECMbgHMZm4QymESFZ9tr4ADVDyePJChBrHH6s1Vp728PdQcPbGNoG6HjPx9pH3SzmtmJuiBPhmVBhYgJF6t9tz1SADXpvqeexwWCq79KoRa",
            ),
            decode_xpub(
                "tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka",
            ),
        ];
        let paths = alloc::vec![alloc::vec![1], alloc::vec![1]];

        assert_eq!(
            pure_rust::liquid_confidential_multisig_address_from_xpubs(
                &xpubs,
                &paths,
                LiquidNetwork::Test,
                MultisigScriptVariant::P2wshP2sh,
                false,
                2,
                &master_unblinding_key,
            )
            .unwrap(),
            "vjTyeX1qFEukxp2Yi3T9ohfyLxxSKfn2NnRNHuniCqpQhkTv53HkUi9i4hunmxbm1WFy1QVogAeXkQ6A"
        );
    }

    #[test]
    fn bitcoin_multisig_addresses_match_wally_script_shapes() {
        let xpub = decode_xpub(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe\
             PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        );
        let xpubs = [xpub, xpub];
        let paths = alloc::vec![alloc::vec![0], alloc::vec![1]];

        assert_eq!(
            pure_rust::bitcoin_multisig_address_from_xpubs(
                &xpubs,
                &paths,
                BitcoinNetwork::Main,
                MultisigScriptVariant::P2wsh,
                false,
                2,
            )
            .unwrap(),
            "bc1qyjkdrj9rr6uzt46fgr7j7kelx92n0lu99ex2zsxlmlvcsaf3yy3qaxune3"
        );
        assert_eq!(
            pure_rust::bitcoin_multisig_address_from_xpubs(
                &xpubs,
                &paths,
                BitcoinNetwork::Main,
                MultisigScriptVariant::P2sh,
                false,
                2,
            )
            .unwrap(),
            "39M71fsuoh16JaZp7ptvKvYSJeiXmkMue7"
        );
        assert_eq!(
            pure_rust::bitcoin_multisig_address_from_xpubs(
                &xpubs,
                &paths,
                BitcoinNetwork::Test,
                MultisigScriptVariant::P2wshP2sh,
                true,
                2,
            )
            .unwrap(),
            "2NFbXyq2uQHdM15WcETxmTdYTfAsTPuhEkp"
        );
    }

    #[test]
    fn bip85_bip39_entropy_matches_jade_python_vectors() {
        let mnemonic = bip39::Mnemonic::parse(
            "fish inner face ginger orchard permit useful method fence kidney chuckle party \
             favorite sunset draw limb science crane oval letter slot invite sadness banana",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");

        for (nwords, index, expected) in [
            (
                12,
                0,
                "elephant this puppy lucky fatigue skate aerobic emotion peanut outer clinic casino",
            ),
            (
                12,
                65535,
                "curtain angle fatigue siren involve bleak detail frame name spare size cycle",
            ),
            (
                24,
                0,
                "certain act palace ball plug they divide fold climb hand tuition inside choose \
                 sponsor grass scheme choose split top twenty always vendor fit thank",
            ),
            (
                24,
                65535,
                "humble museum grab fitness wrap window front job quarter update rich grape gap \
                 daring blame cricket traffic sad trade easily genius boost lumber rhythm",
            ),
        ] {
            let entropy = pure_rust::bip85_bip39_entropy_from_seed(&seed, nwords, index).unwrap();
            let derived = bip39::Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(derived.to_string(), expected);
        }
    }

    #[test]
    fn bip85_bip39_entropy_rejects_unsupported_word_counts_and_indices() {
        let seed = [0x11; SHA512_LEN];

        assert_eq!(pure_rust::bip85_bip39_entropy_from_seed(&seed, 18, 0), None);
        assert_eq!(
            pure_rust::bip85_bip39_entropy_from_seed(&seed, 12, 0x8000_0000),
            None
        );
    }

    #[test]
    fn bip85_bip39_encrypted_entropy_uses_wally_envelope_shape() {
        let mnemonic = bip39::Mnemonic::parse(
            "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let host_pubkey =
            decode_hex_33("03e581be89d1ef8ce11d60746d08e4f8aedf934d1d861dd436042ee2e3b16db918");
        let ephemeral_private_key =
            decode_hex_32("0b6b3dc90d203d854100110788ac87d43aa00620c9cdb361b281b09022ef4b53");
        let iv = [
            0xbd, 0x5d, 0x47, 0x24, 0x24, 0x38, 0x80, 0x73, 0x8e, 0x7e, 0x8b, 0x0c, 0x02, 0x65,
            0x87, 0x00,
        ];

        let encrypted = pure_rust::bip85_bip39_encrypted_entropy_from_seed(
            &seed,
            12,
            0,
            &host_pubkey,
            &ephemeral_private_key,
            &iv,
        )
        .unwrap();

        assert_eq!(
            encrypted.pubkey,
            decode_hex_33("03ff06999ad61c0f3a733b93fc1e6b75ecfb1439b326e840de590a56454f0eeb0d")
        );
        assert_eq!(encrypted.encrypted.len(), 80);
        assert_eq!(&encrypted.encrypted[..16], &iv);
    }

    #[test]
    fn bip85_rsa_entropy_matches_jade_python_vectors() {
        let mnemonic = bip39::Mnemonic::parse(
            "fish inner face ginger orchard permit useful method fence kidney chuckle party \
             favorite sunset draw limb science crane oval letter slot invite sadness banana",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");

        for (key_bits, index, expected) in [
            (
                1024,
                0,
                "45954a1a1b82976d9cf16ded12d304abaff7c6786f0556ef38335ec447116074e12ad6857334958b69a3aaf56d9dac5fab9ff515b031887b859dd08a7a806e42",
            ),
            (
                4096,
                1,
                "99e120fc417959b4145bbfc7dede19622c4223466b63866a3b1ac4bdac2344ad85ecacd930a98c8d9ffc918803e873d6b351a6b003ee2e58d9f73f4e97342338",
            ),
            (
                8192,
                0,
                "0cbc707c69602095287624e78aaae4ab8048fa8b5407dadf87a6a0abd9162cabb618900bcec641053edda87e412a93344a4d14a0c2e22ba9af9759a9114f8f20",
            ),
        ] {
            assert_eq!(
                pure_rust::bip85_rsa_entropy_from_seed(&seed, key_bits, index).unwrap(),
                decode_hex_64(expected),
                "{key_bits}/{index}"
            );
        }
    }

    #[test]
    fn identity_public_keys_match_jade_fixtures() {
        let mnemonic = bip39::Mnemonic::parse(
            "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let identity = "ssh://satoshi@bitcoin.org";

        assert_eq!(
            pure_rust::identity_public_key_from_seed(&seed, identity, 47, IdentityKeyType::Slip13)
                .unwrap(),
            decode_hex_65(
                "0473f21a3da3d0e96fc2189f81dd826658c3d76b2d55bd1da349bc6c3573b13ae4d564710ca0bf84b81c6850e916cb94ae9c397b550589da476ace7aee39ebcb37"
            )
        );
        assert_eq!(
            pure_rust::identity_public_key_from_seed(&seed, identity, 47, IdentityKeyType::Slip17)
                .unwrap(),
            decode_hex_65(
                "04248befa95e9dbcf0a2ef7cf6957651ee25a168355590c4c84a6a8601758ca230d397bcba67b4676c3f2711b59083fff9157c16899da6d4ed76f8eaf57a100fa8"
            )
        );
    }

    #[test]
    fn identity_shared_key_matches_jade_fixture() {
        let mnemonic = bip39::Mnemonic::parse(
            "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let identity = "ssh://satoshi@bitcoin.org";
        let slip17_pubkey = decode_hex_65(
            "04248befa95e9dbcf0a2ef7cf6957651ee25a168355590c4c84a6a8601758ca230d397bcba67b4676c3f2711b59083fff9157c16899da6d4ed76f8eaf57a100fa8",
        );

        assert_eq!(
            pure_rust::identity_shared_key_from_seed(&seed, identity, 47, &slip17_pubkey).unwrap(),
            decode_hex_32("de7c569bea8fd78f724671e2b645e3debb58af1c869c5c0a3a901ff2b9413ffa")
        );
    }

    #[test]
    fn identity_signatures_match_jade_fixtures() {
        let mnemonic = bip39::Mnemonic::parse(
            "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");

        for (challenge, identity, index, signature, pubkey) in [
            (
                "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
                "ssh://satoshi@bitcoin.org",
                47,
                "005122cebabb852cdd32103b602662afa88e54c0c0c1b38d7099c64dcd49efe908288114e66ed2d8c82f23a70b769a4db723173ec53840c08aafb840d3f09a18d3",
                "0473f21a3da3d0e96fc2189f81dd826658c3d76b2d55bd1da349bc6c3573b13ae4d564710ca0bf84b81c6850e916cb94ae9c397b550589da476ace7aee39ebcb37",
            ),
            (
                "c16e1456df150491c50722a9d02fa04c74ef065a94f1936f7db029f71138c239",
                "ssh://jade@jadepin.blockstream.com",
                112,
                "00d0472ffa6a6b0075b71a60c7abd3faf9f6d49b7bb86bace344e23c68b888ebc273d48b62b4af70f2ad1ca213f6886e26d74d31cfbbd7f4ac917af4d243939813",
                "04a88f160249fd794bdb12fc56896e8dac6bf5e72e33960e2a7d11252f6a93ef28fa183f3eca7ac84aa0d2e1488f281dbe4af394fcbeda3ab368e7fe98fc25f16f",
            ),
            (
                "ff732d6499071333f13170d2184054b6dffc1296ca43cb1599a68cea65071e6f",
                "ssh://someuser@github.com",
                0,
                "0013372b354ff22cbc2d5d1731d7764567bac1ee99fb92eada9c190b7a4e6b47a42ef117610a85995d9c94bb537e6ca03b3692202de949ee2b69238a20dd1440c2",
                "04406cebcd21fe37c081c4c3a17df7d238e6ce93272d39d792f08f2651a511ec79760593520019b224f7784e648296d8762804b6937aded7ab807690177e4c8f7e",
            ),
            (
                "bcfc224438bd07742c4a3ad6db530e3f071f93645728e9f69eaee21c2f4ed54a",
                "gpg://GreenAddress <greenaddress@blockstream.io>",
                16,
                "007a9e6f1d2b4f14185b1046d70a1b56ecde775b3fc0ad3f9d6f408eb0c6d9f320510ffeff560ba8a0ae9d7bb1c8ddd14f84cf58ceca62803a813e9ab7f30f9765",
                "045158eadf95d518871eb8b1ca5e363d389ba2af83a4b26d66259399ab7da7ed73facfd38891624126075573294e5bedc9fc8909df88c2a78ec1c153eeeb709bc1",
            ),
            (
                "fa94545d4f18e4cc4655c87869fc8a790a07eb58a3e5b599ab9f7da6d8ab5061",
                "gpg://Jade <jade@blockstream.com>",
                0,
                "000118565f7363337ad72a1c497a1e1de5d336a99b09af8c49b36518e925a0ca517dafffb2e95dc777c4d7df504ced12fd668f81a11d14d30033831df1434b59d7",
                "041127ef35e4690ff035e13ebab340ab3fa2327c0409bbed3dbf03b8932777d929bd8ade43e3ebceb9fc74c23a32cd0e380d9b529a70ee0e83763e0c7af5f0bb1f",
            ),
        ] {
            let signed = pure_rust::sign_identity_from_seed(
                &seed,
                identity,
                index,
                &decode_hex_32(challenge),
            )
            .unwrap();
            assert_eq!(signed.signature, decode_hex_65(signature), "{identity}");
            assert_eq!(signed.pubkey, decode_hex_65(pubkey), "{identity}");
        }
    }

    #[test]
    fn identity_public_key_rejects_empty_identity_and_oversized_index() {
        let seed = [0x11; SHA512_LEN];

        assert_eq!(
            pure_rust::identity_public_key_from_seed(&seed, "", 0, IdentityKeyType::Slip13),
            None
        );
        assert_eq!(
            pure_rust::identity_public_key_from_seed(
                &seed,
                "ssh://satoshi@bitcoin.org",
                0x8000_0000,
                IdentityKeyType::Slip13,
            ),
            None
        );
    }

    #[test]
    fn bitcoin_taproot_address_matches_bip86_vector() {
        let seed = [
            0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55,
            0x56, 0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6,
            0xf6, 0xda, 0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86,
            0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
            0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
        ];
        let path = [0x8000_0056, 0x8000_0000, 0x8000_0000, 0, 0];
        let public_key = pure_rust::public_key_from_seed_path(&seed, &path).unwrap();

        assert_eq!(
            pure_rust::taproot_keyspend_output_key(&public_key).unwrap(),
            [
                0xa6, 0x08, 0x69, 0xf0, 0xdb, 0xcf, 0x1d, 0xc6, 0x59, 0xc9, 0xce, 0xcb, 0xaf, 0x80,
                0x50, 0x13, 0x5e, 0xa9, 0xe8, 0xcd, 0xc4, 0x87, 0x05, 0x3f, 0x1d, 0xc6, 0x88, 0x09,
                0x49, 0xdc, 0x68, 0x4c,
            ]
        );
        assert_eq!(
            pure_rust::bitcoin_singlesig_address_from_seed(
                &seed,
                &path,
                BitcoinNetwork::Main,
                SinglesigScriptVariant::Tr,
            )
            .unwrap(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    #[test]
    fn ecdh_nonce_hash_matches_libsecp_default_hash_then_wally_hash() {
        let mut private_key = [0u8; EC_PRIVATE_KEY_LEN];
        private_key[EC_PRIVATE_KEY_LEN - 1] = 1;
        let peer_public_key = pure_rust::public_key_from_private_key(&private_key).unwrap();

        assert_eq!(
            pure_rust::ecdh_nonce_hash(&private_key, &peer_public_key).unwrap(),
            [
                0xb1, 0xcd, 0x0a, 0x4e, 0xb6, 0xd1, 0xce, 0xa5, 0xeb, 0x28, 0x8f, 0xb4, 0x47, 0x4a,
                0xc4, 0x03, 0xea, 0xb0, 0x44, 0x00, 0x4c, 0xc4, 0x8f, 0x12, 0xbc, 0xb4, 0xca, 0x83,
                0x46, 0xd4, 0x87, 0xe1,
            ]
        );
    }

    #[test]
    fn ecdh_nonce_hash_rejects_invalid_inputs() {
        let mut private_key = [0u8; EC_PRIVATE_KEY_LEN];
        private_key[EC_PRIVATE_KEY_LEN - 1] = 1;
        let peer_public_key = [0u8; EC_PUBLIC_KEY_COMPRESSED_LEN];

        assert_eq!(
            pure_rust::ecdh_nonce_hash(&private_key, &peer_public_key),
            None
        );
    }

    #[test]
    fn deterministic_blinding_factor_matches_wally_hmac_layout() {
        let master = [0x11; 64];
        let hash_prevouts = [0x22; SHA256_LEN];

        assert_eq!(
            pure_rust::deterministic_blinding_factor(
                &master,
                &hash_prevouts,
                5,
                BlindingFactorKind::Asset
            )
            .unwrap()
            .as_slice(),
            &[
                0xc8, 0xa0, 0xa1, 0x77, 0x26, 0xfb, 0xcc, 0xa8, 0x0f, 0x97, 0xd5, 0x65, 0x5b, 0xc0,
                0xd0, 0xf5, 0x97, 0xbe, 0x99, 0xe2, 0xd4, 0xb4, 0xcf, 0xec, 0x95, 0xfa, 0x7b, 0x70,
                0x9b, 0x20, 0xbc, 0xdc,
            ]
        );

        assert_eq!(
            pure_rust::deterministic_blinding_factor(
                &master,
                &hash_prevouts,
                5,
                BlindingFactorKind::Value
            )
            .unwrap()
            .as_slice(),
            &[
                0xe4, 0x53, 0xd4, 0xd9, 0x71, 0xbf, 0x08, 0x87, 0x69, 0xf0, 0x58, 0x08, 0xc9, 0x35,
                0xd5, 0x26, 0x2e, 0xbc, 0xbb, 0xc0, 0xe1, 0xe7, 0x6a, 0x9e, 0x17, 0xde, 0xfb, 0x5a,
                0xf1, 0xa4, 0x85, 0x1b,
            ]
        );

        assert_eq!(
            pure_rust::deterministic_blinding_factor(
                &master,
                &hash_prevouts,
                5,
                BlindingFactorKind::AssetAndValue
            )
            .unwrap()
            .as_slice()
            .len(),
            SHA256_LEN * 2
        );
    }

    fn decode_hex_65(input: &str) -> [u8; 65] {
        assert_eq!(input.len(), 130);
        let mut output = [0u8; 65];
        let bytes = input.as_bytes();
        for (index, output_byte) in output.iter_mut().enumerate() {
            *output_byte = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        }
        output
    }

    fn decode_hex_64(input: &str) -> [u8; 64] {
        assert_eq!(input.len(), 128);
        let mut output = [0u8; 64];
        let bytes = input.as_bytes();
        for (index, output_byte) in output.iter_mut().enumerate() {
            *output_byte = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        }
        output
    }

    fn decode_hex_33(input: &str) -> [u8; 33] {
        assert_eq!(input.len(), 66);
        let mut output = [0u8; 33];
        let bytes = input.as_bytes();
        for (index, output_byte) in output.iter_mut().enumerate() {
            *output_byte = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        }
        output
    }

    fn decode_hex_32(input: &str) -> [u8; 32] {
        assert_eq!(input.len(), 64);
        let mut output = [0u8; 32];
        let bytes = input.as_bytes();
        for (index, output_byte) in output.iter_mut().enumerate() {
            *output_byte = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        }
        output
    }

    fn decode_xpub(input: &str) -> [u8; 78] {
        let bytes = base58ck::decode_check(input).unwrap();
        bytes.try_into().unwrap()
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex"),
        }
    }
}
