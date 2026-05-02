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
pub enum SinglesigScriptVariant {
    Pkh,
    Wpkh,
    ShWpkh,
    Tr,
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
        IdentityKeyType, SinglesigScriptVariant, XpubPrefix, EC_PRIVATE_KEY_LEN,
        EC_PUBLIC_KEY_COMPRESSED_LEN, SHA256_LEN, SHA512_LEN,
    };
    use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
    use aes::{Aes256, Block};
    use alloc::string::String;
    use alloc::vec::Vec;
    use hmac::{Hmac, KeyInit, Mac};
    pub use k256;
    use k256::ecdsa::SigningKey as K256SigningKey;
    use k256::elliptic_curve::{bigint::U256, ops::Reduce, sec1::ToEncodedPoint};
    use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey};
    pub use p256;
    use p256::{
        ecdsa::{
            signature::hazmat::PrehashSigner, Signature as P256Signature,
            SigningKey as P256SigningKey,
        },
        FieldBytes as P256FieldBytes, ProjectivePoint as P256ProjectivePoint,
        PublicKey as P256PublicKey, Scalar as P256Scalar, SecretKey as P256SecretKey,
    };
    use sha2::{Digest, Sha256, Sha512};

    type HmacSha256 = Hmac<Sha256>;
    type HmacSha512 = Hmac<Sha512>;

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

    fn segwit_hrp(network: BitcoinNetwork) -> bech32::Hrp {
        match network {
            BitcoinNetwork::Main => bech32::hrp::BC,
            BitcoinNetwork::Test => bech32::hrp::TB,
            BitcoinNetwork::Regtest => bech32::hrp::BCRT,
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

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex"),
        }
    }
}
