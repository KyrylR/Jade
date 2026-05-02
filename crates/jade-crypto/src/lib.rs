#![no_std]

extern crate alloc;

use zeroize::Zeroize;

pub const SHA256_LEN: usize = 32;
pub const SHA512_LEN: usize = 64;
pub const EC_PRIVATE_KEY_LEN: usize = 32;
pub const EC_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;

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
        BitcoinNetwork, BlindingFactorBytes, BlindingFactorKind, SinglesigScriptVariant,
        XpubPrefix, EC_PRIVATE_KEY_LEN, EC_PUBLIC_KEY_COMPRESSED_LEN, SHA256_LEN,
    };
    use alloc::string::String;
    use alloc::vec::Vec;
    use hmac::{Hmac, KeyInit, Mac};
    pub use k256;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, PublicKey, SecretKey};
    pub use p256;
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

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
}

#[cfg(all(test, feature = "pure-rust-curves"))]
mod tests {
    use super::*;

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
}
