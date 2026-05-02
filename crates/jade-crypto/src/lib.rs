#![no_std]

extern crate alloc;

use zeroize::Zeroize;

pub const SHA256_LEN: usize = 32;
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

#[cfg(feature = "pure-rust-curves")]
pub mod pure_rust {
    use super::{EC_PRIVATE_KEY_LEN, EC_PUBLIC_KEY_COMPRESSED_LEN, SHA256_LEN};
    use hmac::{Hmac, KeyInit, Mac};
    pub use k256;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, PublicKey, SecretKey};
    pub use p256;
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

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
}

#[cfg(all(test, feature = "pure-rust-curves"))]
mod tests {
    use super::*;

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
}
