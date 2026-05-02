use crate::{CoreError, CoreResult};

pub const OTA_HASH_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaKind {
    Full,
    Delta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaHashType {
    FullFirmware,
    CompressedUpload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtaRequest {
    pub kind: OtaKind,
    pub firmware_size: u64,
    pub compressed_size: u64,
    pub patch_size: Option<u64>,
    pub hash_type: OtaHashType,
    pub expected_hash: [u8; OTA_HASH_LEN],
    pub extended_replies: bool,
}

impl OtaRequest {
    pub fn full(
        firmware_size: u64,
        compressed_size: u64,
        full_firmware_hash: Option<[u8; OTA_HASH_LEN]>,
        compressed_upload_hash: Option<[u8; OTA_HASH_LEN]>,
        extended_replies: bool,
    ) -> CoreResult<Self> {
        validate_full_sizes(firmware_size, compressed_size)?;
        let (hash_type, expected_hash) = select_hash(full_firmware_hash, compressed_upload_hash)?;

        Ok(Self {
            kind: OtaKind::Full,
            firmware_size,
            compressed_size,
            patch_size: None,
            hash_type,
            expected_hash,
            extended_replies,
        })
    }

    pub fn delta(
        firmware_size: u64,
        patch_size: u64,
        compressed_size: u64,
        full_firmware_hash: Option<[u8; OTA_HASH_LEN]>,
        compressed_upload_hash: Option<[u8; OTA_HASH_LEN]>,
        extended_replies: bool,
    ) -> CoreResult<Self> {
        validate_full_sizes(firmware_size, compressed_size)?;
        if patch_size <= compressed_size {
            return Err(CoreError::BadParameters);
        }
        let (hash_type, expected_hash) = select_hash(full_firmware_hash, compressed_upload_hash)?;

        Ok(Self {
            kind: OtaKind::Delta,
            firmware_size,
            compressed_size,
            patch_size: Some(patch_size),
            hash_type,
            expected_hash,
            extended_replies,
        })
    }

    pub fn upload_progress_percent(&self, received_compressed: u64) -> u64 {
        if self.compressed_size == 0 {
            return 0;
        }

        received_compressed
            .saturating_mul(100)
            .checked_div(self.compressed_size)
            .unwrap_or(0)
            .min(100)
    }
}

fn validate_full_sizes(firmware_size: u64, compressed_size: u64) -> CoreResult<()> {
    if firmware_size <= compressed_size {
        return Err(CoreError::BadParameters);
    }
    Ok(())
}

fn select_hash(
    full_firmware_hash: Option<[u8; OTA_HASH_LEN]>,
    compressed_upload_hash: Option<[u8; OTA_HASH_LEN]>,
) -> CoreResult<(OtaHashType, [u8; OTA_HASH_LEN])> {
    if let Some(hash) = full_firmware_hash {
        Ok((OtaHashType::FullFirmware, hash))
    } else if let Some(hash) = compressed_upload_hash {
        Ok((OtaHashType::CompressedUpload, hash))
    } else {
        Err(CoreError::BadParameters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_ota_validates_sizes_and_prefers_final_firmware_hash() {
        let full_hash = [0x11; OTA_HASH_LEN];
        let compressed_hash = [0x22; OTA_HASH_LEN];

        let request =
            OtaRequest::full(1_000, 600, Some(full_hash), Some(compressed_hash), true).unwrap();

        assert_eq!(request.kind, OtaKind::Full);
        assert_eq!(request.hash_type, OtaHashType::FullFirmware);
        assert_eq!(request.expected_hash, full_hash);
        assert!(request.extended_replies);
        assert_eq!(request.upload_progress_percent(300), 50);
    }

    #[test]
    fn full_ota_accepts_legacy_compressed_hash() {
        let compressed_hash = [0x22; OTA_HASH_LEN];

        let request = OtaRequest::full(1_000, 600, None, Some(compressed_hash), false).unwrap();

        assert_eq!(request.hash_type, OtaHashType::CompressedUpload);
        assert_eq!(request.expected_hash, compressed_hash);
    }

    #[test]
    fn delta_ota_requires_patch_larger_than_compressed_upload() {
        assert_eq!(
            OtaRequest::delta(1_000, 600, 600, None, Some([0x22; OTA_HASH_LEN]), false),
            Err(CoreError::BadParameters)
        );

        let request =
            OtaRequest::delta(1_000, 700, 600, None, Some([0x22; OTA_HASH_LEN]), false).unwrap();
        assert_eq!(request.kind, OtaKind::Delta);
        assert_eq!(request.patch_size, Some(700));
    }

    #[test]
    fn ota_requires_hash_and_firmware_larger_than_compressed_upload() {
        assert_eq!(
            OtaRequest::full(600, 600, None, Some([0x22; OTA_HASH_LEN]), false),
            Err(CoreError::BadParameters)
        );
        assert_eq!(
            OtaRequest::full(1_000, 600, None, None, false),
            Err(CoreError::BadParameters)
        );
    }
}
