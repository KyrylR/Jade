use alloc::borrow::Cow;

use crate::{AllocationBudget, CoreState, OtaRequest, Platform};
use jade_protocol_v2::{Request, Response, VersionInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSoc {
    Esp32,
    Esp32S3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTarget {
    Jade,
    JadeV1_1,
    JadeV2,
    JadeV2c,
}

impl DeviceTarget {
    pub const fn soc(self) -> DeviceSoc {
        match self {
            Self::Jade | Self::JadeV1_1 => DeviceSoc::Esp32,
            Self::JadeV2 | Self::JadeV2c => DeviceSoc::Esp32S3,
        }
    }

    pub const fn public_name(self) -> &'static str {
        match self {
            Self::Jade => "jade",
            Self::JadeV1_1 => "jade_v1_1",
            Self::JadeV2 => "jade_v2",
            Self::JadeV2c => "jade_v2c",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceFeatureSet {
    pub serial: bool,
    pub ble: bool,
    pub usb: bool,
    pub camera_qr: bool,
    pub touch: bool,
    pub hardware_attestation: bool,
    pub secure_boot: bool,
    pub flash_encryption: bool,
    pub anti_rollback: bool,
}

impl DeviceFeatureSet {
    pub const ESP32_BASE: Self = Self {
        serial: true,
        ble: true,
        usb: false,
        camera_qr: true,
        touch: false,
        hardware_attestation: false,
        secure_boot: true,
        flash_encryption: true,
        anti_rollback: true,
    };

    pub const ESP32S3_BASE: Self = Self {
        serial: true,
        ble: true,
        usb: true,
        camera_qr: true,
        touch: true,
        hardware_attestation: true,
        secure_boot: true,
        flash_encryption: true,
        anti_rollback: true,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceMemoryBudget {
    pub allocation: AllocationBudget,
    pub stack_bytes: usize,
    pub heap_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePartitionLayout {
    pub name: &'static str,
    pub ota_slots: u8,
    pub nvs_bytes: usize,
    pub factory_app_bytes: usize,
    pub ota_app_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceManifest {
    pub target: DeviceTarget,
    pub features: DeviceFeatureSet,
    pub memory: DeviceMemoryBudget,
    pub partitions: DevicePartitionLayout,
}

impl DeviceManifest {
    pub const fn target_name(self) -> &'static str {
        self.target.public_name()
    }

    pub const fn soc(self) -> DeviceSoc {
        self.target.soc()
    }

    pub const fn supports_real_attestation(self) -> bool {
        self.features.hardware_attestation && matches!(self.soc(), DeviceSoc::Esp32S3)
    }

    pub fn validate_ota_request(self, request: &OtaRequest) -> Result<(), DeviceOtaError> {
        if self.partitions.ota_slots == 0 || self.partitions.ota_app_bytes == 0 {
            return Err(DeviceOtaError::NoOtaSlot);
        }

        let slot_bytes = self.partitions.ota_app_bytes as u64;
        if request.firmware_size > slot_bytes {
            return Err(DeviceOtaError::FirmwareTooLarge);
        }
        if request.compressed_size > slot_bytes {
            return Err(DeviceOtaError::CompressedUploadTooLarge);
        }
        if request
            .patch_size
            .is_some_and(|patch_size| patch_size > slot_bytes)
        {
            return Err(DeviceOtaError::DeltaPatchTooLarge);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceOtaError {
    NoOtaSlot,
    FirmwareTooLarge,
    CompressedUploadTooLarge,
    DeltaPatchTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceBootFailure {
    EntropyUnavailable,
    StorageUnavailable,
    OtaStateInvalid,
    TransportUnavailable,
    DisplayUnavailable,
    RollbackStateInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceBootReadiness {
    pub entropy_ready: bool,
    pub storage_ready: bool,
    pub ota_ready: bool,
    pub transport_ready: bool,
    pub display_ready: bool,
    pub rollback_ready: bool,
}

impl DeviceBootReadiness {
    pub const fn ready() -> Self {
        Self {
            entropy_ready: true,
            storage_ready: true,
            ota_ready: true,
            transport_ready: true,
            display_ready: true,
            rollback_ready: true,
        }
    }

    pub const fn first_failure(self) -> Option<DeviceBootFailure> {
        if !self.entropy_ready {
            Some(DeviceBootFailure::EntropyUnavailable)
        } else if !self.storage_ready {
            Some(DeviceBootFailure::StorageUnavailable)
        } else if !self.ota_ready {
            Some(DeviceBootFailure::OtaStateInvalid)
        } else if !self.transport_ready {
            Some(DeviceBootFailure::TransportUnavailable)
        } else if !self.display_ready {
            Some(DeviceBootFailure::DisplayUnavailable)
        } else if !self.rollback_ready {
            Some(DeviceBootFailure::RollbackStateInvalid)
        } else {
            None
        }
    }
}

impl Default for DeviceBootReadiness {
    fn default() -> Self {
        Self::ready()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceBootReport {
    pub target: DeviceTarget,
    pub entropy_ready: bool,
    pub storage_ready: bool,
    pub ota_ready: bool,
    pub transport_ready: bool,
    pub display_ready: bool,
    pub rollback_ready: bool,
}

impl DeviceBootReport {
    pub const fn ok(target: DeviceTarget) -> Self {
        Self::from_readiness(target, DeviceBootReadiness::ready())
    }

    pub const fn from_readiness(target: DeviceTarget, readiness: DeviceBootReadiness) -> Self {
        Self {
            target,
            entropy_ready: readiness.entropy_ready,
            storage_ready: readiness.storage_ready,
            ota_ready: readiness.ota_ready,
            transport_ready: readiness.transport_ready,
            display_ready: readiness.display_ready,
            rollback_ready: readiness.rollback_ready,
        }
    }

    pub const fn readiness(self) -> DeviceBootReadiness {
        DeviceBootReadiness {
            entropy_ready: self.entropy_ready,
            storage_ready: self.storage_ready,
            ota_ready: self.ota_ready,
            transport_ready: self.transport_ready,
            display_ready: self.display_ready,
            rollback_ready: self.rollback_ready,
        }
    }

    pub const fn first_failure(self) -> Option<DeviceBootFailure> {
        self.readiness().first_failure()
    }
}

pub trait DevicePlatform: Platform {
    fn manifest(&self) -> DeviceManifest;
    fn boot_report(&mut self) -> DeviceBootReport;
    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), DeviceBootFailure>;
    fn monotonic_millis(&self) -> u64;
    fn rollback_secure_version(&self) -> u32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRuntimeError {
    Boot(DeviceBootFailure),
}

#[derive(Debug)]
pub struct DeviceRuntime<P> {
    state: CoreState,
    platform: P,
    booted: bool,
}

impl<P> DeviceRuntime<P>
where
    P: DevicePlatform,
{
    pub fn new(platform: P) -> Self {
        Self {
            state: CoreState::default(),
            platform,
            booted: false,
        }
    }

    pub fn boot(&mut self) -> Result<DeviceBootReport, DeviceRuntimeError> {
        let report = self.platform.boot_report();
        if let Some(failure) = report.first_failure() {
            self.booted = false;
            Err(DeviceRuntimeError::Boot(failure))
        } else {
            self.booted = true;
            Ok(report)
        }
    }

    pub fn is_booted(&self) -> bool {
        self.booted
    }

    pub fn state(&self) -> &CoreState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut CoreState {
        &mut self.state
    }

    pub fn platform(&self) -> &P {
        &self.platform
    }

    pub fn platform_mut(&mut self) -> &mut P {
        &mut self.platform
    }

    pub(crate) fn state_and_platform_mut(&mut self) -> (&mut CoreState, &mut P) {
        (&mut self.state, &mut self.platform)
    }

    pub fn manifest(&self) -> DeviceManifest {
        self.platform.manifest()
    }

    pub fn version_info(&self) -> VersionInfo<'_> {
        self.state.version_info(&self.platform)
    }

    pub fn handle_v2<'a>(&'a mut self, request: Request<'a>) -> Response<'a> {
        self.state.handle_v2(&mut self.platform, request)
    }
}

pub fn static_version_info(
    manifest: DeviceManifest,
    state: &CoreState,
    idf_version: &'static str,
    efusemac: &'static str,
    has_pin: bool,
) -> VersionInfo<'static> {
    VersionInfo {
        jade_version: Cow::Borrowed(env!("CARGO_PKG_VERSION")),
        jade_ota_max_chunk: 4096,
        jade_config: Cow::Borrowed(match manifest.soc() {
            DeviceSoc::Esp32 => "ESP32",
            DeviceSoc::Esp32S3 => "ESP32S3",
        }),
        board_type: Cow::Borrowed(manifest.target_name()),
        jade_features: Cow::Borrowed(if manifest.features.ble {
            "BLE,RUST"
        } else {
            "NORADIO,RUST"
        }),
        idf_version: Cow::Borrowed(idf_version),
        chip_features: Cow::Borrowed(match manifest.soc() {
            DeviceSoc::Esp32 => "ESP32",
            DeviceSoc::Esp32S3 => "ESP32S3",
        }),
        efusemac: Cow::Borrowed(efusemac),
        attestation_initialised: manifest.supports_real_attestation(),
        battery_status: 0,
        battery_millivolts: 0,
        battery_charging: false,
        jade_state: state.wallet.into(),
        jade_networks: crate::NetworkRestriction::All,
        jade_has_pin: has_pin,
        debug: Some(crate::VersionDebugInfo {
            nvs_entries_used: 0,
            nvs_entries_free: 0,
            free_heap: manifest.memory.heap_bytes as u64,
            free_dram: manifest.memory.heap_bytes as u64,
            largest_dram: manifest.memory.heap_bytes as u64,
            free_spiram: 0,
            largest_spiram: 0,
            gcov: false,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use jade_protocol_v2::{NetworkRestriction, VersionDebugInfo, VersionInfoState};

    #[derive(Debug)]
    struct TestDevice {
        manifest: DeviceManifest,
        report: DeviceBootReport,
    }

    impl Platform for TestDevice {
        fn version_info<'a>(&'a self, state: &CoreState) -> VersionInfo<'a> {
            VersionInfo {
                jade_version: Cow::Borrowed("device-test"),
                jade_ota_max_chunk: 4096,
                jade_config: Cow::Borrowed("TEST"),
                board_type: Cow::Borrowed(self.manifest.target_name()),
                jade_features: Cow::Borrowed("RUST"),
                idf_version: Cow::Borrowed("host"),
                chip_features: Cow::Borrowed("test"),
                efusemac: Cow::Borrowed("000000000000"),
                attestation_initialised: false,
                battery_status: 0,
                battery_millivolts: 0,
                battery_charging: false,
                jade_state: state.wallet.into(),
                jade_networks: NetworkRestriction::All,
                jade_has_pin: false,
                debug: Some(VersionDebugInfo {
                    nvs_entries_used: 0,
                    nvs_entries_free: 0,
                    free_heap: 1,
                    free_dram: 1,
                    largest_dram: 1,
                    free_spiram: 0,
                    largest_spiram: 0,
                    gcov: false,
                }),
            }
        }

        fn add_entropy(&mut self, entropy: &[u8]) -> crate::CoreResult<()> {
            if entropy.is_empty() {
                Err(crate::CoreError::BadParameters)
            } else {
                Ok(())
            }
        }

        fn set_epoch(&mut self, _epoch: u64) -> crate::CoreResult<()> {
            Ok(())
        }
    }

    impl DevicePlatform for TestDevice {
        fn manifest(&self) -> DeviceManifest {
            self.manifest
        }

        fn boot_report(&mut self) -> DeviceBootReport {
            self.report
        }

        fn fill_random(&mut self, out: &mut [u8]) -> Result<(), DeviceBootFailure> {
            out.fill(0xa5);
            Ok(())
        }

        fn monotonic_millis(&self) -> u64 {
            42
        }

        fn rollback_secure_version(&self) -> u32 {
            1
        }
    }

    const TEST_MANIFEST: DeviceManifest = DeviceManifest {
        target: DeviceTarget::JadeV2,
        features: DeviceFeatureSet::ESP32S3_BASE,
        memory: DeviceMemoryBudget {
            allocation: AllocationBudget::ESP32_SPIRAM,
            stack_bytes: 16 * 1024,
            heap_bytes: 512 * 1024,
        },
        partitions: DevicePartitionLayout {
            name: "partitionss3.csv",
            ota_slots: 2,
            nvs_bytes: 0x6000,
            factory_app_bytes: 0x1f0000,
            ota_app_bytes: 0x1f0000,
        },
    };

    #[test]
    fn runtime_boots_only_when_all_platform_checks_pass() {
        let platform = TestDevice {
            manifest: TEST_MANIFEST,
            report: DeviceBootReport::ok(DeviceTarget::JadeV2),
        };
        let mut runtime = DeviceRuntime::new(platform);

        assert_eq!(runtime.boot().unwrap().target, DeviceTarget::JadeV2);
        assert!(runtime.is_booted());
        assert!(runtime.manifest().supports_real_attestation());
    }

    #[test]
    fn runtime_reports_first_boot_failure() {
        let platform = TestDevice {
            manifest: TEST_MANIFEST,
            report: DeviceBootReport {
                entropy_ready: false,
                ..DeviceBootReport::ok(DeviceTarget::JadeV2)
            },
        };
        let mut runtime = DeviceRuntime::new(platform);

        assert_eq!(
            runtime.boot(),
            Err(DeviceRuntimeError::Boot(
                DeviceBootFailure::EntropyUnavailable
            ))
        );
        assert!(!runtime.is_booted());
    }

    #[test]
    fn boot_readiness_builds_target_report_and_preserves_failure_order() {
        let readiness = DeviceBootReadiness {
            transport_ready: false,
            display_ready: false,
            ..DeviceBootReadiness::ready()
        };
        let report = DeviceBootReport::from_readiness(DeviceTarget::JadeV1_1, readiness);

        assert_eq!(report.target, DeviceTarget::JadeV1_1);
        assert_eq!(report.readiness(), readiness);
        assert_eq!(
            readiness.first_failure(),
            Some(DeviceBootFailure::TransportUnavailable)
        );
        assert_eq!(
            report.first_failure(),
            Some(DeviceBootFailure::TransportUnavailable)
        );
    }

    #[test]
    fn static_version_info_is_target_specific() {
        let state = CoreState::default();
        let info = static_version_info(TEST_MANIFEST, &state, "esp-idf-rust", "aabbccddeeff", true);

        assert_eq!(info.board_type, "jade_v2");
        assert_eq!(info.jade_config, "ESP32S3");
        assert_eq!(info.jade_state, VersionInfoState::Uninit);
        assert!(info.attestation_initialised);
        assert!(info.jade_has_pin);
    }

    #[test]
    fn ota_request_must_fit_target_slot() {
        let request = OtaRequest::full(
            TEST_MANIFEST.partitions.ota_app_bytes as u64,
            512 * 1024,
            Some([0x11; crate::OTA_HASH_LEN]),
            None,
            false,
        )
        .unwrap();
        assert_eq!(TEST_MANIFEST.validate_ota_request(&request), Ok(()));

        let too_large = OtaRequest::full(
            TEST_MANIFEST.partitions.ota_app_bytes as u64 + 1,
            512 * 1024,
            Some([0x11; crate::OTA_HASH_LEN]),
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            TEST_MANIFEST.validate_ota_request(&too_large),
            Err(DeviceOtaError::FirmwareTooLarge)
        );

        let patch_too_large = OtaRequest::delta(
            1_000,
            TEST_MANIFEST.partitions.ota_app_bytes as u64 + 1,
            600,
            Some([0x11; crate::OTA_HASH_LEN]),
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            TEST_MANIFEST.validate_ota_request(&patch_too_large),
            Err(DeviceOtaError::DeltaPatchTooLarge)
        );
    }
}
