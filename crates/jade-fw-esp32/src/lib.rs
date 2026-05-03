#![no_std]

#[cfg(test)]
extern crate alloc;

use jade_core::{
    AllocationBudget, DeviceBootFailure, DeviceFeatureSet, DeviceManifest, DeviceMemoryBudget,
    DevicePartitionLayout, DevicePlatform, DeviceRuntime, DeviceTarget, FirmwareFrameError,
    FirmwareProtocol,
};

pub const TARGET_SOC: &str = "esp32";
pub const OFFICIAL_TARGETS: &[DeviceTarget] = &[DeviceTarget::Jade, DeviceTarget::JadeV1_1];

pub const PARTITION_LAYOUT: DevicePartitionLayout = DevicePartitionLayout {
    name: "partitions.csv",
    ota_slots: 2,
    nvs_bytes: 0x4000,
    factory_app_bytes: 1984 * 1024,
    ota_app_bytes: 1984 * 1024,
};

pub const MEMORY_BUDGET: DeviceMemoryBudget = DeviceMemoryBudget {
    allocation: AllocationBudget::ESP32_NO_SPIRAM,
    stack_bytes: 16 * 1024,
    heap_bytes: 256 * 1024,
};

pub const JADE_MANIFEST: DeviceManifest = DeviceManifest {
    target: DeviceTarget::Jade,
    features: DeviceFeatureSet::ESP32_BASE,
    memory: MEMORY_BUDGET,
    partitions: PARTITION_LAYOUT,
};

pub const JADE_V1_1_MANIFEST: DeviceManifest = DeviceManifest {
    target: DeviceTarget::JadeV1_1,
    features: DeviceFeatureSet::ESP32_BASE,
    memory: MEMORY_BUDGET,
    partitions: PARTITION_LAYOUT,
};

pub trait Esp32PlatformShim: DevicePlatform {
    fn serial_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure>;
    fn serial_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure>;
    fn ble_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure>;
    fn ble_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure>;
    fn camera_qr_scan(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure>;
}

pub type Esp32Runtime<P> = DeviceRuntime<P>;
pub type Esp32V1Runtime<P, B> = jade_emulator::JadeRuntime<P, B>;

pub fn runtime_for_v1<P>(platform: P) -> Esp32Runtime<P>
where
    P: Esp32PlatformShim,
{
    DeviceRuntime::new(platform)
}

pub fn v1_runtime_for_v1<P, B>(platform: P, storage_backend: B) -> Esp32V1Runtime<P, B>
where
    P: jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    jade_emulator::JadeRuntime::from_parts(
        platform,
        storage_backend,
        jade_storage::StorageLimits::ESP32_NVS_DEFAULT,
    )
}

pub fn manifest_for_target(target: DeviceTarget) -> Option<DeviceManifest> {
    match target {
        DeviceTarget::Jade => Some(JADE_MANIFEST),
        DeviceTarget::JadeV1_1 => Some(JADE_V1_1_MANIFEST),
        _ => None,
    }
}

pub fn assert_manifest_matches_real_device(manifest: DeviceManifest) -> Result<(), &'static str> {
    if !matches!(manifest.target, DeviceTarget::Jade | DeviceTarget::JadeV1_1) {
        return Err("not an esp32 Jade target");
    }
    if manifest.partitions.ota_slots != 2 {
        return Err("esp32 firmware requires dual OTA slots");
    }
    if manifest.partitions.ota_app_bytes < 1984 * 1024 {
        return Err("esp32 OTA slot is smaller than the shipping partition table");
    }
    if manifest.features.usb || manifest.features.touch || manifest.features.hardware_attestation {
        return Err("esp32 target advertises esp32s3-only capabilities");
    }
    if !manifest.features.serial || !manifest.features.ble || !manifest.features.camera_qr {
        return Err("esp32 target is missing required user I/O");
    }
    if !manifest.features.secure_boot
        || !manifest.features.flash_encryption
        || !manifest.features.anti_rollback
    {
        return Err("esp32 target is missing release security gates");
    }
    Ok(())
}

pub fn poll_serial_v1<P>(
    runtime: &mut Esp32Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim,
{
    poll_serial(runtime, rx_buffer, FirmwareProtocol::V1Cbor)
}

pub fn poll_serial_v2<P>(
    runtime: &mut Esp32Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim,
{
    poll_serial(runtime, rx_buffer, FirmwareProtocol::V2Cbor)
}

pub fn poll_ble_v1<P>(
    runtime: &mut Esp32Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim,
{
    poll_ble(runtime, rx_buffer, FirmwareProtocol::V1Cbor)
}

pub fn poll_ble_v2<P>(
    runtime: &mut Esp32Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim,
{
    poll_ble(runtime, rx_buffer, FirmwareProtocol::V2Cbor)
}

fn poll_serial<P>(
    runtime: &mut Esp32Runtime<P>,
    rx_buffer: &mut [u8],
    protocol: FirmwareProtocol,
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim,
{
    let len = runtime
        .platform_mut()
        .serial_recv(rx_buffer)
        .map_err(FirmwareFrameError::Io)?;
    if len == 0 {
        return Ok(false);
    }
    if let Some(reply) = runtime.handle_firmware_frame(protocol, &rx_buffer[..len])? {
        runtime
            .platform_mut()
            .serial_send(&reply)
            .map_err(FirmwareFrameError::Io)?;
    }
    Ok(true)
}

fn poll_ble<P>(
    runtime: &mut Esp32Runtime<P>,
    rx_buffer: &mut [u8],
    protocol: FirmwareProtocol,
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim,
{
    let len = runtime
        .platform_mut()
        .ble_recv(rx_buffer)
        .map_err(FirmwareFrameError::Io)?;
    if len == 0 {
        return Ok(false);
    }
    if let Some(reply) = runtime.handle_firmware_frame(protocol, &rx_buffer[..len])? {
        runtime
            .platform_mut()
            .ble_send(&reply)
            .map_err(FirmwareFrameError::Io)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{borrow::Cow, vec::Vec};
    use jade_core::{CoreResult, CoreState, Platform, VersionInfo};
    use jade_protocol_v2::{RequestBody, RequestKind, ResponseBody};
    use minicbor::{Decoder, Encoder};

    #[derive(Debug)]
    struct TestPlatform {
        manifest: DeviceManifest,
        serial_rx: Option<Vec<u8>>,
        serial_tx: Vec<Vec<u8>>,
        ble_rx: Option<Vec<u8>>,
        ble_tx: Vec<Vec<u8>>,
    }

    impl TestPlatform {
        fn new(manifest: DeviceManifest) -> Self {
            Self {
                manifest,
                serial_rx: None,
                serial_tx: Vec::new(),
                ble_rx: None,
                ble_tx: Vec::new(),
            }
        }

        fn recv_frame(
            slot: &mut Option<Vec<u8>>,
            out: &mut [u8],
        ) -> Result<usize, DeviceBootFailure> {
            let Some(frame) = slot.take() else {
                return Ok(0);
            };
            if frame.len() > out.len() {
                return Err(DeviceBootFailure::TransportUnavailable);
            }
            out[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }
    }

    impl Platform for TestPlatform {
        fn version_info<'a>(&'a self, state: &CoreState) -> VersionInfo<'a> {
            jade_core::static_version_info(
                self.manifest,
                state,
                "esp-idf-rust",
                "001122334455",
                false,
            )
        }

        fn add_entropy(&mut self, _entropy: &[u8]) -> CoreResult<()> {
            Ok(())
        }

        fn set_epoch(&mut self, _epoch: u64) -> CoreResult<()> {
            Ok(())
        }
    }

    impl DevicePlatform for TestPlatform {
        fn manifest(&self) -> DeviceManifest {
            self.manifest
        }

        fn boot_report(&mut self) -> jade_core::DeviceBootReport {
            jade_core::DeviceBootReport::ok(self.manifest.target)
        }

        fn fill_random(&mut self, out: &mut [u8]) -> Result<(), DeviceBootFailure> {
            out.fill(0x5a);
            Ok(())
        }

        fn monotonic_millis(&self) -> u64 {
            1
        }

        fn rollback_secure_version(&self) -> u32 {
            1
        }
    }

    impl Esp32PlatformShim for TestPlatform {
        fn serial_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure> {
            self.serial_tx.push(bytes.to_vec());
            Ok(())
        }

        fn serial_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Self::recv_frame(&mut self.serial_rx, out)
        }

        fn ble_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure> {
            self.ble_tx.push(bytes.to_vec());
            Ok(())
        }

        fn ble_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Self::recv_frame(&mut self.ble_rx, out)
        }

        fn camera_qr_scan(&mut self, _out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Ok(0)
        }
    }

    #[test]
    fn esp32_manifests_match_shipping_targets() {
        assert_eq!(manifest_for_target(DeviceTarget::Jade), Some(JADE_MANIFEST));
        assert_eq!(
            manifest_for_target(DeviceTarget::JadeV1_1),
            Some(JADE_V1_1_MANIFEST)
        );
        assert_eq!(manifest_for_target(DeviceTarget::JadeV2), None);
        assert_manifest_matches_real_device(JADE_MANIFEST).unwrap();
        assert_manifest_matches_real_device(JADE_V1_1_MANIFEST).unwrap();
    }

    #[test]
    fn esp32_runtime_uses_shared_core_boot_path() {
        let mut runtime = runtime_for_v1(TestPlatform::new(JADE_MANIFEST));
        assert_eq!(runtime.boot().unwrap().target, DeviceTarget::Jade);
        assert!(runtime.is_booted());
        assert_eq!(runtime.version_info().board_type, Cow::Borrowed("jade"));
    }

    #[test]
    fn esp32_exposes_full_v1_runtime_constructor() {
        let runtime = v1_runtime_for_v1(
            jade_emulator::HostPlatform::default(),
            jade_storage::MemoryStorage::new(),
        );

        assert_eq!(runtime.state().wallet, jade_core::WalletLifecycle::Uninit);
    }

    #[test]
    fn esp32_serial_polls_v1_cbor_frames() {
        let mut runtime = runtime_for_v1(TestPlatform::new(JADE_MANIFEST));
        runtime.boot().unwrap();
        runtime.platform_mut().serial_rx = Some(v1_request("p", "ping"));

        let mut rx = [0u8; 128];
        assert_eq!(poll_serial_v1(&mut runtime, &mut rx), Ok(true));
        assert_eq!(runtime.platform().serial_tx.len(), 1);

        let mut decoder = Decoder::new(&runtime.platform().serial_tx[0]);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "p");
        assert_eq!(decoder.str().unwrap(), "result");
        assert_eq!(decoder.u64().unwrap(), 0);
    }

    #[test]
    fn esp32_ble_polls_v2_cbor_frames() {
        let mut runtime = runtime_for_v1(TestPlatform::new(JADE_MANIFEST));
        runtime.boot().unwrap();
        runtime.platform_mut().ble_rx = Some(v2_ping_request("b"));

        let mut rx = [0u8; 128];
        assert_eq!(poll_ble_v2(&mut runtime, &mut rx), Ok(true));
        assert_eq!(runtime.platform().ble_tx.len(), 1);

        let response: jade_protocol_v2::Response<'_> =
            minicbor::decode(&runtime.platform().ble_tx[0]).unwrap();
        assert_eq!(response.id, "b");
        assert_eq!(
            response.body,
            ResponseBody::Busy {
                activity: jade_protocol_v2::OperationActivity::Idle
            }
        );
    }

    fn v1_request(id: &str, method: &str) -> Vec<u8> {
        let mut output = Vec::new();
        Encoder::new(&mut output)
            .map(2)
            .and_then(|encoder| encoder.str("id"))
            .and_then(|encoder| encoder.str(id))
            .and_then(|encoder| encoder.str("method"))
            .and_then(|encoder| encoder.str(method))
            .expect("Vec-backed CBOR encoding is infallible");
        output
    }

    fn v2_ping_request(id: &str) -> Vec<u8> {
        minicbor::to_vec(jade_protocol_v2::Request {
            id: Cow::Borrowed(id),
            kind: RequestKind::Ping,
            session: None,
            body: RequestBody::Empty,
        })
        .unwrap()
    }
}
