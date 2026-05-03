#![no_std]

#[cfg(test)]
extern crate alloc;

use jade_core::{
    AllocationBudget, DeviceBootFailure, DeviceFeatureSet, DeviceManifest, DeviceMemoryBudget,
    DevicePartitionLayout, DevicePlatform, DeviceRuntime, DeviceRuntimeError, DeviceTarget,
    FirmwareFrameError, FirmwareProtocol, OtaImageWriter, OtaRequest, OtaWriteError,
    OtaWriteSession,
};

pub const TARGET_SOC: &str = "esp32s3";
pub const OFFICIAL_TARGETS: &[DeviceTarget] = &[DeviceTarget::JadeV2, DeviceTarget::JadeV2c];

pub const PARTITION_LAYOUT: DevicePartitionLayout = DevicePartitionLayout {
    name: "partitionss3.csv",
    ota_slots: 2,
    nvs_bytes: 0x10000,
    factory_app_bytes: 4024 * 1024,
    ota_app_bytes: 4024 * 1024,
};

pub const MEMORY_BUDGET: DeviceMemoryBudget = DeviceMemoryBudget {
    allocation: AllocationBudget::ESP32_SPIRAM,
    stack_bytes: 24 * 1024,
    heap_bytes: 768 * 1024,
};

pub const JADE_V2_MANIFEST: DeviceManifest = DeviceManifest {
    target: DeviceTarget::JadeV2,
    features: DeviceFeatureSet::ESP32S3_BASE,
    memory: MEMORY_BUDGET,
    partitions: PARTITION_LAYOUT,
};

pub const JADE_V2C_MANIFEST: DeviceManifest = DeviceManifest {
    target: DeviceTarget::JadeV2c,
    features: DeviceFeatureSet::ESP32S3_BASE,
    memory: MEMORY_BUDGET,
    partitions: PARTITION_LAYOUT,
};

pub trait Esp32s3PlatformShim: DevicePlatform {
    fn serial_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure>;
    fn serial_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure>;
    fn usb_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure>;
    fn usb_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure>;
    fn ble_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure>;
    fn ble_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure>;
    fn camera_qr_scan(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure>;
    fn touch_poll(&mut self) -> Result<Option<TouchEvent>, DeviceBootFailure>;
    fn hardware_attestation_available(&self) -> bool;
    fn hardware_attestation_public_key_pem(
        &mut self,
        out: &mut [u8],
    ) -> Result<usize, DeviceBootFailure>;
    fn hardware_attestation_ext_signature(
        &mut self,
        out: &mut [u8],
    ) -> Result<usize, DeviceBootFailure>;
    fn hardware_attestation_sign(
        &mut self,
        challenge: &[u8],
        out: &mut [u8],
    ) -> Result<usize, DeviceBootFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchEvent {
    Press { x: u16, y: u16 },
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareAttestationReply<'a> {
    pub signature: &'a [u8],
    pub pubkey_pem: &'a [u8],
    pub ext_signature: &'a [u8],
}

pub type Esp32s3Runtime<P> = DeviceRuntime<P>;
pub type Esp32s3V1Runtime<P, B> = jade_emulator::JadeRuntime<P, B>;
pub type Esp32s3OtaSession<W> = OtaWriteSession<W>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Esp32s3V1PollReport {
    pub serial: bool,
    pub usb: bool,
    pub ble: bool,
}

impl Esp32s3V1PollReport {
    pub const fn any(self) -> bool {
        self.serial || self.usb || self.ble
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Esp32s3OtaStartError<E> {
    Manifest(&'static str),
    Partition(jade_core::DeviceOtaError),
    Writer(OtaWriteError<E>),
}

pub fn begin_ota_update<W>(
    manifest: DeviceManifest,
    writer: W,
    request: OtaRequest,
) -> Result<Esp32s3OtaSession<W>, Esp32s3OtaStartError<W::Error>>
where
    W: OtaImageWriter,
{
    assert_manifest_matches_real_device(manifest).map_err(Esp32s3OtaStartError::Manifest)?;
    manifest
        .validate_ota_request(&request)
        .map_err(Esp32s3OtaStartError::Partition)?;
    OtaWriteSession::begin(writer, request).map_err(Esp32s3OtaStartError::Writer)
}

#[derive(Debug)]
pub struct Esp32s3V1BoardRuntime<P, B> {
    runtime: Esp32s3V1Runtime<P, B>,
    booted: bool,
}

impl<P, B> Esp32s3V1BoardRuntime<P, B>
where
    P: Esp32s3PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    pub fn new(platform: P, storage_backend: B) -> Self {
        Self {
            runtime: v1_runtime_for_v2(platform, storage_backend),
            booted: false,
        }
    }

    pub fn boot(&mut self) -> Result<jade_core::DeviceBootReport, DeviceRuntimeError> {
        let report = self.runtime.runtime_platform_mut().boot_report();
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

    pub fn runtime(&self) -> &Esp32s3V1Runtime<P, B> {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut Esp32s3V1Runtime<P, B> {
        &mut self.runtime
    }

    pub fn platform(&self) -> &P {
        self.runtime.runtime_platform()
    }

    pub fn platform_mut(&mut self) -> &mut P {
        self.runtime.runtime_platform_mut()
    }

    pub fn poll_serial_v1(&mut self, rx_buffer: &mut [u8]) -> Result<bool, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        poll_serial_full_v1(&mut self.runtime, rx_buffer)
    }

    pub fn poll_usb_v1(&mut self, rx_buffer: &mut [u8]) -> Result<bool, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        poll_usb_full_v1(&mut self.runtime, rx_buffer)
    }

    pub fn poll_ble_v1(&mut self, rx_buffer: &mut [u8]) -> Result<bool, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        poll_ble_full_v1(&mut self.runtime, rx_buffer)
    }

    pub fn poll_v1_transports(
        &mut self,
        rx_buffer: &mut [u8],
    ) -> Result<Esp32s3V1PollReport, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }

        Ok(Esp32s3V1PollReport {
            serial: poll_serial_full_v1(&mut self.runtime, rx_buffer)?,
            usb: poll_usb_full_v1(&mut self.runtime, rx_buffer)?,
            ble: poll_ble_full_v1(&mut self.runtime, rx_buffer)?,
        })
    }

    pub fn poll_camera_qr<'a>(
        &mut self,
        out: &'a mut [u8],
    ) -> Result<Option<&'a [u8]>, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        poll_camera_qr(self.platform_mut(), out).map_err(FirmwareFrameError::Io)
    }

    pub fn poll_touch(&mut self) -> Result<Option<TouchEvent>, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        poll_touch(self.platform_mut()).map_err(FirmwareFrameError::Io)
    }

    pub fn sign_hardware_attestation<'a>(
        &mut self,
        challenge: &[u8],
        signature_out: &'a mut [u8],
        pubkey_out: &'a mut [u8],
        ext_signature_out: &'a mut [u8],
    ) -> Result<Option<HardwareAttestationReply<'a>>, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        sign_hardware_attestation(
            self.platform_mut(),
            challenge,
            signature_out,
            pubkey_out,
            ext_signature_out,
        )
        .map_err(FirmwareFrameError::Io)
    }
}

pub fn runtime_for_v2<P>(platform: P) -> Esp32s3Runtime<P>
where
    P: Esp32s3PlatformShim,
{
    DeviceRuntime::new(platform)
}

pub fn v1_runtime_for_v2<P, B>(platform: P, storage_backend: B) -> Esp32s3V1Runtime<P, B>
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
        DeviceTarget::JadeV2 => Some(JADE_V2_MANIFEST),
        DeviceTarget::JadeV2c => Some(JADE_V2C_MANIFEST),
        _ => None,
    }
}

pub fn assert_manifest_matches_real_device(manifest: DeviceManifest) -> Result<(), &'static str> {
    if !matches!(
        manifest.target,
        DeviceTarget::JadeV2 | DeviceTarget::JadeV2c
    ) {
        return Err("not an esp32s3 Jade target");
    }
    if manifest.partitions.ota_slots != 2 {
        return Err("esp32s3 firmware requires dual OTA slots");
    }
    if manifest.partitions.ota_app_bytes < 4024 * 1024 {
        return Err("esp32s3 OTA slot is smaller than the shipping partition table");
    }
    if !manifest.features.usb || !manifest.features.touch || !manifest.features.camera_qr {
        return Err("esp32s3 target is missing required user I/O");
    }
    if !manifest.supports_real_attestation() {
        return Err("esp32s3 target must expose hardware attestation");
    }
    if !manifest.features.secure_boot
        || !manifest.features.flash_encryption
        || !manifest.features.anti_rollback
    {
        return Err("esp32s3 target is missing release security gates");
    }
    Ok(())
}

pub fn poll_camera_qr<'a, P>(
    platform: &mut P,
    out: &'a mut [u8],
) -> Result<Option<&'a [u8]>, DeviceBootFailure>
where
    P: Esp32s3PlatformShim,
{
    let len = platform.camera_qr_scan(out)?;
    if len == 0 {
        return Ok(None);
    }
    out.get(..len)
        .ok_or(DeviceBootFailure::TransportUnavailable)
        .map(Some)
}

pub fn poll_touch<P>(platform: &mut P) -> Result<Option<TouchEvent>, DeviceBootFailure>
where
    P: Esp32s3PlatformShim,
{
    platform.touch_poll()
}

pub fn sign_hardware_attestation<'a, P>(
    platform: &mut P,
    challenge: &[u8],
    signature_out: &'a mut [u8],
    pubkey_out: &'a mut [u8],
    ext_signature_out: &'a mut [u8],
) -> Result<Option<HardwareAttestationReply<'a>>, DeviceBootFailure>
where
    P: Esp32s3PlatformShim,
{
    if !platform.hardware_attestation_available() {
        return Ok(None);
    }

    let pubkey_len = platform.hardware_attestation_public_key_pem(pubkey_out)?;
    let ext_signature_len = platform.hardware_attestation_ext_signature(ext_signature_out)?;
    let signature_len = platform.hardware_attestation_sign(challenge, signature_out)?;
    if pubkey_len == 0 || ext_signature_len == 0 || signature_len == 0 {
        return Err(DeviceBootFailure::RollbackStateInvalid);
    }

    let pubkey_pem = pubkey_out
        .get(..pubkey_len)
        .ok_or(DeviceBootFailure::TransportUnavailable)?;
    let ext_signature = ext_signature_out
        .get(..ext_signature_len)
        .ok_or(DeviceBootFailure::TransportUnavailable)?;
    let signature = signature_out
        .get(..signature_len)
        .ok_or(DeviceBootFailure::TransportUnavailable)?;

    Ok(Some(HardwareAttestationReply {
        signature,
        pubkey_pem,
        ext_signature,
    }))
}

pub fn poll_serial_v1<P>(
    runtime: &mut Esp32s3Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim,
{
    poll_serial(runtime, rx_buffer, FirmwareProtocol::V1Cbor)
}

pub fn poll_serial_v2<P>(
    runtime: &mut Esp32s3Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim,
{
    poll_serial(runtime, rx_buffer, FirmwareProtocol::V2Cbor)
}

pub fn poll_usb_v1<P>(
    runtime: &mut Esp32s3Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim,
{
    poll_usb(runtime, rx_buffer, FirmwareProtocol::V1Cbor)
}

pub fn poll_usb_v2<P>(
    runtime: &mut Esp32s3Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim,
{
    poll_usb(runtime, rx_buffer, FirmwareProtocol::V2Cbor)
}

pub fn poll_ble_v1<P>(
    runtime: &mut Esp32s3Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim,
{
    poll_ble(runtime, rx_buffer, FirmwareProtocol::V1Cbor)
}

pub fn poll_ble_v2<P>(
    runtime: &mut Esp32s3Runtime<P>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim,
{
    poll_ble(runtime, rx_buffer, FirmwareProtocol::V2Cbor)
}

pub fn poll_serial_full_v1<P, B>(
    runtime: &mut Esp32s3V1Runtime<P, B>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    let len = runtime
        .runtime_platform_mut()
        .serial_recv(rx_buffer)
        .map_err(FirmwareFrameError::Io)?;
    if len == 0 {
        return Ok(false);
    }

    let reply = runtime.handle_v1_cbor(&rx_buffer[..len]);
    if !reply.is_empty() {
        runtime
            .runtime_platform_mut()
            .serial_send(&reply)
            .map_err(FirmwareFrameError::Io)?;
    }
    Ok(true)
}

pub fn poll_usb_full_v1<P, B>(
    runtime: &mut Esp32s3V1Runtime<P, B>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    let len = runtime
        .runtime_platform_mut()
        .usb_recv(rx_buffer)
        .map_err(FirmwareFrameError::Io)?;
    if len == 0 {
        return Ok(false);
    }

    let reply = runtime.handle_v1_cbor(&rx_buffer[..len]);
    if !reply.is_empty() {
        runtime
            .runtime_platform_mut()
            .usb_send(&reply)
            .map_err(FirmwareFrameError::Io)?;
    }
    Ok(true)
}

pub fn poll_ble_full_v1<P, B>(
    runtime: &mut Esp32s3V1Runtime<P, B>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    let len = runtime
        .runtime_platform_mut()
        .ble_recv(rx_buffer)
        .map_err(FirmwareFrameError::Io)?;
    if len == 0 {
        return Ok(false);
    }

    let reply = runtime.handle_v1_cbor(&rx_buffer[..len]);
    if !reply.is_empty() {
        runtime
            .runtime_platform_mut()
            .ble_send(&reply)
            .map_err(FirmwareFrameError::Io)?;
    }
    Ok(true)
}

fn poll_serial<P>(
    runtime: &mut Esp32s3Runtime<P>,
    rx_buffer: &mut [u8],
    protocol: FirmwareProtocol,
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim,
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

fn poll_usb<P>(
    runtime: &mut Esp32s3Runtime<P>,
    rx_buffer: &mut [u8],
    protocol: FirmwareProtocol,
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim,
{
    let len = runtime
        .platform_mut()
        .usb_recv(rx_buffer)
        .map_err(FirmwareFrameError::Io)?;
    if len == 0 {
        return Ok(false);
    }
    if let Some(reply) = runtime.handle_firmware_frame(protocol, &rx_buffer[..len])? {
        runtime
            .platform_mut()
            .usb_send(&reply)
            .map_err(FirmwareFrameError::Io)?;
    }
    Ok(true)
}

fn poll_ble<P>(
    runtime: &mut Esp32s3Runtime<P>,
    rx_buffer: &mut [u8],
    protocol: FirmwareProtocol,
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32s3PlatformShim,
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
    use jade_emulator::{RuntimePlatformState, RuntimePlatformStateAccess};
    use jade_protocol_v2::{RequestBody, RequestKind, ResponseBody};
    use minicbor::{Decoder, Encoder};

    #[derive(Debug)]
    struct TestPlatform {
        runtime_state: RuntimePlatformState,
        epoch: Option<u64>,
        manifest: DeviceManifest,
        serial_rx: Option<Vec<u8>>,
        serial_tx: Vec<Vec<u8>>,
        usb_rx: Option<Vec<u8>>,
        usb_tx: Vec<Vec<u8>>,
        ble_rx: Option<Vec<u8>>,
        ble_tx: Vec<Vec<u8>>,
        camera_rx: Option<Vec<u8>>,
        touch_rx: Option<TouchEvent>,
        attestation_available: bool,
        attestation_pubkey_pem: Option<Vec<u8>>,
        attestation_ext_signature: Option<Vec<u8>>,
        attestation_signature: Option<Vec<u8>>,
        attestation_challenge: Option<Vec<u8>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestOtaWriter {
        writes: Vec<(u64, Vec<u8>)>,
        begun: bool,
        finished: bool,
        aborted: bool,
    }

    impl TestOtaWriter {
        fn new() -> Self {
            Self {
                writes: Vec::new(),
                begun: false,
                finished: false,
                aborted: false,
            }
        }
    }

    impl OtaImageWriter for TestOtaWriter {
        type Error = DeviceBootFailure;

        fn begin(&mut self, _request: &OtaRequest) -> Result<(), Self::Error> {
            self.begun = true;
            Ok(())
        }

        fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.writes.push((offset, data.to_vec()));
            Ok(())
        }

        fn finish(
            &mut self,
            _request: &OtaRequest,
            _received_compressed: u64,
        ) -> Result<(), Self::Error> {
            self.finished = true;
            Ok(())
        }

        fn abort(&mut self) {
            self.aborted = true;
        }
    }

    impl TestPlatform {
        fn new(manifest: DeviceManifest) -> Self {
            Self {
                runtime_state: RuntimePlatformState::default(),
                epoch: None,
                manifest,
                serial_rx: None,
                serial_tx: Vec::new(),
                usb_rx: None,
                usb_tx: Vec::new(),
                ble_rx: None,
                ble_tx: Vec::new(),
                camera_rx: None,
                touch_rx: None,
                attestation_available: true,
                attestation_pubkey_pem: None,
                attestation_ext_signature: None,
                attestation_signature: None,
                attestation_challenge: None,
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

        fn copy_frame(frame: &Option<Vec<u8>>, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            let Some(frame) = frame else {
                return Err(DeviceBootFailure::TransportUnavailable);
            };
            if frame.len() > out.len() {
                return Err(DeviceBootFailure::TransportUnavailable);
            }
            out[..frame.len()].copy_from_slice(frame);
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

        fn set_epoch(&mut self, epoch: u64) -> CoreResult<()> {
            self.epoch = Some(epoch);
            Ok(())
        }
    }

    impl RuntimePlatformStateAccess for TestPlatform {
        fn runtime_state(&self) -> &RuntimePlatformState {
            &self.runtime_state
        }

        fn runtime_state_mut(&mut self) -> &mut RuntimePlatformState {
            &mut self.runtime_state
        }

        fn runtime_current_epoch(&self) -> Option<u64> {
            self.epoch
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

    impl Esp32s3PlatformShim for TestPlatform {
        fn serial_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure> {
            self.serial_tx.push(bytes.to_vec());
            Ok(())
        }

        fn serial_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Self::recv_frame(&mut self.serial_rx, out)
        }

        fn usb_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure> {
            self.usb_tx.push(bytes.to_vec());
            Ok(())
        }

        fn usb_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Self::recv_frame(&mut self.usb_rx, out)
        }

        fn ble_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure> {
            self.ble_tx.push(bytes.to_vec());
            Ok(())
        }

        fn ble_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Self::recv_frame(&mut self.ble_rx, out)
        }

        fn camera_qr_scan(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Self::recv_frame(&mut self.camera_rx, out)
        }

        fn touch_poll(&mut self) -> Result<Option<TouchEvent>, DeviceBootFailure> {
            Ok(self.touch_rx.take())
        }

        fn hardware_attestation_available(&self) -> bool {
            self.attestation_available
        }

        fn hardware_attestation_public_key_pem(
            &mut self,
            out: &mut [u8],
        ) -> Result<usize, DeviceBootFailure> {
            Self::copy_frame(&self.attestation_pubkey_pem, out)
        }

        fn hardware_attestation_ext_signature(
            &mut self,
            out: &mut [u8],
        ) -> Result<usize, DeviceBootFailure> {
            Self::copy_frame(&self.attestation_ext_signature, out)
        }

        fn hardware_attestation_sign(
            &mut self,
            challenge: &[u8],
            out: &mut [u8],
        ) -> Result<usize, DeviceBootFailure> {
            self.attestation_challenge = Some(challenge.to_vec());
            Self::copy_frame(&self.attestation_signature, out)
        }
    }

    #[test]
    fn s3_manifests_match_shipping_targets() {
        assert_eq!(
            manifest_for_target(DeviceTarget::JadeV2),
            Some(JADE_V2_MANIFEST)
        );
        assert_eq!(
            manifest_for_target(DeviceTarget::JadeV2c),
            Some(JADE_V2C_MANIFEST)
        );
        assert_eq!(manifest_for_target(DeviceTarget::Jade), None);
        assert_manifest_matches_real_device(JADE_V2_MANIFEST).unwrap();
        assert_manifest_matches_real_device(JADE_V2C_MANIFEST).unwrap();
    }

    #[test]
    fn s3_runtime_uses_shared_core_boot_path() {
        let mut runtime = runtime_for_v2(TestPlatform::new(JADE_V2_MANIFEST));
        assert_eq!(runtime.boot().unwrap().target, DeviceTarget::JadeV2);
        assert!(runtime.is_booted());
        assert_eq!(runtime.version_info().board_type, Cow::Borrowed("jade_v2"));
    }

    #[test]
    fn s3_ota_update_uses_manifest_slot_gate_before_writer() {
        let request = OtaRequest::full(
            1_000,
            600,
            Some([0x11; jade_core::OTA_HASH_LEN]),
            None,
            false,
        )
        .unwrap();
        let mut session =
            begin_ota_update(JADE_V2_MANIFEST, TestOtaWriter::new(), request).unwrap();
        assert!(session.writer().begun);
        assert_eq!(session.write(&[0; 600]).unwrap(), 100);
        let writer = session.finish().unwrap();
        assert!(writer.finished);

        let too_large = OtaRequest::full(
            JADE_V2_MANIFEST.partitions.ota_app_bytes as u64 + 1,
            600,
            Some([0x11; jade_core::OTA_HASH_LEN]),
            None,
            false,
        )
        .unwrap();
        assert!(matches!(
            begin_ota_update(JADE_V2_MANIFEST, TestOtaWriter::new(), too_large),
            Err(Esp32s3OtaStartError::Partition(
                jade_core::DeviceOtaError::FirmwareTooLarge
            ))
        ));
    }

    #[test]
    fn s3_exposes_full_v1_runtime_constructor() {
        let runtime = v1_runtime_for_v2(
            jade_emulator::HostPlatform::default(),
            jade_storage::MemoryStorage::new(),
        );

        assert_eq!(runtime.state().wallet, jade_core::WalletLifecycle::Uninit);
    }

    #[test]
    fn s3_board_runtime_boots_before_polling_full_v1() {
        let mut board = Esp32s3V1BoardRuntime::new(
            TestPlatform::new(JADE_V2_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().usb_rx = Some(v1_request("p", "ping"));

        let mut rx = [0u8; 128];
        assert_eq!(
            board.poll_usb_v1(&mut rx),
            Err(FirmwareFrameError::BootRequired)
        );
        assert_eq!(board.boot().unwrap().target, DeviceTarget::JadeV2);
        assert!(board.is_booted());
        assert_eq!(board.poll_usb_v1(&mut rx), Ok(true));
        assert_eq!(board.platform().usb_tx.len(), 1);

        let mut decoder = Decoder::new(&board.platform().usb_tx[0]);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "p");
        assert_eq!(decoder.str().unwrap(), "result");
        assert_eq!(decoder.u64().unwrap(), 0);
    }

    #[test]
    fn s3_board_runtime_polls_camera_qr_after_boot() {
        let mut board = Esp32s3V1BoardRuntime::new(
            TestPlatform::new(JADE_V2_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().camera_rx = Some(b"ur:bytes/s3-test".to_vec());

        let mut qr = [0u8; 64];
        assert_eq!(
            board.poll_camera_qr(&mut qr),
            Err(FirmwareFrameError::BootRequired)
        );
        board.boot().unwrap();
        assert_eq!(
            board.poll_camera_qr(&mut qr).unwrap(),
            Some(&b"ur:bytes/s3-test"[..])
        );
        assert_eq!(board.poll_camera_qr(&mut qr), Ok(None));
    }

    #[test]
    fn s3_board_runtime_polls_all_v1_transports_once() {
        let mut board = Esp32s3V1BoardRuntime::new(
            TestPlatform::new(JADE_V2_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().serial_rx = Some(v1_request("s", "ping"));
        board.platform_mut().usb_rx = Some(v1_request("u", "ping"));
        board.platform_mut().ble_rx = Some(v1_request("b", "ping"));

        let mut rx = [0u8; 128];
        assert_eq!(
            board.poll_v1_transports(&mut rx),
            Err(FirmwareFrameError::BootRequired)
        );
        board.boot().unwrap();
        let report = board.poll_v1_transports(&mut rx).unwrap();
        assert_eq!(
            report,
            Esp32s3V1PollReport {
                serial: true,
                usb: true,
                ble: true
            }
        );
        assert!(report.any());
        assert_eq!(board.platform().serial_tx.len(), 1);
        assert_eq!(board.platform().usb_tx.len(), 1);
        assert_eq!(board.platform().ble_tx.len(), 1);
        assert_eq!(
            board.poll_v1_transports(&mut rx).unwrap(),
            Esp32s3V1PollReport::default()
        );
    }

    #[test]
    fn s3_camera_qr_rejects_oversized_platform_payloads() {
        let mut platform = TestPlatform::new(JADE_V2_MANIFEST);
        platform.camera_rx = Some(b"too-large".to_vec());

        let mut qr = [0u8; 4];
        assert_eq!(
            poll_camera_qr(&mut platform, &mut qr),
            Err(DeviceBootFailure::TransportUnavailable)
        );
    }

    #[test]
    fn s3_board_runtime_polls_touch_after_boot() {
        let mut board = Esp32s3V1BoardRuntime::new(
            TestPlatform::new(JADE_V2_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().touch_rx = Some(TouchEvent::Press { x: 123, y: 45 });

        assert_eq!(board.poll_touch(), Err(FirmwareFrameError::BootRequired));
        board.boot().unwrap();
        assert_eq!(
            board.poll_touch().unwrap(),
            Some(TouchEvent::Press { x: 123, y: 45 })
        );
        assert_eq!(board.poll_touch(), Ok(None));
    }

    #[test]
    fn s3_board_runtime_signs_hardware_attestation_after_boot() {
        let mut board = Esp32s3V1BoardRuntime::new(
            TestPlatform::new(JADE_V2_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().attestation_pubkey_pem = Some(b"pubkey".to_vec());
        board.platform_mut().attestation_ext_signature = Some(b"external-signature".to_vec());
        board.platform_mut().attestation_signature = Some(b"device-signature".to_vec());

        let mut signature = [0u8; 32];
        let mut pubkey = [0u8; 16];
        let mut ext_signature = [0u8; 32];
        assert_eq!(
            board.sign_hardware_attestation(
                b"challenge",
                &mut signature,
                &mut pubkey,
                &mut ext_signature
            ),
            Err(FirmwareFrameError::BootRequired)
        );

        board.boot().unwrap();
        let reply = board
            .sign_hardware_attestation(
                b"challenge",
                &mut signature,
                &mut pubkey,
                &mut ext_signature,
            )
            .unwrap()
            .unwrap();
        assert_eq!(reply.signature, b"device-signature");
        assert_eq!(reply.pubkey_pem, b"pubkey");
        assert_eq!(reply.ext_signature, b"external-signature");
        assert_eq!(
            board.platform().attestation_challenge.as_deref(),
            Some(&b"challenge"[..])
        );
    }

    #[test]
    fn s3_hardware_attestation_reports_unavailable_or_oversized_material() {
        let mut platform = TestPlatform::new(JADE_V2_MANIFEST);
        platform.attestation_available = false;
        let mut signature = [0u8; 4];
        let mut pubkey = [0u8; 4];
        let mut ext_signature = [0u8; 4];
        assert_eq!(
            sign_hardware_attestation(
                &mut platform,
                b"challenge",
                &mut signature,
                &mut pubkey,
                &mut ext_signature
            ),
            Ok(None)
        );

        platform.attestation_available = true;
        platform.attestation_pubkey_pem = Some(b"too-large".to_vec());
        platform.attestation_ext_signature = Some(b"ok".to_vec());
        platform.attestation_signature = Some(b"ok".to_vec());
        assert_eq!(
            sign_hardware_attestation(
                &mut platform,
                b"challenge",
                &mut signature,
                &mut pubkey,
                &mut ext_signature
            ),
            Err(DeviceBootFailure::TransportUnavailable)
        );
    }

    #[test]
    fn s3_serial_polls_v1_cbor_frames() {
        let mut runtime = runtime_for_v2(TestPlatform::new(JADE_V2_MANIFEST));
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
    fn s3_usb_polls_full_v1_runtime_frames() {
        let mut runtime = v1_runtime_for_v2(
            TestPlatform::new(JADE_V2_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        runtime.runtime_platform_mut().usb_rx = Some(v1_request("p", "ping"));

        let mut rx = [0u8; 128];
        assert_eq!(poll_usb_full_v1(&mut runtime, &mut rx), Ok(true));
        assert_eq!(runtime.runtime_platform().usb_tx.len(), 1);

        let mut decoder = Decoder::new(&runtime.runtime_platform().usb_tx[0]);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "p");
        assert_eq!(decoder.str().unwrap(), "result");
        assert_eq!(decoder.u64().unwrap(), 0);
    }

    #[test]
    fn s3_usb_polls_v2_cbor_frames() {
        let mut runtime = runtime_for_v2(TestPlatform::new(JADE_V2_MANIFEST));
        runtime.boot().unwrap();
        runtime.platform_mut().usb_rx = Some(v2_ping_request("u"));

        let mut rx = [0u8; 128];
        assert_eq!(poll_usb_v2(&mut runtime, &mut rx), Ok(true));
        assert_eq!(runtime.platform().usb_tx.len(), 1);

        let response: jade_protocol_v2::Response<'_> =
            minicbor::decode(&runtime.platform().usb_tx[0]).unwrap();
        assert_eq!(response.id, "u");
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
