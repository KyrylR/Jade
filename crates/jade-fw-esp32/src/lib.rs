#![no_std]

#[cfg(test)]
extern crate alloc;

use jade_core::{
    AllocationBudget, CborFrameBuffer, DeviceBootFailure, DeviceFeatureSet, DeviceManifest,
    DeviceMemoryBudget, DevicePartitionLayout, DevicePlatform, DeviceRuntime, DeviceRuntimeError,
    DeviceTarget, DisplayStatus, FirmwareFrameError, FirmwareProtocol, OtaImageWriter, OtaRequest,
    OtaWriteError, OtaWriteSession, UserConfirmation, UserConfirmationDecision,
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
pub const RX_BUFFER_BYTES: usize = AllocationBudget::ESP32_NO_SPIRAM.max_request_bytes;
pub const QR_BUFFER_BYTES: usize = 1024;

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
    fn display_status(&mut self, status: DisplayStatus<'_>) -> Result<(), DeviceBootFailure>;
    fn confirm_user(
        &mut self,
        request: UserConfirmation<'_>,
    ) -> Result<UserConfirmationDecision, DeviceBootFailure>;
}

pub type Esp32Runtime<P> = DeviceRuntime<P>;
pub type Esp32V1Runtime<P, B> = jade_emulator::JadeRuntime<P, B>;
pub type Esp32NvsStorage<B> = jade_storage::NvsStorage<B>;
pub type Esp32OtaSession<W> = OtaWriteSession<W>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Esp32V1PollReport {
    pub serial: bool,
    pub ble: bool,
}

impl Esp32V1PollReport {
    pub const fn any(self) -> bool {
        self.serial || self.ble
    }
}

#[derive(Debug)]
pub struct Esp32BoardTick<'a> {
    pub rx_buffer: &'a mut [u8],
    pub qr_buffer: Option<&'a mut [u8]>,
    pub display_status: Option<DisplayStatus<'a>>,
    pub confirmation: Option<UserConfirmation<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Esp32BoardTickReport<'a> {
    pub transports: Esp32V1PollReport,
    pub qr_payload: Option<&'a [u8]>,
    pub confirmation: Option<UserConfirmationDecision>,
    pub monotonic_millis: u64,
    pub rollback_secure_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Esp32BoardAppError {
    RxBufferTooSmall { required: usize, actual: usize },
    QrBufferTooSmall { required: usize, actual: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Esp32OtaStartError<E> {
    BootRequired,
    Manifest(&'static str),
    Partition(jade_core::DeviceOtaError),
    Writer(OtaWriteError<E>),
}

pub fn begin_ota_update<W>(
    manifest: DeviceManifest,
    writer: W,
    request: OtaRequest,
) -> Result<Esp32OtaSession<W>, Esp32OtaStartError<W::Error>>
where
    W: OtaImageWriter,
{
    assert_manifest_matches_real_device(manifest).map_err(Esp32OtaStartError::Manifest)?;
    manifest
        .validate_ota_request(&request)
        .map_err(Esp32OtaStartError::Partition)?;
    OtaWriteSession::begin(writer, request).map_err(Esp32OtaStartError::Writer)
}

#[derive(Debug)]
pub struct Esp32BoardApp<'a, P, B> {
    runtime: Esp32V1BoardRuntime<P, B>,
    rx_buffer: &'a mut [u8],
    qr_buffer: &'a mut [u8],
}

#[derive(Debug)]
pub struct Esp32BoardStreamApp<'a, P, B> {
    runtime: Esp32V1BoardRuntime<P, B>,
    serial_frames: CborFrameBuffer<'a>,
    ble_frames: CborFrameBuffer<'a>,
    qr_buffer: &'a mut [u8],
}

impl<'a, P, B> Esp32BoardApp<'a, P, B>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    pub fn new(
        platform: P,
        storage_backend: B,
        rx_buffer: &'a mut [u8],
        qr_buffer: &'a mut [u8],
    ) -> Result<Self, Esp32BoardAppError> {
        validate_board_buffers(rx_buffer, qr_buffer)?;
        Ok(Self {
            runtime: Esp32V1BoardRuntime::new(platform, storage_backend),
            rx_buffer,
            qr_buffer,
        })
    }

    pub fn boot(&mut self) -> Result<jade_core::DeviceBootReport, DeviceRuntimeError> {
        self.runtime.boot()
    }

    pub fn is_booted(&self) -> bool {
        self.runtime.is_booted()
    }

    pub fn runtime(&self) -> &Esp32V1BoardRuntime<P, B> {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut Esp32V1BoardRuntime<P, B> {
        &mut self.runtime
    }

    pub fn tick<'b>(
        &'b mut self,
        display_status: Option<DisplayStatus<'b>>,
        confirmation: Option<UserConfirmation<'b>>,
    ) -> Result<Esp32BoardTickReport<'b>, FirmwareFrameError> {
        let Self {
            runtime,
            rx_buffer,
            qr_buffer,
        } = self;
        runtime.tick(Esp32BoardTick {
            rx_buffer,
            qr_buffer: Some(qr_buffer),
            display_status,
            confirmation,
        })
    }

    pub fn begin_ota_update<W>(
        &mut self,
        writer: W,
        request: OtaRequest,
    ) -> Result<Esp32OtaSession<W>, Esp32OtaStartError<W::Error>>
    where
        W: OtaImageWriter,
    {
        self.runtime.begin_ota_update(writer, request)
    }
}

impl<'a, P, B> Esp32BoardApp<'a, P, Esp32NvsStorage<B>>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::NvsKeyValueBackend,
{
    pub fn new_with_nvs(
        platform: P,
        nvs_backend: B,
        rx_buffer: &'a mut [u8],
        qr_buffer: &'a mut [u8],
    ) -> Result<Self, Esp32BoardAppError> {
        Self::new(
            platform,
            jade_storage::NvsStorage::new(nvs_backend),
            rx_buffer,
            qr_buffer,
        )
    }
}

impl<'a, P, B> Esp32BoardStreamApp<'a, P, B>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    pub fn new(
        platform: P,
        storage_backend: B,
        serial_frame_buffer: &'a mut [u8],
        ble_frame_buffer: &'a mut [u8],
        qr_buffer: &'a mut [u8],
    ) -> Result<Self, Esp32BoardAppError> {
        validate_board_stream_buffers(serial_frame_buffer, ble_frame_buffer, qr_buffer)?;
        Ok(Self {
            runtime: Esp32V1BoardRuntime::new(platform, storage_backend),
            serial_frames: CborFrameBuffer::new(serial_frame_buffer),
            ble_frames: CborFrameBuffer::new(ble_frame_buffer),
            qr_buffer,
        })
    }

    pub fn boot(&mut self) -> Result<jade_core::DeviceBootReport, DeviceRuntimeError> {
        self.runtime.boot()
    }

    pub fn is_booted(&self) -> bool {
        self.runtime.is_booted()
    }

    pub fn runtime(&self) -> &Esp32V1BoardRuntime<P, B> {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut Esp32V1BoardRuntime<P, B> {
        &mut self.runtime
    }

    pub fn serial_pending(&self) -> &[u8] {
        self.serial_frames.pending()
    }

    pub fn ble_pending(&self) -> &[u8] {
        self.ble_frames.pending()
    }

    pub fn tick<'b>(
        &'b mut self,
        display_status: Option<DisplayStatus<'b>>,
        confirmation: Option<UserConfirmation<'b>>,
    ) -> Result<Esp32BoardTickReport<'b>, FirmwareFrameError> {
        let Self {
            runtime,
            serial_frames,
            ble_frames,
            qr_buffer,
        } = self;
        runtime.tick_streams(
            serial_frames,
            ble_frames,
            Some(qr_buffer),
            display_status,
            confirmation,
        )
    }

    pub fn begin_ota_update<W>(
        &mut self,
        writer: W,
        request: OtaRequest,
    ) -> Result<Esp32OtaSession<W>, Esp32OtaStartError<W::Error>>
    where
        W: OtaImageWriter,
    {
        self.runtime.begin_ota_update(writer, request)
    }
}

impl<'a, P, B> Esp32BoardStreamApp<'a, P, Esp32NvsStorage<B>>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::NvsKeyValueBackend,
{
    pub fn new_with_nvs(
        platform: P,
        nvs_backend: B,
        serial_frame_buffer: &'a mut [u8],
        ble_frame_buffer: &'a mut [u8],
        qr_buffer: &'a mut [u8],
    ) -> Result<Self, Esp32BoardAppError> {
        Self::new(
            platform,
            jade_storage::NvsStorage::new(nvs_backend),
            serial_frame_buffer,
            ble_frame_buffer,
            qr_buffer,
        )
    }
}

#[derive(Debug)]
pub struct Esp32V1BoardRuntime<P, B> {
    runtime: Esp32V1Runtime<P, B>,
    booted: bool,
}

impl<P, B> Esp32V1BoardRuntime<P, B>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    pub fn new(platform: P, storage_backend: B) -> Self {
        Self {
            runtime: v1_runtime_for_v1(platform, storage_backend),
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

    pub fn runtime(&self) -> &Esp32V1Runtime<P, B> {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut Esp32V1Runtime<P, B> {
        &mut self.runtime
    }

    pub fn platform(&self) -> &P {
        self.runtime.runtime_platform()
    }

    pub fn platform_mut(&mut self) -> &mut P {
        self.runtime.runtime_platform_mut()
    }

    pub fn fill_random(&mut self, out: &mut [u8]) -> Result<(), FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        self.platform_mut()
            .fill_random(out)
            .map_err(FirmwareFrameError::Io)
    }

    pub fn monotonic_millis(&self) -> Result<u64, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        Ok(self.platform().monotonic_millis())
    }

    pub fn rollback_secure_version(&self) -> Result<u32, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        Ok(self.platform().rollback_secure_version())
    }

    pub fn poll_serial_v1(&mut self, rx_buffer: &mut [u8]) -> Result<bool, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        poll_serial_full_v1(&mut self.runtime, rx_buffer)
    }

    pub fn poll_serial_v1_stream(
        &mut self,
        frame_buffer: &mut CborFrameBuffer<'_>,
    ) -> Result<bool, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        poll_serial_full_v1_stream(&mut self.runtime, frame_buffer)
    }

    pub fn poll_ble_v1(&mut self, rx_buffer: &mut [u8]) -> Result<bool, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        poll_ble_full_v1(&mut self.runtime, rx_buffer)
    }

    pub fn poll_ble_v1_stream(
        &mut self,
        frame_buffer: &mut CborFrameBuffer<'_>,
    ) -> Result<bool, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        poll_ble_full_v1_stream(&mut self.runtime, frame_buffer)
    }

    pub fn poll_v1_transports(
        &mut self,
        rx_buffer: &mut [u8],
    ) -> Result<Esp32V1PollReport, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }

        Ok(Esp32V1PollReport {
            serial: poll_serial_full_v1(&mut self.runtime, rx_buffer)?,
            ble: poll_ble_full_v1(&mut self.runtime, rx_buffer)?,
        })
    }

    pub fn poll_v1_transport_streams(
        &mut self,
        serial_frames: &mut CborFrameBuffer<'_>,
        ble_frames: &mut CborFrameBuffer<'_>,
    ) -> Result<Esp32V1PollReport, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }

        Ok(Esp32V1PollReport {
            serial: poll_serial_full_v1_stream(&mut self.runtime, serial_frames)?,
            ble: poll_ble_full_v1_stream(&mut self.runtime, ble_frames)?,
        })
    }

    pub fn tick<'a>(
        &mut self,
        tick: Esp32BoardTick<'a>,
    ) -> Result<Esp32BoardTickReport<'a>, FirmwareFrameError> {
        let transports = self.poll_v1_transports(tick.rx_buffer)?;
        if let Some(status) = tick.display_status {
            self.display_status(status)?;
        }
        let confirmation = match tick.confirmation {
            Some(request) => Some(self.confirm_user(request)?),
            None => None,
        };
        let monotonic_millis = self.monotonic_millis()?;
        let rollback_secure_version = self.rollback_secure_version()?;
        let qr_payload = match tick.qr_buffer {
            Some(out) => self.poll_camera_qr(out)?,
            None => None,
        };

        Ok(Esp32BoardTickReport {
            transports,
            qr_payload,
            confirmation,
            monotonic_millis,
            rollback_secure_version,
        })
    }

    pub fn tick_streams<'a>(
        &mut self,
        serial_frames: &mut CborFrameBuffer<'_>,
        ble_frames: &mut CborFrameBuffer<'_>,
        qr_buffer: Option<&'a mut [u8]>,
        display_status: Option<DisplayStatus<'a>>,
        confirmation: Option<UserConfirmation<'a>>,
    ) -> Result<Esp32BoardTickReport<'a>, FirmwareFrameError> {
        let transports = self.poll_v1_transport_streams(serial_frames, ble_frames)?;
        if let Some(status) = display_status {
            self.display_status(status)?;
        }
        let confirmation = match confirmation {
            Some(request) => Some(self.confirm_user(request)?),
            None => None,
        };
        let monotonic_millis = self.monotonic_millis()?;
        let rollback_secure_version = self.rollback_secure_version()?;
        let qr_payload = match qr_buffer {
            Some(out) => self.poll_camera_qr(out)?,
            None => None,
        };

        Ok(Esp32BoardTickReport {
            transports,
            qr_payload,
            confirmation,
            monotonic_millis,
            rollback_secure_version,
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

    pub fn display_status(&mut self, status: DisplayStatus<'_>) -> Result<(), FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        display_status(self.platform_mut(), status).map_err(FirmwareFrameError::Io)
    }

    pub fn confirm_user(
        &mut self,
        request: UserConfirmation<'_>,
    ) -> Result<UserConfirmationDecision, FirmwareFrameError> {
        if !self.booted {
            return Err(FirmwareFrameError::BootRequired);
        }
        confirm_user(self.platform_mut(), request).map_err(FirmwareFrameError::Io)
    }

    pub fn begin_ota_update<W>(
        &mut self,
        writer: W,
        request: OtaRequest,
    ) -> Result<Esp32OtaSession<W>, Esp32OtaStartError<W::Error>>
    where
        W: OtaImageWriter,
    {
        if !self.booted {
            return Err(Esp32OtaStartError::BootRequired);
        }
        begin_ota_update(self.platform().manifest(), writer, request)
    }
}

impl<P, B> Esp32V1BoardRuntime<P, Esp32NvsStorage<B>>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::NvsKeyValueBackend,
{
    pub fn new_with_nvs(platform: P, nvs_backend: B) -> Self {
        Self::new(platform, jade_storage::NvsStorage::new(nvs_backend))
    }
}

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

pub fn nvs_runtime_for_v1<P, B>(
    platform: P,
    nvs_backend: B,
) -> Esp32V1Runtime<P, Esp32NvsStorage<B>>
where
    P: jade_emulator::RuntimePlatform,
    B: jade_storage::NvsKeyValueBackend,
{
    v1_runtime_for_v1(platform, jade_storage::NvsStorage::new(nvs_backend))
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

pub fn validate_board_buffers(
    rx_buffer: &[u8],
    qr_buffer: &[u8],
) -> Result<(), Esp32BoardAppError> {
    validate_rx_buffer(rx_buffer)?;
    validate_qr_buffer(qr_buffer)
}

pub fn validate_board_stream_buffers(
    serial_frame_buffer: &[u8],
    ble_frame_buffer: &[u8],
    qr_buffer: &[u8],
) -> Result<(), Esp32BoardAppError> {
    validate_rx_buffer(serial_frame_buffer)?;
    validate_rx_buffer(ble_frame_buffer)?;
    validate_qr_buffer(qr_buffer)
}

fn validate_rx_buffer(rx_buffer: &[u8]) -> Result<(), Esp32BoardAppError> {
    if rx_buffer.len() < RX_BUFFER_BYTES {
        return Err(Esp32BoardAppError::RxBufferTooSmall {
            required: RX_BUFFER_BYTES,
            actual: rx_buffer.len(),
        });
    }
    Ok(())
}

fn validate_qr_buffer(qr_buffer: &[u8]) -> Result<(), Esp32BoardAppError> {
    if qr_buffer.len() < QR_BUFFER_BYTES {
        return Err(Esp32BoardAppError::QrBufferTooSmall {
            required: QR_BUFFER_BYTES,
            actual: qr_buffer.len(),
        });
    }
    Ok(())
}

pub fn poll_camera_qr<'a, P>(
    platform: &mut P,
    out: &'a mut [u8],
) -> Result<Option<&'a [u8]>, DeviceBootFailure>
where
    P: Esp32PlatformShim,
{
    let len = platform.camera_qr_scan(out)?;
    if len == 0 {
        return Ok(None);
    }
    out.get(..len)
        .ok_or(DeviceBootFailure::TransportUnavailable)
        .map(Some)
}

pub fn display_status<P>(
    platform: &mut P,
    status: DisplayStatus<'_>,
) -> Result<(), DeviceBootFailure>
where
    P: Esp32PlatformShim,
{
    platform.display_status(status)
}

pub fn confirm_user<P>(
    platform: &mut P,
    request: UserConfirmation<'_>,
) -> Result<UserConfirmationDecision, DeviceBootFailure>
where
    P: Esp32PlatformShim,
{
    platform.confirm_user(request)
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

pub fn poll_serial_full_v1<P, B>(
    runtime: &mut Esp32V1Runtime<P, B>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    let len = runtime
        .runtime_platform_mut()
        .serial_recv(rx_buffer)
        .map_err(FirmwareFrameError::Io)?;
    if len == 0 {
        return Ok(false);
    }
    runtime
        .runtime_platform()
        .manifest()
        .memory
        .allocation
        .ensure_request(len)
        .map_err(FirmwareFrameError::Allocation)?;

    let reply = runtime.handle_v1_cbor(&rx_buffer[..len]);
    send_budgeted_reply(
        runtime.runtime_platform_mut(),
        &reply,
        Esp32PlatformShim::serial_send,
    )?;
    Ok(true)
}

pub fn poll_serial_full_v1_stream<P, B>(
    runtime: &mut Esp32V1Runtime<P, B>,
    frame_buffer: &mut CborFrameBuffer<'_>,
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    poll_full_v1_stream(
        runtime,
        frame_buffer,
        Esp32PlatformShim::serial_recv,
        Esp32PlatformShim::serial_send,
    )
}

pub fn poll_ble_full_v1<P, B>(
    runtime: &mut Esp32V1Runtime<P, B>,
    rx_buffer: &mut [u8],
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    let len = runtime
        .runtime_platform_mut()
        .ble_recv(rx_buffer)
        .map_err(FirmwareFrameError::Io)?;
    if len == 0 {
        return Ok(false);
    }
    runtime
        .runtime_platform()
        .manifest()
        .memory
        .allocation
        .ensure_request(len)
        .map_err(FirmwareFrameError::Allocation)?;

    let reply = runtime.handle_v1_cbor(&rx_buffer[..len]);
    send_budgeted_reply(
        runtime.runtime_platform_mut(),
        &reply,
        Esp32PlatformShim::ble_send,
    )?;
    Ok(true)
}

pub fn poll_ble_full_v1_stream<P, B>(
    runtime: &mut Esp32V1Runtime<P, B>,
    frame_buffer: &mut CborFrameBuffer<'_>,
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    poll_full_v1_stream(
        runtime,
        frame_buffer,
        Esp32PlatformShim::ble_recv,
        Esp32PlatformShim::ble_send,
    )
}

fn poll_full_v1_stream<P, B>(
    runtime: &mut Esp32V1Runtime<P, B>,
    frame_buffer: &mut CborFrameBuffer<'_>,
    recv: impl FnOnce(&mut P, &mut [u8]) -> Result<usize, DeviceBootFailure>,
    mut send: impl FnMut(&mut P, &[u8]) -> Result<(), DeviceBootFailure>,
) -> Result<bool, FirmwareFrameError>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    let spare = frame_buffer.spare_capacity_mut();
    if !spare.is_empty() {
        let len = recv(runtime.runtime_platform_mut(), spare).map_err(FirmwareFrameError::Io)?;
        frame_buffer
            .advance(len)
            .map_err(|_| FirmwareFrameError::Decode)?;
    }

    let mut handled = false;
    loop {
        let Some(frame_len) = frame_buffer
            .next_frame_len()
            .map_err(|_| FirmwareFrameError::Decode)?
        else {
            break;
        };
        runtime
            .runtime_platform()
            .manifest()
            .memory
            .allocation
            .ensure_request(frame_len)
            .map_err(FirmwareFrameError::Allocation)?;

        let Some(reply) = frame_buffer
            .handle_next_frame(|frame| runtime.handle_v1_cbor(frame))
            .map_err(|_| FirmwareFrameError::Decode)?
        else {
            break;
        };
        handled = true;
        send_budgeted_reply(runtime.runtime_platform_mut(), &reply, |platform, bytes| {
            send(platform, bytes)
        })?;
    }

    Ok(handled)
}

fn send_budgeted_reply<P>(
    platform: &mut P,
    reply: &[u8],
    mut send: impl FnMut(&mut P, &[u8]) -> Result<(), DeviceBootFailure>,
) -> Result<(), FirmwareFrameError>
where
    P: DevicePlatform,
{
    if reply.is_empty() {
        return Ok(());
    }
    platform
        .manifest()
        .memory
        .allocation
        .ensure_response(reply.len())
        .map_err(FirmwareFrameError::Allocation)?;
    send(platform, reply).map_err(FirmwareFrameError::Io)
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
    use alloc::{
        borrow::Cow,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
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
        ble_rx: Option<Vec<u8>>,
        ble_tx: Vec<Vec<u8>>,
        camera_rx: Option<Vec<u8>>,
        display_status_count: usize,
        confirmation_count: usize,
        confirmation_decision: UserConfirmationDecision,
        monotonic_millis: u64,
        rollback_secure_version: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestOtaWriter {
        writes: Vec<(u64, Vec<u8>)>,
        begun: bool,
        finished: bool,
        aborted: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestNvs {
        records: Vec<(String, String, Vec<u8>)>,
    }

    impl TestNvs {
        fn new() -> Self {
            Self {
                records: Vec::new(),
            }
        }

        fn index(&self, namespace: &str, key: &str) -> Option<usize> {
            self.records
                .iter()
                .position(|(record_namespace, record_key, _)| {
                    record_namespace == namespace && record_key == key
                })
        }
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

    impl jade_storage::NvsKeyValueBackend for TestNvs {
        fn get(
            &self,
            namespace: &str,
            key: &str,
            out: &mut Vec<u8>,
        ) -> jade_storage::StorageResult<()> {
            let Some(index) = self.index(namespace, key) else {
                return Err(jade_storage::StorageError::NotFound);
            };
            out.clear();
            out.extend_from_slice(&self.records[index].2);
            Ok(())
        }

        fn set(
            &mut self,
            namespace: &str,
            key: &str,
            value: &[u8],
        ) -> jade_storage::StorageResult<()> {
            match self.index(namespace, key) {
                Some(index) => self.records[index].2 = value.to_vec(),
                None => self
                    .records
                    .push((namespace.to_string(), key.to_string(), value.to_vec())),
            }
            Ok(())
        }

        fn erase(&mut self, namespace: &str, key: &str) -> jade_storage::StorageResult<()> {
            let Some(index) = self.index(namespace, key) else {
                return Err(jade_storage::StorageError::NotFound);
            };
            self.records.remove(index);
            Ok(())
        }

        fn list(&self, namespace: &str, out: &mut Vec<String>) -> jade_storage::StorageResult<()> {
            out.clear();
            out.extend(
                self.records
                    .iter()
                    .filter(|(record_namespace, _, _)| record_namespace == namespace)
                    .map(|(_, key, _)| key.clone()),
            );
            Ok(())
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
                ble_rx: None,
                ble_tx: Vec::new(),
                camera_rx: None,
                display_status_count: 0,
                confirmation_count: 0,
                confirmation_decision: UserConfirmationDecision::Approved,
                monotonic_millis: 1,
                rollback_secure_version: 1,
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

        fn set_epoch(&mut self, epoch: u64) -> CoreResult<()> {
            self.epoch = Some(epoch);
            Ok(())
        }
    }

    fn manifest_with_allocation(
        manifest: DeviceManifest,
        allocation: AllocationBudget,
    ) -> DeviceManifest {
        DeviceManifest {
            memory: DeviceMemoryBudget {
                allocation,
                ..manifest.memory
            },
            ..manifest
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
            self.monotonic_millis
        }

        fn rollback_secure_version(&self) -> u32 {
            self.rollback_secure_version
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

        fn camera_qr_scan(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Self::recv_frame(&mut self.camera_rx, out)
        }

        fn display_status(&mut self, _status: DisplayStatus<'_>) -> Result<(), DeviceBootFailure> {
            self.display_status_count += 1;
            Ok(())
        }

        fn confirm_user(
            &mut self,
            _request: UserConfirmation<'_>,
        ) -> Result<UserConfirmationDecision, DeviceBootFailure> {
            self.confirmation_count += 1;
            Ok(self.confirmation_decision)
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
        for (manifest, target, board_type) in [
            (JADE_MANIFEST, DeviceTarget::Jade, "jade"),
            (JADE_V1_1_MANIFEST, DeviceTarget::JadeV1_1, "jade_v1_1"),
        ] {
            let mut runtime = runtime_for_v1(TestPlatform::new(manifest));
            assert_eq!(runtime.boot().unwrap().target, target);
            assert!(runtime.is_booted());
            assert_eq!(runtime.version_info().board_type, Cow::Borrowed(board_type));
        }
    }

    #[test]
    fn esp32_ota_update_uses_manifest_slot_gate_before_writer() {
        let request = OtaRequest::full(
            1_000,
            600,
            Some([0x11; jade_core::OTA_HASH_LEN]),
            None,
            false,
        )
        .unwrap();
        let mut session = begin_ota_update(JADE_MANIFEST, TestOtaWriter::new(), request).unwrap();
        assert!(session.writer().unwrap().begun);
        assert_eq!(session.write(&[0; 600]).unwrap(), 100);
        let writer = session.finish().unwrap();
        assert!(writer.finished);

        let too_large = OtaRequest::full(
            JADE_MANIFEST.partitions.ota_app_bytes as u64 + 1,
            600,
            Some([0x11; jade_core::OTA_HASH_LEN]),
            None,
            false,
        )
        .unwrap();
        assert!(matches!(
            begin_ota_update(JADE_MANIFEST, TestOtaWriter::new(), too_large),
            Err(Esp32OtaStartError::Partition(
                jade_core::DeviceOtaError::FirmwareTooLarge
            ))
        ));
    }

    #[test]
    fn esp32_board_runtime_starts_ota_after_boot() {
        let request = OtaRequest::full(
            1_000,
            600,
            Some([0x11; jade_core::OTA_HASH_LEN]),
            None,
            false,
        )
        .unwrap();
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );

        assert!(matches!(
            board.begin_ota_update(TestOtaWriter::new(), request),
            Err(Esp32OtaStartError::BootRequired)
        ));
        board.boot().unwrap();
        let session = board
            .begin_ota_update(TestOtaWriter::new(), request)
            .unwrap();
        assert!(session.writer().unwrap().begun);
    }

    #[test]
    fn esp32_board_apps_start_ota_after_boot() {
        let request = OtaRequest::full(
            1_000,
            600,
            Some([0x11; jade_core::OTA_HASH_LEN]),
            None,
            false,
        )
        .unwrap();

        let mut rx = vec![0; RX_BUFFER_BYTES];
        let mut qr = vec![0; QR_BUFFER_BYTES];
        let mut app = Esp32BoardApp::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
            &mut rx,
            &mut qr,
        )
        .unwrap();
        assert!(matches!(
            app.begin_ota_update(TestOtaWriter::new(), request),
            Err(Esp32OtaStartError::BootRequired)
        ));
        app.boot().unwrap();
        assert!(
            app.begin_ota_update(TestOtaWriter::new(), request)
                .unwrap()
                .writer()
                .unwrap()
                .begun
        );

        let mut serial_frames = vec![0; RX_BUFFER_BYTES];
        let mut ble_frames = vec![0; RX_BUFFER_BYTES];
        let mut stream_qr = vec![0; QR_BUFFER_BYTES];
        let mut stream_app = Esp32BoardStreamApp::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
            &mut serial_frames,
            &mut ble_frames,
            &mut stream_qr,
        )
        .unwrap();
        assert!(matches!(
            stream_app.begin_ota_update(TestOtaWriter::new(), request),
            Err(Esp32OtaStartError::BootRequired)
        ));
        stream_app.boot().unwrap();
        assert!(
            stream_app
                .begin_ota_update(TestOtaWriter::new(), request)
                .unwrap()
                .writer()
                .unwrap()
                .begun
        );
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
    fn esp32_board_runtime_can_use_nvs_storage_backend() {
        let mut board =
            Esp32V1BoardRuntime::new_with_nvs(TestPlatform::new(JADE_MANIFEST), TestNvs::new());
        board.boot().unwrap();

        board
            .runtime_mut()
            .runtime_storage_mut()
            .set_record(
                jade_storage::StorageRecord::BleFlags,
                &[jade_storage::BLE_ENABLED],
            )
            .unwrap();

        let mut stored = Vec::new();
        board
            .runtime()
            .runtime_storage()
            .get_record(jade_storage::StorageRecord::BleFlags, &mut stored)
            .unwrap();
        assert_eq!(stored, Vec::from([jade_storage::BLE_ENABLED]));
    }

    #[test]
    fn esp32_board_runtime_boots_before_polling_full_v1() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().serial_rx = Some(v1_request("p", "ping"));

        let mut rx = [0u8; 128];
        assert_eq!(
            board.poll_serial_v1(&mut rx),
            Err(FirmwareFrameError::BootRequired)
        );
        assert_eq!(board.boot().unwrap().target, DeviceTarget::Jade);
        assert!(board.is_booted());
        assert_eq!(board.poll_serial_v1(&mut rx), Ok(true));
        assert_eq!(board.platform().serial_tx.len(), 1);

        let mut decoder = Decoder::new(&board.platform().serial_tx[0]);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "p");
        assert_eq!(decoder.str().unwrap(), "result");
        assert_eq!(decoder.u64().unwrap(), 0);
    }

    #[test]
    fn esp32_board_constructors_preserve_v1_1_target() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_V1_1_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        assert_eq!(board.boot().unwrap().target, DeviceTarget::JadeV1_1);

        let mut rx = vec![0; RX_BUFFER_BYTES];
        let mut qr = vec![0; QR_BUFFER_BYTES];
        let mut app = Esp32BoardApp::new(
            TestPlatform::new(JADE_V1_1_MANIFEST),
            jade_storage::MemoryStorage::new(),
            &mut rx,
            &mut qr,
        )
        .unwrap();
        assert_eq!(app.boot().unwrap().target, DeviceTarget::JadeV1_1);

        let mut serial_frames = vec![0; RX_BUFFER_BYTES];
        let mut ble_frames = vec![0; RX_BUFFER_BYTES];
        let mut stream_qr = vec![0; QR_BUFFER_BYTES];
        let mut stream_app = Esp32BoardStreamApp::new(
            TestPlatform::new(JADE_V1_1_MANIFEST),
            jade_storage::MemoryStorage::new(),
            &mut serial_frames,
            &mut ble_frames,
            &mut stream_qr,
        )
        .unwrap();
        assert_eq!(stream_app.boot().unwrap().target, DeviceTarget::JadeV1_1);
    }

    #[test]
    fn esp32_board_runtime_polls_camera_qr_after_boot() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().camera_rx = Some(b"ur:bytes/test".to_vec());

        let mut qr = [0u8; 64];
        assert_eq!(
            board.poll_camera_qr(&mut qr),
            Err(FirmwareFrameError::BootRequired)
        );
        board.boot().unwrap();
        assert_eq!(
            board.poll_camera_qr(&mut qr).unwrap(),
            Some(&b"ur:bytes/test"[..])
        );
        assert_eq!(board.poll_camera_qr(&mut qr), Ok(None));
    }

    #[test]
    fn esp32_board_runtime_polls_all_v1_transports_once() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().serial_rx = Some(v1_request("s", "ping"));
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
            Esp32V1PollReport {
                serial: true,
                ble: true
            }
        );
        assert!(report.any());
        assert_eq!(board.platform().serial_tx.len(), 1);
        assert_eq!(board.platform().ble_tx.len(), 1);
        assert_eq!(
            board.poll_v1_transports(&mut rx).unwrap(),
            Esp32V1PollReport::default()
        );
    }

    #[test]
    fn esp32_board_runtime_polls_all_v1_transport_streams() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        let serial = v1_request("s", "ping");
        let split = serial.len() / 2;
        board.platform_mut().serial_rx = Some(serial[..split].to_vec());
        board.platform_mut().ble_rx = Some(v1_request("b", "ping"));

        let mut serial_storage = [0u8; 256];
        let mut ble_storage = [0u8; 256];
        let mut serial_frames = CborFrameBuffer::new(&mut serial_storage);
        let mut ble_frames = CborFrameBuffer::new(&mut ble_storage);
        assert_eq!(
            board.poll_v1_transport_streams(&mut serial_frames, &mut ble_frames),
            Err(FirmwareFrameError::BootRequired)
        );

        board.boot().unwrap();
        let report = board
            .poll_v1_transport_streams(&mut serial_frames, &mut ble_frames)
            .unwrap();
        assert_eq!(
            report,
            Esp32V1PollReport {
                serial: false,
                ble: true
            }
        );
        assert_eq!(serial_frames.len(), split);
        assert_eq!(board.platform().serial_tx.len(), 0);
        assert_eq!(board.platform().ble_tx.len(), 1);

        board.platform_mut().serial_rx = Some(serial[split..].to_vec());
        let report = board
            .poll_v1_transport_streams(&mut serial_frames, &mut ble_frames)
            .unwrap();
        assert_eq!(
            report,
            Esp32V1PollReport {
                serial: true,
                ble: false
            }
        );
        assert!(serial_frames.is_empty());
        assert_eq!(board.platform().serial_tx.len(), 1);
    }

    #[test]
    fn esp32_board_runtime_tick_polls_services_once() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().serial_rx = Some(v1_request("s", "ping"));
        board.platform_mut().ble_rx = Some(v1_request("b", "ping"));
        board.platform_mut().camera_rx = Some(b"ur:bytes/tick".to_vec());
        board.platform_mut().confirmation_decision = UserConfirmationDecision::Approved;
        board.platform_mut().monotonic_millis = 55;
        board.platform_mut().rollback_secure_version = 4;

        let mut rx = [0u8; 128];
        let mut qr = [0u8; 64];
        assert!(matches!(
            board.tick(Esp32BoardTick {
                rx_buffer: &mut rx,
                qr_buffer: Some(&mut qr),
                display_status: Some(DisplayStatus::Busy("tick")),
                confirmation: Some(UserConfirmation::Export { label: "xpub" }),
            }),
            Err(FirmwareFrameError::BootRequired)
        ));

        board.boot().unwrap();
        let report = board
            .tick(Esp32BoardTick {
                rx_buffer: &mut rx,
                qr_buffer: Some(&mut qr),
                display_status: Some(DisplayStatus::Busy("tick")),
                confirmation: Some(UserConfirmation::Export { label: "xpub" }),
            })
            .unwrap();
        assert_eq!(
            report.transports,
            Esp32V1PollReport {
                serial: true,
                ble: true
            }
        );
        assert_eq!(report.qr_payload, Some(&b"ur:bytes/tick"[..]));
        assert_eq!(
            report.confirmation,
            Some(UserConfirmationDecision::Approved)
        );
        assert_eq!(report.monotonic_millis, 55);
        assert_eq!(report.rollback_secure_version, 4);
        assert_eq!(board.platform().display_status_count, 1);
        assert_eq!(board.platform().confirmation_count, 1);
    }

    #[test]
    fn esp32_board_runtime_stream_tick_polls_services() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        let serial = v1_request("s", "ping");
        let split = serial.len() / 2;
        board.platform_mut().serial_rx = Some(serial[..split].to_vec());
        board.platform_mut().ble_rx = Some(v1_request("b", "ping"));
        board.platform_mut().camera_rx = Some(b"ur:bytes/stream-tick".to_vec());
        board.platform_mut().confirmation_decision = UserConfirmationDecision::Approved;
        board.platform_mut().monotonic_millis = 66;
        board.platform_mut().rollback_secure_version = 6;

        let mut serial_storage = [0u8; 256];
        let mut ble_storage = [0u8; 256];
        let mut qr = [0u8; 64];
        let mut serial_frames = CborFrameBuffer::new(&mut serial_storage);
        let mut ble_frames = CborFrameBuffer::new(&mut ble_storage);
        assert!(matches!(
            board.tick_streams(
                &mut serial_frames,
                &mut ble_frames,
                Some(&mut qr),
                Some(DisplayStatus::Busy("stream")),
                Some(UserConfirmation::Export { label: "xpub" }),
            ),
            Err(FirmwareFrameError::BootRequired)
        ));

        board.boot().unwrap();
        let report = board
            .tick_streams(
                &mut serial_frames,
                &mut ble_frames,
                Some(&mut qr),
                Some(DisplayStatus::Busy("stream")),
                Some(UserConfirmation::Export { label: "xpub" }),
            )
            .unwrap();
        assert_eq!(
            report.transports,
            Esp32V1PollReport {
                serial: false,
                ble: true
            }
        );
        assert_eq!(report.qr_payload, Some(&b"ur:bytes/stream-tick"[..]));
        assert_eq!(
            report.confirmation,
            Some(UserConfirmationDecision::Approved)
        );
        assert_eq!(report.monotonic_millis, 66);
        assert_eq!(report.rollback_secure_version, 6);
        assert_eq!(board.platform().display_status_count, 1);
        assert_eq!(board.platform().confirmation_count, 1);

        board.platform_mut().serial_rx = Some(serial[split..].to_vec());
        let report = board
            .tick_streams(&mut serial_frames, &mut ble_frames, None, None, None)
            .unwrap();
        assert_eq!(
            report.transports,
            Esp32V1PollReport {
                serial: true,
                ble: false
            }
        );
        assert_eq!(board.platform().serial_tx.len(), 1);
    }

    #[test]
    fn esp32_board_app_validates_static_buffer_sizes() {
        let short_rx = vec![0; RX_BUFFER_BYTES - 1];
        let qr = vec![0; QR_BUFFER_BYTES];
        assert_eq!(
            validate_board_buffers(&short_rx, &qr),
            Err(Esp32BoardAppError::RxBufferTooSmall {
                required: RX_BUFFER_BYTES,
                actual: RX_BUFFER_BYTES - 1,
            })
        );

        let rx = vec![0; RX_BUFFER_BYTES];
        let short_qr = vec![0; QR_BUFFER_BYTES - 1];
        assert_eq!(
            validate_board_buffers(&rx, &short_qr),
            Err(Esp32BoardAppError::QrBufferTooSmall {
                required: QR_BUFFER_BYTES,
                actual: QR_BUFFER_BYTES - 1,
            })
        );

        assert_eq!(validate_board_buffers(&rx, &qr), Ok(()));
    }

    #[test]
    fn esp32_board_app_ticks_runtime_with_fixed_buffers() {
        let mut rx = vec![0; RX_BUFFER_BYTES];
        let mut qr = vec![0; QR_BUFFER_BYTES];
        let mut app = Esp32BoardApp::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
            &mut rx,
            &mut qr,
        )
        .unwrap();
        app.runtime_mut().platform_mut().serial_rx = Some(v1_request("s", "ping"));
        app.runtime_mut().platform_mut().camera_rx = Some(b"ur:bytes/app".to_vec());
        app.runtime_mut().platform_mut().monotonic_millis = 77;
        app.runtime_mut().platform_mut().rollback_secure_version = 5;

        assert!(matches!(
            app.tick(Some(DisplayStatus::Busy("app")), None),
            Err(FirmwareFrameError::BootRequired)
        ));
        app.boot().unwrap();
        let report = app.tick(Some(DisplayStatus::Busy("app")), None).unwrap();

        assert_eq!(
            report.transports,
            Esp32V1PollReport {
                serial: true,
                ble: false,
            }
        );
        assert_eq!(report.qr_payload, Some(&b"ur:bytes/app"[..]));
        assert_eq!(report.monotonic_millis, 77);
        assert_eq!(report.rollback_secure_version, 5);
        assert_eq!(app.runtime().platform().serial_tx.len(), 1);
        assert_eq!(app.runtime().platform().display_status_count, 1);
    }

    #[test]
    fn esp32_board_stream_app_preserves_transport_frames_across_ticks() {
        let mut serial_frames = vec![0; RX_BUFFER_BYTES];
        let mut ble_frames = vec![0; RX_BUFFER_BYTES];
        let mut qr = vec![0; QR_BUFFER_BYTES];
        let mut app = Esp32BoardStreamApp::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
            &mut serial_frames,
            &mut ble_frames,
            &mut qr,
        )
        .unwrap();
        let serial = v1_request("s", "ping");
        let split = serial.len() / 2;
        app.runtime_mut().platform_mut().serial_rx = Some(serial[..split].to_vec());
        app.runtime_mut().platform_mut().ble_rx = Some(v1_request("b", "ping"));
        app.runtime_mut().platform_mut().camera_rx = Some(b"ur:bytes/stream-app".to_vec());
        app.runtime_mut().platform_mut().monotonic_millis = 88;
        app.runtime_mut().platform_mut().rollback_secure_version = 6;

        assert!(matches!(
            app.tick(Some(DisplayStatus::Busy("stream-app")), None),
            Err(FirmwareFrameError::BootRequired)
        ));
        app.boot().unwrap();
        let report = app
            .tick(Some(DisplayStatus::Busy("stream-app")), None)
            .unwrap();
        assert_eq!(
            report.transports,
            Esp32V1PollReport {
                serial: false,
                ble: true,
            }
        );
        assert_eq!(report.qr_payload, Some(&b"ur:bytes/stream-app"[..]));
        assert_eq!(report.monotonic_millis, 88);
        assert_eq!(report.rollback_secure_version, 6);
        assert_eq!(app.serial_pending(), &serial[..split]);
        assert_eq!(app.runtime().platform().serial_tx.len(), 0);
        assert_eq!(app.runtime().platform().ble_tx.len(), 1);

        app.runtime_mut().platform_mut().serial_rx = Some(serial[split..].to_vec());
        let report = app.tick(None, None).unwrap();
        assert_eq!(
            report.transports,
            Esp32V1PollReport {
                serial: true,
                ble: false,
            }
        );
        assert!(app.serial_pending().is_empty());
        assert_eq!(app.runtime().platform().serial_tx.len(), 1);
    }

    #[test]
    fn esp32_board_runtime_gates_display_and_confirmation() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );

        assert_eq!(
            board.display_status(DisplayStatus::Ready),
            Err(FirmwareFrameError::BootRequired)
        );
        assert_eq!(
            board.confirm_user(UserConfirmation::Export {
                label: "master blinding key"
            }),
            Err(FirmwareFrameError::BootRequired)
        );

        board.boot().unwrap();
        board.display_status(DisplayStatus::Ready).unwrap();
        assert_eq!(board.platform().display_status_count, 1);

        board.platform_mut().confirmation_decision = UserConfirmationDecision::Rejected;
        assert_eq!(
            board
                .confirm_user(UserConfirmation::Address {
                    network: "mainnet",
                    address: "bc1qexample"
                })
                .unwrap(),
            UserConfirmationDecision::Rejected
        );
        assert_eq!(board.platform().confirmation_count, 1);
    }

    #[test]
    fn esp32_board_runtime_gates_rng_clock_and_rollback_state() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        board.platform_mut().monotonic_millis = 42;
        board.platform_mut().rollback_secure_version = 7;

        let mut random = [0u8; 4];
        assert_eq!(
            board.fill_random(&mut random),
            Err(FirmwareFrameError::BootRequired)
        );
        assert_eq!(
            board.monotonic_millis(),
            Err(FirmwareFrameError::BootRequired)
        );
        assert_eq!(
            board.rollback_secure_version(),
            Err(FirmwareFrameError::BootRequired)
        );

        board.boot().unwrap();
        board.fill_random(&mut random).unwrap();
        assert_eq!(random, [0x5a; 4]);
        assert_eq!(board.monotonic_millis().unwrap(), 42);
        assert_eq!(board.rollback_secure_version().unwrap(), 7);
    }

    #[test]
    fn esp32_camera_qr_rejects_oversized_platform_payloads() {
        let mut platform = TestPlatform::new(JADE_MANIFEST);
        platform.camera_rx = Some(b"too-large".to_vec());

        let mut qr = [0u8; 4];
        assert_eq!(
            poll_camera_qr(&mut platform, &mut qr),
            Err(DeviceBootFailure::TransportUnavailable)
        );
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
    fn esp32_serial_polls_full_v1_runtime_frames() {
        let mut runtime = v1_runtime_for_v1(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        runtime.runtime_platform_mut().serial_rx = Some(v1_request("p", "ping"));

        let mut rx = [0u8; 128];
        assert_eq!(poll_serial_full_v1(&mut runtime, &mut rx), Ok(true));
        assert_eq!(runtime.runtime_platform().serial_tx.len(), 1);

        let mut decoder = Decoder::new(&runtime.runtime_platform().serial_tx[0]);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "p");
        assert_eq!(decoder.str().unwrap(), "result");
        assert_eq!(decoder.u64().unwrap(), 0);
    }

    #[test]
    fn esp32_full_v1_transport_enforces_manifest_allocation_budget() {
        let request = v1_request("p", "ping");
        let mut request_runtime = v1_runtime_for_v1(
            TestPlatform::new(manifest_with_allocation(
                JADE_MANIFEST,
                AllocationBudget {
                    max_request_bytes: 4,
                    max_response_bytes: 4096,
                    max_scratch_bytes: 1024,
                },
            )),
            jade_storage::MemoryStorage::new(),
        );
        request_runtime.runtime_platform_mut().serial_rx = Some(request.clone());

        let mut rx = [0u8; 128];
        assert_eq!(
            poll_serial_full_v1(&mut request_runtime, &mut rx),
            Err(FirmwareFrameError::Allocation(
                jade_core::AllocationFailure::RequestTooLarge {
                    requested: request.len(),
                    limit: 4
                }
            ))
        );
        assert!(request_runtime.runtime_platform().serial_tx.is_empty());

        let mut response_runtime = v1_runtime_for_v1(
            TestPlatform::new(manifest_with_allocation(
                JADE_MANIFEST,
                AllocationBudget {
                    max_request_bytes: 1024,
                    max_response_bytes: 4,
                    max_scratch_bytes: 1024,
                },
            )),
            jade_storage::MemoryStorage::new(),
        );
        response_runtime.runtime_platform_mut().serial_rx = Some(request);
        let mut frame_storage = [0u8; 256];
        let mut frames = CborFrameBuffer::new(&mut frame_storage);

        assert!(matches!(
            poll_serial_full_v1_stream(&mut response_runtime, &mut frames),
            Err(FirmwareFrameError::Allocation(
                jade_core::AllocationFailure::ResponseTooLarge { limit: 4, .. }
            ))
        ));
        assert!(response_runtime.runtime_platform().serial_tx.is_empty());
    }

    #[test]
    fn esp32_serial_stream_polls_split_and_trailing_full_v1_frames() {
        let mut runtime = v1_runtime_for_v1(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        let first = v1_request("a", "ping");
        let second = v1_request("b", "ping");
        let split = first.len() / 2;
        let mut frame_storage = [0u8; 256];
        let mut frames = CborFrameBuffer::new(&mut frame_storage);

        runtime.runtime_platform_mut().serial_rx = Some(first[..split].to_vec());
        assert_eq!(
            poll_serial_full_v1_stream(&mut runtime, &mut frames),
            Ok(false)
        );
        assert_eq!(runtime.runtime_platform().serial_tx.len(), 0);
        assert_eq!(frames.len(), split);

        let mut next = first[split..].to_vec();
        next.extend_from_slice(&second);
        runtime.runtime_platform_mut().serial_rx = Some(next);
        assert_eq!(
            poll_serial_full_v1_stream(&mut runtime, &mut frames),
            Ok(true)
        );
        assert!(frames.is_empty());
        assert_eq!(runtime.runtime_platform().serial_tx.len(), 2);
    }

    #[test]
    fn esp32_board_runtime_stream_polling_is_boot_gated() {
        let mut board = Esp32V1BoardRuntime::new(
            TestPlatform::new(JADE_MANIFEST),
            jade_storage::MemoryStorage::new(),
        );
        let mut frame_storage = [0u8; 256];
        let mut frames = CborFrameBuffer::new(&mut frame_storage);
        board.platform_mut().ble_rx = Some(v1_request("b", "ping"));

        assert_eq!(
            board.poll_ble_v1_stream(&mut frames),
            Err(FirmwareFrameError::BootRequired)
        );
        board.boot().unwrap();
        assert_eq!(board.poll_ble_v1_stream(&mut frames), Ok(true));
        assert_eq!(board.platform().ble_tx.len(), 1);
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
