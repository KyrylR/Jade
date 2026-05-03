#![no_std]

#[cfg(test)]
extern crate alloc;

use jade_core::{
    AllocationBudget, CborFrameBuffer, CoreResult, CoreState, DeviceBootFailure,
    DeviceBootReadiness, DeviceBootReport, DeviceFeatureSet, DeviceManifest, DeviceMemoryBudget,
    DevicePartitionLayout, DevicePlatform, DeviceRunningImage, DeviceRuntime, DeviceRuntimeError,
    DeviceServiceReadiness, DeviceTarget, DisplayStatus, FirmwareFrameError, FirmwareProtocol,
    OtaImageWriter, OtaRequest, OtaUploadVerifier, OtaWriteError, OtaWriteSession, Platform,
    StaticVersionContext, UserConfirmation, UserConfirmationDecision, VersionDebugInfo,
    VersionInfo,
};
use jade_emulator::{RuntimePlatformState, RuntimePlatformStateAccess};

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

pub trait Esp32Hardware {
    fn manifest(&self) -> DeviceManifest;
    fn service_readiness(&mut self) -> DeviceServiceReadiness {
        DeviceServiceReadiness::ready_for_manifest(self.manifest())
    }
    fn boot_readiness(&mut self) -> DeviceBootReadiness {
        let manifest = self.manifest();
        self.service_readiness().boot_readiness(manifest)
    }
    fn boot_report(&mut self) -> DeviceBootReport {
        DeviceBootReport::from_readiness(self.manifest().target, self.boot_readiness())
    }
    fn running_image(&mut self) -> Result<Option<DeviceRunningImage>, DeviceBootFailure> {
        Ok(None)
    }
    fn mark_running_image_valid_cancel_rollback(&mut self) -> Result<(), DeviceBootFailure> {
        Ok(())
    }
    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), DeviceBootFailure>;
    fn monotonic_millis(&self) -> u64;
    fn rollback_secure_version(&self) -> u32;
    fn idf_version(&self) -> &'static str {
        "rust"
    }
    fn chip_features(&self) -> &'static str {
        "ESP32"
    }
    fn efusemac(&self) -> &'static str {
        ""
    }
    fn attestation_initialised(&self) -> bool {
        false
    }
    fn battery_status(&self) -> u64 {
        0
    }
    fn battery_millivolts(&self) -> u64 {
        0
    }
    fn battery_charging(&self) -> bool {
        false
    }
    fn version_debug_info(&self) -> Option<VersionDebugInfo> {
        Some(jade_core::default_version_debug_info(self.manifest()))
    }
    fn add_entropy(&mut self, _entropy: &[u8]) -> CoreResult<()> {
        Ok(())
    }
    fn set_epoch(&mut self, _epoch: u64) -> CoreResult<()> {
        Ok(())
    }
    fn current_epoch(&self) -> Option<u64> {
        None
    }
    fn ota_begin(&mut self, _request: &OtaRequest) -> CoreResult<()> {
        Ok(())
    }
    fn ota_write(&mut self, _offset: u64, _data: &[u8]) -> CoreResult<()> {
        Ok(())
    }
    fn ota_finish(&mut self, _request: &OtaRequest, _received_compressed: u64) -> CoreResult<()> {
        Ok(())
    }
    fn ota_abort(&mut self) {}
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

#[derive(Debug)]
pub struct Esp32DevicePlatform<H> {
    runtime_state: RuntimePlatformState,
    hardware: H,
}

impl<H> Esp32DevicePlatform<H> {
    pub fn new(hardware: H) -> Self {
        Self {
            runtime_state: RuntimePlatformState::default(),
            hardware,
        }
    }

    pub fn with_runtime_state(hardware: H, runtime_state: RuntimePlatformState) -> Self {
        Self {
            runtime_state,
            hardware,
        }
    }

    pub fn hardware(&self) -> &H {
        &self.hardware
    }

    pub fn hardware_mut(&mut self) -> &mut H {
        &mut self.hardware
    }

    pub fn into_inner(self) -> (H, RuntimePlatformState) {
        (self.hardware, self.runtime_state)
    }
}

impl<H: Esp32Hardware> Platform for Esp32DevicePlatform<H> {
    fn version_info<'a>(&'a self, state: &CoreState) -> VersionInfo<'a> {
        jade_core::static_version_info_with_context(
            self.hardware.manifest(),
            state,
            StaticVersionContext {
                idf_version: self.hardware.idf_version(),
                chip_features: self.hardware.chip_features(),
                efusemac: self.hardware.efusemac(),
                attestation_initialised: self.hardware.attestation_initialised(),
                battery_status: self.hardware.battery_status(),
                battery_millivolts: self.hardware.battery_millivolts(),
                battery_charging: self.hardware.battery_charging(),
                has_pin: self.runtime_state.jade_has_pin(),
                debug: self.hardware.version_debug_info(),
            },
        )
    }

    fn add_entropy(&mut self, entropy: &[u8]) -> CoreResult<()> {
        self.hardware.add_entropy(entropy)
    }

    fn set_epoch(&mut self, epoch: u64) -> CoreResult<()> {
        self.hardware.set_epoch(epoch)
    }
}

impl<H: Esp32Hardware> RuntimePlatformStateAccess for Esp32DevicePlatform<H> {
    fn runtime_state(&self) -> &RuntimePlatformState {
        &self.runtime_state
    }

    fn runtime_state_mut(&mut self) -> &mut RuntimePlatformState {
        &mut self.runtime_state
    }

    fn runtime_current_epoch(&self) -> Option<u64> {
        self.hardware.current_epoch()
    }

    fn runtime_ota_begin(&mut self, request: &OtaRequest) -> CoreResult<()> {
        self.hardware.ota_begin(request)
    }

    fn runtime_ota_write(&mut self, offset: u64, data: &[u8]) -> CoreResult<()> {
        self.hardware.ota_write(offset, data)
    }

    fn runtime_ota_finish(
        &mut self,
        request: &OtaRequest,
        received_compressed: u64,
    ) -> CoreResult<()> {
        self.hardware.ota_finish(request, received_compressed)
    }

    fn runtime_ota_abort(&mut self) {
        self.hardware.ota_abort();
    }
}

impl<H: Esp32Hardware> DevicePlatform for Esp32DevicePlatform<H> {
    fn manifest(&self) -> DeviceManifest {
        self.hardware.manifest()
    }

    fn boot_report(&mut self) -> DeviceBootReport {
        self.hardware.boot_report()
    }

    fn running_image(&mut self) -> Result<Option<DeviceRunningImage>, DeviceBootFailure> {
        self.hardware.running_image()
    }

    fn mark_running_image_valid_cancel_rollback(&mut self) -> Result<(), DeviceBootFailure> {
        self.hardware.mark_running_image_valid_cancel_rollback()
    }

    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), DeviceBootFailure> {
        self.hardware.fill_random(out)
    }

    fn monotonic_millis(&self) -> u64 {
        self.hardware.monotonic_millis()
    }

    fn rollback_secure_version(&self) -> u32 {
        self.hardware.rollback_secure_version()
    }
}

impl<H: Esp32Hardware> Esp32PlatformShim for Esp32DevicePlatform<H> {
    fn serial_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure> {
        self.hardware.serial_send(bytes)
    }

    fn serial_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
        self.hardware.serial_recv(out)
    }

    fn ble_send(&mut self, bytes: &[u8]) -> Result<(), DeviceBootFailure> {
        self.hardware.ble_send(bytes)
    }

    fn ble_recv(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
        self.hardware.ble_recv(out)
    }

    fn camera_qr_scan(&mut self, out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
        self.hardware.camera_qr_scan(out)
    }

    fn display_status(&mut self, status: DisplayStatus<'_>) -> Result<(), DeviceBootFailure> {
        self.hardware.display_status(status)
    }

    fn confirm_user(
        &mut self,
        request: UserConfirmation<'_>,
    ) -> Result<UserConfirmationDecision, DeviceBootFailure> {
        self.hardware.confirm_user(request)
    }
}

pub type Esp32Runtime<P> = DeviceRuntime<P>;
pub type Esp32V1Runtime<P, B> = jade_emulator::JadeRuntime<P, B>;
pub type Esp32NvsStorage<B> = jade_storage::NvsStorage<B>;
pub type Esp32OtaSession<W, V = jade_core::NoOtaUploadVerifier> = OtaWriteSession<W, V>;

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

#[derive(Debug)]
pub struct Esp32BoardStreamBuffers<'a> {
    pub serial_frame_buffer: &'a mut [u8],
    pub ble_frame_buffer: &'a mut [u8],
    pub qr_buffer: &'a mut [u8],
}

#[derive(Debug)]
pub struct Esp32BoardStreamStorage {
    serial_frame_buffer: [u8; RX_BUFFER_BYTES],
    ble_frame_buffer: [u8; RX_BUFFER_BYTES],
    qr_buffer: [u8; QR_BUFFER_BYTES],
}

impl Esp32BoardStreamStorage {
    pub const SERIAL_CAPACITY: usize = RX_BUFFER_BYTES;
    pub const BLE_CAPACITY: usize = RX_BUFFER_BYTES;
    pub const QR_CAPACITY: usize = QR_BUFFER_BYTES;

    pub const fn new() -> Self {
        Self {
            serial_frame_buffer: [0; Self::SERIAL_CAPACITY],
            ble_frame_buffer: [0; Self::BLE_CAPACITY],
            qr_buffer: [0; Self::QR_CAPACITY],
        }
    }

    pub fn buffers(&mut self) -> Esp32BoardStreamBuffers<'_> {
        Esp32BoardStreamBuffers {
            serial_frame_buffer: &mut self.serial_frame_buffer,
            ble_frame_buffer: &mut self.ble_frame_buffer,
            qr_buffer: &mut self.qr_buffer,
        }
    }

    pub const fn serial_capacity(&self) -> usize {
        Self::SERIAL_CAPACITY
    }

    pub const fn ble_capacity(&self) -> usize {
        Self::BLE_CAPACITY
    }

    pub const fn qr_capacity(&self) -> usize {
        Self::QR_CAPACITY
    }
}

impl Default for Esp32BoardStreamStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Esp32BoardStreamBuffers<'a> {
    pub fn validate(&self) -> Result<(), Esp32BoardAppError> {
        validate_board_stream_buffers(
            self.serial_frame_buffer,
            self.ble_frame_buffer,
            self.qr_buffer,
        )
    }

    pub fn serial_capacity(&self) -> usize {
        self.serial_frame_buffer.len()
    }

    pub fn ble_capacity(&self) -> usize {
        self.ble_frame_buffer.len()
    }

    pub fn qr_capacity(&self) -> usize {
        self.qr_buffer.len()
    }
}

#[derive(Debug, Default)]
pub struct Esp32BoardLoopInputs {
    pub display_status: Option<DisplayStatus<'static>>,
    pub confirmation: Option<UserConfirmation<'static>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Esp32BoardLoopDecision {
    Continue,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Esp32BoardLoopStopReason {
    Hook,
    TickLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Esp32BoardLoopRun {
    pub booted: bool,
    pub ticks: u64,
    pub stop_reason: Esp32BoardLoopStopReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Esp32BoardLoopError {
    Boot(DeviceRuntimeError),
    Tick(FirmwareFrameError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Esp32BoardEntrypointError {
    App(Esp32BoardAppError),
    Loop(Esp32BoardLoopError),
}

pub trait Esp32BoardLoopHooks {
    fn next_inputs(&mut self) -> Esp32BoardLoopInputs {
        Esp32BoardLoopInputs::default()
    }

    fn on_boot(&mut self, _report: &jade_core::DeviceBootReport) -> Esp32BoardLoopDecision {
        Esp32BoardLoopDecision::Continue
    }

    fn on_boot_error(&mut self, _error: DeviceRuntimeError) -> Esp32BoardLoopDecision {
        Esp32BoardLoopDecision::Stop
    }

    fn on_tick(&mut self, _report: &Esp32BoardTickReport<'_>) -> Esp32BoardLoopDecision {
        Esp32BoardLoopDecision::Continue
    }

    fn on_tick_error(&mut self, _error: FirmwareFrameError) -> Esp32BoardLoopDecision {
        Esp32BoardLoopDecision::Stop
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Esp32OtaStartError<E, V = core::convert::Infallible> {
    BootRequired,
    Manifest(&'static str),
    Partition(jade_core::DeviceOtaError),
    Writer(OtaWriteError<E, V>),
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

pub fn begin_ota_update_verified<W, V>(
    manifest: DeviceManifest,
    writer: W,
    request: OtaRequest,
    verifier: V,
) -> Result<Esp32OtaSession<W, V>, Esp32OtaStartError<W::Error, V::Error>>
where
    W: OtaImageWriter,
    V: OtaUploadVerifier,
{
    assert_manifest_matches_real_device(manifest).map_err(Esp32OtaStartError::Manifest)?;
    manifest
        .validate_ota_request(&request)
        .map_err(Esp32OtaStartError::Partition)?;
    OtaWriteSession::begin_verified(writer, request, verifier).map_err(Esp32OtaStartError::Writer)
}

pub fn run_board_stream_loop_from_storage<P, B, H>(
    platform: P,
    storage_backend: B,
    storage: &mut Esp32BoardStreamStorage,
    hooks: &mut H,
) -> Result<Esp32BoardLoopRun, Esp32BoardEntrypointError>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
    H: Esp32BoardLoopHooks,
{
    let mut event_loop = Esp32BoardStreamLoop::new_from_storage(platform, storage_backend, storage)
        .map_err(Esp32BoardEntrypointError::App)?;
    event_loop
        .run_until_hook_stop(hooks)
        .map_err(Esp32BoardEntrypointError::Loop)
}

pub fn run_board_stream_loop_with_nvs_storage<P, B, H>(
    platform: P,
    nvs_backend: B,
    storage: &mut Esp32BoardStreamStorage,
    hooks: &mut H,
) -> Result<Esp32BoardLoopRun, Esp32BoardEntrypointError>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::NvsKeyValueBackend,
    H: Esp32BoardLoopHooks,
{
    run_board_stream_loop_from_storage(
        platform,
        jade_storage::NvsStorage::new(nvs_backend),
        storage,
        hooks,
    )
}

pub fn run_board_stream_loop_with_hardware_and_nvs_storage<Hw, B, H>(
    hardware: Hw,
    nvs_backend: B,
    storage: &mut Esp32BoardStreamStorage,
    hooks: &mut H,
) -> Result<Esp32BoardLoopRun, Esp32BoardEntrypointError>
where
    Hw: Esp32Hardware,
    B: jade_storage::NvsKeyValueBackend,
    H: Esp32BoardLoopHooks,
{
    run_board_stream_loop_with_nvs_storage(
        Esp32DevicePlatform::new(hardware),
        nvs_backend,
        storage,
        hooks,
    )
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

#[derive(Debug)]
pub struct Esp32BoardStreamLoop<'a, P, B> {
    app: Esp32BoardStreamApp<'a, P, B>,
    ticks: u64,
}

impl<'a, P, B> Esp32BoardStreamLoop<'a, P, B>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::StorageBackend,
{
    pub fn new(app: Esp32BoardStreamApp<'a, P, B>) -> Self {
        Self { app, ticks: 0 }
    }

    pub fn new_from_parts(
        platform: P,
        storage_backend: B,
        buffers: Esp32BoardStreamBuffers<'a>,
    ) -> Result<Self, Esp32BoardAppError> {
        Ok(Self::new(Esp32BoardStreamApp::new_with_buffers(
            platform,
            storage_backend,
            buffers,
        )?))
    }

    pub fn new_from_storage(
        platform: P,
        storage_backend: B,
        storage: &'a mut Esp32BoardStreamStorage,
    ) -> Result<Self, Esp32BoardAppError> {
        Self::new_from_parts(platform, storage_backend, storage.buffers())
    }

    pub fn app(&self) -> &Esp32BoardStreamApp<'a, P, B> {
        &self.app
    }

    pub fn app_mut(&mut self) -> &mut Esp32BoardStreamApp<'a, P, B> {
        &mut self.app
    }

    pub fn into_app(self) -> Esp32BoardStreamApp<'a, P, B> {
        self.app
    }

    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    pub fn run_once<H>(
        &mut self,
        hooks: &mut H,
    ) -> Result<Esp32BoardLoopDecision, Esp32BoardLoopError>
    where
        H: Esp32BoardLoopHooks,
    {
        if !self.app.is_booted() {
            let report = match self.app.boot() {
                Ok(report) => report,
                Err(error) => {
                    if hooks.on_boot_error(error) == Esp32BoardLoopDecision::Stop {
                        return Err(Esp32BoardLoopError::Boot(error));
                    }
                    return Ok(Esp32BoardLoopDecision::Continue);
                }
            };
            if hooks.on_boot(&report) == Esp32BoardLoopDecision::Stop {
                return Ok(Esp32BoardLoopDecision::Stop);
            }
        }

        let tick = {
            let inputs = hooks.next_inputs();
            self.app.tick(inputs.display_status, inputs.confirmation)
        };
        match tick {
            Ok(report) => {
                self.ticks = self.ticks.saturating_add(1);
                Ok(hooks.on_tick(&report))
            }
            Err(error) => {
                let decision = hooks.on_tick_error(error);
                if decision == Esp32BoardLoopDecision::Stop {
                    Err(Esp32BoardLoopError::Tick(error))
                } else {
                    Ok(decision)
                }
            }
        }
    }

    pub fn run_until_stop<H>(
        &mut self,
        hooks: &mut H,
        max_ticks: usize,
    ) -> Result<Esp32BoardLoopRun, Esp32BoardLoopError>
    where
        H: Esp32BoardLoopHooks,
    {
        for _ in 0..max_ticks {
            if self.run_once(hooks)? == Esp32BoardLoopDecision::Stop {
                return Ok(Esp32BoardLoopRun {
                    booted: self.app.is_booted(),
                    ticks: self.ticks,
                    stop_reason: Esp32BoardLoopStopReason::Hook,
                });
            }
        }

        Ok(Esp32BoardLoopRun {
            booted: self.app.is_booted(),
            ticks: self.ticks,
            stop_reason: Esp32BoardLoopStopReason::TickLimit,
        })
    }

    pub fn run_until_hook_stop<H>(
        &mut self,
        hooks: &mut H,
    ) -> Result<Esp32BoardLoopRun, Esp32BoardLoopError>
    where
        H: Esp32BoardLoopHooks,
    {
        loop {
            if self.run_once(hooks)? == Esp32BoardLoopDecision::Stop {
                return Ok(Esp32BoardLoopRun {
                    booted: self.app.is_booted(),
                    ticks: self.ticks,
                    stop_reason: Esp32BoardLoopStopReason::Hook,
                });
            }
        }
    }
}

impl<'a, P, B> Esp32BoardStreamLoop<'a, P, Esp32NvsStorage<B>>
where
    P: Esp32PlatformShim + jade_emulator::RuntimePlatform,
    B: jade_storage::NvsKeyValueBackend,
{
    pub fn new_with_nvs(
        platform: P,
        nvs_backend: B,
        buffers: Esp32BoardStreamBuffers<'a>,
    ) -> Result<Self, Esp32BoardAppError> {
        Self::new_from_parts(
            platform,
            jade_storage::NvsStorage::new(nvs_backend),
            buffers,
        )
    }

    pub fn new_with_nvs_storage(
        platform: P,
        nvs_backend: B,
        storage: &'a mut Esp32BoardStreamStorage,
    ) -> Result<Self, Esp32BoardAppError> {
        Self::new_with_nvs(platform, nvs_backend, storage.buffers())
    }
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

    pub fn begin_ota_update_verified<W, V>(
        &mut self,
        writer: W,
        request: OtaRequest,
        verifier: V,
    ) -> Result<Esp32OtaSession<W, V>, Esp32OtaStartError<W::Error, V::Error>>
    where
        W: OtaImageWriter,
        V: OtaUploadVerifier,
    {
        self.runtime
            .begin_ota_update_verified(writer, request, verifier)
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
        Self::new_with_buffers(
            platform,
            storage_backend,
            Esp32BoardStreamBuffers {
                serial_frame_buffer,
                ble_frame_buffer,
                qr_buffer,
            },
        )
    }

    pub fn new_with_buffers(
        platform: P,
        storage_backend: B,
        buffers: Esp32BoardStreamBuffers<'a>,
    ) -> Result<Self, Esp32BoardAppError> {
        buffers.validate()?;
        Ok(Self {
            runtime: Esp32V1BoardRuntime::new(platform, storage_backend),
            serial_frames: CborFrameBuffer::new(buffers.serial_frame_buffer),
            ble_frames: CborFrameBuffer::new(buffers.ble_frame_buffer),
            qr_buffer: buffers.qr_buffer,
        })
    }

    pub fn new_with_storage(
        platform: P,
        storage_backend: B,
        storage: &'a mut Esp32BoardStreamStorage,
    ) -> Result<Self, Esp32BoardAppError> {
        Self::new_with_buffers(platform, storage_backend, storage.buffers())
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

    pub fn begin_ota_update_verified<W, V>(
        &mut self,
        writer: W,
        request: OtaRequest,
        verifier: V,
    ) -> Result<Esp32OtaSession<W, V>, Esp32OtaStartError<W::Error, V::Error>>
    where
        W: OtaImageWriter,
        V: OtaUploadVerifier,
    {
        self.runtime
            .begin_ota_update_verified(writer, request, verifier)
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

    pub fn new_with_nvs_storage(
        platform: P,
        nvs_backend: B,
        storage: &'a mut Esp32BoardStreamStorage,
    ) -> Result<Self, Esp32BoardAppError> {
        Self::new_with_nvs(
            platform,
            nvs_backend,
            storage.serial_frame_buffer.as_mut_slice(),
            storage.ble_frame_buffer.as_mut_slice(),
            storage.qr_buffer.as_mut_slice(),
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

    pub fn begin_ota_update_verified<W, V>(
        &mut self,
        writer: W,
        request: OtaRequest,
        verifier: V,
    ) -> Result<Esp32OtaSession<W, V>, Esp32OtaStartError<W::Error, V::Error>>
    where
        W: OtaImageWriter,
        V: OtaUploadVerifier,
    {
        if !self.booted {
            return Err(Esp32OtaStartError::BootRequired);
        }
        begin_ota_update_verified(self.platform().manifest(), writer, request, verifier)
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
    use jade_emulator::{RuntimePlatform, RuntimePlatformState, RuntimePlatformStateAccess};
    use jade_protocol_v2::{RequestBody, RequestKind, ResponseBody};
    use minicbor::{Decoder, Encoder};

    #[derive(Debug)]
    struct TestPlatform {
        runtime_state: RuntimePlatformState,
        epoch: Option<u64>,
        manifest: DeviceManifest,
        boot_report: jade_core::DeviceBootReport,
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
        running_image: Option<DeviceRunningImage>,
        mark_valid_count: usize,
        ota_begun: Option<OtaRequest>,
        ota_writes: Vec<(u64, Vec<u8>)>,
        ota_finished: Option<(OtaRequest, u64)>,
        ota_aborted: bool,
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestUploadVerifier {
        received: usize,
    }

    impl TestUploadVerifier {
        fn new() -> Self {
            Self { received: 0 }
        }

        fn hash_for_len(len: usize) -> [u8; jade_core::OTA_HASH_LEN] {
            let mut hash = [0; jade_core::OTA_HASH_LEN];
            hash[0] = len as u8;
            hash
        }
    }

    impl OtaUploadVerifier for TestUploadVerifier {
        type Error = DeviceBootFailure;

        fn update(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.received += data.len();
            Ok(())
        }

        fn verify(
            &mut self,
            request: &OtaRequest,
        ) -> Result<(), jade_core::OtaVerifyError<Self::Error>> {
            if request.hash_type != jade_core::OtaHashType::CompressedUpload {
                return Ok(());
            }
            let actual = Self::hash_for_len(self.received);
            if actual == request.expected_hash {
                Ok(())
            } else {
                Err(jade_core::OtaVerifyError::HashMismatch {
                    expected: request.expected_hash,
                    actual,
                })
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
                boot_report: jade_core::DeviceBootReport::ok(manifest.target),
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
                running_image: None,
                mark_valid_count: 0,
                ota_begun: None,
                ota_writes: Vec::new(),
                ota_finished: None,
                ota_aborted: false,
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
            self.boot_report
        }

        fn running_image(&mut self) -> Result<Option<DeviceRunningImage>, DeviceBootFailure> {
            Ok(self.running_image)
        }

        fn mark_running_image_valid_cancel_rollback(&mut self) -> Result<(), DeviceBootFailure> {
            self.mark_valid_count += 1;
            Ok(())
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

    impl Esp32Hardware for TestPlatform {
        fn manifest(&self) -> DeviceManifest {
            self.manifest
        }

        fn boot_report(&mut self) -> jade_core::DeviceBootReport {
            self.boot_report
        }

        fn running_image(&mut self) -> Result<Option<DeviceRunningImage>, DeviceBootFailure> {
            Ok(self.running_image)
        }

        fn mark_running_image_valid_cancel_rollback(&mut self) -> Result<(), DeviceBootFailure> {
            self.mark_valid_count += 1;
            Ok(())
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

        fn idf_version(&self) -> &'static str {
            "esp-idf-rust"
        }

        fn efusemac(&self) -> &'static str {
            "001122334455"
        }

        fn set_epoch(&mut self, epoch: u64) -> CoreResult<()> {
            self.epoch = Some(epoch);
            Ok(())
        }

        fn current_epoch(&self) -> Option<u64> {
            self.epoch
        }

        fn ota_begin(&mut self, request: &OtaRequest) -> CoreResult<()> {
            self.ota_begun = Some(*request);
            self.ota_writes.clear();
            self.ota_finished = None;
            self.ota_aborted = false;
            Ok(())
        }

        fn ota_write(&mut self, offset: u64, data: &[u8]) -> CoreResult<()> {
            self.ota_writes.push((offset, data.to_vec()));
            Ok(())
        }

        fn ota_finish(&mut self, request: &OtaRequest, received_compressed: u64) -> CoreResult<()> {
            self.ota_finished = Some((*request, received_compressed));
            Ok(())
        }

        fn ota_abort(&mut self) {
            self.ota_aborted = true;
        }

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

    #[derive(Debug)]
    struct ReadinessHardware {
        manifest: DeviceManifest,
        readiness: DeviceBootReadiness,
    }

    #[derive(Debug)]
    struct ServiceReadinessHardware {
        manifest: DeviceManifest,
        services: DeviceServiceReadiness,
    }

    impl Esp32Hardware for ReadinessHardware {
        fn manifest(&self) -> DeviceManifest {
            self.manifest
        }

        fn boot_readiness(&mut self) -> DeviceBootReadiness {
            self.readiness
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

        fn serial_send(&mut self, _bytes: &[u8]) -> Result<(), DeviceBootFailure> {
            Ok(())
        }

        fn serial_recv(&mut self, _out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Ok(0)
        }

        fn ble_send(&mut self, _bytes: &[u8]) -> Result<(), DeviceBootFailure> {
            Ok(())
        }

        fn ble_recv(&mut self, _out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Ok(0)
        }

        fn camera_qr_scan(&mut self, _out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Ok(0)
        }

        fn display_status(&mut self, _status: DisplayStatus<'_>) -> Result<(), DeviceBootFailure> {
            Ok(())
        }

        fn confirm_user(
            &mut self,
            _request: UserConfirmation<'_>,
        ) -> Result<UserConfirmationDecision, DeviceBootFailure> {
            Ok(UserConfirmationDecision::Rejected)
        }
    }

    impl Esp32Hardware for ServiceReadinessHardware {
        fn manifest(&self) -> DeviceManifest {
            self.manifest
        }

        fn service_readiness(&mut self) -> DeviceServiceReadiness {
            self.services
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

        fn serial_send(&mut self, _bytes: &[u8]) -> Result<(), DeviceBootFailure> {
            Ok(())
        }

        fn serial_recv(&mut self, _out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Ok(0)
        }

        fn ble_send(&mut self, _bytes: &[u8]) -> Result<(), DeviceBootFailure> {
            Ok(())
        }

        fn ble_recv(&mut self, _out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Ok(0)
        }

        fn camera_qr_scan(&mut self, _out: &mut [u8]) -> Result<usize, DeviceBootFailure> {
            Ok(0)
        }

        fn display_status(&mut self, _status: DisplayStatus<'_>) -> Result<(), DeviceBootFailure> {
            Ok(())
        }

        fn confirm_user(
            &mut self,
            _request: UserConfirmation<'_>,
        ) -> Result<UserConfirmationDecision, DeviceBootFailure> {
            Ok(UserConfirmationDecision::Rejected)
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
    fn esp32_device_platform_can_derive_boot_report_from_readiness() {
        let readiness = DeviceBootReadiness {
            storage_ready: false,
            ..DeviceBootReadiness::ready()
        };
        let mut runtime = runtime_for_v1(Esp32DevicePlatform::new(ReadinessHardware {
            manifest: JADE_MANIFEST,
            readiness,
        }));

        assert_eq!(
            runtime.boot(),
            Err(DeviceRuntimeError::Boot(
                DeviceBootFailure::StorageUnavailable
            ))
        );
        assert_eq!(
            runtime.platform_mut().boot_report(),
            DeviceBootReport::from_readiness(DeviceTarget::Jade, readiness)
        );
    }

    #[test]
    fn esp32_device_platform_derives_boot_gate_from_service_readiness() {
        let services = DeviceServiceReadiness {
            ble_ready: false,
            ..DeviceServiceReadiness::ready()
        };
        let mut runtime = runtime_for_v1(Esp32DevicePlatform::new(ServiceReadinessHardware {
            manifest: JADE_MANIFEST,
            services,
        }));

        assert_eq!(
            runtime.boot(),
            Err(DeviceRuntimeError::Boot(
                DeviceBootFailure::TransportUnavailable
            ))
        );
        assert_eq!(
            runtime.platform_mut().boot_report(),
            DeviceBootReport::from_readiness(
                DeviceTarget::Jade,
                services.boot_readiness(JADE_MANIFEST)
            )
        );
    }

    #[test]
    fn esp32_device_platform_blocks_insecure_release_boot() {
        let readiness = DeviceBootReadiness {
            secure_boot_ready: false,
            ..DeviceBootReadiness::ready()
        };
        let mut runtime = runtime_for_v1(Esp32DevicePlatform::new(ReadinessHardware {
            manifest: JADE_MANIFEST,
            readiness,
        }));

        assert_eq!(
            runtime.boot(),
            Err(DeviceRuntimeError::Boot(
                DeviceBootFailure::SecureBootDisabled
            ))
        );
    }

    #[test]
    fn esp32_device_platform_adapter_delegates_hardware_and_runtime_state() {
        let mut platform = Esp32DevicePlatform::new(TestPlatform::new(JADE_MANIFEST));
        platform.set_wallet_seed(vec![1, 2, 3, 4]);
        platform.set_jade_has_pin(true);
        assert_eq!(platform.wallet_seed(), Some(&[1, 2, 3, 4][..]));

        let info = platform.version_info(&CoreState::default());
        assert_eq!(info.board_type, Cow::Borrowed("jade"));
        assert!(info.jade_has_pin);
        assert_eq!(info.idf_version, Cow::Borrowed("esp-idf-rust"));
        assert_eq!(info.efusemac, Cow::Borrowed("001122334455"));

        platform.set_epoch(42).unwrap();
        assert_eq!(platform.runtime_current_epoch(), Some(42));

        let mut random = [0u8; 4];
        platform.fill_random(&mut random).unwrap();
        assert_eq!(random, [0x5a; 4]);
        assert_eq!(platform.monotonic_millis(), 1);
        assert_eq!(platform.rollback_secure_version(), 1);

        platform.hardware_mut().serial_rx = Some(vec![1, 2, 3]);
        platform.hardware_mut().ble_rx = Some(vec![4, 5]);
        platform.hardware_mut().camera_rx = Some(b"qr".to_vec());
        let mut out = [0u8; 8];
        assert_eq!(
            Esp32PlatformShim::serial_recv(&mut platform, &mut out).unwrap(),
            3
        );
        assert_eq!(&out[..3], &[1, 2, 3]);
        assert_eq!(
            Esp32PlatformShim::ble_recv(&mut platform, &mut out).unwrap(),
            2
        );
        assert_eq!(&out[..2], &[4, 5]);
        assert_eq!(
            Esp32PlatformShim::camera_qr_scan(&mut platform, &mut out).unwrap(),
            2
        );
        assert_eq!(&out[..2], b"qr");

        Esp32PlatformShim::serial_send(&mut platform, b"serial").unwrap();
        Esp32PlatformShim::ble_send(&mut platform, b"ble").unwrap();
        assert_eq!(platform.hardware().serial_tx, vec![b"serial".to_vec()]);
        assert_eq!(platform.hardware().ble_tx, vec![b"ble".to_vec()]);

        Esp32PlatformShim::display_status(&mut platform, DisplayStatus::Busy("busy")).unwrap();
        assert_eq!(
            Esp32PlatformShim::confirm_user(
                &mut platform,
                UserConfirmation::Export { label: "xpub" }
            )
            .unwrap(),
            UserConfirmationDecision::Approved
        );
        assert_eq!(platform.hardware().display_status_count, 1);
        assert_eq!(platform.hardware().confirmation_count, 1);

        let (hardware, runtime_state) = platform.into_inner();
        assert_eq!(hardware.epoch, Some(42));
        assert!(runtime_state.jade_has_pin());
    }

    #[test]
    fn esp32_device_platform_marks_pending_ota_image_valid_at_boot() {
        let mut hardware = TestPlatform::new(JADE_MANIFEST);
        let image = DeviceRunningImage {
            state: jade_core::DeviceOtaImageState::PendingVerify,
            secure_version: 5,
        };
        hardware.running_image = Some(image);
        let mut runtime = runtime_for_v1(Esp32DevicePlatform::new(hardware));

        runtime.boot().unwrap();

        assert_eq!(
            runtime.ota_boot_report(),
            Some(jade_core::DeviceOtaBootReport {
                image: Some(image),
                action: jade_core::DeviceOtaBootAction::MarkedValidCancelRollback,
            })
        );
        assert_eq!(runtime.platform().hardware().mark_valid_count, 1);
    }

    #[test]
    fn esp32_device_platform_adapter_runs_board_stream_loop() {
        let mut platform = Esp32DevicePlatform::new(TestPlatform::new(JADE_MANIFEST));
        platform.hardware_mut().serial_rx = Some(v1_request("s", "ping"));

        let mut serial_frames = vec![0; RX_BUFFER_BYTES];
        let mut ble_frames = vec![0; RX_BUFFER_BYTES];
        let mut qr = vec![0; QR_BUFFER_BYTES];
        let mut app = Esp32BoardStreamApp::new(
            platform,
            jade_storage::MemoryStorage::new(),
            &mut serial_frames,
            &mut ble_frames,
            &mut qr,
        )
        .unwrap();

        app.boot().unwrap();
        let report = app.tick(None, None).unwrap();
        assert_eq!(
            report.transports,
            Esp32V1PollReport {
                serial: true,
                ble: false
            }
        );
        assert_eq!(app.runtime().platform().hardware().serial_tx.len(), 1);
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

        let compressed_hash = TestUploadVerifier::hash_for_len(600);
        let verified_request =
            OtaRequest::full(1_000, 600, None, Some(compressed_hash), false).unwrap();
        let mut verified_session = begin_ota_update_verified(
            JADE_MANIFEST,
            TestOtaWriter::new(),
            verified_request,
            TestUploadVerifier::new(),
        )
        .unwrap();
        assert_eq!(verified_session.write(&[0; 600]).unwrap(), 100);
        let writer = verified_session.finish().unwrap();
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

        let mut short_serial = vec![0; RX_BUFFER_BYTES - 1];
        let mut ble = vec![0; RX_BUFFER_BYTES];
        let mut stream_qr = vec![0; QR_BUFFER_BYTES];
        assert_eq!(
            Esp32BoardStreamBuffers {
                serial_frame_buffer: &mut short_serial,
                ble_frame_buffer: &mut ble,
                qr_buffer: &mut stream_qr,
            }
            .validate(),
            Err(Esp32BoardAppError::RxBufferTooSmall {
                required: RX_BUFFER_BYTES,
                actual: RX_BUFFER_BYTES - 1,
            })
        );

        let mut serial = vec![0; RX_BUFFER_BYTES];
        let mut ble = vec![0; RX_BUFFER_BYTES];
        let mut stream_qr = vec![0; QR_BUFFER_BYTES];
        let buffers = Esp32BoardStreamBuffers {
            serial_frame_buffer: &mut serial,
            ble_frame_buffer: &mut ble,
            qr_buffer: &mut stream_qr,
        };
        assert_eq!(buffers.validate(), Ok(()));
        assert_eq!(buffers.serial_capacity(), RX_BUFFER_BYTES);
        assert_eq!(buffers.ble_capacity(), RX_BUFFER_BYTES);
        assert_eq!(buffers.qr_capacity(), QR_BUFFER_BYTES);
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

    #[derive(Debug)]
    struct Esp32LoopTestHooks {
        boots: usize,
        ticks: usize,
        stop_after: usize,
        last_transports: Esp32V1PollReport,
        last_confirmation: Option<UserConfirmationDecision>,
    }

    impl Esp32LoopTestHooks {
        fn new(stop_after: usize) -> Self {
            Self {
                boots: 0,
                ticks: 0,
                stop_after,
                last_transports: Esp32V1PollReport::default(),
                last_confirmation: None,
            }
        }
    }

    impl Esp32BoardLoopHooks for Esp32LoopTestHooks {
        fn next_inputs(&mut self) -> Esp32BoardLoopInputs {
            Esp32BoardLoopInputs {
                display_status: Some(DisplayStatus::Busy("loop")),
                confirmation: Some(UserConfirmation::Export { label: "xpub" }),
            }
        }

        fn on_boot(&mut self, report: &jade_core::DeviceBootReport) -> Esp32BoardLoopDecision {
            self.boots += 1;
            assert_eq!(report.target, DeviceTarget::Jade);
            Esp32BoardLoopDecision::Continue
        }

        fn on_tick(&mut self, report: &Esp32BoardTickReport<'_>) -> Esp32BoardLoopDecision {
            self.ticks += 1;
            self.last_transports = report.transports;
            self.last_confirmation = report.confirmation;
            if self.ticks >= self.stop_after {
                Esp32BoardLoopDecision::Stop
            } else {
                Esp32BoardLoopDecision::Continue
            }
        }
    }

    #[derive(Debug, Default)]
    struct Esp32BootRetryHooks {
        boot_errors: usize,
        boots: usize,
        ticks: usize,
    }

    impl Esp32BoardLoopHooks for Esp32BootRetryHooks {
        fn on_boot_error(&mut self, error: DeviceRuntimeError) -> Esp32BoardLoopDecision {
            assert_eq!(
                error,
                DeviceRuntimeError::Boot(DeviceBootFailure::EntropyUnavailable)
            );
            self.boot_errors += 1;
            Esp32BoardLoopDecision::Continue
        }

        fn on_boot(&mut self, report: &jade_core::DeviceBootReport) -> Esp32BoardLoopDecision {
            assert_eq!(report.target, DeviceTarget::Jade);
            self.boots += 1;
            Esp32BoardLoopDecision::Continue
        }

        fn on_tick(&mut self, _report: &Esp32BoardTickReport<'_>) -> Esp32BoardLoopDecision {
            self.ticks += 1;
            Esp32BoardLoopDecision::Stop
        }
    }

    #[test]
    fn esp32_board_stream_loop_boots_and_runs_until_hook_stop() {
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
        app.runtime_mut().platform_mut().serial_rx = Some(v1_request("s", "ping"));
        app.runtime_mut().platform_mut().confirmation_decision = UserConfirmationDecision::Approved;

        let mut event_loop = Esp32BoardStreamLoop::new(app);
        let mut hooks = Esp32LoopTestHooks::new(1);
        let run = event_loop.run_until_stop(&mut hooks, 4).unwrap();

        assert_eq!(
            run,
            Esp32BoardLoopRun {
                booted: true,
                ticks: 1,
                stop_reason: Esp32BoardLoopStopReason::Hook,
            }
        );
        assert_eq!(event_loop.ticks(), 1);
        assert_eq!(hooks.boots, 1);
        assert_eq!(hooks.ticks, 1);
        assert_eq!(
            hooks.last_transports,
            Esp32V1PollReport {
                serial: true,
                ble: false,
            }
        );
        assert_eq!(
            hooks.last_confirmation,
            Some(UserConfirmationDecision::Approved)
        );
        assert_eq!(event_loop.app().runtime().platform().serial_tx.len(), 1);
        assert_eq!(
            event_loop.app().runtime().platform().display_status_count,
            1
        );
        assert_eq!(event_loop.app().runtime().platform().confirmation_count, 1);
    }

    #[test]
    fn esp32_board_stream_loop_can_retry_after_boot_error_hook() {
        let mut serial_frames = vec![0; RX_BUFFER_BYTES];
        let mut ble_frames = vec![0; RX_BUFFER_BYTES];
        let mut qr = vec![0; QR_BUFFER_BYTES];
        let mut platform = TestPlatform::new(JADE_MANIFEST);
        platform.boot_report = jade_core::DeviceBootReport {
            entropy_ready: false,
            ..jade_core::DeviceBootReport::ok(DeviceTarget::Jade)
        };
        let app = Esp32BoardStreamApp::new(
            platform,
            jade_storage::MemoryStorage::new(),
            &mut serial_frames,
            &mut ble_frames,
            &mut qr,
        )
        .unwrap();
        let mut event_loop = Esp32BoardStreamLoop::new(app);
        let mut hooks = Esp32BootRetryHooks::default();

        assert_eq!(
            event_loop.run_once(&mut hooks),
            Ok(Esp32BoardLoopDecision::Continue)
        );
        assert!(!event_loop.app().is_booted());
        assert_eq!(hooks.boot_errors, 1);
        assert_eq!(hooks.boots, 0);
        assert_eq!(hooks.ticks, 0);

        event_loop
            .app_mut()
            .runtime_mut()
            .platform_mut()
            .boot_report = jade_core::DeviceBootReport::ok(DeviceTarget::Jade);
        assert_eq!(
            event_loop.run_once(&mut hooks),
            Ok(Esp32BoardLoopDecision::Stop)
        );
        assert!(event_loop.app().is_booted());
        assert_eq!(hooks.boot_errors, 1);
        assert_eq!(hooks.boots, 1);
        assert_eq!(hooks.ticks, 1);
    }

    #[test]
    fn esp32_board_stream_loop_runs_without_tick_limit_until_hook_stop() {
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
        app.runtime_mut().platform_mut().serial_rx = Some(v1_request("s", "ping"));
        app.runtime_mut().platform_mut().confirmation_decision = UserConfirmationDecision::Approved;

        let mut event_loop = Esp32BoardStreamLoop::new(app);
        let mut hooks = Esp32LoopTestHooks::new(2);
        let run = event_loop.run_until_hook_stop(&mut hooks).unwrap();

        assert_eq!(
            run,
            Esp32BoardLoopRun {
                booted: true,
                ticks: 2,
                stop_reason: Esp32BoardLoopStopReason::Hook,
            }
        );
        assert_eq!(event_loop.ticks(), 2);
        assert_eq!(hooks.boots, 1);
        assert_eq!(hooks.ticks, 2);
        assert_eq!(event_loop.app().runtime().platform().serial_tx.len(), 1);
        assert_eq!(
            event_loop.app().runtime().platform().display_status_count,
            2
        );
        assert_eq!(event_loop.app().runtime().platform().confirmation_count, 2);
    }

    #[test]
    fn esp32_board_stream_loop_builds_from_startup_buffers_and_nvs() {
        let mut storage = Esp32BoardStreamStorage::new();
        assert_eq!(storage.serial_capacity(), RX_BUFFER_BYTES);
        assert_eq!(storage.ble_capacity(), RX_BUFFER_BYTES);
        assert_eq!(storage.qr_capacity(), QR_BUFFER_BYTES);
        assert_eq!(storage.buffers().validate(), Ok(()));

        let mut event_loop = Esp32BoardStreamLoop::new_with_nvs(
            TestPlatform::new(JADE_MANIFEST),
            TestNvs::new(),
            storage.buffers(),
        )
        .unwrap();
        event_loop.app_mut().runtime_mut().platform_mut().serial_rx = Some(v1_request("s", "ping"));

        let mut hooks = Esp32LoopTestHooks::new(1);
        let run = event_loop.run_until_stop(&mut hooks, 1).unwrap();

        assert_eq!(run.stop_reason, Esp32BoardLoopStopReason::Hook);
        assert_eq!(run.ticks, 1);
        assert_eq!(event_loop.app().runtime().platform().serial_tx.len(), 1);
    }

    #[test]
    fn esp32_board_stream_loop_builds_directly_from_static_storage() {
        let mut storage = Esp32BoardStreamStorage::default();
        let mut event_loop = Esp32BoardStreamLoop::new_with_nvs_storage(
            TestPlatform::new(JADE_MANIFEST),
            TestNvs::new(),
            &mut storage,
        )
        .unwrap();
        event_loop.app_mut().runtime_mut().platform_mut().serial_rx = Some(v1_request("s", "ping"));

        let mut hooks = Esp32LoopTestHooks::new(1);
        let run = event_loop.run_until_stop(&mut hooks, 1).unwrap();

        assert_eq!(run.stop_reason, Esp32BoardLoopStopReason::Hook);
        assert_eq!(run.ticks, 1);
        assert_eq!(event_loop.app().runtime().platform().serial_tx.len(), 1);
    }

    #[test]
    fn esp32_board_entrypoint_runs_from_nvs_and_static_storage() {
        let mut storage = Esp32BoardStreamStorage::default();
        let mut hooks = Esp32LoopTestHooks::new(2);

        let run = run_board_stream_loop_with_nvs_storage(
            TestPlatform::new(JADE_MANIFEST),
            TestNvs::new(),
            &mut storage,
            &mut hooks,
        )
        .unwrap();

        assert_eq!(
            run,
            Esp32BoardLoopRun {
                booted: true,
                ticks: 2,
                stop_reason: Esp32BoardLoopStopReason::Hook,
            }
        );
        assert_eq!(hooks.boots, 1);
        assert_eq!(hooks.ticks, 2);
    }

    #[test]
    fn esp32_board_entrypoint_wraps_raw_hardware_and_nvs() {
        let mut storage = Esp32BoardStreamStorage::default();
        let mut hooks = Esp32LoopTestHooks::new(1);
        let mut hardware = TestPlatform::new(JADE_MANIFEST);
        hardware.serial_rx = Some(v1_request("s", "ping"));

        let run = run_board_stream_loop_with_hardware_and_nvs_storage(
            hardware,
            TestNvs::new(),
            &mut storage,
            &mut hooks,
        )
        .unwrap();

        assert_eq!(
            run,
            Esp32BoardLoopRun {
                booted: true,
                ticks: 1,
                stop_reason: Esp32BoardLoopStopReason::Hook,
            }
        );
        assert_eq!(hooks.boots, 1);
        assert_eq!(hooks.ticks, 1);
        assert_eq!(
            hooks.last_transports,
            Esp32V1PollReport {
                serial: true,
                ble: false,
            }
        );
    }

    #[test]
    fn esp32_board_stream_loop_surfaces_tick_errors_without_sending() {
        let mut serial_frames = vec![0; RX_BUFFER_BYTES];
        let mut ble_frames = vec![0; RX_BUFFER_BYTES];
        let mut qr = vec![0; QR_BUFFER_BYTES];
        let mut app = Esp32BoardStreamApp::new(
            TestPlatform::new(manifest_with_allocation(
                JADE_MANIFEST,
                AllocationBudget {
                    max_request_bytes: 1024,
                    max_response_bytes: 4,
                    max_scratch_bytes: 1024,
                },
            )),
            jade_storage::MemoryStorage::new(),
            &mut serial_frames,
            &mut ble_frames,
            &mut qr,
        )
        .unwrap();
        app.runtime_mut().platform_mut().serial_rx = Some(v1_request("s", "ping"));

        let mut event_loop = Esp32BoardStreamLoop::new(app);
        let mut hooks = Esp32LoopTestHooks::new(1);
        assert!(matches!(
            event_loop.run_once(&mut hooks),
            Err(Esp32BoardLoopError::Tick(FirmwareFrameError::Allocation(
                jade_core::AllocationFailure::ResponseTooLarge { limit: 4, .. }
            )))
        ));
        assert_eq!(hooks.boots, 1);
        assert_eq!(hooks.ticks, 0);
        assert_eq!(event_loop.app().runtime().platform().serial_tx.len(), 0);
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
    fn esp32_full_v1_ota_flow_reaches_hardware_ota_hooks() {
        let expected_hash = [0x11; jade_core::OTA_HASH_LEN];
        let expected_request = OtaRequest::full(10, 3, Some(expected_hash), None, false).unwrap();
        let mut runtime = v1_runtime_for_v1(
            Esp32DevicePlatform::new(TestPlatform::new(JADE_MANIFEST)),
            jade_storage::MemoryStorage::new(),
        );

        assert_v1_bool_result(
            &runtime.handle_v1_cbor(&v1_ota_start_request("ota", expected_hash)),
            "ota",
            true,
        );
        assert_eq!(
            runtime.runtime_platform().hardware().ota_begun,
            Some(expected_request)
        );

        assert_v1_bool_result(
            &runtime.handle_v1_cbor(&v1_ota_data_request("ota-data", b"abc")),
            "ota-data",
            true,
        );
        assert_eq!(
            runtime.runtime_platform().hardware().ota_writes,
            vec![(0, b"abc".to_vec())]
        );

        assert_v1_bool_result(
            &runtime.handle_v1_cbor(&v1_request("ota-complete", "ota_complete")),
            "ota-complete",
            true,
        );
        assert_eq!(
            runtime.runtime_platform().hardware().ota_finished,
            Some((expected_request, 3))
        );
        assert!(!runtime.runtime_platform().hardware().ota_aborted);
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

    fn v1_ota_start_request(id: &str, expected_hash: [u8; jade_core::OTA_HASH_LEN]) -> Vec<u8> {
        let mut output = Vec::new();
        Encoder::new(&mut output)
            .map(3)
            .and_then(|encoder| encoder.str("id"))
            .and_then(|encoder| encoder.str(id))
            .and_then(|encoder| encoder.str("method"))
            .and_then(|encoder| encoder.str("ota"))
            .and_then(|encoder| encoder.str("params"))
            .and_then(|encoder| encoder.map(3))
            .and_then(|encoder| encoder.str("fwsize"))
            .and_then(|encoder| encoder.u64(10))
            .and_then(|encoder| encoder.str("cmpsize"))
            .and_then(|encoder| encoder.u64(3))
            .and_then(|encoder| encoder.str("fwhash"))
            .and_then(|encoder| encoder.bytes(&expected_hash))
            .expect("Vec-backed CBOR encoding is infallible");
        output
    }

    fn v1_ota_data_request(id: &str, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        Encoder::new(&mut output)
            .map(3)
            .and_then(|encoder| encoder.str("id"))
            .and_then(|encoder| encoder.str(id))
            .and_then(|encoder| encoder.str("method"))
            .and_then(|encoder| encoder.str("ota_data"))
            .and_then(|encoder| encoder.str("params"))
            .and_then(|encoder| encoder.bytes(data))
            .expect("Vec-backed CBOR encoding is infallible");
        output
    }

    fn assert_v1_bool_result(response: &[u8], id: &str, result: bool) {
        let mut decoder = Decoder::new(response);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), id);
        assert_eq!(decoder.str().unwrap(), "result");
        assert_eq!(decoder.bool().unwrap(), result);
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
