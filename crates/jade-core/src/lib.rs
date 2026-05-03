#![no_std]

extern crate alloc;

use alloc::{borrow::Cow, boxed::Box};
use jade_protocol_v2::{
    OperationActivity, Request as V2Request, RequestBody as V2RequestBody, RequestKind, Response,
    ResponseBody,
};

pub mod allocation;
pub mod bip32_path;
pub mod device;
pub mod firmware;
pub mod ota;
pub mod platform;
pub mod state;
pub mod ui;

pub use allocation::{AllocationBudget, AllocationFailure};
pub use bip32_path::{JadeDerivationPath, PathError};
pub use device::{
    static_version_info, DeviceBootFailure, DeviceBootReport, DeviceFeatureSet, DeviceManifest,
    DeviceMemoryBudget, DeviceOtaError, DevicePartitionLayout, DevicePlatform, DeviceRuntime,
    DeviceRuntimeError, DeviceSoc, DeviceTarget,
};
pub use firmware::{handle_v1_cbor, FirmwareFrameError, FirmwareProtocol};
pub use jade_protocol_v2::{NetworkRestriction, VersionDebugInfo, VersionInfo, VersionInfoState};
pub use ota::{
    OtaHashType, OtaImageWriter, OtaKind, OtaRequest, OtaWriteError, OtaWriteSession, OTA_HASH_LEN,
};
pub use platform::Platform;
pub use state::{InterfaceKind, InterfaceSession, OperationState, WalletLifecycle};
pub use ui::{DisplayStatus, UserConfirmation, UserConfirmationDecision};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    InvalidRequest,
    UnknownMethod,
    BadParameters,
    InternalError,
    HardwareLocked,
    OutOfMemory,
    Deferred(&'static str),
    Unsupported(&'static str),
}

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreState {
    pub wallet: WalletLifecycle,
    pub operation: OperationState,
}

impl Default for CoreState {
    fn default() -> Self {
        Self {
            wallet: WalletLifecycle::Uninit,
            operation: OperationState::Idle,
        }
    }
}

impl CoreState {
    pub fn logout(&mut self) {
        self.wallet = WalletLifecycle::Locked;
        self.operation = OperationState::Idle;
    }

    pub fn version_info<'a>(&self, platform: &'a impl Platform) -> VersionInfo<'a> {
        platform.version_info(self)
    }

    pub fn add_entropy(&mut self, platform: &mut impl Platform, entropy: &[u8]) -> CoreResult<()> {
        if entropy.is_empty() {
            return Err(CoreError::BadParameters);
        }
        platform.add_entropy(entropy)
    }

    pub fn set_epoch(&mut self, platform: &mut impl Platform, epoch: u64) -> CoreResult<()> {
        platform.set_epoch(epoch)
    }

    pub fn handle_v2<'a>(
        &'a mut self,
        platform: &'a mut impl Platform,
        request: V2Request<'a>,
    ) -> Response<'a> {
        let body = match (request.kind, request.body) {
            (RequestKind::Ping, V2RequestBody::Empty) => {
                return self.ping_response(request.id);
            }
            (RequestKind::GetVersionInfo, V2RequestBody::GetVersionInfo { .. }) => {
                ResponseBody::VersionInfo {
                    info: Box::new(self.version_info(platform)),
                }
            }
            (RequestKind::AddEntropy, V2RequestBody::AddEntropy { entropy }) => {
                match self.add_entropy(platform, &entropy) {
                    Ok(()) => ResponseBody::Ok,
                    Err(err) => v2_error_body(err),
                }
            }
            (RequestKind::SetEpoch, V2RequestBody::SetEpoch { epoch }) => {
                match self.set_epoch(platform, epoch) {
                    Ok(()) => ResponseBody::Ok,
                    Err(err) => v2_error_body(err),
                }
            }
            (RequestKind::Logout, V2RequestBody::Logout) => {
                self.logout();
                ResponseBody::Ok
            }
            _ => v2_error_body(CoreError::BadParameters),
        };

        Response {
            id: request.id,
            body,
        }
    }

    pub fn ping_response<'a>(&self, id: Cow<'a, str>) -> Response<'a> {
        Response {
            id,
            body: ResponseBody::Busy {
                activity: match self.operation {
                    OperationState::Idle => OperationActivity::Idle,
                    OperationState::ClientMessage => OperationActivity::ClientMessage,
                    OperationState::UiNavigation => OperationActivity::UiNavigation,
                    OperationState::Signing { .. } => OperationActivity::Signing,
                    OperationState::Ota { .. } => OperationActivity::Ota,
                },
            },
        }
    }
}

fn v2_error_body(err: CoreError) -> ResponseBody<'static> {
    let (code, message) = match err {
        CoreError::InvalidRequest => (
            jade_protocol_v2::ErrorCode::InvalidRequest,
            "invalid request",
        ),
        CoreError::UnknownMethod => (jade_protocol_v2::ErrorCode::UnknownMethod, "unknown method"),
        CoreError::BadParameters => (jade_protocol_v2::ErrorCode::BadParameters, "bad parameters"),
        CoreError::InternalError => (jade_protocol_v2::ErrorCode::InternalError, "internal error"),
        CoreError::HardwareLocked => (
            jade_protocol_v2::ErrorCode::HardwareLocked,
            "hardware locked",
        ),
        CoreError::OutOfMemory => (jade_protocol_v2::ErrorCode::OutOfMemory, "out of memory"),
        CoreError::Deferred(method) => (jade_protocol_v2::ErrorCode::Unsupported, method),
        CoreError::Unsupported(feature) => (jade_protocol_v2::ErrorCode::Unsupported, feature),
    };
    ResponseBody::Error {
        code,
        message: Cow::Borrowed(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use jade_protocol_v2::{Request, RequestBody, RequestKind};
    use minicbor::bytes::ByteVec;

    #[test]
    fn logout_clears_active_operation_and_locks_wallet() {
        let mut state = CoreState {
            wallet: WalletLifecycle::Ready,
            operation: OperationState::ClientMessage,
        };

        state.logout();

        assert_eq!(state.wallet, WalletLifecycle::Locked);
        assert_eq!(state.operation, OperationState::Idle);
    }

    #[derive(Debug, Default)]
    struct TestPlatform {
        entropy_bytes: usize,
        epoch: Option<u64>,
    }

    impl Platform for TestPlatform {
        fn version_info<'a>(&'a self, state: &CoreState) -> VersionInfo<'a> {
            VersionInfo {
                jade_version: Cow::Borrowed("test"),
                jade_ota_max_chunk: 1024,
                jade_config: Cow::Borrowed("BLE"),
                board_type: Cow::Borrowed("HOST"),
                jade_features: Cow::Borrowed("DEBUG"),
                idf_version: Cow::Borrowed("host"),
                chip_features: Cow::Borrowed("00000000"),
                efusemac: Cow::Borrowed("000000000000"),
                attestation_initialised: false,
                battery_status: 0,
                battery_millivolts: 0,
                battery_charging: false,
                jade_state: state.wallet.into(),
                jade_networks: NetworkRestriction::All,
                jade_has_pin: false,
                debug: None,
            }
        }

        fn add_entropy(&mut self, entropy: &[u8]) -> CoreResult<()> {
            self.entropy_bytes += entropy.len();
            Ok(())
        }

        fn set_epoch(&mut self, epoch: u64) -> CoreResult<()> {
            self.epoch = Some(epoch);
            Ok(())
        }
    }

    #[test]
    fn version_info_uses_orthogonal_wallet_lifecycle() {
        let state = CoreState {
            wallet: WalletLifecycle::Temporary,
            operation: OperationState::UiNavigation,
        };
        let platform = TestPlatform::default();

        assert_eq!(
            state.version_info(&platform).jade_state,
            VersionInfoState::Temporary
        );
    }

    #[test]
    fn entropy_and_epoch_are_platform_side_effects() {
        let mut state = CoreState::default();
        let mut platform = TestPlatform::default();

        state.add_entropy(&mut platform, b"noise").unwrap();
        state.set_epoch(&mut platform, 1_700_000_000).unwrap();

        assert_eq!(platform.entropy_bytes, 5);
        assert_eq!(platform.epoch, Some(1_700_000_000));
        assert_eq!(
            state.add_entropy(&mut platform, b""),
            Err(CoreError::BadParameters)
        );
    }

    #[test]
    fn v2_handles_same_management_surface_without_v1_adapter() {
        let mut state = CoreState::default();
        let mut platform = TestPlatform::default();

        let add_entropy = Request {
            id: Cow::Borrowed("e"),
            kind: RequestKind::AddEntropy,
            session: None,
            body: RequestBody::AddEntropy {
                entropy: ByteVec::from(vec![b'n', b'o', b'i', b's', b'e']),
            },
        };
        assert_eq!(
            state.handle_v2(&mut platform, add_entropy).body,
            ResponseBody::Ok
        );

        let set_epoch = Request {
            id: Cow::Borrowed("t"),
            kind: RequestKind::SetEpoch,
            session: None,
            body: RequestBody::SetEpoch {
                epoch: 1_700_000_000,
            },
        };
        assert_eq!(
            state.handle_v2(&mut platform, set_epoch).body,
            ResponseBody::Ok
        );

        let version = Request {
            id: Cow::Borrowed("v"),
            kind: RequestKind::GetVersionInfo,
            session: None,
            body: RequestBody::GetVersionInfo { nonblocking: true },
        };
        let response = state.handle_v2(&mut platform, version);
        let version_state = match response.body {
            ResponseBody::VersionInfo { info } => info.jade_state,
            _ => panic!("expected version info"),
        };

        assert_eq!(platform.entropy_bytes, 5);
        assert_eq!(platform.epoch, Some(1_700_000_000));
        assert_eq!(version_state, VersionInfoState::Uninit);
    }
}
