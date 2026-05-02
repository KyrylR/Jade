#![no_std]

extern crate alloc;

use alloc::borrow::Cow;
use jade_protocol_v2::{OperationActivity, Response, ResponseBody};

pub mod allocation;
pub mod platform;
pub mod state;

pub use allocation::{AllocationBudget, AllocationFailure};
pub use platform::{NetworkRestriction, Platform, VersionDebugInfo, VersionInfo, VersionInfoState};
pub use state::{InterfaceKind, InterfaceSession, OperationState, WalletLifecycle};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
