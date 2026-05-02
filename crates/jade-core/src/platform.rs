use crate::{CoreResult, CoreState, WalletLifecycle};
use jade_protocol_v2::{VersionInfo, VersionInfoState};

impl From<WalletLifecycle> for VersionInfoState {
    fn from(wallet: WalletLifecycle) -> Self {
        match wallet {
            WalletLifecycle::Uninit => Self::Uninit,
            WalletLifecycle::Unsaved => Self::Unsaved,
            WalletLifecycle::Locked => Self::Locked,
            WalletLifecycle::Ready => Self::Ready,
            WalletLifecycle::Temporary => Self::Temporary,
        }
    }
}

pub trait Platform {
    fn version_info<'a>(&'a self, state: &CoreState) -> VersionInfo<'a>;
    fn add_entropy(&mut self, entropy: &[u8]) -> CoreResult<()>;
    fn set_epoch(&mut self, epoch: u64) -> CoreResult<()>;
}
