use alloc::borrow::Cow;

use crate::{CoreResult, CoreState, WalletLifecycle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo<'a> {
    pub jade_version: Cow<'a, str>,
    pub jade_ota_max_chunk: u64,
    pub jade_config: Cow<'a, str>,
    pub board_type: Cow<'a, str>,
    pub jade_features: Cow<'a, str>,
    pub idf_version: Cow<'a, str>,
    pub chip_features: Cow<'a, str>,
    pub efusemac: Cow<'a, str>,
    pub attestation_initialised: bool,
    pub battery_status: u64,
    pub battery_millivolts: u64,
    pub battery_charging: bool,
    pub jade_state: VersionInfoState,
    pub jade_networks: NetworkRestriction,
    pub jade_has_pin: bool,
    pub debug: Option<VersionDebugInfo>,
}

impl VersionInfo<'_> {
    pub fn v1_field_count(&self) -> usize {
        15 + usize::from(self.debug.is_some()) * 8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionDebugInfo {
    pub nvs_entries_used: u64,
    pub nvs_entries_free: u64,
    pub free_heap: u64,
    pub free_dram: u64,
    pub largest_dram: u64,
    pub free_spiram: u64,
    pub largest_spiram: u64,
    pub gcov: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionInfoState {
    Ready,
    Locked,
    Temporary,
    Unsaved,
    Uninit,
}

impl VersionInfoState {
    pub fn as_v1_str(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Locked => "LOCKED",
            Self::Temporary => "TEMP",
            Self::Unsaved => "UNSAVED",
            Self::Uninit => "UNINIT",
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkRestriction {
    All,
    Main,
    Test,
}

impl NetworkRestriction {
    pub fn as_v1_str(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::Main => "MAIN",
            Self::Test => "TEST",
        }
    }
}

pub trait Platform {
    fn version_info<'a>(&'a self, state: &CoreState) -> VersionInfo<'a>;
    fn add_entropy(&mut self, entropy: &[u8]) -> CoreResult<()>;
    fn set_epoch(&mut self, epoch: u64) -> CoreResult<()>;
}
