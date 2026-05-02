#![no_std]

extern crate alloc;

use alloc::borrow::Cow;
use jade_protocol_v2::{OperationActivity, Response, ResponseBody};

pub mod allocation;
pub mod state;

pub use allocation::{AllocationBudget, AllocationFailure};
pub use state::{InterfaceKind, InterfaceSession, OperationState, WalletLifecycle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    InvalidRequest,
    UnknownMethod,
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
