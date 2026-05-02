#![no_std]

extern crate alloc;

use alloc::{borrow::Cow, boxed::Box};
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};

pub const PROTOCOL_VERSION: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum RequestKind {
    #[n(0)]
    Ping,
    #[n(1)]
    GetVersionInfo,
    #[n(2)]
    AddEntropy,
    #[n(3)]
    SetEpoch,
    #[n(4)]
    Logout,
    #[n(5)]
    AuthUser,
    #[n(6)]
    RegisterAttestation,
    #[n(7)]
    SignAttestation,
    #[n(8)]
    UpdatePinserver,
    #[n(9)]
    Wallet,
    #[n(10)]
    Signing,
    #[n(11)]
    Ota,
    #[n(12)]
    Continuation,
    #[n(13)]
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Request<'a> {
    #[n(0)]
    pub id: Cow<'a, str>,
    #[n(1)]
    pub kind: RequestKind,
    #[n(2)]
    pub session: Option<SessionId>,
    #[n(3)]
    pub body: RequestBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum RequestBody {
    #[n(0)]
    Empty,
    #[n(1)]
    GetVersionInfo {
        #[n(0)]
        nonblocking: bool,
    },
    #[n(2)]
    AddEntropy {
        #[n(0)]
        entropy: ByteVec,
    },
    #[n(3)]
    SetEpoch {
        #[n(0)]
        epoch: u64,
    },
    #[n(4)]
    Logout,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Response<'a> {
    #[n(0)]
    pub id: Cow<'a, str>,
    #[n(1)]
    pub body: ResponseBody<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ResponseBody<'a> {
    #[n(0)]
    Ok,
    #[n(1)]
    Busy {
        #[n(0)]
        activity: OperationActivity,
    },
    #[n(2)]
    Error {
        #[n(0)]
        code: ErrorCode,
        #[n(1)]
        message: Cow<'a, str>,
    },
    #[n(3)]
    VersionInfo {
        #[n(0)]
        info: Box<VersionInfo<'a>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct SessionId(#[n(0)] pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum ErrorCode {
    #[n(0)]
    InvalidRequest,
    #[n(1)]
    UnknownMethod,
    #[n(2)]
    BadParameters,
    #[n(3)]
    InternalError,
    #[n(4)]
    UserCancelled,
    #[n(5)]
    ProtocolError,
    #[n(6)]
    HardwareLocked,
    #[n(7)]
    NetworkMismatch,
    #[n(8)]
    OutOfMemory,
    #[n(9)]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum OperationActivity {
    #[n(0)]
    Idle,
    #[n(1)]
    ClientMessage,
    #[n(2)]
    UiNavigation,
    #[n(3)]
    Ota,
    #[n(4)]
    Signing,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct VersionInfo<'a> {
    #[n(0)]
    pub jade_version: Cow<'a, str>,
    #[n(1)]
    pub jade_ota_max_chunk: u64,
    #[n(2)]
    pub jade_config: Cow<'a, str>,
    #[n(3)]
    pub board_type: Cow<'a, str>,
    #[n(4)]
    pub jade_features: Cow<'a, str>,
    #[n(5)]
    pub idf_version: Cow<'a, str>,
    #[n(6)]
    pub chip_features: Cow<'a, str>,
    #[n(7)]
    pub efusemac: Cow<'a, str>,
    #[n(8)]
    pub attestation_initialised: bool,
    #[n(9)]
    pub battery_status: u64,
    #[n(10)]
    pub battery_millivolts: u64,
    #[n(11)]
    pub battery_charging: bool,
    #[n(12)]
    pub jade_state: VersionInfoState,
    #[n(13)]
    pub jade_networks: NetworkRestriction,
    #[n(14)]
    pub jade_has_pin: bool,
    #[n(15)]
    pub debug: Option<VersionDebugInfo>,
}

impl VersionInfo<'_> {
    pub fn v1_field_count(&self) -> usize {
        15 + usize::from(self.debug.is_some()) * 8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct VersionDebugInfo {
    #[n(0)]
    pub nvs_entries_used: u64,
    #[n(1)]
    pub nvs_entries_free: u64,
    #[n(2)]
    pub free_heap: u64,
    #[n(3)]
    pub free_dram: u64,
    #[n(4)]
    pub largest_dram: u64,
    #[n(5)]
    pub free_spiram: u64,
    #[n(6)]
    pub largest_spiram: u64,
    #[n(7)]
    pub gcov: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum VersionInfoState {
    #[n(0)]
    Ready,
    #[n(1)]
    Locked,
    #[n(2)]
    Temporary,
    #[n(3)]
    Unsaved,
    #[n(4)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum NetworkRestriction {
    #[n(0)]
    All,
    #[n(1)]
    Main,
    #[n(2)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use minicbor::{decode, to_vec};

    #[test]
    fn typed_add_entropy_request_round_trips_as_cbor_bytes() {
        let request = Request {
            id: Cow::Borrowed("e"),
            kind: RequestKind::AddEntropy,
            session: Some(SessionId(7)),
            body: RequestBody::AddEntropy {
                entropy: ByteVec::from(vec![1, 2, 3, 4]),
            },
        };

        let encoded = to_vec(request.clone()).unwrap();
        let decoded: Request<'_> = decode(&encoded).unwrap();

        assert_eq!(decoded, request);
    }

    #[test]
    fn version_info_keeps_public_v1_field_count() {
        let info = VersionInfo {
            jade_version: Cow::Borrowed("test"),
            jade_ota_max_chunk: 4096,
            jade_config: Cow::Borrowed("HOST"),
            board_type: Cow::Borrowed("HOST"),
            jade_features: Cow::Borrowed("DEBUG,RUST"),
            idf_version: Cow::Borrowed("host"),
            chip_features: Cow::Borrowed("00000000"),
            efusemac: Cow::Borrowed("000000000000"),
            attestation_initialised: false,
            battery_status: 0,
            battery_millivolts: 0,
            battery_charging: false,
            jade_state: VersionInfoState::Uninit,
            jade_networks: NetworkRestriction::All,
            jade_has_pin: false,
            debug: None,
        };

        assert_eq!(info.v1_field_count(), 15);
        assert_eq!(info.jade_state.as_v1_str(), "UNINIT");
        assert_eq!(info.jade_networks.as_v1_str(), "ALL");
    }
}
