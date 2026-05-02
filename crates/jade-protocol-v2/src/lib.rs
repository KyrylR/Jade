#![no_std]

extern crate alloc;

use alloc::borrow::Cow;
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
