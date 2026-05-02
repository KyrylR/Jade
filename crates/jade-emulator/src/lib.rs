use std::borrow::Cow;

use jade_core::{CoreState, OperationState};
use jade_protocol_v1::{
    decode_request, encode_error_response, encode_uint_result, method_spec, ErrorCode,
    ErrorResponse, MethodClass, Request,
};

#[derive(Debug, Default)]
pub struct Emulator {
    state: CoreState,
}

impl Emulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handle_v1_request(&mut self, request: &Request<'_>) -> V1Outcome {
        if let Err(err) = request.validate() {
            return V1Outcome::Reject {
                code: ErrorCode::InvalidRequest,
                message: format!("invalid v1 request: {err:?}"),
            };
        }

        match method_spec(&request.method).map(|spec| spec.class) {
            Some(MethodClass::Immediate) if request.method == "ping" => V1Outcome::ImmediatePing {
                activity: self.state.operation,
            },
            Some(_) => V1Outcome::DeferredToCore {
                method: request.method.to_string(),
            },
            None => V1Outcome::Reject {
                code: ErrorCode::UnknownMethod,
                message: "unknown method".to_string(),
            },
        }
    }

    pub fn handle_v1_cbor(&mut self, bytes: &[u8]) -> Vec<u8> {
        match decode_request(bytes) {
            Ok(request) => match self.handle_v1_request(&request) {
                V1Outcome::ImmediatePing { activity } => {
                    encode_uint_result(&request.id, v1_activity_code(activity))
                }
                V1Outcome::Reject { code, message } => encode_error_response(&ErrorResponse {
                    id: request.id,
                    code: code as i32,
                    message: Cow::Owned(message),
                }),
                V1Outcome::DeferredToCore { method } => encode_error_response(&ErrorResponse {
                    id: request.id,
                    code: ErrorCode::InternalError as i32,
                    message: Cow::Owned(format!("method not yet ported to Rust core: {method}")),
                }),
            },
            Err(err) => encode_error_response(&ErrorResponse {
                id: Cow::Borrowed(""),
                code: ErrorCode::InvalidRequest as i32,
                message: Cow::Owned(format!("invalid v1 request: {err:?}")),
            }),
        }
    }

    pub fn ping_v2(&self, id: impl Into<Cow<'static, str>>) -> jade_protocol_v2::Response<'static> {
        self.state.ping_response(id.into())
    }
}

fn v1_activity_code(activity: OperationState) -> u64 {
    match activity {
        OperationState::Idle => 0,
        OperationState::ClientMessage
        | OperationState::Signing { .. }
        | OperationState::Ota { .. } => 1,
        OperationState::UiNavigation => 2,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V1Outcome {
    ImmediatePing { activity: jade_core::OperationState },
    DeferredToCore { method: String },
    Reject { code: ErrorCode, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_is_immediate() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("1"),
            method: Cow::Borrowed("ping"),
            params: None,
        };

        assert!(matches!(
            emulator.handle_v1_request(&request),
            V1Outcome::ImmediatePing { .. }
        ));
    }

    #[test]
    fn raw_v1_ping_returns_result() {
        let mut emulator = Emulator::new();
        let request = [
            0xa2, 0x62, b'i', b'd', 0x61, b'1', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x64,
            b'p', b'i', b'n', b'g',
        ];

        assert_eq!(
            emulator.handle_v1_cbor(&request),
            [0xa2, 0x62, b'i', b'd', 0x61, b'1', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0x00,]
        );
    }

    #[test]
    fn signing_methods_are_deferred() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("2"),
            method: Cow::Borrowed("sign_psbt"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::DeferredToCore {
                method: "sign_psbt".to_string()
            }
        );
    }
}
