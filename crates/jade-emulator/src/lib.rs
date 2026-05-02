use std::borrow::Cow;

use jade_core::CoreState;
use jade_protocol_v1::{method_spec, ErrorCode, MethodClass, Request};

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

    pub fn ping_v2(&self, id: impl Into<Cow<'static, str>>) -> jade_protocol_v2::Response<'static> {
        self.state.ping_response(id.into())
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
        };

        assert!(matches!(
            emulator.handle_v1_request(&request),
            V1Outcome::ImmediatePing { .. }
        ));
    }

    #[test]
    fn signing_methods_are_deferred() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("2"),
            method: Cow::Borrowed("sign_psbt"),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::DeferredToCore {
                method: "sign_psbt".to_string()
            }
        );
    }
}
