use alloc::vec::Vec;

use jade_protocol_v1::{
    decode_request, encode_bool_result, encode_error_response, encode_map_result,
    encode_uint_result, method_spec, ErrorCode as V1ErrorCode, ErrorResponse, MethodClass,
    Request as V1Request, ResultMapEntry, V1Value,
};
use jade_protocol_v2::{Request as V2Request, Response as V2Response, VersionInfo};
use minicbor::Decoder;

use crate::{
    AllocationFailure, CoreError, CoreState, DeviceBootFailure, DevicePlatform, DeviceRuntime,
    OperationState, Platform,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareProtocol {
    V1Cbor,
    V2Cbor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareFrameError {
    BootRequired,
    Decode,
    Encode,
    Allocation(AllocationFailure),
    Io(DeviceBootFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborFrameBufferError {
    Overflow { capacity: usize, attempted: usize },
    InvalidOrIncomplete { buffered: usize },
}

#[derive(Debug)]
pub struct CborFrameBuffer<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl<'a> CborFrameBuffer<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }

    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn pending(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn remaining_capacity(&self) -> usize {
        self.capacity() - self.len
    }

    pub fn spare_capacity_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.len..]
    }

    pub fn advance(&mut self, additional: usize) -> Result<(), CborFrameBufferError> {
        let next = self
            .len
            .checked_add(additional)
            .ok_or(CborFrameBufferError::Overflow {
                capacity: self.capacity(),
                attempted: usize::MAX,
            })?;
        if next > self.capacity() {
            return Err(CborFrameBufferError::Overflow {
                capacity: self.capacity(),
                attempted: next,
            });
        }

        self.len = next;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn reject_pending(&mut self) -> usize {
        let rejected = self.len;
        self.clear();
        rejected
    }

    pub fn push(&mut self, input: &[u8]) -> Result<(), CborFrameBufferError> {
        let offset = self.len;
        self.advance(input.len())?;
        self.bytes[offset..self.len].copy_from_slice(input);
        Ok(())
    }

    pub fn next_frame_len(&self) -> Result<Option<usize>, CborFrameBufferError> {
        match complete_cbor_frame_len(self.pending())? {
            Some(len) => Ok(Some(len)),
            None if self.len == self.capacity() && self.len > 0 => {
                Err(CborFrameBufferError::InvalidOrIncomplete { buffered: self.len })
            }
            None => Ok(None),
        }
    }

    pub fn handle_next_frame<R>(
        &mut self,
        handler: impl FnOnce(&[u8]) -> R,
    ) -> Result<Option<R>, CborFrameBufferError> {
        let Some(frame_len) = self.next_frame_len()? else {
            return Ok(None);
        };

        let result = handler(&self.bytes[..frame_len]);
        self.consume(frame_len);
        Ok(Some(result))
    }

    fn consume(&mut self, frame_len: usize) {
        if frame_len >= self.len {
            self.clear();
            return;
        }

        self.bytes.copy_within(frame_len..self.len, 0);
        self.len -= frame_len;
    }
}

pub fn complete_cbor_frame_len(input: &[u8]) -> Result<Option<usize>, CborFrameBufferError> {
    if input.is_empty() {
        return Ok(None);
    }

    let mut decoder = Decoder::new(input);
    match decoder.skip() {
        Ok(()) => Ok(Some(decoder.position())),
        Err(_) => Ok(None),
    }
}

impl<P> DeviceRuntime<P>
where
    P: DevicePlatform,
{
    pub fn handle_firmware_frame(
        &mut self,
        protocol: FirmwareProtocol,
        input: &[u8],
    ) -> Result<Option<Vec<u8>>, FirmwareFrameError> {
        if !self.is_booted() {
            return Err(FirmwareFrameError::BootRequired);
        }

        let allocation = self.manifest().memory.allocation;
        allocation
            .ensure_request(input.len())
            .map_err(FirmwareFrameError::Allocation)?;

        let reply = match protocol {
            FirmwareProtocol::V1Cbor => {
                let (state, platform) = self.state_and_platform_mut();
                handle_v1_cbor(state, platform, input)
            }
            FirmwareProtocol::V2Cbor => {
                let request: V2Request<'_> =
                    minicbor::decode(input).map_err(|_| FirmwareFrameError::Decode)?;
                let (state, platform) = self.state_and_platform_mut();
                let response: V2Response<'_> = state.handle_v2(platform, request);
                let bytes = minicbor::to_vec(response).map_err(|_| FirmwareFrameError::Encode)?;
                Some(bytes)
            }
        };
        if let Some(bytes) = &reply {
            allocation
                .ensure_response(bytes.len())
                .map_err(FirmwareFrameError::Allocation)?;
        }
        Ok(reply)
    }
}

pub fn handle_v1_cbor(
    state: &mut CoreState,
    platform: &mut impl Platform,
    input: &[u8],
) -> Option<Vec<u8>> {
    match decode_request(input) {
        Ok(request) => handle_v1_request(state, platform, &request),
        Err(_) => Some(v1_error("", V1ErrorCode::InvalidRequest, "invalid request")),
    }
}

fn handle_v1_request(
    state: &mut CoreState,
    platform: &mut impl Platform,
    request: &V1Request<'_>,
) -> Option<Vec<u8>> {
    match method_spec(&request.method).map(|spec| spec.class) {
        Some(MethodClass::Immediate) if request.method == "ping" => Some(encode_uint_result(
            &request.id,
            v1_activity_code(state.operation),
        )),
        Some(MethodClass::PreAuth) if request.method == "get_version_info" => Some(
            encode_version_info_result(&request.id, &state.version_info(platform)),
        ),
        Some(MethodClass::PreAuth) if request.method == "add_entropy" => {
            let Some(params) = request.params() else {
                return Some(v1_error(
                    &request.id,
                    V1ErrorCode::BadParameters,
                    "Expecting parameters map",
                ));
            };
            let entropy = match params.bytes("entropy") {
                Ok(Some(entropy)) if !entropy.is_empty() => entropy,
                Ok(_) | Err(_) => {
                    return Some(v1_error(
                        &request.id,
                        V1ErrorCode::BadParameters,
                        "Failed to extract valid entropy bytes from parameters",
                    ));
                }
            };
            match state.add_entropy(platform, entropy) {
                Ok(()) => Some(encode_bool_result(&request.id, true)),
                Err(err) => Some(v1_core_error(&request.id, err)),
            }
        }
        Some(MethodClass::PreAuth) if request.method == "set_epoch" => {
            let Some(params) = request.params() else {
                return Some(v1_error(
                    &request.id,
                    V1ErrorCode::BadParameters,
                    "Expecting parameters map",
                ));
            };
            let epoch = match params.u64("epoch") {
                Ok(Some(epoch)) => epoch,
                Ok(None) | Err(_) => {
                    return Some(v1_error(
                        &request.id,
                        V1ErrorCode::BadParameters,
                        "Failed to extract valid epoch value from parameters",
                    ));
                }
            };
            match state.set_epoch(platform, epoch) {
                Ok(()) => Some(encode_bool_result(&request.id, true)),
                Err(err) => Some(v1_core_error(&request.id, err)),
            }
        }
        Some(MethodClass::PreAuth) if request.method == "logout" => {
            state.logout();
            Some(encode_bool_result(&request.id, true))
        }
        Some(MethodClass::PreAuth) if request.method == "cancel" => None,
        Some(MethodClass::Continuation) => Some(v1_error(
            &request.id,
            V1ErrorCode::ProtocolError,
            "Unexpected method",
        )),
        Some(_) => Some(v1_error(
            &request.id,
            V1ErrorCode::InternalError,
            "unsupported by Rust core",
        )),
        None => Some(v1_error(
            &request.id,
            V1ErrorCode::UnknownMethod,
            "Unknown method",
        )),
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

fn encode_version_info_result(id: &str, info: &VersionInfo<'_>) -> Vec<u8> {
    let mut entries = Vec::with_capacity(info.v1_field_count());
    entries.extend_from_slice(&[
        ResultMapEntry {
            key: "JADE_VERSION",
            value: V1Value::Text(info.jade_version.as_ref()),
        },
        ResultMapEntry {
            key: "JADE_OTA_MAX_CHUNK",
            value: V1Value::U64(info.jade_ota_max_chunk),
        },
        ResultMapEntry {
            key: "JADE_CONFIG",
            value: V1Value::Text(info.jade_config.as_ref()),
        },
        ResultMapEntry {
            key: "BOARD_TYPE",
            value: V1Value::Text(info.board_type.as_ref()),
        },
        ResultMapEntry {
            key: "JADE_FEATURES",
            value: V1Value::Text(info.jade_features.as_ref()),
        },
        ResultMapEntry {
            key: "IDF_VERSION",
            value: V1Value::Text(info.idf_version.as_ref()),
        },
        ResultMapEntry {
            key: "CHIP_FEATURES",
            value: V1Value::Text(info.chip_features.as_ref()),
        },
        ResultMapEntry {
            key: "EFUSEMAC",
            value: V1Value::Text(info.efusemac.as_ref()),
        },
        ResultMapEntry {
            key: "ATTESTATION_INITIALISED",
            value: V1Value::Bool(info.attestation_initialised),
        },
        ResultMapEntry {
            key: "BATTERY_STATUS",
            value: V1Value::U64(info.battery_status),
        },
        ResultMapEntry {
            key: "BATTERY_MILLIVOLTS",
            value: V1Value::U64(info.battery_millivolts),
        },
        ResultMapEntry {
            key: "BATTERY_CHARGING",
            value: V1Value::Bool(info.battery_charging),
        },
        ResultMapEntry {
            key: "JADE_STATE",
            value: V1Value::Text(info.jade_state.as_v1_str()),
        },
        ResultMapEntry {
            key: "JADE_NETWORKS",
            value: V1Value::Text(info.jade_networks.as_v1_str()),
        },
        ResultMapEntry {
            key: "JADE_HAS_PIN",
            value: V1Value::Bool(info.jade_has_pin),
        },
    ]);

    if let Some(debug) = info.debug {
        entries.extend_from_slice(&[
            ResultMapEntry {
                key: "JADE_NVS_ENTRIES_USED",
                value: V1Value::U64(debug.nvs_entries_used),
            },
            ResultMapEntry {
                key: "JADE_NVS_ENTRIES_FREE",
                value: V1Value::U64(debug.nvs_entries_free),
            },
            ResultMapEntry {
                key: "JADE_FREE_HEAP",
                value: V1Value::U64(debug.free_heap),
            },
            ResultMapEntry {
                key: "JADE_FREE_DRAM",
                value: V1Value::U64(debug.free_dram),
            },
            ResultMapEntry {
                key: "JADE_LARGEST_DRAM",
                value: V1Value::U64(debug.largest_dram),
            },
            ResultMapEntry {
                key: "JADE_FREE_SPIRAM",
                value: V1Value::U64(debug.free_spiram),
            },
            ResultMapEntry {
                key: "JADE_LARGEST_SPIRAM",
                value: V1Value::U64(debug.largest_spiram),
            },
            ResultMapEntry {
                key: "GCOV",
                value: V1Value::Bool(debug.gcov),
            },
        ]);
    }

    encode_map_result(id, &entries)
}

fn v1_core_error(id: &str, err: CoreError) -> Vec<u8> {
    let (code, message) = match err {
        CoreError::InvalidRequest => (V1ErrorCode::InvalidRequest, "invalid request"),
        CoreError::UnknownMethod => (V1ErrorCode::UnknownMethod, "unknown method"),
        CoreError::BadParameters => (V1ErrorCode::BadParameters, "bad parameters"),
        CoreError::InternalError => (V1ErrorCode::InternalError, "internal error"),
        CoreError::HardwareLocked => (V1ErrorCode::HardwareLocked, "hardware locked"),
        CoreError::OutOfMemory => (V1ErrorCode::InternalError, "out of memory"),
        CoreError::Unsupported(_) => (V1ErrorCode::InternalError, "unsupported"),
    };
    v1_error(id, code, message)
}

fn v1_error(id: &str, code: V1ErrorCode, message: &'static str) -> Vec<u8> {
    encode_error_response(&ErrorResponse {
        id: id.into(),
        code: code as i32,
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{borrow::Cow, vec};
    use jade_protocol_v2::{NetworkRestriction, RequestBody, RequestKind, VersionDebugInfo};
    use minicbor::{bytes::ByteVec, Decoder, Encoder};

    use crate::{
        AllocationBudget, DeviceBootFailure, DeviceBootReport, DeviceFeatureSet, DeviceManifest,
        DeviceMemoryBudget, DevicePartitionLayout, DeviceTarget, VersionInfoState,
    };

    #[derive(Debug)]
    struct TestDevice {
        manifest: DeviceManifest,
        entropy_bytes: usize,
        epoch: Option<u64>,
    }

    impl Platform for TestDevice {
        fn version_info<'a>(&'a self, state: &CoreState) -> VersionInfo<'a> {
            VersionInfo {
                jade_version: Cow::Borrowed("firmware-test"),
                jade_ota_max_chunk: 4096,
                jade_config: Cow::Borrowed("ESP32S3"),
                board_type: Cow::Borrowed(self.manifest.target_name()),
                jade_features: Cow::Borrowed("BLE,RUST"),
                idf_version: Cow::Borrowed("rust"),
                chip_features: Cow::Borrowed("ESP32S3"),
                efusemac: Cow::Borrowed("001122334455"),
                attestation_initialised: true,
                battery_status: 0,
                battery_millivolts: 0,
                battery_charging: false,
                jade_state: state.wallet.into(),
                jade_networks: NetworkRestriction::All,
                jade_has_pin: false,
                debug: Some(VersionDebugInfo {
                    nvs_entries_used: 1,
                    nvs_entries_free: 2,
                    free_heap: 3,
                    free_dram: 4,
                    largest_dram: 5,
                    free_spiram: 6,
                    largest_spiram: 7,
                    gcov: false,
                }),
            }
        }

        fn add_entropy(&mut self, entropy: &[u8]) -> crate::CoreResult<()> {
            self.entropy_bytes += entropy.len();
            Ok(())
        }

        fn set_epoch(&mut self, epoch: u64) -> crate::CoreResult<()> {
            self.epoch = Some(epoch);
            Ok(())
        }
    }

    impl DevicePlatform for TestDevice {
        fn manifest(&self) -> DeviceManifest {
            self.manifest
        }

        fn boot_report(&mut self) -> DeviceBootReport {
            DeviceBootReport::ok(self.manifest.target)
        }

        fn fill_random(&mut self, out: &mut [u8]) -> Result<(), DeviceBootFailure> {
            out.fill(0x7b);
            Ok(())
        }

        fn monotonic_millis(&self) -> u64 {
            9
        }

        fn rollback_secure_version(&self) -> u32 {
            1
        }
    }

    const TEST_MANIFEST: DeviceManifest = DeviceManifest {
        target: DeviceTarget::JadeV2,
        features: DeviceFeatureSet::ESP32S3_BASE,
        memory: DeviceMemoryBudget {
            allocation: AllocationBudget::ESP32_SPIRAM,
            stack_bytes: 24 * 1024,
            heap_bytes: 512 * 1024,
        },
        partitions: DevicePartitionLayout {
            name: "partitionss3.csv",
            ota_slots: 2,
            nvs_bytes: 0x10000,
            factory_app_bytes: 4024 * 1024,
            ota_app_bytes: 4024 * 1024,
        },
    };

    fn test_device() -> TestDevice {
        TestDevice {
            manifest: TEST_MANIFEST,
            entropy_bytes: 0,
            epoch: None,
        }
    }

    fn test_device_with_allocation(allocation: AllocationBudget) -> TestDevice {
        TestDevice {
            manifest: DeviceManifest {
                memory: DeviceMemoryBudget {
                    allocation,
                    ..TEST_MANIFEST.memory
                },
                ..TEST_MANIFEST
            },
            entropy_bytes: 0,
            epoch: None,
        }
    }

    fn v1_request(id: &str, method: &str, params: Option<&[u8]>) -> Vec<u8> {
        let mut output = Vec::new();
        {
            let mut encoder = Encoder::new(&mut output);
            let fields = if params.is_some() { 3 } else { 2 };
            encoder
                .map(fields)
                .and_then(|e| e.str("id"))
                .and_then(|e| e.str(id))
                .and_then(|e| e.str("method"))
                .and_then(|e| e.str(method))
                .expect("Vec-backed CBOR encoding is infallible");
            if params.is_some() {
                encoder
                    .str("params")
                    .expect("Vec-backed CBOR encoding is infallible");
            }
        }
        if let Some(params) = params {
            output.extend_from_slice(params);
        }
        output
    }

    fn one_field_params(
        key: &str,
        encode_value: impl FnOnce(&mut Encoder<&mut Vec<u8>>),
    ) -> Vec<u8> {
        let mut output = Vec::new();
        let mut encoder = Encoder::new(&mut output);
        encoder
            .map(1)
            .and_then(|e| e.str(key))
            .expect("Vec-backed CBOR encoding is infallible");
        encode_value(&mut encoder);
        output
    }

    fn decode_bool_result(bytes: &[u8]) -> bool {
        let mut decoder = Decoder::new(bytes);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        decoder.skip().unwrap();
        assert_eq!(decoder.str().unwrap(), "result");
        decoder.bool().unwrap()
    }

    #[test]
    fn cbor_frame_buffer_assembles_split_and_trailing_frames() {
        let first = v1_request("a", "ping", None);
        let second = v1_request("b", "get_version_info", None);
        let mut joined = first.clone();
        joined.extend_from_slice(&second);
        assert_eq!(complete_cbor_frame_len(&joined).unwrap(), Some(first.len()));

        let mut storage = [0u8; 512];
        let mut buffer = CborFrameBuffer::new(&mut storage);
        let split = first.len() / 2;
        buffer.push(&first[..split]).unwrap();
        assert_eq!(buffer.next_frame_len().unwrap(), None);
        let spare = buffer.spare_capacity_mut();
        spare[..first.len() - split].copy_from_slice(&first[split..]);
        buffer.advance(first.len() - split).unwrap();
        buffer.push(&second).unwrap();

        let frame = buffer
            .handle_next_frame(|frame| Vec::from(frame))
            .unwrap()
            .unwrap();
        assert_eq!(frame, first);
        assert_eq!(buffer.pending(), &second[..]);

        let frame = buffer
            .handle_next_frame(|frame| Vec::from(frame))
            .unwrap()
            .unwrap();
        assert_eq!(frame, second);
        assert!(buffer.is_empty());
    }

    #[test]
    fn cbor_frame_buffer_rejects_overflow_and_full_invalid_data() {
        let mut storage = [0u8; 4];
        let mut buffer = CborFrameBuffer::new(&mut storage);
        assert_eq!(
            buffer.push(&[0; 5]),
            Err(CborFrameBufferError::Overflow {
                capacity: 4,
                attempted: 5
            })
        );

        buffer.push(&[0x83, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(buffer.next_frame_len().unwrap(), Some(4));
        assert!(buffer.handle_next_frame(|_| ()).unwrap().is_some());
        assert!(buffer.is_empty());

        buffer.push(&[0x83, 0x01, 0x02, 0x9f]).unwrap();
        assert_eq!(
            buffer.next_frame_len(),
            Err(CborFrameBufferError::InvalidOrIncomplete { buffered: 4 })
        );
        assert_eq!(buffer.reject_pending(), 4);
        assert!(buffer.is_empty());
    }

    #[test]
    fn v1_management_frames_are_core_handled_without_emulator() {
        let mut state = CoreState::default();
        let mut platform = test_device();

        let entropy_params = one_field_params("entropy", |encoder| {
            encoder
                .bytes(b"noise")
                .expect("Vec-backed CBOR encoding is infallible");
        });
        let entropy_reply = handle_v1_cbor(
            &mut state,
            &mut platform,
            &v1_request("e", "add_entropy", Some(&entropy_params)),
        )
        .unwrap();
        assert!(decode_bool_result(&entropy_reply));
        assert_eq!(platform.entropy_bytes, 5);

        let epoch_params = one_field_params("epoch", |encoder| {
            encoder
                .u64(1_700_000_000)
                .expect("Vec-backed CBOR encoding is infallible");
        });
        let epoch_reply = handle_v1_cbor(
            &mut state,
            &mut platform,
            &v1_request("t", "set_epoch", Some(&epoch_params)),
        )
        .unwrap();
        assert!(decode_bool_result(&epoch_reply));
        assert_eq!(platform.epoch, Some(1_700_000_000));

        let version_reply = handle_v1_cbor(
            &mut state,
            &mut platform,
            &v1_request("v", "get_version_info", None),
        )
        .unwrap();
        let mut decoder = Decoder::new(&version_reply);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "v");
        assert_eq!(decoder.str().unwrap(), "result");
        assert_eq!(decoder.map().unwrap(), Some(23));
    }

    #[test]
    fn v1_cancel_keeps_no_reply_semantics() {
        let mut state = CoreState::default();
        let mut platform = test_device();

        assert_eq!(
            handle_v1_cbor(&mut state, &mut platform, &v1_request("c", "cancel", None)),
            None
        );
    }

    #[test]
    fn v1_bad_parameters_are_encoded_as_protocol_errors() {
        let mut state = CoreState::default();
        let mut platform = test_device();

        let reply = handle_v1_cbor(
            &mut state,
            &mut platform,
            &v1_request("e", "add_entropy", None),
        )
        .unwrap();
        let mut decoder = Decoder::new(&reply);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "e");
        assert_eq!(decoder.str().unwrap(), "error");
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "code");
        assert_eq!(decoder.i32().unwrap(), V1ErrorCode::BadParameters as i32);
    }

    #[test]
    fn firmware_runtime_dispatches_v2_frames_after_boot() {
        let mut runtime = DeviceRuntime::new(test_device());
        let request = jade_protocol_v2::Request {
            id: Cow::Borrowed("e"),
            kind: RequestKind::AddEntropy,
            session: None,
            body: RequestBody::AddEntropy {
                entropy: ByteVec::from(vec![1, 2, 3]),
            },
        };
        let request_bytes = minicbor::to_vec(request).unwrap();

        assert_eq!(
            runtime.handle_firmware_frame(FirmwareProtocol::V2Cbor, &request_bytes),
            Err(FirmwareFrameError::BootRequired)
        );

        runtime.boot().unwrap();
        let reply = runtime
            .handle_firmware_frame(FirmwareProtocol::V2Cbor, &request_bytes)
            .unwrap()
            .unwrap();
        let decoded: jade_protocol_v2::Response<'_> = minicbor::decode(&reply).unwrap();
        assert_eq!(decoded.id, "e");
        assert_eq!(decoded.body, jade_protocol_v2::ResponseBody::Ok);
        assert_eq!(runtime.platform().entropy_bytes, 3);
    }

    #[test]
    fn firmware_runtime_enforces_manifest_request_budget() {
        let mut runtime = DeviceRuntime::new(test_device_with_allocation(AllocationBudget {
            max_request_bytes: 4,
            max_response_bytes: 4096,
            max_scratch_bytes: 1024,
        }));
        runtime.boot().unwrap();
        let request = v1_request("p", "ping", None);

        assert_eq!(
            runtime.handle_firmware_frame(FirmwareProtocol::V1Cbor, &request),
            Err(FirmwareFrameError::Allocation(
                AllocationFailure::RequestTooLarge {
                    requested: request.len(),
                    limit: 4
                }
            ))
        );
    }

    #[test]
    fn firmware_runtime_enforces_manifest_response_budget() {
        let mut runtime = DeviceRuntime::new(test_device_with_allocation(AllocationBudget {
            max_request_bytes: 1024,
            max_response_bytes: 4,
            max_scratch_bytes: 1024,
        }));
        runtime.boot().unwrap();

        assert!(matches!(
            runtime.handle_firmware_frame(FirmwareProtocol::V1Cbor, &v1_request("p", "ping", None)),
            Err(FirmwareFrameError::Allocation(
                AllocationFailure::ResponseTooLarge { limit: 4, .. }
            ))
        ));
        assert!(matches!(
            runtime.handle_firmware_frame(
                FirmwareProtocol::V2Cbor,
                &minicbor::to_vec(jade_protocol_v2::Request {
                    id: Cow::Borrowed("e"),
                    kind: RequestKind::AddEntropy,
                    session: None,
                    body: RequestBody::AddEntropy {
                        entropy: ByteVec::from(vec![1]),
                    },
                })
                .unwrap(),
            ),
            Err(FirmwareFrameError::Allocation(
                AllocationFailure::ResponseTooLarge { limit: 4, .. }
            ))
        ));
    }

    #[test]
    fn firmware_runtime_dispatches_v1_frames_after_boot() {
        let mut runtime = DeviceRuntime::new(test_device());
        runtime.boot().unwrap();
        runtime.state_mut().wallet = crate::WalletLifecycle::Ready;

        let reply = runtime
            .handle_firmware_frame(
                FirmwareProtocol::V1Cbor,
                &v1_request("p", "get_version_info", None),
            )
            .unwrap()
            .unwrap();

        let mut decoder = Decoder::new(&reply);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "p");
        assert_eq!(decoder.str().unwrap(), "result");
        let Some(len) = decoder.map().unwrap() else {
            panic!("expected version map");
        };
        let mut state = None;
        for _ in 0..len {
            match decoder.str().unwrap() {
                "JADE_STATE" => state = Some(decoder.str().unwrap()),
                _ => decoder.skip().unwrap(),
            }
        }
        assert_eq!(state, Some(VersionInfoState::Ready.as_v1_str()));
    }
}
