use std::borrow::Cow;
use std::boxed::Box;
use std::vec::Vec;

use jade_core::{
    CoreError, CoreResult, CoreState, NetworkRestriction, OperationState, Platform,
    VersionDebugInfo, VersionInfo,
};
use jade_protocol_v1::{
    decode_request, encode_bool_result, encode_error_response, encode_map_result,
    encode_owned_map_result, encode_uint_result, method_spec, ErrorCode, ErrorResponse,
    MethodClass, OwnedResultMapEntry, OwnedV1Value, Request, ResultMapEntry, V1Value,
};
use jade_storage::{
    key_name_valid, parse_descriptor_details, parse_descriptor_summary, parse_multisig_summary,
    JadeStorage, MemoryStorage, RecordAuthenticator, StorageLimits, StorageNamespace,
    StorageRecord, HMAC_SHA256_LEN,
};

#[derive(Debug)]
pub struct Emulator {
    state: CoreState,
    platform: HostPlatform,
    storage: JadeStorage<MemoryStorage>,
}

impl Default for Emulator {
    fn default() -> Self {
        Self {
            state: CoreState::default(),
            platform: HostPlatform::default(),
            storage: JadeStorage::new(MemoryStorage::new(), StorageLimits::ESP32_NVS_DEFAULT),
        }
    }
}

impl Emulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn platform(&self) -> &HostPlatform {
        &self.platform
    }

    pub fn storage_mut(&mut self) -> &mut JadeStorage<MemoryStorage> {
        &mut self.storage
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
            Some(MethodClass::PreAuth) if request.method == "get_version_info" => {
                V1Outcome::VersionInfo {
                    info: Box::new(self.state.version_info(&self.platform).into_static()),
                }
            }
            Some(MethodClass::PreAuth) if request.method == "add_entropy" => {
                let Some(params) = request.params() else {
                    return V1Outcome::Reject {
                        code: ErrorCode::BadParameters,
                        message: "Expecting parameters map".to_string(),
                    };
                };
                let entropy = match params.bytes("entropy") {
                    Ok(Some(entropy)) if !entropy.is_empty() => entropy,
                    Ok(_) | Err(_) => {
                        return V1Outcome::Reject {
                            code: ErrorCode::BadParameters,
                            message: "Failed to extract valid entropy bytes from parameters"
                                .to_string(),
                        };
                    }
                };
                match self.state.add_entropy(&mut self.platform, entropy) {
                    Ok(()) => V1Outcome::BoolResult { result: true },
                    Err(err) => reject_core_error(err),
                }
            }
            Some(MethodClass::PreAuth) if request.method == "set_epoch" => {
                let Some(params) = request.params() else {
                    return V1Outcome::Reject {
                        code: ErrorCode::BadParameters,
                        message: "Expecting parameters map".to_string(),
                    };
                };
                let epoch = match params.u64("epoch") {
                    Ok(Some(epoch)) => epoch,
                    Ok(None) | Err(_) => {
                        return V1Outcome::Reject {
                            code: ErrorCode::BadParameters,
                            message: "Failed to extract valid epoch value from parameters"
                                .to_string(),
                        };
                    }
                };
                match self.state.set_epoch(&mut self.platform, epoch) {
                    Ok(()) => V1Outcome::BoolResult { result: true },
                    Err(err) => reject_core_error(err),
                }
            }
            Some(MethodClass::PreAuth) if request.method == "logout" => {
                self.state.logout();
                V1Outcome::BoolResult { result: true }
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_multisigs" => {
                self.registered_wallets_result(StorageNamespace::Multisig, "multisig")
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_descriptors" => {
                self.registered_wallets_result(StorageNamespace::Descriptor, "descriptor")
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_descriptor" => {
                self.registered_descriptor_details(request)
            }
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
                V1Outcome::VersionInfo { info } => encode_version_info_result(&request.id, &info),
                V1Outcome::BoolResult { result } => encode_bool_result(&request.id, result),
                V1Outcome::EmptyMapResult => encode_map_result(&request.id, &[]),
                V1Outcome::OwnedMapResult { entries } => {
                    encode_owned_map_result(&request.id, &entries)
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

    fn registered_wallets_result(
        &self,
        namespace: StorageNamespace,
        wallet_kind: &'static str,
    ) -> V1Outcome {
        match self.storage.count(namespace) {
            Ok(0) => V1Outcome::EmptyMapResult,
            Ok(_) if namespace == StorageNamespace::Multisig => {
                self.registered_multisig_summaries()
            }
            Ok(_) if namespace == StorageNamespace::Descriptor => {
                self.registered_descriptor_summaries()
            }
            Ok(_) => V1Outcome::EmptyMapResult,
            Err(_) => V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: format!("failed to load registered {wallet_kind} records"),
            },
        }
    }

    fn registered_multisig_summaries(&self) -> V1Outcome {
        let mut names = Vec::new();
        if self
            .storage
            .list_names(StorageNamespace::Multisig, &mut names)
            .is_err()
        {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "failed to load registered multisig records".to_string(),
            };
        }

        let authenticator = HostRecordAuthenticator;
        let mut entries = Vec::new();
        for name in names {
            let mut record = Vec::new();
            if self
                .storage
                .get_record(
                    StorageRecord::MultisigRegistration { name: &name },
                    &mut record,
                )
                .is_err()
            {
                continue;
            }
            let Ok(summary) = parse_multisig_summary(&record, &authenticator) else {
                continue;
            };
            entries.push(OwnedResultMapEntry {
                key: name,
                value: OwnedV1Value::Map(vec![
                    OwnedResultMapEntry {
                        key: "variant".to_string(),
                        value: OwnedV1Value::Text(summary.variant.as_v1_str().to_string()),
                    },
                    OwnedResultMapEntry {
                        key: "sorted".to_string(),
                        value: OwnedV1Value::Bool(summary.sorted),
                    },
                    OwnedResultMapEntry {
                        key: "threshold".to_string(),
                        value: OwnedV1Value::U64(summary.threshold.into()),
                    },
                    OwnedResultMapEntry {
                        key: "num_signers".to_string(),
                        value: OwnedV1Value::U64(summary.num_signers.into()),
                    },
                    OwnedResultMapEntry {
                        key: "master_blinding_key".to_string(),
                        value: OwnedV1Value::Bytes(
                            summary
                                .master_blinding_key
                                .map(|key| key.to_vec())
                                .unwrap_or_default(),
                        ),
                    },
                ]),
            });
        }

        V1Outcome::OwnedMapResult { entries }
    }

    fn registered_descriptor_summaries(&self) -> V1Outcome {
        let mut names = Vec::new();
        if self
            .storage
            .list_names(StorageNamespace::Descriptor, &mut names)
            .is_err()
        {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "failed to load registered descriptor records".to_string(),
            };
        }

        let authenticator = HostRecordAuthenticator;
        let mut entries = Vec::new();
        for name in names {
            let mut record = Vec::new();
            if self
                .storage
                .get_record(
                    StorageRecord::DescriptorRegistration { name: &name },
                    &mut record,
                )
                .is_err()
            {
                continue;
            }
            let Ok(summary) = parse_descriptor_summary(&record, &authenticator) else {
                continue;
            };
            entries.push(OwnedResultMapEntry {
                key: name,
                value: OwnedV1Value::Map(vec![
                    OwnedResultMapEntry {
                        key: "descriptor_len".to_string(),
                        value: OwnedV1Value::U64(summary.descriptor_len.into()),
                    },
                    OwnedResultMapEntry {
                        key: "num_datavalues".to_string(),
                        value: OwnedV1Value::U64(summary.num_datavalues.into()),
                    },
                ]),
            });
        }

        V1Outcome::OwnedMapResult { entries }
    }

    fn registered_descriptor_details(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let descriptor_name = match params.str("descriptor_name") {
            Ok(Some(name)) if key_name_valid(name) => name,
            Ok(_) | Err(_) => {
                return V1Outcome::Reject {
                    code: ErrorCode::BadParameters,
                    message: "Missing or invalid descriptor name parameter".to_string(),
                };
            }
        };

        let mut record = Vec::new();
        if self
            .storage
            .get_record(
                StorageRecord::DescriptorRegistration {
                    name: descriptor_name,
                },
                &mut record,
            )
            .is_err()
        {
            return missing_descriptor_result();
        }

        let Ok(details) = parse_descriptor_details(&record, &HostRecordAuthenticator) else {
            return missing_descriptor_result();
        };

        V1Outcome::OwnedMapResult {
            entries: vec![
                OwnedResultMapEntry {
                    key: "descriptor_name".to_string(),
                    value: OwnedV1Value::Text(descriptor_name.to_string()),
                },
                OwnedResultMapEntry {
                    key: "descriptor".to_string(),
                    value: OwnedV1Value::Text(details.descriptor),
                },
                OwnedResultMapEntry {
                    key: "datavalues".to_string(),
                    value: OwnedV1Value::Map(
                        details
                            .datavalues
                            .into_iter()
                            .map(|datavalue| OwnedResultMapEntry {
                                key: datavalue.key,
                                value: OwnedV1Value::Text(datavalue.value),
                            })
                            .collect(),
                    ),
                },
            ],
        }
    }
}

fn missing_descriptor_result() -> V1Outcome {
    V1Outcome::Reject {
        code: ErrorCode::BadParameters,
        message: "Named descriptor wallet does not exist for this signer".to_string(),
    }
}

#[derive(Debug, Clone, Copy)]
struct HostRecordAuthenticator;

impl RecordAuthenticator for HostRecordAuthenticator {
    fn verify_record(&self, _payload: &[u8], tag: &[u8; HMAC_SHA256_LEN]) -> bool {
        tag == &[0xa5; HMAC_SHA256_LEN]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPlatform {
    version: Cow<'static, str>,
    entropy_bytes_received: usize,
    epoch: Option<u64>,
}

impl Default for HostPlatform {
    fn default() -> Self {
        Self {
            version: Cow::Borrowed("rust-emulator"),
            entropy_bytes_received: 0,
            epoch: None,
        }
    }
}

impl HostPlatform {
    pub fn entropy_bytes_received(&self) -> usize {
        self.entropy_bytes_received
    }

    pub fn epoch(&self) -> Option<u64> {
        self.epoch
    }
}

impl Platform for HostPlatform {
    fn version_info<'a>(&'a self, state: &CoreState) -> VersionInfo<'a> {
        VersionInfo {
            jade_version: Cow::Borrowed(self.version.as_ref()),
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
            jade_state: state.wallet.into(),
            jade_networks: NetworkRestriction::All,
            jade_has_pin: false,
            debug: Some(VersionDebugInfo {
                nvs_entries_used: 0,
                nvs_entries_free: 0,
                free_heap: 0,
                free_dram: 0,
                largest_dram: 0,
                free_spiram: 0,
                largest_spiram: 0,
                gcov: false,
            }),
        }
    }

    fn add_entropy(&mut self, entropy: &[u8]) -> CoreResult<()> {
        self.entropy_bytes_received += entropy.len();
        Ok(())
    }

    fn set_epoch(&mut self, epoch: u64) -> CoreResult<()> {
        self.epoch = Some(epoch);
        Ok(())
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

fn reject_core_error(err: CoreError) -> V1Outcome {
    let (code, message) = match err {
        CoreError::InvalidRequest => (ErrorCode::InvalidRequest, "invalid request"),
        CoreError::UnknownMethod => (ErrorCode::UnknownMethod, "unknown method"),
        CoreError::BadParameters => (ErrorCode::BadParameters, "bad parameters"),
        CoreError::InternalError => (ErrorCode::InternalError, "internal error"),
        CoreError::HardwareLocked => (ErrorCode::HardwareLocked, "hardware locked"),
        CoreError::OutOfMemory => (ErrorCode::InternalError, "out of memory"),
        CoreError::Deferred(method) => (ErrorCode::InternalError, method),
        CoreError::Unsupported(feature) => (ErrorCode::InternalError, feature),
    };
    V1Outcome::Reject {
        code,
        message: message.to_string(),
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

trait StaticVersionInfo {
    fn into_static(self) -> VersionInfo<'static>;
}

impl StaticVersionInfo for VersionInfo<'_> {
    fn into_static(self) -> VersionInfo<'static> {
        VersionInfo {
            jade_version: Cow::Owned(self.jade_version.into_owned()),
            jade_ota_max_chunk: self.jade_ota_max_chunk,
            jade_config: Cow::Owned(self.jade_config.into_owned()),
            board_type: Cow::Owned(self.board_type.into_owned()),
            jade_features: Cow::Owned(self.jade_features.into_owned()),
            idf_version: Cow::Owned(self.idf_version.into_owned()),
            chip_features: Cow::Owned(self.chip_features.into_owned()),
            efusemac: Cow::Owned(self.efusemac.into_owned()),
            attestation_initialised: self.attestation_initialised,
            battery_status: self.battery_status,
            battery_millivolts: self.battery_millivolts,
            battery_charging: self.battery_charging,
            jade_state: self.jade_state,
            jade_networks: self.jade_networks,
            jade_has_pin: self.jade_has_pin,
            debug: self.debug,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V1Outcome {
    ImmediatePing { activity: jade_core::OperationState },
    VersionInfo { info: Box<VersionInfo<'static>> },
    BoolResult { result: bool },
    EmptyMapResult,
    OwnedMapResult { entries: Vec<OwnedResultMapEntry> },
    DeferredToCore { method: String },
    Reject { code: ErrorCode, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use jade_storage::{BIP32_SERIALIZED_LEN, MULTISIG_MASTER_BLINDING_KEY_SIZE};
    use minicbor::Decoder;

    fn authenticated_record(mut payload: Vec<u8>) -> Vec<u8> {
        payload.extend_from_slice(&[0xa5; HMAC_SHA256_LEN]);
        payload
    }

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
    fn get_version_info_returns_debug_compatible_map() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("v"),
            method: Cow::Borrowed("get_version_info"),
            params: None,
        };

        let V1Outcome::VersionInfo { info } = emulator.handle_v1_request(&request) else {
            panic!("expected version info response");
        };
        assert_eq!(info.v1_field_count(), 23);
        assert_eq!(info.jade_state.as_v1_str(), "UNINIT");
    }

    #[test]
    fn raw_v1_get_version_info_returns_public_fields() {
        let mut emulator = Emulator::new();
        let request = [
            0xa2, 0x62, b'i', b'd', 0x61, b'v', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x70,
            b'g', b'e', b't', b'_', b'v', b'e', b'r', b's', b'i', b'o', b'n', b'_', b'i', b'n',
            b'f', b'o',
        ];

        let response = emulator.handle_v1_cbor(&request);
        let mut decoder = Decoder::new(&response);
        let mut result_len = None;
        let mut state = None;

        assert_eq!(decoder.map().unwrap(), Some(2));
        for _ in 0..2 {
            match decoder.str().unwrap() {
                "id" => assert_eq!(decoder.str().unwrap(), "v"),
                "result" => {
                    let len = decoder.map().unwrap();
                    result_len = len.map(|value| value as usize);
                    for _ in 0..len.unwrap() {
                        match decoder.str().unwrap() {
                            "JADE_STATE" => state = Some(decoder.str().unwrap()),
                            _ => decoder.skip().unwrap(),
                        }
                    }
                }
                _ => decoder.skip().unwrap(),
            }
        }

        assert_eq!(result_len, Some(23));
        assert_eq!(state, Some("UNINIT"));
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

    #[test]
    fn registered_wallet_enumeration_returns_empty_maps() {
        let mut emulator = Emulator::new();

        for method in ["get_registered_multisigs", "get_registered_descriptors"] {
            let request = Request {
                id: Cow::Borrowed("w"),
                method: Cow::Borrowed(method),
                params: None,
            };

            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::EmptyMapResult
            );
        }
    }

    #[test]
    fn raw_v1_registered_wallet_enumeration_returns_empty_map() {
        let mut emulator = Emulator::new();
        let mut request = Vec::new();
        minicbor::Encoder::new(&mut request)
            .map(2)
            .unwrap()
            .str("id")
            .unwrap()
            .str("w")
            .unwrap()
            .str("method")
            .unwrap()
            .str("get_registered_multisigs")
            .unwrap();

        let response = emulator.handle_v1_cbor(&request);
        let mut decoder = Decoder::new(&response);
        let mut result_len = None;

        assert_eq!(decoder.map().unwrap(), Some(2));
        for _ in 0..2 {
            match decoder.str().unwrap() {
                "id" => assert_eq!(decoder.str().unwrap(), "w"),
                "result" => result_len = decoder.map().unwrap(),
                _ => decoder.skip().unwrap(),
            }
        }

        assert_eq!(result_len, Some(0));
    }

    #[test]
    fn registered_wallet_enumeration_skips_unauthenticated_records() {
        let mut emulator = Emulator::new();
        emulator
            .storage_mut()
            .set_multisig_registration("wallet-a", b"hmac-protected-c-record")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("w"),
            method: Cow::Borrowed("get_registered_multisigs"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::OwnedMapResult { entries: vec![] }
        );
    }

    #[test]
    fn registered_multisig_enumeration_uses_authenticated_summary_parser() {
        let mut emulator = Emulator::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&[3, 4, 1, 2]);
        payload.push(MULTISIG_MASTER_BLINDING_KEY_SIZE as u8);
        payload.extend_from_slice(&[0x22; MULTISIG_MASTER_BLINDING_KEY_SIZE]);
        payload.push(2);
        for signer in 0..2u8 {
            payload.extend_from_slice(&[signer; 4]);
            payload.push(0);
            payload.extend_from_slice(&[0; BIP32_SERIALIZED_LEN]);
            payload.push(0);
        }
        emulator
            .storage_mut()
            .set_multisig_registration("wallet-a", &authenticated_record(payload))
            .unwrap();

        let request = Request {
            id: Cow::Borrowed("w"),
            method: Cow::Borrowed("get_registered_multisigs"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::OwnedMapResult {
                entries: vec![OwnedResultMapEntry {
                    key: "wallet-a".to_string(),
                    value: OwnedV1Value::Map(vec![
                        OwnedResultMapEntry {
                            key: "variant".to_string(),
                            value: OwnedV1Value::Text("wsh(multi(k))".to_string()),
                        },
                        OwnedResultMapEntry {
                            key: "sorted".to_string(),
                            value: OwnedV1Value::Bool(true),
                        },
                        OwnedResultMapEntry {
                            key: "threshold".to_string(),
                            value: OwnedV1Value::U64(2),
                        },
                        OwnedResultMapEntry {
                            key: "num_signers".to_string(),
                            value: OwnedV1Value::U64(2),
                        },
                        OwnedResultMapEntry {
                            key: "master_blinding_key".to_string(),
                            value: OwnedV1Value::Bytes(vec![
                                0x22;
                                MULTISIG_MASTER_BLINDING_KEY_SIZE
                            ]),
                        },
                    ]),
                }]
            }
        );
    }

    #[test]
    fn registered_descriptor_enumeration_uses_authenticated_summary_parser() {
        let mut emulator = Emulator::new();
        let mut payload = Vec::new();
        let script = b"wsh(sorted)";
        payload.extend_from_slice(&[0, 2]);
        payload.extend_from_slice(&(script.len() as u16).to_le_bytes());
        payload.extend_from_slice(script);
        payload.push(1);
        payload.extend_from_slice(&4u16.to_le_bytes());
        payload.extend_from_slice(b"xpub");
        payload.extend_from_slice(&3u16.to_le_bytes());
        payload.extend_from_slice(b"abc");
        emulator
            .storage_mut()
            .set_descriptor_registration("desc-a", &authenticated_record(payload))
            .unwrap();

        let request = Request {
            id: Cow::Borrowed("d"),
            method: Cow::Borrowed("get_registered_descriptors"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::OwnedMapResult {
                entries: vec![OwnedResultMapEntry {
                    key: "desc-a".to_string(),
                    value: OwnedV1Value::Map(vec![
                        OwnedResultMapEntry {
                            key: "descriptor_len".to_string(),
                            value: OwnedV1Value::U64(script.len() as u64),
                        },
                        OwnedResultMapEntry {
                            key: "num_datavalues".to_string(),
                            value: OwnedV1Value::U64(1),
                        },
                    ]),
                }]
            }
        );
    }

    #[test]
    fn registered_descriptor_detail_requires_valid_name() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("d"),
            method: Cow::Borrowed("get_registered_descriptor"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("bad name")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("d"),
            method: Cow::Borrowed("get_registered_descriptor"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Missing or invalid descriptor name parameter".to_string(),
            }
        );
    }

    #[test]
    fn registered_descriptor_detail_uses_authenticated_record_parser() {
        let mut emulator = Emulator::new();
        let mut payload = Vec::new();
        let script = b"wsh(sortedmulti(2,@0/**,@1/**))";
        payload.extend_from_slice(&[0, 2]);
        payload.extend_from_slice(&(script.len() as u16).to_le_bytes());
        payload.extend_from_slice(script);
        payload.push(2);
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(b"@0");
        payload.extend_from_slice(&5u16.to_le_bytes());
        payload.extend_from_slice(b"xpub0");
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(b"@1");
        payload.extend_from_slice(&5u16.to_le_bytes());
        payload.extend_from_slice(b"xpub1");
        emulator
            .storage_mut()
            .set_descriptor_registration("desc-a", &authenticated_record(payload))
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("desc-a")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("d"),
            method: Cow::Borrowed("get_registered_descriptor"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "descriptor_name".to_string(),
                        value: OwnedV1Value::Text("desc-a".to_string()),
                    },
                    OwnedResultMapEntry {
                        key: "descriptor".to_string(),
                        value: OwnedV1Value::Text("wsh(sortedmulti(2,@0/**,@1/**))".to_string()),
                    },
                    OwnedResultMapEntry {
                        key: "datavalues".to_string(),
                        value: OwnedV1Value::Map(vec![
                            OwnedResultMapEntry {
                                key: "@0".to_string(),
                                value: OwnedV1Value::Text("xpub0".to_string()),
                            },
                            OwnedResultMapEntry {
                                key: "@1".to_string(),
                                value: OwnedV1Value::Text("xpub1".to_string()),
                            },
                        ]),
                    },
                ]
            }
        );
    }

    #[test]
    fn raw_v1_registered_descriptor_detail_returns_nested_datavalues() {
        let mut emulator = Emulator::new();
        let mut payload = Vec::new();
        let script = b"wsh(@0/**)";
        payload.extend_from_slice(&[0, 2]);
        payload.extend_from_slice(&(script.len() as u16).to_le_bytes());
        payload.extend_from_slice(script);
        payload.push(1);
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(b"@0");
        payload.extend_from_slice(&5u16.to_le_bytes());
        payload.extend_from_slice(b"xpub0");
        emulator
            .storage_mut()
            .set_descriptor_registration("desc-a", &authenticated_record(payload))
            .unwrap();

        let mut request = Vec::new();
        minicbor::Encoder::new(&mut request)
            .map(3)
            .unwrap()
            .str("id")
            .unwrap()
            .str("d")
            .unwrap()
            .str("method")
            .unwrap()
            .str("get_registered_descriptor")
            .unwrap()
            .str("params")
            .unwrap()
            .map(1)
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("desc-a")
            .unwrap();

        let response = emulator.handle_v1_cbor(&request);
        let mut decoder = Decoder::new(&response);
        let mut descriptor_name = None;
        let mut descriptor = None;
        let mut data_value = None;

        assert_eq!(decoder.map().unwrap(), Some(2));
        for _ in 0..2 {
            match decoder.str().unwrap() {
                "id" => assert_eq!(decoder.str().unwrap(), "d"),
                "result" => {
                    assert_eq!(decoder.map().unwrap(), Some(3));
                    for _ in 0..3 {
                        match decoder.str().unwrap() {
                            "descriptor_name" => descriptor_name = Some(decoder.str().unwrap()),
                            "descriptor" => descriptor = Some(decoder.str().unwrap()),
                            "datavalues" => {
                                assert_eq!(decoder.map().unwrap(), Some(1));
                                assert_eq!(decoder.str().unwrap(), "@0");
                                data_value = Some(decoder.str().unwrap());
                            }
                            _ => decoder.skip().unwrap(),
                        }
                    }
                }
                _ => decoder.skip().unwrap(),
            }
        }

        assert_eq!(descriptor_name, Some("desc-a"));
        assert_eq!(descriptor, Some("wsh(@0/**)"));
        assert_eq!(data_value, Some("xpub0"));
    }

    #[test]
    fn add_entropy_updates_host_platform_rng_boundary() {
        let mut emulator = Emulator::new();
        let request = [
            0xa3, 0x62, b'i', b'd', 0x61, b'e', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x6b,
            b'a', b'd', b'd', b'_', b'e', b'n', b't', b'r', b'o', b'p', b'y', 0x66, b'p', b'a',
            b'r', b'a', b'm', b's', 0xa1, 0x67, b'e', b'n', b't', b'r', b'o', b'p', b'y', 0x45,
            b'n', b'o', b'i', b's', b'e',
        ];

        assert_eq!(
            emulator.handle_v1_cbor(&request),
            [0xa2, 0x62, b'i', b'd', 0x61, b'e', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0xf5,]
        );
        assert_eq!(emulator.platform().entropy_bytes_received(), 5);
    }

    #[test]
    fn add_entropy_rejects_missing_params() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("e"),
            method: Cow::Borrowed("add_entropy"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string()
            }
        );
    }

    #[test]
    fn set_epoch_updates_host_platform_clock_boundary() {
        let mut emulator = Emulator::new();
        let request = [
            0xa3, 0x62, b'i', b'd', 0x61, b't', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x69,
            b's', b'e', b't', b'_', b'e', b'p', b'o', b'c', b'h', 0x66, b'p', b'a', b'r', b'a',
            b'm', b's', 0xa1, 0x65, b'e', b'p', b'o', b'c', b'h', 0x1a, 0x65, 0x53, 0xf1, 0x00,
        ];

        assert_eq!(
            emulator.handle_v1_cbor(&request),
            [0xa2, 0x62, b'i', b'd', 0x61, b't', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0xf5,]
        );
        assert_eq!(emulator.platform().epoch(), Some(1_700_000_000));
    }

    #[test]
    fn logout_returns_ok_boolean() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("3"),
            method: Cow::Borrowed("logout"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );
    }

    #[test]
    fn raw_v1_logout_returns_true() {
        let mut emulator = Emulator::new();
        let request = [
            0xa2, 0x62, b'i', b'd', 0x61, b'3', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x66,
            b'l', b'o', b'g', b'o', b'u', b't',
        ];

        assert_eq!(
            emulator.handle_v1_cbor(&request),
            [0xa2, 0x62, b'i', b'd', 0x61, b'3', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0xf5,]
        );
    }
}
