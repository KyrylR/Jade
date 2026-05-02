use std::borrow::Cow;
use std::boxed::Box;
use std::fmt;
use std::string::String;
use std::vec::Vec;

use jade_core::{
    bip32_path::MAX_PATH_LEN, CoreError, CoreResult, CoreState, NetworkRestriction, OperationState,
    OtaHashType, OtaRequest, Platform, VersionDebugInfo, VersionInfo, WalletLifecycle,
};
use jade_protocol_v1::{
    decode_request, encode_bool_result, encode_bytes_result, encode_error_response,
    encode_map_result, encode_owned_map_result, encode_text_result, encode_uint_result,
    method_spec, ErrorCode, ErrorResponse, MethodClass, OwnedResultMapEntry, OwnedV1Value, Request,
    ResultMapEntry, V1Value,
};
use jade_storage::{
    key_name_valid, parse_descriptor_details, parse_descriptor_summary, parse_multisig_details,
    parse_multisig_summary, JadeStorage, MemoryStorage, MultisigDetails, MultisigSignerDetails,
    MultisigVariant, RecordAuthenticator, StorageLimits, StorageNamespace, StorageRecord,
    HMAC_SHA256_LEN,
};
use minicbor::Decoder;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct Emulator {
    state: CoreState,
    platform: HostPlatform,
    storage: JadeStorage<MemoryStorage>,
    ota: Option<HostOtaSession>,
}

impl Default for Emulator {
    fn default() -> Self {
        Self {
            state: CoreState::default(),
            platform: HostPlatform::default(),
            storage: JadeStorage::new(MemoryStorage::new(), StorageLimits::ESP32_NVS_DEFAULT),
            ota: None,
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

    pub fn platform_mut(&mut self) -> &mut HostPlatform {
        &mut self.platform
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
            Some(MethodClass::PreAuth) if request.method == "cancel" => V1Outcome::NoReply,
            Some(MethodClass::PreAuth) if request.method == "ota" => self.start_ota(request, false),
            Some(MethodClass::PreAuth) if request.method == "ota_delta" => {
                self.start_ota(request, true)
            }
            Some(MethodClass::PreAuth) if request.method == "update_pinserver" => {
                self.update_pinserver(request)
            }
            Some(MethodClass::Debug) if request.method == "debug_clean_reset" => {
                match self.storage.debug_clean_reset() {
                    Ok(()) => {
                        self.state = CoreState::default();
                        self.platform.clear_debug_wallet();
                        self.ota = None;
                        V1Outcome::BoolResult { result: true }
                    }
                    Err(_) => V1Outcome::Reject {
                        code: ErrorCode::InternalError,
                        message: "debug clean reset failed".to_string(),
                    },
                }
            }
            Some(MethodClass::Debug) if request.method == "debug_selfcheck" => {
                V1Outcome::UintResult { result: 0 }
            }
            Some(MethodClass::Debug) if request.method == "debug_set_mnemonic" => {
                self.debug_set_mnemonic(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_multisigs" => {
                self.registered_wallets_result(StorageNamespace::Multisig, "multisig")
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_multisig" => {
                self.registered_multisig_details(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_descriptors" => {
                self.registered_wallets_result(StorageNamespace::Descriptor, "descriptor")
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_descriptor" => {
                self.registered_descriptor_details(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_xpub" => {
                self.xpub_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_receive_address" => {
                self.receive_address_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_identity_pubkey" => {
                self.identity_pubkey_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_identity_shared_key" => {
                self.identity_shared_key_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_master_blinding_key" => {
                self.master_blinding_key_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_blinding_key" => {
                self.blinding_key_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_shared_nonce" => {
                self.shared_nonce_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_blinding_factor" => {
                self.blinding_factor_result(request)
            }
            Some(MethodClass::Continuation) if request.method == "ota_data" => {
                self.handle_ota_data(request)
            }
            Some(MethodClass::Continuation) if request.method == "ota_complete" => {
                self.handle_ota_complete()
            }
            Some(MethodClass::Continuation) => V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Unexpected method".to_string(),
            },
            Some(_) => V1Outcome::DeferredToCore {
                method: request.method.to_string(),
            },
            None => V1Outcome::Reject {
                code: ErrorCode::UnknownMethod,
                message: "Unknown method".to_string(),
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
                V1Outcome::UintResult { result } => encode_uint_result(&request.id, result),
                V1Outcome::TextResult { result } => encode_text_result(&request.id, &result),
                V1Outcome::BytesResult { result } => encode_bytes_result(&request.id, &result),
                V1Outcome::EmptyMapResult => encode_map_result(&request.id, &[]),
                V1Outcome::OwnedMapResult { entries } => {
                    encode_owned_map_result(&request.id, &entries)
                }
                V1Outcome::NoReply => Vec::new(),
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

    fn registered_multisig_details(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let multisig_name = match params.str("multisig_name") {
            Ok(Some(name)) if key_name_valid(name) => name,
            Ok(_) | Err(_) => {
                return V1Outcome::Reject {
                    code: ErrorCode::BadParameters,
                    message: "Missing or invalid multisig name parameter".to_string(),
                };
            }
        };
        let as_file = match params.bool("as_file") {
            Ok(value) => value.unwrap_or(false),
            Err(_) => {
                return V1Outcome::Reject {
                    code: ErrorCode::BadParameters,
                    message: "Failed to extract valid as_file parameter".to_string(),
                };
            }
        };

        let mut record = Vec::new();
        if self
            .storage
            .get_record(
                StorageRecord::MultisigRegistration {
                    name: multisig_name,
                },
                &mut record,
            )
            .is_err()
        {
            return missing_multisig_result();
        }

        let Ok(details) = parse_multisig_details(&record, &HostRecordAuthenticator) else {
            return missing_multisig_result();
        };
        let Some(signers) = details.signers.as_ref() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Named multisig too old include detailed signer data".to_string(),
            };
        };
        if signers.len() != details.summary.num_signers as usize {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Named multisig too old include detailed signer data".to_string(),
            };
        }

        if as_file {
            return match multisig_export_file(multisig_name, &details) {
                Some(multisig_file) => V1Outcome::OwnedMapResult {
                    entries: vec![
                        OwnedResultMapEntry {
                            key: "multisig_name".to_string(),
                            value: OwnedV1Value::Text(multisig_name.to_string()),
                        },
                        OwnedResultMapEntry {
                            key: "multisig_file".to_string(),
                            value: OwnedV1Value::Text(multisig_file),
                        },
                    ],
                },
                None => V1Outcome::Reject {
                    code: ErrorCode::InternalError,
                    message: "Failed to produce multisig export file".to_string(),
                },
            };
        }

        V1Outcome::OwnedMapResult {
            entries: vec![
                OwnedResultMapEntry {
                    key: "multisig_name".to_string(),
                    value: OwnedV1Value::Text(multisig_name.to_string()),
                },
                OwnedResultMapEntry {
                    key: "descriptor".to_string(),
                    value: OwnedV1Value::Map(vec![
                        OwnedResultMapEntry {
                            key: "variant".to_string(),
                            value: OwnedV1Value::Text(
                                details.summary.variant.as_v1_str().to_string(),
                            ),
                        },
                        OwnedResultMapEntry {
                            key: "sorted".to_string(),
                            value: OwnedV1Value::Bool(details.summary.sorted),
                        },
                        OwnedResultMapEntry {
                            key: "threshold".to_string(),
                            value: OwnedV1Value::U64(details.summary.threshold.into()),
                        },
                        OwnedResultMapEntry {
                            key: "master_blinding_key".to_string(),
                            value: OwnedV1Value::Bytes(
                                details
                                    .summary
                                    .master_blinding_key
                                    .map(|key| key.to_vec())
                                    .unwrap_or_default(),
                            ),
                        },
                        OwnedResultMapEntry {
                            key: "signers".to_string(),
                            value: OwnedV1Value::Array(
                                signers
                                    .iter()
                                    .map(|signer| {
                                        OwnedV1Value::Map(multisig_signer_entries(signer))
                                    })
                                    .collect(),
                            ),
                        },
                    ]),
                },
            ],
        }
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

    fn master_blinding_key_result(&self, request: &Request<'_>) -> V1Outcome {
        let only_if_silent = request
            .params()
            .and_then(|params| params.bool("only_if_silent").ok())
            .flatten()
            .unwrap_or(false);
        if only_if_silent && self.platform.confirm_export_blinding_key {
            return V1Outcome::Reject {
                code: ErrorCode::UserCancelled,
                message: "User declined to export master blinding key".to_string(),
            };
        }

        V1Outcome::BytesResult {
            result: self.platform.master_blinding_key().to_vec(),
        }
    }

    fn xpub_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };

        let prefix = match params.str("network") {
            Ok(Some(network)) => match xpub_prefix_for_network(network) {
                Some(prefix) => prefix,
                None => return bad_parameters("Failed to extract valid network from parameters"),
            },
            Ok(None) | Err(_) => {
                return bad_parameters("Failed to extract valid network from parameters");
            }
        };
        let path = match params.u32_array("path", MAX_PATH_LEN) {
            Ok(Some(path)) => path,
            Ok(None) | Err(_) => {
                return bad_parameters("Failed to extract valid path from parameters");
            }
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Cannot get xpub for path".to_string(),
            };
        };
        let Some(xpub) = jade_crypto::pure_rust::xpub_from_seed(seed, &path, prefix) else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Cannot get xpub for path".to_string(),
            };
        };

        V1Outcome::TextResult { result: xpub }
    }

    fn receive_address_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };

        let network_name = match params.str("network") {
            Ok(Some(network)) if valid_network_name(network) => network,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid network from parameters");
            }
        };
        let is_liquid = is_liquid_network(network_name);
        let confidential = if params.contains("confidential").unwrap_or(false) {
            match params.bool("confidential") {
                Ok(Some(confidential)) => confidential,
                Ok(None) | Err(_) => return bad_parameters("Invalid confidential flag"),
            }
        } else {
            is_liquid
        };
        if confidential && !is_liquid {
            return bad_parameters("Confidential addresses only apply to liquid networks");
        }

        if is_liquid
            || params.contains("multisig_name").unwrap_or(false)
            || params.contains("descriptor_name").unwrap_or(false)
            || !params.contains("variant").unwrap_or(false)
        {
            return V1Outcome::DeferredToCore {
                method: "get_receive_address".to_string(),
            };
        }

        let variant = match params.str("variant") {
            Ok(Some("pkh(k)")) => jade_crypto::SinglesigScriptVariant::Pkh,
            Ok(Some("wpkh(k)")) => jade_crypto::SinglesigScriptVariant::Wpkh,
            Ok(Some("sh(wpkh(k))")) => jade_crypto::SinglesigScriptVariant::ShWpkh,
            Ok(Some("tr(k)")) => jade_crypto::SinglesigScriptVariant::Tr,
            Ok(Some(_)) | Ok(None) | Err(_) => {
                return bad_parameters("Invalid script variant parameter");
            }
        };
        let path = match params.u32_array("path", MAX_PATH_LEN) {
            Ok(Some(path)) if !path.is_empty() => path,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid path from parameters");
            }
        };
        let Some(network) = bitcoin_network_for_name(network_name) else {
            return V1Outcome::DeferredToCore {
                method: "get_receive_address".to_string(),
            };
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return bad_parameters("Failed to generate valid singlesig script");
        };
        let Some(address) = jade_crypto::pure_rust::bitcoin_singlesig_address_from_seed(
            seed, &path, network, variant,
        ) else {
            return bad_parameters("Failed to generate valid singlesig script");
        };

        V1Outcome::TextResult { result: address }
    }

    fn identity_pubkey_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let identity = match params.str("identity") {
            Ok(Some(identity)) if valid_identity(identity) => identity,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid identity from parameters");
            }
        };
        match params.str("curve") {
            Ok(Some("nist256p1")) => {}
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid curve name from parameters");
            }
        }
        let index = match params.u64("index") {
            Ok(Some(index)) if index <= 0x7fff_ffff => index as u32,
            Ok(None) => 0,
            Ok(Some(_)) | Err(_) => {
                return bad_parameters("Failed to extract valid index from parameters");
            }
        };
        let key_type = match params.str("type") {
            Ok(Some("slip-0013")) => jade_crypto::IdentityKeyType::Slip13,
            Ok(Some("slip-0017")) => jade_crypto::IdentityKeyType::Slip17,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid key type from parameters");
            }
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Feature requires resetting Jade".to_string(),
            };
        };
        let Some(pubkey) =
            jade_crypto::pure_rust::identity_public_key_from_seed(seed, identity, index, key_type)
        else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to get identity pubkey".to_string(),
            };
        };

        V1Outcome::BytesResult {
            result: pubkey.to_vec(),
        }
    }

    fn identity_shared_key_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let identity = match params.str("identity") {
            Ok(Some(identity)) if valid_identity(identity) => identity,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid identity from parameters");
            }
        };
        match params.str("curve") {
            Ok(Some("nist256p1")) => {}
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid curve name from parameters");
            }
        }
        let index = match params.u64("index") {
            Ok(Some(index)) if index <= 0x7fff_ffff => index as u32,
            Ok(None) => 0,
            Ok(Some(_)) | Err(_) => {
                return bad_parameters("Failed to extract valid index from parameters");
            }
        };
        let their_pubkey = match params.bytes("their_pubkey") {
            Ok(Some(bytes)) => match <&[u8; 65]>::try_from(bytes) {
                Ok(bytes) => bytes,
                Err(_) => return bad_parameters("Failed to extract valid pubkey from parameters"),
            },
            Ok(None) | Err(_) => {
                return bad_parameters("Failed to extract valid pubkey from parameters")
            }
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Feature requires resetting Jade".to_string(),
            };
        };
        let Some(shared_key) = jade_crypto::pure_rust::identity_shared_key_from_seed(
            seed,
            identity,
            index,
            their_pubkey,
        ) else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to get identity pubkey".to_string(),
            };
        };

        V1Outcome::BytesResult {
            result: shared_key.to_vec(),
        }
    }

    fn blinding_key_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let script = match params.bytes("script") {
            Ok(Some(script)) if !script.is_empty() => script,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract script from parameters");
            }
        };

        let master_unblinding_key = match self.master_unblinding_key_for_params(params) {
            Ok(key) => key,
            Err(outcome) => return outcome,
        };
        let Some(private_key) =
            jade_crypto::pure_rust::slip77_blinding_private_key(&master_unblinding_key, script)
        else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Cannot get blinding key for script".to_string(),
            };
        };
        let Some(public_key) = jade_crypto::pure_rust::public_key_from_private_key(&private_key)
        else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Cannot get blinding key for script".to_string(),
            };
        };

        V1Outcome::BytesResult {
            result: public_key.to_vec(),
        }
    }

    fn shared_nonce_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let script = match params.bytes("script") {
            Ok(Some(script)) if !script.is_empty() => script,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract script from parameters");
            }
        };
        let their_pubkey = match params.bytes("their_pubkey") {
            Ok(Some(pubkey)) if pubkey.len() == jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN => {
                let mut bytes = [0u8; jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN];
                bytes.copy_from_slice(pubkey);
                bytes
            }
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract their_pubkey from parameters");
            }
        };
        let include_pubkey = if params.contains("include_pubkey").unwrap_or(false) {
            match params.bool("include_pubkey") {
                Ok(Some(include_pubkey)) => include_pubkey,
                Ok(None) | Err(_) => {
                    return bad_parameters("Failed to extract valid pubkey flag from parameters");
                }
            }
        } else {
            false
        };

        let master_unblinding_key = match self.master_unblinding_key_for_params(params) {
            Ok(key) => key,
            Err(outcome) => return outcome,
        };
        let Some(private_key) =
            jade_crypto::pure_rust::slip77_blinding_private_key(&master_unblinding_key, script)
        else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to compute hashed shared nonce value for the parameters"
                    .to_string(),
            };
        };
        let Some(shared_nonce) =
            jade_crypto::pure_rust::ecdh_nonce_hash(&private_key, &their_pubkey)
        else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to compute hashed shared nonce value for the parameters"
                    .to_string(),
            };
        };

        if include_pubkey {
            let Some(blinding_key) =
                jade_crypto::pure_rust::public_key_from_private_key(&private_key)
            else {
                return V1Outcome::Reject {
                    code: ErrorCode::InternalError,
                    message: "Failed to compute hashed shared nonce value for the parameters"
                        .to_string(),
                };
            };
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "shared_nonce".to_string(),
                        value: OwnedV1Value::Bytes(shared_nonce.to_vec()),
                    },
                    OwnedResultMapEntry {
                        key: "blinding_key".to_string(),
                        value: OwnedV1Value::Bytes(blinding_key.to_vec()),
                    },
                ],
            }
        } else {
            V1Outcome::BytesResult {
                result: shared_nonce.to_vec(),
            }
        }
    }

    fn blinding_factor_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let hash_prevouts = match params.bytes("hash_prevouts") {
            Ok(Some(hash_prevouts)) if hash_prevouts.len() == jade_crypto::SHA256_LEN => {
                let mut bytes = [0u8; jade_crypto::SHA256_LEN];
                bytes.copy_from_slice(hash_prevouts);
                bytes
            }
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract hash_prevouts from parameters");
            }
        };
        let output_index = match params.u64("output_index") {
            Ok(Some(index)) if index <= u32::MAX as u64 => index as u32,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract output index from parameters")
            }
        };
        let kind = match params.str("type") {
            Ok(Some("ASSET_AND_VALUE")) => jade_crypto::BlindingFactorKind::AssetAndValue,
            Ok(Some("ASSET")) => jade_crypto::BlindingFactorKind::Asset,
            Ok(Some("VALUE")) => jade_crypto::BlindingFactorKind::Value,
            Ok(Some(_)) => {
                return bad_parameters(
                    "Invalid blinding factor type - must be either 'ASSET', 'VALUE' or 'ASSET_AND_VALUE'",
                );
            }
            Ok(None) | Err(_) => {
                return bad_parameters("Cannot extract blinding factor type from parameters");
            }
        };
        let master_unblinding_key = match self.master_unblinding_key_for_params(params) {
            Ok(key) => key,
            Err(outcome) => return outcome,
        };

        let Some(blinding_factor) = jade_crypto::pure_rust::deterministic_blinding_factor(
            &master_unblinding_key,
            &hash_prevouts,
            output_index,
            kind,
        ) else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Cannot get blinding factor for output".to_string(),
            };
        };

        V1Outcome::BytesResult {
            result: blinding_factor.as_slice().to_vec(),
        }
    }

    fn start_ota(&mut self, request: &Request<'_>, is_delta: bool) -> V1Outcome {
        let Some(params) = request.params() else {
            return bad_parameters("Expecting parameters map");
        };
        if self.ota.is_some() {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "OTA already in progress".to_string(),
            };
        }

        let firmware_size = match params.u64("fwsize") {
            Ok(Some(size)) => size,
            Ok(None) | Err(_) => return bad_parameters("Bad filesize parameters"),
        };
        let compressed_size = match params.u64("cmpsize") {
            Ok(Some(size)) => size,
            Ok(None) | Err(_) => return bad_parameters("Bad filesize parameters"),
        };
        let full_hash = hash32_param(params, "fwhash");
        let compressed_hash = hash32_param(params, "cmphash");
        let extended_replies = optional_bool(params, "extended_replies");

        let request = if is_delta {
            let patch_size = match params.u64("patchsize") {
                Ok(Some(size)) => size,
                Ok(None) | Err(_) => return bad_parameters("Bad delta filesize parameters"),
            };
            match OtaRequest::delta(
                firmware_size,
                patch_size,
                compressed_size,
                full_hash,
                compressed_hash,
                extended_replies,
            ) {
                Ok(request) => request,
                Err(_) if patch_size <= compressed_size => {
                    return bad_parameters("Bad delta filesize parameters")
                }
                Err(_) => return bad_parameters("Cannot extract valid fw hash value"),
            }
        } else {
            match OtaRequest::full(
                firmware_size,
                compressed_size,
                full_hash,
                compressed_hash,
                extended_replies,
            ) {
                Ok(request) => request,
                Err(_) if firmware_size <= compressed_size => {
                    return bad_parameters("Bad filesize parameters")
                }
                Err(_) => return bad_parameters("Cannot extract valid fw hash value"),
            }
        };

        self.ota = Some(HostOtaSession {
            request,
            received_compressed: 0,
            compressed_hasher: Sha256::new(),
        });
        self.state.operation = OperationState::Ota {
            session: jade_protocol_v2::SessionId(0),
        };

        V1Outcome::BoolResult { result: true }
    }

    fn handle_ota_data(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(session) = self.ota.as_mut() else {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Unexpected method".to_string(),
            };
        };
        let Ok(data) = direct_bytes_params(request) else {
            return bad_parameters("Invalid OTA data");
        };
        if data.is_empty() {
            return bad_parameters("Invalid OTA data");
        }

        let Some(next_received) = session.received_compressed.checked_add(data.len() as u64) else {
            return bad_parameters("Invalid OTA data");
        };
        if next_received > session.request.compressed_size {
            return bad_parameters("Invalid OTA data");
        }

        session.compressed_hasher.update(data);
        session.received_compressed = next_received;

        if session.request.extended_replies {
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "confirmed".to_string(),
                        value: OwnedV1Value::Bool(false),
                    },
                    OwnedResultMapEntry {
                        key: "progress".to_string(),
                        value: OwnedV1Value::U64(
                            session
                                .request
                                .upload_progress_percent(session.received_compressed),
                        ),
                    },
                ],
            }
        } else {
            V1Outcome::BoolResult { result: true }
        }
    }

    fn handle_ota_complete(&mut self) -> V1Outcome {
        let Some(session) = self.ota.take() else {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Unexpected method".to_string(),
            };
        };
        self.state.operation = OperationState::Idle;

        if session.received_compressed != session.request.compressed_size {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Error completing OTA".to_string(),
            };
        }

        if session.request.hash_type == OtaHashType::CompressedUpload {
            let calculated: [u8; jade_core::OTA_HASH_LEN] =
                session.compressed_hasher.finalize().into();
            if calculated != session.request.expected_hash {
                return V1Outcome::Reject {
                    code: ErrorCode::InternalError,
                    message: "Error completing OTA".to_string(),
                };
            }
        }

        V1Outcome::BoolResult { result: true }
    }

    fn master_unblinding_key_for_params(
        &self,
        params: jade_protocol_v1::Params<'_>,
    ) -> Result<[u8; 64], V1Outcome> {
        if !params.contains("multisig_name").unwrap_or(false) {
            return Ok(self.platform.master_unblinding_key);
        }

        let multisig_name = match params.str("multisig_name") {
            Ok(Some(name)) if key_name_valid(name) => name,
            Ok(_) | Err(_) => return Err(bad_parameters("Invalid multisig name parameter")),
        };
        let mut record = Vec::new();
        if self
            .storage
            .get_record(
                StorageRecord::MultisigRegistration {
                    name: multisig_name,
                },
                &mut record,
            )
            .is_err()
        {
            return Err(bad_parameters("Cannot find named multisig wallet"));
        }
        let details = parse_multisig_details(&record, &HostRecordAuthenticator)
            .map_err(|_| bad_parameters("Cannot de-serialise multisig wallet data"))?;
        let Some(master_blinding_key) = details.summary.master_blinding_key else {
            return Err(bad_parameters("No blinding key for multisig record"));
        };

        let mut master_unblinding_key = [0u8; 64];
        master_unblinding_key[32..64].copy_from_slice(&master_blinding_key);
        Ok(master_unblinding_key)
    }

    fn update_pinserver(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };

        let reset_details = optional_bool(params, "reset_details");
        let url_a_present = params.contains("urlA").unwrap_or(false);
        let url_a = optional_str(params, "urlA").unwrap_or("");
        let url_b = optional_str(params, "urlB").unwrap_or("");
        let pubkey = optional_bytes(params, "pubkey");

        if url_a_present && !valid_pinserver_url(url_a) {
            return bad_parameters("Empty or invalid first URL");
        }
        if !url_b.is_empty() && !valid_pinserver_url(url_b) {
            return bad_parameters("Invalid second URL");
        }
        if !url_b.is_empty() && url_a.is_empty() {
            return bad_parameters("Cannot set only second URL");
        }
        if (url_a_present || pubkey.is_some()) && reset_details {
            return bad_parameters("Cannot set and reset details");
        }
        if let Some(pubkey) = pubkey {
            if url_a.is_empty() {
                return bad_parameters("Cannot set pubkey without URL");
            }
            if !valid_compressed_secp256k1_pubkey(pubkey) {
                return bad_parameters("Invalid Oracle pubkey");
            }
        }

        let reset_certificate = optional_bool(params, "reset_certificate");
        let set_certificate = params.contains("certificate").unwrap_or(false);
        if set_certificate && reset_certificate {
            return bad_parameters("Cannot set and reset certificate");
        }
        let certificate = optional_str(params, "certificate").unwrap_or("");

        let storage_result = if !url_a.is_empty() {
            self.storage.set_pinserver_details(
                url_a,
                if url_b.is_empty() { None } else { Some(url_b) },
                pubkey,
            )
        } else if reset_details {
            self.storage.erase_pinserver_details()
        } else {
            Ok(())
        };
        if storage_result.is_err() {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to persist Oracle details".to_string(),
            };
        }

        let storage_result = if set_certificate {
            self.storage.set_pinserver_certificate(certificate)
        } else if reset_certificate {
            self.storage.erase_pinserver_certificate()
        } else {
            Ok(())
        };
        if storage_result.is_err() {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to persist Oracle certificate".to_string(),
            };
        }

        V1Outcome::BoolResult { result: true }
    }

    fn debug_set_mnemonic(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };

        let mut temporary_wallet = optional_bool(params, "temporary_wallet");
        let seed = if params.contains("seed").unwrap_or(false) {
            let Some(seed) = optional_bytes(params, "seed") else {
                return bad_parameters("Failed to extract valid seed from parameters");
            };
            if !matches!(seed.len(), 32 | 64) {
                return bad_parameters("Failed to extract valid seed from parameters");
            }
            temporary_wallet = true;
            seed.to_vec()
        } else {
            let mnemonic = match params.str("mnemonic") {
                Ok(Some(mnemonic)) if !mnemonic.is_empty() => mnemonic.to_string(),
                _ => {
                    let Some(mnemonic_bytes) = optional_bytes(params, "mnemonic") else {
                        return bad_parameters(
                            "Failed to extract mnemonic prefixes from parameters",
                        );
                    };
                    match core::str::from_utf8(mnemonic_bytes) {
                        Ok(mnemonic) if !mnemonic.is_empty() => mnemonic.to_string(),
                        _ => {
                            return bad_parameters(
                                "Failed to extract mnemonic prefixes from parameters",
                            );
                        }
                    }
                }
            };
            let passphrase = if params.contains("passphrase").unwrap_or(false) {
                let Some(passphrase) = optional_str(params, "passphrase") else {
                    return bad_parameters("Failed to extract valid passphrase from parameters");
                };
                if passphrase.is_empty() || passphrase.len() > 100 {
                    return bad_parameters("Failed to extract valid passphrase from parameters");
                }
                passphrase
            } else {
                ""
            };
            let mnemonic = match bip39::Mnemonic::parse_in(bip39::Language::English, mnemonic) {
                Ok(mnemonic) => mnemonic,
                Err(_) => {
                    return bad_parameters(
                        "Failed to expand mnemonic prefixes into full mnemonic words",
                    );
                }
            };
            mnemonic.to_seed(passphrase).to_vec()
        };

        let Some(master_unblinding_key) =
            jade_crypto::slip77_master_unblinding_key_from_seed(&seed)
        else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to derive keychain from mnemonic".to_string(),
            };
        };

        self.platform.set_debug_wallet_seed(seed);
        self.platform
            .set_master_unblinding_key(master_unblinding_key);
        self.platform.set_confirm_export_blinding_key(true);
        self.state.wallet = if temporary_wallet {
            WalletLifecycle::Temporary
        } else {
            WalletLifecycle::Ready
        };

        V1Outcome::BoolResult { result: true }
    }
}

fn missing_descriptor_result() -> V1Outcome {
    V1Outcome::Reject {
        code: ErrorCode::BadParameters,
        message: "Named descriptor wallet does not exist for this signer".to_string(),
    }
}

fn missing_multisig_result() -> V1Outcome {
    V1Outcome::Reject {
        code: ErrorCode::BadParameters,
        message: "Named multisig wallet does not exist for this signer".to_string(),
    }
}

fn bad_parameters(message: &'static str) -> V1Outcome {
    V1Outcome::Reject {
        code: ErrorCode::BadParameters,
        message: message.to_string(),
    }
}

fn hash32_param(
    params: jade_protocol_v1::Params<'_>,
    field: &str,
) -> Option<[u8; jade_core::OTA_HASH_LEN]> {
    let bytes = optional_bytes(params, field)?;
    bytes.try_into().ok()
}

fn direct_bytes_params<'a>(request: &Request<'a>) -> Result<&'a [u8], ()> {
    let Some(params) = request.params() else {
        return Err(());
    };
    let raw = params.raw();
    let mut decoder = Decoder::new(raw);
    let bytes = decoder.bytes().map_err(|_| ())?;
    if decoder.position() != raw.len() {
        return Err(());
    }
    Ok(bytes)
}

fn optional_bool(params: jade_protocol_v1::Params<'_>, field: &str) -> bool {
    params.bool(field).ok().flatten().unwrap_or(false)
}

fn optional_str<'a>(params: jade_protocol_v1::Params<'a>, field: &str) -> Option<&'a str> {
    params.str(field).ok().flatten()
}

fn optional_bytes<'a>(params: jade_protocol_v1::Params<'a>, field: &str) -> Option<&'a [u8]> {
    params.bytes(field).ok().flatten()
}

fn valid_identity(identity: &str) -> bool {
    identity.len() < 192
        && ((identity.len() > "ssh://".len() && identity.starts_with("ssh://"))
            || (identity.len() > "gpg://".len() && identity.starts_with("gpg://")))
}

fn valid_network_name(network: &str) -> bool {
    matches!(
        network,
        "mainnet" | "liquid" | "testnet" | "testnet-liquid" | "localtest" | "localtest-liquid"
    )
}

fn is_liquid_network(network: &str) -> bool {
    matches!(network, "liquid" | "testnet-liquid" | "localtest-liquid")
}

fn bitcoin_network_for_name(network: &str) -> Option<jade_crypto::BitcoinNetwork> {
    match network {
        "mainnet" => Some(jade_crypto::BitcoinNetwork::Main),
        "testnet" => Some(jade_crypto::BitcoinNetwork::Test),
        "localtest" => Some(jade_crypto::BitcoinNetwork::Regtest),
        _ => None,
    }
}

fn xpub_prefix_for_network(network: &str) -> Option<jade_crypto::XpubPrefix> {
    match network {
        "mainnet" | "liquid" => Some(jade_crypto::XpubPrefix::Main),
        "testnet" | "testnet-liquid" | "localtest" | "localtest-liquid" => {
            Some(jade_crypto::XpubPrefix::Test)
        }
        _ => None,
    }
}

fn valid_pinserver_url(url: &str) -> bool {
    (url.len() > "http://".len() && url.starts_with("http://"))
        || (url.len() > "https://".len() && url.starts_with("https://"))
}

fn valid_compressed_secp256k1_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN
        && matches!(pubkey.first(), Some(0x02 | 0x03))
        && jade_crypto::pure_rust::k256::PublicKey::from_sec1_bytes(pubkey).is_ok()
}

fn multisig_signer_entries(signer: &MultisigSignerDetails) -> Vec<OwnedResultMapEntry> {
    vec![
        OwnedResultMapEntry {
            key: "fingerprint".to_string(),
            value: OwnedV1Value::Bytes(signer.fingerprint.to_vec()),
        },
        OwnedResultMapEntry {
            key: "derivation".to_string(),
            value: owned_u32_array(&signer.derivation),
        },
        OwnedResultMapEntry {
            key: "xpub".to_string(),
            value: OwnedV1Value::Text(base58ck::encode_check(&signer.xpub)),
        },
        OwnedResultMapEntry {
            key: "path".to_string(),
            value: owned_u32_array(&signer.path),
        },
    ]
}

fn owned_u32_array(values: &[u32]) -> OwnedV1Value {
    OwnedV1Value::Array(
        values
            .iter()
            .map(|value| OwnedV1Value::U64((*value).into()))
            .collect(),
    )
}

fn multisig_export_file(multisig_name: &str, details: &MultisigDetails) -> Option<String> {
    let signers = details.signers.as_ref()?;
    if signers.iter().any(|signer| !signer.path.is_empty()) {
        return None;
    }

    let mut output = String::new();
    output.push_str("# Exported by Blockstream Jade\n");
    push_key_value_line(&mut output, "Name", multisig_name);
    push_key_value_line(
        &mut output,
        "Policy",
        &format!(
            "{} of {}",
            details.summary.threshold, details.summary.num_signers
        ),
    );
    push_key_value_line(
        &mut output,
        "Format",
        multisig_export_format(details.summary.variant),
    );
    if !details.summary.sorted {
        push_key_value_line(&mut output, "Sorted", "False");
    }
    if let Some(master_blinding_key) = details.summary.master_blinding_key {
        push_key_value_line(&mut output, "BlindingKey", &hex_lower(&master_blinding_key));
    }
    for signer in signers {
        push_key_value_line(
            &mut output,
            "Derivation",
            &bip32_path_to_string(&signer.derivation),
        );
        push_key_value_line(
            &mut output,
            &hex_lower(&signer.fingerprint),
            &base58ck::encode_check(&signer.xpub),
        );
    }

    Some(output)
}

fn multisig_export_format(variant: MultisigVariant) -> &'static str {
    match variant {
        MultisigVariant::P2wsh => "P2WSH",
        MultisigVariant::P2sh => "P2SH",
        MultisigVariant::P2wshP2sh => "P2SH-P2WSH",
    }
}

fn push_key_value_line(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push_str(": ");
    output.push_str(value);
    output.push('\n');
}

fn bip32_path_to_string(path: &[u32]) -> String {
    let mut output = String::from("m");
    for value in path {
        output.push('/');
        let hardened = value & 0x8000_0000 != 0;
        output.push_str(&(value & !0x8000_0000).to_string());
        if hardened {
            output.push('\'');
        }
    }
    output
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Clone, Copy)]
struct HostRecordAuthenticator;

impl RecordAuthenticator for HostRecordAuthenticator {
    fn verify_record(&self, _payload: &[u8], tag: &[u8; HMAC_SHA256_LEN]) -> bool {
        tag == &[0xa5; HMAC_SHA256_LEN]
    }
}

struct HostOtaSession {
    request: OtaRequest,
    received_compressed: u64,
    compressed_hasher: Sha256,
}

impl fmt::Debug for HostOtaSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostOtaSession")
            .field("request", &self.request)
            .field("received_compressed", &self.received_compressed)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPlatform {
    version: Cow<'static, str>,
    entropy_bytes_received: usize,
    epoch: Option<u64>,
    wallet_seed: Option<Vec<u8>>,
    master_unblinding_key: [u8; 64],
    confirm_export_blinding_key: bool,
}

impl Default for HostPlatform {
    fn default() -> Self {
        Self {
            version: Cow::Borrowed("rust-emulator"),
            entropy_bytes_received: 0,
            epoch: None,
            wallet_seed: None,
            master_unblinding_key: [0; 64],
            confirm_export_blinding_key: false,
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

    pub fn wallet_seed(&self) -> Option<&[u8]> {
        self.wallet_seed.as_deref()
    }

    pub fn set_debug_wallet_seed(&mut self, seed: Vec<u8>) {
        self.wallet_seed = Some(seed);
    }

    pub fn clear_debug_wallet(&mut self) {
        self.wallet_seed = None;
        self.master_unblinding_key = [0; 64];
        self.confirm_export_blinding_key = false;
    }

    pub fn set_master_unblinding_key(&mut self, key: [u8; 64]) {
        self.master_unblinding_key = key;
    }

    pub fn set_confirm_export_blinding_key(&mut self, confirm: bool) {
        self.confirm_export_blinding_key = confirm;
    }

    fn master_blinding_key(&self) -> &[u8] {
        &self.master_unblinding_key[32..64]
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
    UintResult { result: u64 },
    TextResult { result: String },
    BytesResult { result: Vec<u8> },
    EmptyMapResult,
    OwnedMapResult { entries: Vec<OwnedResultMapEntry> },
    NoReply,
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

    fn decode_v1_error(response: &[u8]) -> (i32, String) {
        let mut decoder = Decoder::new(response);
        let mut code = None;
        let mut message = None;

        assert_eq!(decoder.map().unwrap(), Some(2));
        for _ in 0..2 {
            match decoder.str().unwrap() {
                "id" => {
                    decoder.skip().unwrap();
                }
                "error" => {
                    assert_eq!(decoder.map().unwrap(), Some(2));
                    for _ in 0..2 {
                        match decoder.str().unwrap() {
                            "code" => code = Some(decoder.i32().unwrap()),
                            "message" => message = Some(decoder.str().unwrap().to_string()),
                            _ => decoder.skip().unwrap(),
                        }
                    }
                }
                _ => decoder.skip().unwrap(),
            }
        }

        (code.unwrap(), message.unwrap())
    }

    fn decode_hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2);
        let mut output = [0u8; N];
        let bytes = input.as_bytes();
        for (index, output_byte) in output.iter_mut().enumerate() {
            *output_byte = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        }
        output
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex"),
        }
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
    fn debug_selfcheck_returns_elapsed_ms_uint() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("selfcheck"),
            method: Cow::Borrowed("debug_selfcheck"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::UintResult { result: 0 }
        );

        let mut raw = Vec::new();
        minicbor::Encoder::new(&mut raw)
            .map(2)
            .unwrap()
            .str("id")
            .unwrap()
            .str("s")
            .unwrap()
            .str("method")
            .unwrap()
            .str("debug_selfcheck")
            .unwrap();
        assert_eq!(
            emulator.handle_v1_cbor(&raw),
            [0xa2, 0x62, b'i', b'd', 0x61, b's', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0x00,]
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
    fn top_level_cancel_is_ignored_without_response() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("c"),
            method: Cow::Borrowed("cancel"),
            params: None,
        };

        assert_eq!(emulator.handle_v1_request(&request), V1Outcome::NoReply);

        let mut raw = Vec::new();
        minicbor::Encoder::new(&mut raw)
            .map(2)
            .unwrap()
            .str("id")
            .unwrap()
            .str("c")
            .unwrap()
            .str("method")
            .unwrap()
            .str("cancel")
            .unwrap();
        assert!(emulator.handle_v1_cbor(&raw).is_empty());
    }

    #[test]
    fn continuation_methods_reject_without_active_flow() {
        let mut emulator = Emulator::new();

        for method in [
            "ota_data",
            "ota_complete",
            "tx_input",
            "get_extended_data",
            "get_signature",
            "pin",
        ] {
            let request = Request {
                id: Cow::Borrowed("cont"),
                method: Cow::Borrowed(method),
                params: None,
            };

            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::Reject {
                    code: ErrorCode::ProtocolError,
                    message: "Unexpected method".to_string(),
                },
                "{method}"
            );
        }
    }

    #[test]
    fn raw_v1_continuation_returns_protocol_error() {
        let mut emulator = Emulator::new();
        let mut raw = Vec::new();
        minicbor::Encoder::new(&mut raw)
            .map(2)
            .unwrap()
            .str("id")
            .unwrap()
            .str("cont")
            .unwrap()
            .str("method")
            .unwrap()
            .str("get_extended_data")
            .unwrap();

        let response = emulator.handle_v1_cbor(&raw);

        assert_eq!(
            decode_v1_error(&response),
            (
                ErrorCode::ProtocolError as i32,
                "Unexpected method".to_string()
            )
        );
    }

    #[test]
    fn raw_v1_unknown_method_returns_unknown_method_error() {
        let mut emulator = Emulator::new();
        let mut raw = Vec::new();
        minicbor::Encoder::new(&mut raw)
            .map(2)
            .unwrap()
            .str("id")
            .unwrap()
            .str("unknown")
            .unwrap()
            .str("method")
            .unwrap()
            .str("not_a_method")
            .unwrap();

        let response = emulator.handle_v1_cbor(&raw);

        assert_eq!(
            decode_v1_error(&response),
            (
                ErrorCode::UnknownMethod as i32,
                "Unknown method".to_string()
            )
        );
    }

    #[test]
    fn ota_full_upload_tracks_metadata_progress_and_compressed_hash() {
        let mut emulator = Emulator::new();
        let upload = b"abc";
        let compressed_hash = Sha256::digest(upload);
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("fwsize")
            .unwrap()
            .u64(10)
            .unwrap()
            .str("cmpsize")
            .unwrap()
            .u64(upload.len() as u64)
            .unwrap()
            .str("cmphash")
            .unwrap()
            .bytes(&compressed_hash)
            .unwrap()
            .str("extended_replies")
            .unwrap()
            .bool(true)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("ota"),
            method: Cow::Borrowed("ota"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );
        assert!(matches!(
            emulator.state.operation,
            OperationState::Ota { .. }
        ));

        let mut chunk = Vec::new();
        minicbor::Encoder::new(&mut chunk).bytes(b"a").unwrap();
        let data_request = Request {
            id: Cow::Borrowed("ota-data"),
            method: Cow::Borrowed("ota_data"),
            params: Some(&chunk),
        };
        assert_eq!(
            emulator.handle_v1_request(&data_request),
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "confirmed".to_string(),
                        value: OwnedV1Value::Bool(false),
                    },
                    OwnedResultMapEntry {
                        key: "progress".to_string(),
                        value: OwnedV1Value::U64(33),
                    },
                ],
            }
        );

        let mut chunk = Vec::new();
        minicbor::Encoder::new(&mut chunk).bytes(b"bc").unwrap();
        let data_request = Request {
            id: Cow::Borrowed("ota-data"),
            method: Cow::Borrowed("ota_data"),
            params: Some(&chunk),
        };
        assert_eq!(
            emulator.handle_v1_request(&data_request),
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "confirmed".to_string(),
                        value: OwnedV1Value::Bool(false),
                    },
                    OwnedResultMapEntry {
                        key: "progress".to_string(),
                        value: OwnedV1Value::U64(100),
                    },
                ],
            }
        );

        let complete_request = Request {
            id: Cow::Borrowed("ota-complete"),
            method: Cow::Borrowed("ota_complete"),
            params: None,
        };
        assert_eq!(
            emulator.handle_v1_request(&complete_request),
            V1Outcome::BoolResult { result: true }
        );
        assert_eq!(emulator.state.operation, OperationState::Idle);
    }

    #[test]
    fn ota_delta_rejects_bad_patch_size() {
        let mut emulator = Emulator::new();
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("fwsize")
            .unwrap()
            .u64(10)
            .unwrap()
            .str("patchsize")
            .unwrap()
            .u64(3)
            .unwrap()
            .str("cmpsize")
            .unwrap()
            .u64(3)
            .unwrap()
            .str("cmphash")
            .unwrap()
            .bytes(&[0x22; jade_core::OTA_HASH_LEN])
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("ota"),
            method: Cow::Borrowed("ota_delta"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Bad delta filesize parameters".to_string(),
            }
        );
    }

    #[test]
    fn ota_complete_rejects_compressed_hash_mismatch_and_clears_session() {
        let mut emulator = Emulator::new();
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("fwsize")
            .unwrap()
            .u64(10)
            .unwrap()
            .str("cmpsize")
            .unwrap()
            .u64(3)
            .unwrap()
            .str("cmphash")
            .unwrap()
            .bytes(&[0x22; jade_core::OTA_HASH_LEN])
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("ota"),
            method: Cow::Borrowed("ota"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );

        let mut chunk = Vec::new();
        minicbor::Encoder::new(&mut chunk).bytes(b"abc").unwrap();
        let data_request = Request {
            id: Cow::Borrowed("ota-data"),
            method: Cow::Borrowed("ota_data"),
            params: Some(&chunk),
        };
        assert_eq!(
            emulator.handle_v1_request(&data_request),
            V1Outcome::BoolResult { result: true }
        );

        let complete_request = Request {
            id: Cow::Borrowed("ota-complete"),
            method: Cow::Borrowed("ota_complete"),
            params: None,
        };
        assert_eq!(
            emulator.handle_v1_request(&complete_request),
            V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Error completing OTA".to_string(),
            }
        );
        assert_eq!(emulator.state.operation, OperationState::Idle);

        assert_eq!(
            emulator.handle_v1_request(&complete_request),
            V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Unexpected method".to_string(),
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
    fn get_xpub_derives_root_and_child_public_keys() {
        let mut emulator = Emulator::new();
        let seed = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        emulator.platform_mut().set_debug_wallet_seed(seed.clone());

        let mut root_params = Vec::new();
        minicbor::Encoder::new(&mut root_params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("path")
            .unwrap()
            .array(0)
            .unwrap();
        let root_request = Request {
            id: Cow::Borrowed("x"),
            method: Cow::Borrowed("get_xpub"),
            params: Some(&root_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&root_request),
            V1Outcome::TextResult {
                result: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8".to_string()
            }
        );

        let mut child_params = Vec::new();
        minicbor::Encoder::new(&mut child_params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("liquid")
            .unwrap()
            .str("path")
            .unwrap()
            .array(1)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap();
        let child_request = Request {
            id: Cow::Borrowed("x"),
            method: Cow::Borrowed("get_xpub"),
            params: Some(&child_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&child_request),
            V1Outcome::TextResult {
                result: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw".to_string()
            }
        );
    }

    #[test]
    fn get_xpub_uses_test_prefix_for_test_and_local_networks() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(vec![0x11; jade_crypto::SHA512_LEN]);

        for network in ["testnet", "testnet-liquid", "localtest", "localtest-liquid"] {
            let mut params = Vec::new();
            minicbor::Encoder::new(&mut params)
                .map(2)
                .unwrap()
                .str("network")
                .unwrap()
                .str(network)
                .unwrap()
                .str("path")
                .unwrap()
                .array(1)
                .unwrap()
                .u32(0x8000_0054)
                .unwrap();
            let request = Request {
                id: Cow::Borrowed("x"),
                method: Cow::Borrowed("get_xpub"),
                params: Some(&params),
            };

            let V1Outcome::TextResult { result } = emulator.handle_v1_request(&request) else {
                panic!("expected xpub string for {network}");
            };
            assert!(result.starts_with("tpub"), "{network} returned {result}");
        }
    }

    #[test]
    fn raw_v1_get_xpub_returns_string_result() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(vec![0x22; jade_crypto::SHA512_LEN]);

        let mut request = Vec::new();
        minicbor::Encoder::new(&mut request)
            .map(3)
            .unwrap()
            .str("id")
            .unwrap()
            .str("x")
            .unwrap()
            .str("method")
            .unwrap()
            .str("get_xpub")
            .unwrap()
            .str("params")
            .unwrap()
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("path")
            .unwrap()
            .array(0)
            .unwrap();

        let response = emulator.handle_v1_cbor(&request);
        let mut decoder = Decoder::new(&response);
        let mut result = None;

        assert_eq!(decoder.map().unwrap(), Some(2));
        for _ in 0..2 {
            match decoder.str().unwrap() {
                "id" => assert_eq!(decoder.str().unwrap(), "x"),
                "result" => result = Some(decoder.str().unwrap()),
                _ => decoder.skip().unwrap(),
            }
        }

        assert!(result.unwrap().starts_with("xpub"));
    }

    #[test]
    fn get_xpub_rejects_invalid_inputs() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("x"),
            method: Cow::Borrowed("get_xpub"),
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
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("unknown")
            .unwrap()
            .str("path")
            .unwrap()
            .array(0)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("x"),
            method: Cow::Borrowed("get_xpub"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid network from parameters".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("x"),
            method: Cow::Borrowed("get_xpub"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid path from parameters".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("path")
            .unwrap()
            .array(0)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("x"),
            method: Cow::Borrowed("get_xpub"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Cannot get xpub for path".to_string(),
            }
        );
    }

    #[test]
    fn get_receive_address_derives_bitcoin_singlesig_addresses() {
        let mut emulator = Emulator::new();
        emulator.platform_mut().set_debug_wallet_seed(vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);

        for (variant, network, expected) in [
            ("pkh(k)", "mainnet", "19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh"),
            (
                "wpkh(k)",
                "mainnet",
                "bc1qtsdavj8dyw49l4gt554jg47pr60gpf48ww2ens",
            ),
            (
                "sh(wpkh(k))",
                "mainnet",
                "3AbBmNbPDSzeZKHywDrH3h5v2rL8xGfT7e",
            ),
            (
                "wpkh(k)",
                "localtest",
                "bcrt1qtsdavj8dyw49l4gt554jg47pr60gpf48xpg8l2",
            ),
        ] {
            let mut params = Vec::new();
            minicbor::Encoder::new(&mut params)
                .map(3)
                .unwrap()
                .str("network")
                .unwrap()
                .str(network)
                .unwrap()
                .str("variant")
                .unwrap()
                .str(variant)
                .unwrap()
                .str("path")
                .unwrap()
                .array(1)
                .unwrap()
                .u32(0x8000_0000)
                .unwrap();
            let request = Request {
                id: Cow::Borrowed("a"),
                method: Cow::Borrowed("get_receive_address"),
                params: Some(&params),
            };

            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::TextResult {
                    result: expected.to_string()
                }
            );
        }
    }

    #[test]
    fn get_receive_address_derives_taproot_bip86_address() {
        let mut emulator = Emulator::new();
        emulator.platform_mut().set_debug_wallet_seed(vec![
            0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55,
            0x56, 0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6,
            0xf6, 0xda, 0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86,
            0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
            0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
        ]);
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("variant")
            .unwrap()
            .str("tr(k)")
            .unwrap()
            .str("path")
            .unwrap()
            .array(5)
            .unwrap()
            .u32(0x8000_0056)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap()
            .u32(0)
            .unwrap()
            .u32(0)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
                    .to_string()
            }
        );
    }

    #[test]
    fn raw_v1_get_receive_address_returns_string_result() {
        let mut emulator = Emulator::new();
        emulator.platform_mut().set_debug_wallet_seed(vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);

        let mut request = Vec::new();
        minicbor::Encoder::new(&mut request)
            .map(3)
            .unwrap()
            .str("id")
            .unwrap()
            .str("a")
            .unwrap()
            .str("method")
            .unwrap()
            .str("get_receive_address")
            .unwrap()
            .str("params")
            .unwrap()
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("variant")
            .unwrap()
            .str("wpkh(k)")
            .unwrap()
            .str("path")
            .unwrap()
            .array(1)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap();

        let response = emulator.handle_v1_cbor(&request);
        let mut decoder = Decoder::new(&response);
        let mut result = None;

        assert_eq!(decoder.map().unwrap(), Some(2));
        for _ in 0..2 {
            match decoder.str().unwrap() {
                "id" => assert_eq!(decoder.str().unwrap(), "a"),
                "result" => result = Some(decoder.str().unwrap()),
                _ => decoder.skip().unwrap(),
            }
        }

        assert_eq!(result, Some("bc1qtsdavj8dyw49l4gt554jg47pr60gpf48ww2ens"));
    }

    #[test]
    fn get_identity_pubkey_derives_slip13_and_slip17_keys() {
        let mut emulator = Emulator::new();
        let mnemonic = bip39::Mnemonic::parse(
            "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
        )
        .unwrap();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(mnemonic.to_seed("").to_vec());

        for (key_type, expected) in [
            (
                "slip-0013",
                "0473f21a3da3d0e96fc2189f81dd826658c3d76b2d55bd1da349bc6c3573b13ae4d564710ca0bf84b81c6850e916cb94ae9c397b550589da476ace7aee39ebcb37",
            ),
            (
                "slip-0017",
                "04248befa95e9dbcf0a2ef7cf6957651ee25a168355590c4c84a6a8601758ca230d397bcba67b4676c3f2711b59083fff9157c16899da6d4ed76f8eaf57a100fa8",
            ),
        ] {
            let mut params = Vec::new();
            minicbor::Encoder::new(&mut params)
                .map(4)
                .unwrap()
                .str("identity")
                .unwrap()
                .str("ssh://satoshi@bitcoin.org")
                .unwrap()
                .str("curve")
                .unwrap()
                .str("nist256p1")
                .unwrap()
                .str("type")
                .unwrap()
                .str(key_type)
                .unwrap()
                .str("index")
                .unwrap()
                .u64(47)
                .unwrap();
            let request = Request {
                id: Cow::Borrowed("id"),
                method: Cow::Borrowed("get_identity_pubkey"),
                params: Some(&params),
            };

            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::BytesResult {
                    result: decode_hex::<65>(expected).to_vec(),
                },
                "{key_type}"
            );
        }
    }

    #[test]
    fn get_identity_shared_key_derives_slip17_ecdh_secret() {
        let mut emulator = Emulator::new();
        let mnemonic = bip39::Mnemonic::parse(
            "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
        )
        .unwrap();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(mnemonic.to_seed("").to_vec());

        let their_pubkey = decode_hex::<65>(
            "04248befa95e9dbcf0a2ef7cf6957651ee25a168355590c4c84a6a8601758ca230d397bcba67b4676c3f2711b59083fff9157c16899da6d4ed76f8eaf57a100fa8",
        );
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("identity")
            .unwrap()
            .str("ssh://satoshi@bitcoin.org")
            .unwrap()
            .str("curve")
            .unwrap()
            .str("nist256p1")
            .unwrap()
            .str("their_pubkey")
            .unwrap()
            .bytes(&their_pubkey)
            .unwrap()
            .str("index")
            .unwrap()
            .u64(47)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("get_identity_shared_key"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult {
                result: decode_hex::<32>(
                    "de7c569bea8fd78f724671e2b645e3debb58af1c869c5c0a3a901ff2b9413ffa"
                )
                .to_vec(),
            }
        );
    }

    #[test]
    fn get_identity_pubkey_rejects_invalid_inputs() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(vec![0x11; jade_crypto::SHA512_LEN]);

        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("get_identity_pubkey"),
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
            .map(3)
            .unwrap()
            .str("identity")
            .unwrap()
            .str("ftp://some.xyz.com")
            .unwrap()
            .str("curve")
            .unwrap()
            .str("nist256p1")
            .unwrap()
            .str("type")
            .unwrap()
            .str("slip-0013")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("get_identity_pubkey"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid identity from parameters".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("identity")
            .unwrap()
            .str("ssh://satoshi@bitcoin.org")
            .unwrap()
            .str("curve")
            .unwrap()
            .str("ed25519")
            .unwrap()
            .str("type")
            .unwrap()
            .str("slip-0013")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("get_identity_pubkey"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid curve name from parameters".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("identity")
            .unwrap()
            .str("ssh://satoshi@bitcoin.org")
            .unwrap()
            .str("curve")
            .unwrap()
            .str("nist256p1")
            .unwrap()
            .str("type")
            .unwrap()
            .str("slip-0013")
            .unwrap()
            .str("index")
            .unwrap()
            .u64(0x8000_0000)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("get_identity_pubkey"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid index from parameters".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("identity")
            .unwrap()
            .str("ssh://satoshi@bitcoin.org")
            .unwrap()
            .str("curve")
            .unwrap()
            .str("nist256p1")
            .unwrap()
            .str("type")
            .unwrap()
            .str("not-slip")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("get_identity_pubkey"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid key type from parameters".to_string(),
            }
        );
    }

    #[test]
    fn get_receive_address_rejects_invalid_singlesig_inputs_and_defers_other_branches() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(vec![0x11; jade_crypto::SHA512_LEN]);

        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
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
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("variant")
            .unwrap()
            .str("wpkh(k)")
            .unwrap()
            .str("confidential")
            .unwrap()
            .bool(true)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Confidential addresses only apply to liquid networks".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("variant")
            .unwrap()
            .str("wpkh(k)")
            .unwrap()
            .str("path")
            .unwrap()
            .array(0)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid path from parameters".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::DeferredToCore {
                method: "get_receive_address".to_string()
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("network")
            .unwrap()
            .str("liquid")
            .unwrap()
            .str("variant")
            .unwrap()
            .str("tr(k)")
            .unwrap()
            .str("confidential")
            .unwrap()
            .bool(false)
            .unwrap()
            .str("path")
            .unwrap()
            .array(1)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::DeferredToCore {
                method: "get_receive_address".to_string()
            }
        );
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

    fn current_multisig_payload(path: &[u32]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[3, MultisigVariant::P2wsh as u8, 0, 1]);
        payload.push(0);
        payload.push(1);
        payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        payload.push(2);
        payload.extend_from_slice(&(48u32 | 0x8000_0000).to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&[1; BIP32_SERIALIZED_LEN]);
        payload.push(path.len() as u8);
        for value in path {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        payload
    }

    #[test]
    fn registered_multisig_detail_requires_valid_params() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("m"),
            method: Cow::Borrowed("get_registered_multisig"),
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
            .str("multisig_name")
            .unwrap()
            .str("bad name")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("m"),
            method: Cow::Borrowed("get_registered_multisig"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Missing or invalid multisig name parameter".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("wallet-a")
            .unwrap()
            .str("as_file")
            .unwrap()
            .str("yes")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("m"),
            method: Cow::Borrowed("get_registered_multisig"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid as_file parameter".to_string(),
            }
        );
    }

    #[test]
    fn registered_multisig_detail_returns_structured_signer_metadata() {
        let mut emulator = Emulator::new();
        emulator
            .storage_mut()
            .set_multisig_registration(
                "wallet-a",
                &authenticated_record(current_multisig_payload(&[3, 1])),
            )
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("wallet-a")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("m"),
            method: Cow::Borrowed("get_registered_multisig"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "multisig_name".to_string(),
                        value: OwnedV1Value::Text("wallet-a".to_string()),
                    },
                    OwnedResultMapEntry {
                        key: "descriptor".to_string(),
                        value: OwnedV1Value::Map(vec![
                            OwnedResultMapEntry {
                                key: "variant".to_string(),
                                value: OwnedV1Value::Text("wsh(multi(k))".to_string()),
                            },
                            OwnedResultMapEntry {
                                key: "sorted".to_string(),
                                value: OwnedV1Value::Bool(false),
                            },
                            OwnedResultMapEntry {
                                key: "threshold".to_string(),
                                value: OwnedV1Value::U64(1),
                            },
                            OwnedResultMapEntry {
                                key: "master_blinding_key".to_string(),
                                value: OwnedV1Value::Bytes(vec![]),
                            },
                            OwnedResultMapEntry {
                                key: "signers".to_string(),
                                value: OwnedV1Value::Array(vec![OwnedV1Value::Map(vec![
                                    OwnedResultMapEntry {
                                        key: "fingerprint".to_string(),
                                        value: OwnedV1Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
                                    },
                                    OwnedResultMapEntry {
                                        key: "derivation".to_string(),
                                        value: OwnedV1Value::Array(vec![
                                            OwnedV1Value::U64(48u64 | 0x8000_0000),
                                            OwnedV1Value::U64(0),
                                        ]),
                                    },
                                    OwnedResultMapEntry {
                                        key: "xpub".to_string(),
                                        value: OwnedV1Value::Text(base58ck::encode_check(
                                            &[1; BIP32_SERIALIZED_LEN]
                                        )),
                                    },
                                    OwnedResultMapEntry {
                                        key: "path".to_string(),
                                        value: OwnedV1Value::Array(vec![
                                            OwnedV1Value::U64(3),
                                            OwnedV1Value::U64(1),
                                        ]),
                                    },
                                ])]),
                            },
                        ]),
                    },
                ]
            }
        );
    }

    #[test]
    fn registered_multisig_detail_exports_flat_file() {
        let mut emulator = Emulator::new();
        emulator
            .storage_mut()
            .set_multisig_registration(
                "wallet-a",
                &authenticated_record(current_multisig_payload(&[])),
            )
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("wallet-a")
            .unwrap()
            .str("as_file")
            .unwrap()
            .bool(true)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("m"),
            method: Cow::Borrowed("get_registered_multisig"),
            params: Some(&params),
        };

        let xpub = base58ck::encode_check(&[1; BIP32_SERIALIZED_LEN]);
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "multisig_name".to_string(),
                        value: OwnedV1Value::Text("wallet-a".to_string()),
                    },
                    OwnedResultMapEntry {
                        key: "multisig_file".to_string(),
                        value: OwnedV1Value::Text(format!(
                            "# Exported by Blockstream Jade\nName: wallet-a\nPolicy: 1 of 1\nFormat: P2WSH\nSorted: False\nDerivation: m/48'/0\ndeadbeef: {xpub}\n"
                        )),
                    },
                ]
            }
        );
    }

    #[test]
    fn registered_multisig_detail_rejects_legacy_summary_only_records() {
        let mut emulator = Emulator::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&[2, MultisigVariant::P2wsh as u8, 1, 1, 0]);
        payload.extend_from_slice(&[0; BIP32_SERIALIZED_LEN]);
        emulator
            .storage_mut()
            .set_multisig_registration("wallet-a", &authenticated_record(payload))
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("wallet-a")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("m"),
            method: Cow::Borrowed("get_registered_multisig"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Named multisig too old include detailed signer data".to_string(),
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
    fn get_master_blinding_key_returns_slip77_half() {
        let mut emulator = Emulator::new();
        let mut key = [0u8; 64];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        emulator.platform_mut().set_master_unblinding_key(key);

        let request = Request {
            id: Cow::Borrowed("blind"),
            method: Cow::Borrowed("get_master_blinding_key"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult {
                result: (32u8..64).collect()
            }
        );
    }

    #[test]
    fn get_master_blinding_key_only_if_silent_rejects_when_confirmation_needed() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_confirm_export_blinding_key(true);
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("only_if_silent")
            .unwrap()
            .bool(true)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("blind"),
            method: Cow::Borrowed("get_master_blinding_key"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::UserCancelled,
                message: "User declined to export master blinding key".to_string(),
            }
        );
    }

    #[test]
    fn raw_v1_get_master_blinding_key_returns_bytes() {
        let mut emulator = Emulator::new();
        let mut key = [0u8; 64];
        key[32..64].copy_from_slice(&[0x42; 32]);
        emulator.platform_mut().set_master_unblinding_key(key);
        let request = [
            0xa2, 0x62, b'i', b'd', 0x61, b'b', 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x77,
            b'g', b'e', b't', b'_', b'm', b'a', b's', b't', b'e', b'r', b'_', b'b', b'l', b'i',
            b'n', b'd', b'i', b'n', b'g', b'_', b'k', b'e', b'y',
        ];
        let response = emulator.handle_v1_cbor(&request);
        let mut decoder = Decoder::new(&response);
        let mut result = None;

        assert_eq!(decoder.map().unwrap(), Some(2));
        for _ in 0..2 {
            match decoder.str().unwrap() {
                "id" => assert_eq!(decoder.str().unwrap(), "b"),
                "result" => result = Some(decoder.bytes().unwrap()),
                _ => decoder.skip().unwrap(),
            }
        }

        assert_eq!(result, Some(&[0x42; 32][..]));
    }

    #[test]
    fn get_blinding_key_derives_script_public_key_from_host_master_key() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_master_unblinding_key([0x11; 64]);
        let script = b"\x00\x14script";
        let expected_private =
            jade_crypto::pure_rust::slip77_blinding_private_key(&[0x11; 64], script).unwrap();
        let expected_public =
            jade_crypto::pure_rust::public_key_from_private_key(&expected_private).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("script")
            .unwrap()
            .bytes(script)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("blind"),
            method: Cow::Borrowed("get_blinding_key"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult {
                result: expected_public.to_vec()
            }
        );
    }

    #[test]
    fn get_blinding_key_uses_registered_multisig_master_key_when_named() {
        let mut emulator = Emulator::new();
        emulator.platform_mut().set_master_unblinding_key([0; 64]);
        let mut payload = Vec::new();
        payload.extend_from_slice(&[3, MultisigVariant::P2wsh as u8, 1, 1]);
        payload.push(MULTISIG_MASTER_BLINDING_KEY_SIZE as u8);
        payload.extend_from_slice(&[0x33; MULTISIG_MASTER_BLINDING_KEY_SIZE]);
        payload.push(1);
        payload.extend_from_slice(&[0; 4]);
        payload.push(0);
        payload.extend_from_slice(&[1; BIP32_SERIALIZED_LEN]);
        payload.push(0);
        emulator
            .storage_mut()
            .set_multisig_registration("liquid-a", &authenticated_record(payload))
            .unwrap();

        let script = b"\x00\x14script";
        let mut padded_key = [0u8; 64];
        padded_key[32..64].copy_from_slice(&[0x33; MULTISIG_MASTER_BLINDING_KEY_SIZE]);
        let expected_private =
            jade_crypto::pure_rust::slip77_blinding_private_key(&padded_key, script).unwrap();
        let expected_public =
            jade_crypto::pure_rust::public_key_from_private_key(&expected_private).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("script")
            .unwrap()
            .bytes(script)
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("liquid-a")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("blind"),
            method: Cow::Borrowed("get_blinding_key"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult {
                result: expected_public.to_vec()
            }
        );
    }

    #[test]
    fn get_blinding_key_rejects_missing_script_and_unblinded_multisig() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("blind"),
            method: Cow::Borrowed("get_blinding_key"),
            params: None,
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            }
        );

        let mut payload = Vec::new();
        payload.extend_from_slice(&[3, MultisigVariant::P2wsh as u8, 1, 1, 0]);
        payload.push(1);
        payload.extend_from_slice(&[0; 4]);
        payload.push(0);
        payload.extend_from_slice(&[1; BIP32_SERIALIZED_LEN]);
        payload.push(0);
        emulator
            .storage_mut()
            .set_multisig_registration("plain-a", &authenticated_record(payload))
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("script")
            .unwrap()
            .bytes(b"\x00\x14script")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("plain-a")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("blind"),
            method: Cow::Borrowed("get_blinding_key"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "No blinding key for multisig record".to_string(),
            }
        );
    }

    #[test]
    fn get_shared_nonce_derives_nonce_from_host_master_key() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_master_unblinding_key([0x44; 64]);
        let script = b"\x00\x14script";
        let mut their_private_key = [0u8; jade_crypto::EC_PRIVATE_KEY_LEN];
        their_private_key[jade_crypto::EC_PRIVATE_KEY_LEN - 1] = 1;
        let their_pubkey =
            jade_crypto::pure_rust::public_key_from_private_key(&their_private_key).unwrap();
        let our_private =
            jade_crypto::pure_rust::slip77_blinding_private_key(&[0x44; 64], script).unwrap();
        let expected_nonce =
            jade_crypto::pure_rust::ecdh_nonce_hash(&our_private, &their_pubkey).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("script")
            .unwrap()
            .bytes(script)
            .unwrap()
            .str("their_pubkey")
            .unwrap()
            .bytes(&their_pubkey)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("nonce"),
            method: Cow::Borrowed("get_shared_nonce"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult {
                result: expected_nonce.to_vec()
            }
        );
    }

    #[test]
    fn get_shared_nonce_can_include_our_blinding_public_key() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_master_unblinding_key([0x55; 64]);
        let script = b"\x00\x14script";
        let mut their_private_key = [0u8; jade_crypto::EC_PRIVATE_KEY_LEN];
        their_private_key[jade_crypto::EC_PRIVATE_KEY_LEN - 1] = 2;
        let their_pubkey =
            jade_crypto::pure_rust::public_key_from_private_key(&their_private_key).unwrap();
        let our_private =
            jade_crypto::pure_rust::slip77_blinding_private_key(&[0x55; 64], script).unwrap();
        let expected_nonce =
            jade_crypto::pure_rust::ecdh_nonce_hash(&our_private, &their_pubkey).unwrap();
        let expected_blinding_key =
            jade_crypto::pure_rust::public_key_from_private_key(&our_private).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("script")
            .unwrap()
            .bytes(script)
            .unwrap()
            .str("their_pubkey")
            .unwrap()
            .bytes(&their_pubkey)
            .unwrap()
            .str("include_pubkey")
            .unwrap()
            .bool(true)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("nonce"),
            method: Cow::Borrowed("get_shared_nonce"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "shared_nonce".to_string(),
                        value: OwnedV1Value::Bytes(expected_nonce.to_vec())
                    },
                    OwnedResultMapEntry {
                        key: "blinding_key".to_string(),
                        value: OwnedV1Value::Bytes(expected_blinding_key.to_vec())
                    },
                ]
            }
        );
    }

    #[test]
    fn raw_v1_get_shared_nonce_include_pubkey_returns_result_map() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_master_unblinding_key([0x66; 64]);
        let script = b"\x00\x14script";
        let mut their_private_key = [0u8; jade_crypto::EC_PRIVATE_KEY_LEN];
        their_private_key[jade_crypto::EC_PRIVATE_KEY_LEN - 1] = 3;
        let their_pubkey =
            jade_crypto::pure_rust::public_key_from_private_key(&their_private_key).unwrap();

        let mut request = Vec::new();
        minicbor::Encoder::new(&mut request)
            .map(3)
            .unwrap()
            .str("id")
            .unwrap()
            .str("n")
            .unwrap()
            .str("method")
            .unwrap()
            .str("get_shared_nonce")
            .unwrap()
            .str("params")
            .unwrap()
            .map(3)
            .unwrap()
            .str("script")
            .unwrap()
            .bytes(script)
            .unwrap()
            .str("their_pubkey")
            .unwrap()
            .bytes(&their_pubkey)
            .unwrap()
            .str("include_pubkey")
            .unwrap()
            .bool(true)
            .unwrap();

        let response = emulator.handle_v1_cbor(&request);
        let mut decoder = Decoder::new(&response);
        let mut shared_nonce = None;
        let mut blinding_key = None;

        assert_eq!(decoder.map().unwrap(), Some(2));
        for _ in 0..2 {
            match decoder.str().unwrap() {
                "id" => assert_eq!(decoder.str().unwrap(), "n"),
                "result" => {
                    assert_eq!(decoder.map().unwrap(), Some(2));
                    for _ in 0..2 {
                        match decoder.str().unwrap() {
                            "shared_nonce" => shared_nonce = Some(decoder.bytes().unwrap()),
                            "blinding_key" => blinding_key = Some(decoder.bytes().unwrap()),
                            _ => decoder.skip().unwrap(),
                        }
                    }
                }
                _ => decoder.skip().unwrap(),
            }
        }

        assert_eq!(shared_nonce.map(|bytes| bytes.len()), Some(32));
        assert_eq!(blinding_key.map(|bytes| bytes.len()), Some(33));
    }

    #[test]
    fn get_shared_nonce_rejects_bad_parameters() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("nonce"),
            method: Cow::Borrowed("get_shared_nonce"),
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
            .map(3)
            .unwrap()
            .str("script")
            .unwrap()
            .bytes(b"\x00\x14script")
            .unwrap()
            .str("their_pubkey")
            .unwrap()
            .bytes(&[0u8; jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN])
            .unwrap()
            .str("include_pubkey")
            .unwrap()
            .u8(1)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("nonce"),
            method: Cow::Borrowed("get_shared_nonce"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid pubkey flag from parameters".to_string(),
            }
        );
    }

    #[test]
    fn get_blinding_factor_derives_asset_and_value_factors() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_master_unblinding_key([0x11; 64]);
        let hash_prevouts = [0x22; jade_crypto::SHA256_LEN];
        let expected = jade_crypto::pure_rust::deterministic_blinding_factor(
            &[0x11; 64],
            &hash_prevouts,
            5,
            jade_crypto::BlindingFactorKind::AssetAndValue,
        )
        .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("hash_prevouts")
            .unwrap()
            .bytes(&hash_prevouts)
            .unwrap()
            .str("output_index")
            .unwrap()
            .u8(5)
            .unwrap()
            .str("type")
            .unwrap()
            .str("ASSET_AND_VALUE")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("bf"),
            method: Cow::Borrowed("get_blinding_factor"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult {
                result: expected.as_slice().to_vec()
            }
        );
    }

    #[test]
    fn get_blinding_factor_uses_registered_multisig_master_key_when_named() {
        let mut emulator = Emulator::new();
        emulator.platform_mut().set_master_unblinding_key([0; 64]);
        let mut payload = Vec::new();
        payload.extend_from_slice(&[3, MultisigVariant::P2wsh as u8, 1, 1]);
        payload.push(MULTISIG_MASTER_BLINDING_KEY_SIZE as u8);
        payload.extend_from_slice(&[0x77; MULTISIG_MASTER_BLINDING_KEY_SIZE]);
        payload.push(1);
        payload.extend_from_slice(&[0; 4]);
        payload.push(0);
        payload.extend_from_slice(&[1; BIP32_SERIALIZED_LEN]);
        payload.push(0);
        emulator
            .storage_mut()
            .set_multisig_registration("liquid-b", &authenticated_record(payload))
            .unwrap();

        let hash_prevouts = [0x88; jade_crypto::SHA256_LEN];
        let mut padded_key = [0u8; 64];
        padded_key[32..64].copy_from_slice(&[0x77; MULTISIG_MASTER_BLINDING_KEY_SIZE]);
        let expected = jade_crypto::pure_rust::deterministic_blinding_factor(
            &padded_key,
            &hash_prevouts,
            9,
            jade_crypto::BlindingFactorKind::Asset,
        )
        .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("hash_prevouts")
            .unwrap()
            .bytes(&hash_prevouts)
            .unwrap()
            .str("output_index")
            .unwrap()
            .u8(9)
            .unwrap()
            .str("type")
            .unwrap()
            .str("ASSET")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("liquid-b")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("bf"),
            method: Cow::Borrowed("get_blinding_factor"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult {
                result: expected.as_slice().to_vec()
            }
        );
    }

    #[test]
    fn raw_v1_get_blinding_factor_returns_bytes() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_master_unblinding_key([0x33; 64]);
        let hash_prevouts = [0x44; jade_crypto::SHA256_LEN];

        let mut request = Vec::new();
        minicbor::Encoder::new(&mut request)
            .map(3)
            .unwrap()
            .str("id")
            .unwrap()
            .str("b")
            .unwrap()
            .str("method")
            .unwrap()
            .str("get_blinding_factor")
            .unwrap()
            .str("params")
            .unwrap()
            .map(3)
            .unwrap()
            .str("hash_prevouts")
            .unwrap()
            .bytes(&hash_prevouts)
            .unwrap()
            .str("output_index")
            .unwrap()
            .u8(2)
            .unwrap()
            .str("type")
            .unwrap()
            .str("VALUE")
            .unwrap();

        let response = emulator.handle_v1_cbor(&request);
        let mut decoder = Decoder::new(&response);
        let mut result = None;

        assert_eq!(decoder.map().unwrap(), Some(2));
        for _ in 0..2 {
            match decoder.str().unwrap() {
                "id" => assert_eq!(decoder.str().unwrap(), "b"),
                "result" => result = Some(decoder.bytes().unwrap()),
                _ => decoder.skip().unwrap(),
            }
        }

        assert_eq!(result.map(|bytes| bytes.len()), Some(32));
    }

    #[test]
    fn get_blinding_factor_rejects_bad_parameters() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("bf"),
            method: Cow::Borrowed("get_blinding_factor"),
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
            .map(3)
            .unwrap()
            .str("hash_prevouts")
            .unwrap()
            .bytes(&[0x44; jade_crypto::SHA256_LEN])
            .unwrap()
            .str("output_index")
            .unwrap()
            .u8(2)
            .unwrap()
            .str("type")
            .unwrap()
            .str("BOGUS")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("bf"),
            method: Cow::Borrowed("get_blinding_factor"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Invalid blinding factor type - must be either 'ASSET', 'VALUE' or 'ASSET_AND_VALUE'".to_string(),
            }
        );
    }

    #[test]
    fn update_pinserver_sets_details_and_certificate() {
        let mut emulator = Emulator::new();
        let pubkey = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(5)
            .unwrap()
            .str("urlA")
            .unwrap()
            .str("https://pin.example")
            .unwrap()
            .str("urlB")
            .unwrap()
            .str("http://backup.example")
            .unwrap()
            .str("pubkey")
            .unwrap()
            .bytes(&pubkey)
            .unwrap()
            .str("certificate")
            .unwrap()
            .str("pem")
            .unwrap()
            .str("reset_certificate")
            .unwrap()
            .bool(false)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("pin"),
            method: Cow::Borrowed("update_pinserver"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );

        let mut out = Vec::new();
        emulator
            .storage
            .get_record(StorageRecord::PinserverUrlA, &mut out)
            .unwrap();
        assert_eq!(out, b"https://pin.example");
        emulator
            .storage
            .get_record(StorageRecord::PinserverUrlB, &mut out)
            .unwrap();
        assert_eq!(out, b"http://backup.example");
        emulator
            .storage
            .get_record(StorageRecord::PinserverPubkey, &mut out)
            .unwrap();
        assert_eq!(out, pubkey);
        emulator
            .storage
            .get_record(StorageRecord::PinserverCertificate, &mut out)
            .unwrap();
        assert_eq!(out, b"pem");
    }

    #[test]
    fn update_pinserver_resets_details_and_certificate() {
        let mut emulator = Emulator::new();
        emulator
            .storage_mut()
            .set_record(StorageRecord::PinserverUrlA, b"https://pin.example")
            .unwrap();
        emulator
            .storage_mut()
            .set_record(StorageRecord::PinserverCertificate, b"pem")
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("reset_details")
            .unwrap()
            .bool(true)
            .unwrap()
            .str("reset_certificate")
            .unwrap()
            .bool(true)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("pin"),
            method: Cow::Borrowed("update_pinserver"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );
        let mut out = Vec::new();
        assert_eq!(
            emulator
                .storage
                .get_record(StorageRecord::PinserverUrlA, &mut out),
            Err(jade_storage::StorageError::NotFound)
        );
        assert_eq!(
            emulator
                .storage
                .get_record(StorageRecord::PinserverCertificate, &mut out),
            Err(jade_storage::StorageError::NotFound)
        );
    }

    #[test]
    fn update_pinserver_rejects_invalid_combinations() {
        let mut emulator = Emulator::new();
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("urlB")
            .unwrap()
            .str("http://backup.example")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("pin"),
            method: Cow::Borrowed("update_pinserver"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Cannot set only second URL".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("urlA")
            .unwrap()
            .str("https://pin.example")
            .unwrap()
            .str("reset_details")
            .unwrap()
            .bool(true)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("pin"),
            method: Cow::Borrowed("update_pinserver"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Cannot set and reset details".to_string(),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("urlA")
            .unwrap()
            .str("https://pin.example")
            .unwrap()
            .str("pubkey")
            .unwrap()
            .bytes(&[0x04; 33])
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("pin"),
            method: Cow::Borrowed("update_pinserver"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Invalid Oracle pubkey".to_string(),
            }
        );
    }

    #[test]
    fn debug_set_mnemonic_derives_seed_and_master_blinding_key() {
        let mut emulator = Emulator::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("mnemonic")
            .unwrap()
            .str(mnemonic)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("debug"),
            method: Cow::Borrowed("debug_set_mnemonic"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );
        let expected_seed = bip39::Mnemonic::parse_in(bip39::Language::English, mnemonic)
            .unwrap()
            .to_seed("");
        let expected_master =
            jade_crypto::slip77_master_unblinding_key_from_seed(&expected_seed).unwrap();

        assert_eq!(emulator.state.wallet, jade_core::WalletLifecycle::Ready);
        assert_eq!(emulator.platform().wallet_seed(), Some(&expected_seed[..]));
        assert_eq!(emulator.platform().master_unblinding_key, expected_master);
    }

    #[test]
    fn debug_set_mnemonic_seed_is_temporary_wallet() {
        let mut emulator = Emulator::new();
        let seed = [0x12; 32];
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("seed")
            .unwrap()
            .bytes(&seed)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("debug"),
            method: Cow::Borrowed("debug_set_mnemonic"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );
        assert_eq!(emulator.state.wallet, jade_core::WalletLifecycle::Temporary);
        assert_eq!(emulator.platform().wallet_seed(), Some(&seed[..]));
        assert_eq!(
            emulator.platform().master_unblinding_key,
            jade_crypto::slip77_master_unblinding_key_from_seed(&seed).unwrap()
        );
    }

    #[test]
    fn raw_v1_debug_set_mnemonic_returns_true() {
        let mut emulator = Emulator::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
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
            .str("debug_set_mnemonic")
            .unwrap()
            .str("params")
            .unwrap()
            .map(2)
            .unwrap()
            .str("mnemonic")
            .unwrap()
            .str(mnemonic)
            .unwrap()
            .str("temporary_wallet")
            .unwrap()
            .bool(true)
            .unwrap();

        assert_eq!(
            emulator.handle_v1_cbor(&request),
            [0xa2, 0x62, b'i', b'd', 0x61, b'd', 0x66, b'r', b'e', b's', b'u', b'l', b't', 0xf5,]
        );
        assert_eq!(emulator.state.wallet, jade_core::WalletLifecycle::Temporary);
    }

    #[test]
    fn debug_set_mnemonic_rejects_invalid_inputs() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("debug"),
            method: Cow::Borrowed("debug_set_mnemonic"),
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
            .str("seed")
            .unwrap()
            .bytes(&[0x12; 31])
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("debug"),
            method: Cow::Borrowed("debug_set_mnemonic"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid seed from parameters".to_string(),
            }
        );
    }

    #[test]
    fn debug_clean_reset_wipes_emulator_storage_and_state() {
        let mut emulator = Emulator::new();
        emulator.state.wallet = jade_core::WalletLifecycle::Ready;
        emulator
            .platform_mut()
            .set_debug_wallet_seed(vec![0x11; 64]);
        emulator
            .platform_mut()
            .set_master_unblinding_key([0x22; 64]);
        emulator
            .platform_mut()
            .set_confirm_export_blinding_key(true);
        emulator
            .storage_mut()
            .set_record(StorageRecord::EncryptedBlob, b"blob")
            .unwrap();
        emulator
            .storage_mut()
            .set_record(StorageRecord::PinserverCertificate, b"cert")
            .unwrap();
        emulator
            .storage_mut()
            .set_multisig_registration("wallet-a", b"record-a")
            .unwrap();
        emulator
            .storage_mut()
            .set_descriptor_registration("desc-a", b"record-d")
            .unwrap();
        emulator
            .storage_mut()
            .set_otp_data("otp-a", b"otp")
            .unwrap();

        let request = Request {
            id: Cow::Borrowed("debug"),
            method: Cow::Borrowed("debug_clean_reset"),
            params: None,
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );
        assert_eq!(emulator.state.wallet, jade_core::WalletLifecycle::Uninit);
        assert_eq!(emulator.platform().wallet_seed(), None);
        assert_eq!(emulator.platform().master_unblinding_key, [0; 64]);
        assert_eq!(emulator.storage.count(StorageNamespace::Multisig), Ok(0));
        assert_eq!(emulator.storage.count(StorageNamespace::Descriptor), Ok(0));
        assert_eq!(emulator.storage.count(StorageNamespace::Otp), Ok(0));
        let mut out = Vec::new();
        assert_eq!(
            emulator
                .storage
                .get_record(StorageRecord::EncryptedBlob, &mut out),
            Err(jade_storage::StorageError::NotFound)
        );
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
