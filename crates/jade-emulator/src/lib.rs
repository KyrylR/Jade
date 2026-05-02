use std::borrow::Cow;
use std::boxed::Box;
use std::fmt;
use std::str;
use std::string::String;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::Vec;

use jade_core::{
    bip32_path::{JadeDerivationPath, MAX_PATH_LEN},
    CoreError, CoreResult, CoreState, NetworkRestriction, OperationState, OtaHashType, OtaRequest,
    Platform, VersionDebugInfo, VersionInfo, WalletLifecycle,
};
use jade_protocol_v1::{
    decode_request, encode_bool_result, encode_bytes_result, encode_error_response,
    encode_map_result, encode_owned_map_result, encode_text_result, encode_uint_result,
    method_spec, ErrorCode, ErrorResponse, MethodClass, OwnedResultMapEntry, OwnedV1Value, Request,
    ResultMapEntry, V1Value,
};
use jade_storage::{
    key_name_valid, parse_descriptor_details, parse_descriptor_summary, parse_multisig_details,
    parse_multisig_summary, DescriptorDataValue, DescriptorDetails, JadeStorage, MemoryStorage,
    MultisigDetails, MultisigSignerDetails, MultisigVariant, RecordAuthenticator, StorageLimits,
    StorageNamespace, StorageRecord, HMAC_SHA256_LEN,
};
use minicbor::{data::Type, Decoder};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct Emulator {
    state: CoreState,
    platform: HostPlatform,
    storage: JadeStorage<MemoryStorage>,
    ota: Option<HostOtaSession>,
    sign_tx: Option<BitcoinSignTxSession>,
    sign_message_ae: Option<BitcoinSignMessageAeSession>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultisigAddressNetwork {
    Bitcoin(jade_crypto::BitcoinNetwork),
    LiquidUnconfidential(jade_crypto::LiquidNetwork),
    LiquidConfidential {
        network: jade_crypto::LiquidNetwork,
        master_unblinding_key: [u8; jade_crypto::SHA512_LEN],
    },
}

const MAINNET_SERVICE_XPUB: &str = "xpub661MyMwAqRbcGsMS1UQfLrVW52iFHhKd1WbL4BVBZt8xz8pE6oyz6La2LscN2WADtpZZXwKo4DXMbzUdxVsLYxm7f6instfCnpB3cFdbi2F";
const TESTNET_SERVICE_XPUB: &str = "tpubD6NzVbkrYhZ4Y9k7T65kw2Sx9z67CzZr2Hi7w2pkKutUvm25ryvL79PqQTtDvAaYacd4z5NQTMmdJ37t8VbMVZbDY1z2rqUKLRNpVW6rGC3";
const LIQUID_SERVICE_XPUB: &str = "xpub661MyMwAqRbcEZr3uYPEEP4X2bRmYXmxrcLMH8YEwLAFxonVGqstpNywBvwkUDCEZA1cd6fsLgKvb6iZP5yUtLc3G3L8WynChNJznHLaVrA";
const TESTNET_LIQUID_SERVICE_XPUB: &str = "tpubD6NzVbkrYhZ4YKB74cMgKEpwByD7UWLXt2MxRdwwaQtgrw6E3YPQgSRkaxMWnpDXKtX5LvRmY5mT8FkzCtJcEQ1YhN1o8CU2S5gy9TDFc24";

#[derive(Debug, Clone, PartialEq, Eq)]
struct BitcoinSignTxSession {
    txn: Vec<u8>,
    expected_inputs: usize,
    received_inputs: usize,
    next_signature: usize,
    flow: BitcoinSignTxFlow,
    inputs: Vec<BitcoinTxInputParams>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BitcoinSignMessageAeSession {
    message: Vec<u8>,
    path: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitcoinSignTxFlow {
    Legacy,
    Staged,
}

impl Default for Emulator {
    fn default() -> Self {
        Self {
            state: CoreState::default(),
            platform: HostPlatform::default(),
            storage: JadeStorage::new(MemoryStorage::new(), StorageLimits::ESP32_NVS_DEFAULT),
            ota: None,
            sign_tx: None,
            sign_message_ae: None,
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
            Some(MethodClass::PreAuth) if request.method == "register_attestation" => {
                self.register_attestation_result(request)
            }
            Some(MethodClass::PreAuth) if request.method == "sign_attestation" => {
                self.sign_attestation_result(request)
            }
            Some(MethodClass::PreAuth) if request.method == "cancel" => V1Outcome::NoReply,
            Some(MethodClass::PreAuth) if request.method == "ota" => self.start_ota(request, false),
            Some(MethodClass::PreAuth) if request.method == "ota_delta" => {
                self.start_ota(request, true)
            }
            Some(MethodClass::PreAuth) if request.method == "update_pinserver" => {
                self.update_pinserver(request)
            }
            Some(MethodClass::PreAuth) if request.method == "auth_user" => {
                self.auth_user_result(request)
            }
            Some(MethodClass::Debug) if request.method == "debug_clean_reset" => {
                match self.storage.debug_clean_reset() {
                    Ok(()) => {
                        self.state = CoreState::default();
                        self.platform.clear_debug_wallet();
                        self.ota = None;
                        self.sign_tx = None;
                        self.sign_message_ae = None;
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
            Some(MethodClass::Debug) if request.method == "get_bip85_bip39_entropy" => {
                self.bip85_bip39_entropy_result(request)
            }
            Some(MethodClass::Debug) if request.method == "get_bip85_rsa_entropy" => {
                self.bip85_rsa_entropy_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_multisigs" => {
                self.registered_wallets_result(StorageNamespace::Multisig, "multisig")
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_multisig" => {
                self.registered_multisig_details(request)
            }
            Some(MethodClass::Authenticated) if request.method == "register_multisig" => {
                self.register_multisig_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_descriptors" => {
                self.registered_wallets_result(StorageNamespace::Descriptor, "descriptor")
            }
            Some(MethodClass::Authenticated) if request.method == "get_registered_descriptor" => {
                self.registered_descriptor_details(request)
            }
            Some(MethodClass::Authenticated) if request.method == "register_descriptor" => {
                self.register_descriptor_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "register_otp" => {
                self.register_otp_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "get_otp_code" => {
                self.otp_code_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "sign_message" => {
                self.sign_message_result(request)
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
            Some(MethodClass::Authenticated) if request.method == "sign_identity" => {
                self.sign_identity_result(request)
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
            Some(MethodClass::Authenticated) if request.method == "get_commitments" => {
                self.commitments_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "show_bip85_bip39_entropy" => {
                match self.bip85_bip39_entropy_data(request) {
                    Ok(_) => V1Outcome::BoolResult { result: true },
                    Err(outcome) => outcome,
                }
            }
            Some(MethodClass::Authenticated) if request.method == "get_bip85_pubkey" => {
                self.bip85_rsa_pubkey_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "sign_bip85_digests" => {
                self.sign_bip85_digests_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "sign_tx" => {
                self.sign_tx_result(request)
            }
            Some(MethodClass::Authenticated) if request.method == "sign_psbt" => {
                self.sign_psbt_result(request)
            }
            Some(MethodClass::Continuation) if request.method == "tx_input" => {
                self.tx_input_result(request)
            }
            Some(MethodClass::Continuation) if request.method == "get_signature" => {
                self.get_signature_result(request)
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

    fn register_multisig_result(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };

        if params.contains("multisig_file").unwrap_or(false) {
            let multisig_file = match params.str("multisig_file") {
                Ok(Some(multisig_file)) if !multisig_file.is_empty() => multisig_file,
                Ok(_) | Err(_) => return bad_parameters("Invalid multisig file data"),
            };
            return self.register_multisig_file_result(multisig_file);
        }

        let xpub_prefix = match params.str("network") {
            Ok(Some(network)) if valid_network_name(network) => {
                match xpub_prefix_for_network(network) {
                    Some(prefix) => prefix,
                    None => {
                        return bad_parameters("Failed to extract valid network from parameters")
                    }
                }
            }
            Ok(None) | Err(_) => {
                return bad_parameters("Failed to extract valid network from parameters")
            }
            Ok(Some(_)) => {
                return bad_parameters("Failed to extract valid network from parameters")
            }
        };
        let multisig_name = match params.str("multisig_name") {
            Ok(Some(name)) if key_name_valid(name) => name,
            Ok(_) | Err(_) => {
                return bad_parameters("Missing or invalid multisig name parameter");
            }
        };

        let descriptor_raw = match cbor_map_field(params.raw(), "descriptor") {
            Ok(Some(raw)) => raw,
            Ok(None) | Err(()) => return bad_parameters("Cannot extract multisig descriptor data"),
        };
        let variant = match cbor_map_str(descriptor_raw, "variant") {
            Ok(Some("wsh(multi(k))")) => MultisigVariant::P2wsh,
            Ok(Some("sh(multi(k))")) => MultisigVariant::P2sh,
            Ok(Some("sh(wsh(multi(k)))")) => MultisigVariant::P2wshP2sh,
            Ok(Some(_)) | Ok(None) | Err(()) => {
                return bad_parameters("Invalid script variant parameter");
            }
        };
        let sorted = match cbor_map_bool(descriptor_raw, "sorted") {
            Ok(value) => value.unwrap_or(false),
            Err(()) => return bad_parameters("Invalid sorted flag value"),
        };
        let master_blinding_key = match cbor_map_bytes(descriptor_raw, "master_blinding_key") {
            Ok(Some(bytes)) if bytes.len() == jade_storage::MULTISIG_MASTER_BLINDING_KEY_SIZE => {
                Some(bytes.try_into().expect("checked length"))
            }
            Ok(Some(_)) | Err(()) => return bad_parameters("Invalid blinding key value"),
            Ok(None) => None,
        };
        let threshold = match cbor_map_u64(descriptor_raw, "threshold") {
            Ok(Some(value)) if value > 0 && value <= jade_storage::MAX_ALLOWED_SIGNERS as u64 => {
                value as u8
            }
            Ok(_) | Err(()) => return bad_parameters("Invalid multisig threshold value"),
        };
        let signers =
            match cbor_map_field(descriptor_raw, "signers").and_then(decode_registration_signers) {
                Ok(signers) if !signers.is_empty() => signers,
                Ok(_) | Err(()) => {
                    return bad_parameters("Failed to extract valid co-signers from parameters");
                }
            };

        let registration = ParsedMultisigFile {
            name: multisig_name.to_string(),
            variant,
            sorted,
            threshold,
            master_blinding_key,
            signers,
        };

        self.persist_multisig_registration(&registration, xpub_prefix)
    }

    fn register_multisig_file_result(&mut self, multisig_file: &str) -> V1Outcome {
        let network = jade_crypto::BitcoinNetwork::Main;
        let parsed = match parse_multisig_file(multisig_file, network) {
            Ok(parsed) => parsed,
            Err(message) => return bad_parameters(message),
        };

        self.persist_multisig_registration(&parsed, jade_crypto::XpubPrefix::Main)
    }

    fn persist_multisig_registration(
        &mut self,
        registration: &ParsedMultisigFile,
        xpub_prefix: jade_crypto::XpubPrefix,
    ) -> V1Outcome {
        let multisig_name = registration.name.as_str();
        let signers = registration.signers.as_slice();
        if signers.len() > jade_storage::MAX_ALLOWED_SIGNERS {
            return bad_parameters("Invalid multisig co-signers");
        }
        if registration.threshold as usize > signers.len() {
            return bad_parameters("Invalid multisig threshold");
        }
        if !self.validate_registration_signers(signers, xpub_prefix) {
            return bad_parameters("Failed to validate co-signers");
        }

        let record = match multisig_registration_record(
            registration.variant,
            registration.sorted,
            registration.threshold,
            registration.master_blinding_key,
            signers,
        ) {
            Some(record) => record,
            None => {
                return V1Outcome::Reject {
                    code: ErrorCode::InternalError,
                    message: "Failed to serialise multisig".to_string(),
                };
            }
        };
        let storage_record = StorageRecord::MultisigRegistration {
            name: multisig_name,
        };
        let exists = self.registration_exists(storage_record);
        if exists && self.registration_exists_equal(storage_record, &record) {
            return V1Outcome::BoolResult { result: true };
        }
        if !exists
            && self.storage.count(StorageNamespace::Multisig).unwrap_or(0)
                >= jade_storage::MAX_MULTISIG_REGISTRATIONS
        {
            return bad_parameters("Already have maximum number of multisig wallets");
        }
        if self
            .storage
            .set_multisig_registration(multisig_name, &record)
            .is_err()
        {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to persist multisig data".to_string(),
            };
        }

        V1Outcome::BoolResult { result: true }
    }

    fn register_descriptor_result(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };

        let network_name = match params.str("network") {
            Ok(Some(network)) if valid_network_name(network) => network,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid network from parameters")
            }
        };
        if is_liquid_network(network_name) {
            return bad_parameters("Descriptor wallets not supported on liquid network");
        }
        let Some(network) = bitcoin_network_for_name(network_name) else {
            return bad_parameters("Failed to extract valid network from parameters");
        };
        let descriptor_name = match params.str("descriptor_name") {
            Ok(Some(name)) if key_name_valid(name) => name,
            Ok(_) | Err(_) => {
                return bad_parameters("Missing or invalid descriptor name parameter");
            }
        };
        let descriptor = match params.str("descriptor") {
            Ok(Some(descriptor))
                if !descriptor.is_empty()
                    && descriptor.len() < jade_storage::MAX_DESCRIPTOR_SCRIPT_LEN =>
            {
                descriptor
            }
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid output descriptor string");
            }
        };
        let datavalues = match cbor_map_field(params.raw(), "datavalues")
            .and_then(decode_descriptor_datavalues)
        {
            Ok(datavalues) => datavalues,
            Err(()) => return bad_parameters("Failed to extract valid parameter values"),
        };
        let details = DescriptorDetails {
            descriptor_type: 2,
            descriptor: descriptor.to_string(),
            datavalues,
        };

        if descriptor_receive_address(&details, 0, 0, network).is_none()
            || descriptor_receive_address(&details, 1, 0, network).is_none()
        {
            return bad_parameters("Failed to generate valid descriptor script");
        }

        let record = descriptor_registration_record(&details);
        let storage_record = StorageRecord::DescriptorRegistration {
            name: descriptor_name,
        };
        let exists = self.registration_exists(storage_record);
        if exists && self.registration_exists_equal(storage_record, &record) {
            return V1Outcome::BoolResult { result: true };
        }
        if !exists
            && self
                .storage
                .count(StorageNamespace::Descriptor)
                .unwrap_or(0)
                >= jade_storage::MAX_DESCRIPTOR_REGISTRATIONS
        {
            return bad_parameters("Already have maximum number of descriptor wallets");
        }
        if self
            .storage
            .set_descriptor_registration(descriptor_name, &record)
            .is_err()
        {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to persist descriptor data".to_string(),
            };
        }

        V1Outcome::BoolResult { result: true }
    }

    fn registration_exists(&self, record: StorageRecord<'_>) -> bool {
        let mut existing = Vec::new();
        self.storage.get_record(record, &mut existing).is_ok()
    }

    fn registration_exists_equal(&self, record: StorageRecord<'_>, value: &[u8]) -> bool {
        let mut existing = Vec::new();
        self.storage.get_record(record, &mut existing).is_ok() && existing == value
    }

    fn validate_registration_signers(
        &self,
        signers: &[MultisigSignerDetails],
        xpub_prefix: jade_crypto::XpubPrefix,
    ) -> bool {
        let Some(seed) = self.platform.wallet_seed() else {
            return false;
        };
        let Some(fingerprint) = wallet_fingerprint_from_seed(seed) else {
            return false;
        };

        let mut found_wallet_signer = false;
        for signer in signers {
            if signer.path.iter().any(|value| value & 0x8000_0000 != 0)
                || signer.derivation.len() > MAX_PATH_LEN
                || signer.path.len() > MAX_PATH_LEN
                || !valid_serialized_xpub_for_prefix(&signer.xpub, xpub_prefix)
            {
                return false;
            }
            if signer.fingerprint == fingerprint {
                let Some(expected_xpub) =
                    jade_crypto::pure_rust::xpub_from_seed(seed, &signer.derivation, xpub_prefix)
                else {
                    return false;
                };
                let Ok(expected_bytes) = base58ck::decode_check(&expected_xpub) else {
                    return false;
                };
                if expected_bytes.get(13..45) == Some(&signer.xpub[13..45])
                    && expected_bytes.get(45..78) == Some(&signer.xpub[45..78])
                {
                    found_wallet_signer = true;
                }
            }
        }

        found_wallet_signer
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

        if params.contains("descriptor_name").unwrap_or(false) {
            if is_liquid {
                return bad_parameters("Descriptor wallets not supported on liquid network");
            }
            let Some(network) = bitcoin_network_for_name(network_name) else {
                return V1Outcome::DeferredToCore {
                    method: "get_receive_address".to_string(),
                };
            };
            return self.receive_descriptor_address_result(params, network);
        }

        if params.contains("multisig_name").unwrap_or(false) {
            if is_liquid {
                let Some(network) = liquid_network_for_name(network_name) else {
                    return V1Outcome::DeferredToCore {
                        method: "get_receive_address".to_string(),
                    };
                };
                if confidential {
                    let master_unblinding_key = match self.master_unblinding_key_for_params(params)
                    {
                        Ok(master_unblinding_key) => master_unblinding_key,
                        Err(outcome) => return outcome,
                    };
                    return self.receive_multisig_address_result(
                        params,
                        MultisigAddressNetwork::LiquidConfidential {
                            network,
                            master_unblinding_key,
                        },
                    );
                }
                return self.receive_multisig_address_result(
                    params,
                    MultisigAddressNetwork::LiquidUnconfidential(network),
                );
            }
            let Some(network) = bitcoin_network_for_name(network_name) else {
                return V1Outcome::DeferredToCore {
                    method: "get_receive_address".to_string(),
                };
            };
            return self
                .receive_multisig_address_result(params, MultisigAddressNetwork::Bitcoin(network));
        }
        let variant_name = match params.str("variant") {
            Ok(Some(variant)) => variant,
            Ok(None) => "",
            Err(_) => return bad_parameters("Invalid script variant parameter"),
        };
        if variant_name.is_empty() {
            return self.receive_green_address_result(
                params,
                network_name,
                is_liquid,
                confidential,
            );
        }

        let variant = match variant_name {
            "pkh(k)" => jade_crypto::SinglesigScriptVariant::Pkh,
            "wpkh(k)" => jade_crypto::SinglesigScriptVariant::Wpkh,
            "sh(wpkh(k))" => jade_crypto::SinglesigScriptVariant::ShWpkh,
            "tr(k)" => jade_crypto::SinglesigScriptVariant::Tr,
            "sh(multi(k))" | "wsh(multi(k))" | "sh(wsh(multi(k)))" => {
                return bad_parameters("Unhandled script variant");
            }
            _ => return bad_parameters("Invalid script variant parameter"),
        };
        let path = match params.u32_array("path", MAX_PATH_LEN) {
            Ok(Some(path)) if !path.is_empty() => path,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid path from parameters");
            }
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return bad_parameters("Failed to generate valid singlesig script");
        };

        let address = if is_liquid {
            let Some(network) = liquid_network_for_name(network_name) else {
                return V1Outcome::DeferredToCore {
                    method: "get_receive_address".to_string(),
                };
            };
            if variant == jade_crypto::SinglesigScriptVariant::Tr {
                return V1Outcome::DeferredToCore {
                    method: "get_receive_address".to_string(),
                };
            }
            if confidential {
                jade_crypto::pure_rust::liquid_confidential_singlesig_address_from_seed(
                    seed,
                    &path,
                    network,
                    variant,
                    &self.platform.master_unblinding_key,
                )
            } else {
                jade_crypto::pure_rust::liquid_unconfidential_singlesig_address_from_seed(
                    seed, &path, network, variant,
                )
            }
        } else {
            let Some(network) = bitcoin_network_for_name(network_name) else {
                return V1Outcome::DeferredToCore {
                    method: "get_receive_address".to_string(),
                };
            };
            jade_crypto::pure_rust::bitcoin_singlesig_address_from_seed(
                seed, &path, network, variant,
            )
        };
        let Some(address) = address else {
            return bad_parameters("Failed to generate valid singlesig script");
        };

        V1Outcome::TextResult { result: address }
    }

    fn receive_green_address_result(
        &self,
        params: jade_protocol_v1::Params<'_>,
        network_name: &str,
        is_liquid: bool,
        confidential: bool,
    ) -> V1Outcome {
        const HARDENED: u32 = 0x8000_0000;
        let subaccount = match params.u64("subaccount") {
            Ok(Some(value)) if value <= u32::MAX as u64 => value as u32,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract path elements from parameters");
            }
        };
        let branch = match params.u64("branch") {
            Ok(Some(value)) if value <= u32::MAX as u64 => value as u32,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract path elements from parameters");
            }
        };
        let pointer = match params.u64("pointer") {
            Ok(Some(value)) if value <= u32::MAX as u64 => value as u32,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract path elements from parameters");
            }
        };

        let csv_blocks = match params.u64("csv_blocks") {
            Ok(Some(value)) if value <= u32::MAX as u64 => value as u32,
            Ok(None) => 0,
            Ok(Some(_)) | Err(_) => {
                return bad_parameters("Failed to generate valid green address script");
            }
        };
        if csv_blocks != 0 && !network_allows_csv_blocks(network_name, csv_blocks) {
            return bad_parameters("Failed to generate valid green address script");
        }

        let xpub_prefix = match xpub_prefix_for_network(network_name) {
            Some(prefix) => prefix,
            None => return bad_parameters("Failed to extract valid network from parameters"),
        };
        let service_xpub = match green_service_xpub_for_network(network_name) {
            Some(service_xpub) => service_xpub,
            None => return bad_parameters("Failed to extract valid network from parameters"),
        };
        let recovery_xpub = match params.str("recovery_xpub") {
            Ok(Some(value)) if !value.is_empty() => {
                match decode_xpub_for_prefix(value, xpub_prefix) {
                    Some(xpub) => Some(xpub),
                    None => {
                        return bad_parameters("Failed to generate valid green address script");
                    }
                }
            }
            Ok(_) => None,
            Err(_) => return bad_parameters("Failed to generate valid green address script"),
        };

        let path = if subaccount > 0 {
            Vec::from([HARDENED | 3, HARDENED | subaccount, branch, pointer])
        } else {
            Vec::from([branch, pointer])
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return bad_parameters("Failed to generate valid green address script");
        };

        let address = if is_liquid {
            let Some(network) = liquid_network_for_name(network_name) else {
                return V1Outcome::DeferredToCore {
                    method: "get_receive_address".to_string(),
                };
            };
            if confidential {
                jade_crypto::pure_rust::liquid_confidential_green_address_from_seed(
                    seed,
                    &path,
                    &service_xpub,
                    recovery_xpub.as_ref(),
                    csv_blocks,
                    network,
                    &self.platform.master_unblinding_key,
                )
            } else {
                jade_crypto::pure_rust::liquid_unconfidential_green_address_from_seed(
                    seed,
                    &path,
                    &service_xpub,
                    recovery_xpub.as_ref(),
                    csv_blocks,
                    network,
                )
            }
        } else {
            let Some(network) = bitcoin_network_for_name(network_name) else {
                return V1Outcome::DeferredToCore {
                    method: "get_receive_address".to_string(),
                };
            };
            jade_crypto::pure_rust::bitcoin_green_address_from_seed(
                seed,
                &path,
                &service_xpub,
                recovery_xpub.as_ref(),
                csv_blocks,
                network,
            )
        };
        match address {
            Some(result) => V1Outcome::TextResult { result },
            None => bad_parameters("Failed to generate valid green address script"),
        }
    }

    fn receive_descriptor_address_result(
        &self,
        params: jade_protocol_v1::Params<'_>,
        network: jade_crypto::BitcoinNetwork,
    ) -> V1Outcome {
        let descriptor_name = match params.str("descriptor_name") {
            Ok(Some(name)) if key_name_valid(name) => name,
            Ok(_) | Err(_) => return bad_parameters("Invalid descriptor name parameter"),
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
            return bad_parameters("Cannot find named descriptor wallet");
        }
        let details = match parse_descriptor_details(&record, &HostRecordAuthenticator) {
            Ok(details) => details,
            Err(_) => return bad_parameters("Cannot de-serialise descriptor wallet data"),
        };
        if details.descriptor.is_empty()
            || details.descriptor_type > 2
            || details.datavalues.len() > jade_storage::MAX_ALLOWED_SIGNERS
        {
            return bad_parameters("Descriptor wallet data invalid");
        }

        let branch = match params.u64("branch") {
            Ok(Some(branch)) if branch <= u32::MAX as u64 => branch as u32,
            Ok(None) => 0,
            Ok(Some(_)) | Err(_) => {
                return bad_parameters("Failed to extract path elements from parameters");
            }
        };
        let pointer = match params.u64("pointer") {
            Ok(Some(pointer)) if pointer <= u32::MAX as u64 => pointer as u32,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract path elements from parameters");
            }
        };

        match descriptor_receive_address(&details, branch, pointer, network) {
            Some(address) => V1Outcome::TextResult { result: address },
            None => bad_parameters("Failed to generate valid descriptor script"),
        }
    }

    fn receive_multisig_address_result(
        &self,
        params: jade_protocol_v1::Params<'_>,
        network: MultisigAddressNetwork,
    ) -> V1Outcome {
        let multisig_name = match params.str("multisig_name") {
            Ok(Some(name)) if key_name_valid(name) => name,
            Ok(_) | Err(_) => return bad_parameters("Invalid multisig name parameter"),
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
            return bad_parameters("Cannot find named multisig wallet");
        }
        let details = match parse_multisig_details(&record, &HostRecordAuthenticator) {
            Ok(details) => details,
            Err(_) => return bad_parameters("Cannot de-serialise multisig wallet data"),
        };
        let signer_count = details
            .signers
            .as_ref()
            .map(|signers| signers.len())
            .unwrap_or(details.address_xpubs.len());
        if signer_count != details.summary.num_signers as usize
            || details.summary.threshold == 0
            || details.summary.threshold > details.summary.num_signers
        {
            return bad_parameters("Multisig wallet data invalid");
        }

        let paths = match nested_u32_arrays(
            params,
            "paths",
            jade_storage::MAX_ALLOWED_SIGNERS,
            MAX_PATH_LEN,
        ) {
            Ok(Some(paths)) if !paths.is_empty() => paths,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract signer paths from parameters");
            }
        };
        if paths.len() != signer_count {
            return bad_parameters(
                "Unexpected number of signer paths or invalid path for multisig",
            );
        }

        let (xpubs, effective_paths) = match details.signers.as_ref() {
            Some(signers) => {
                let mut xpubs = Vec::with_capacity(signers.len());
                let mut effective_paths = Vec::with_capacity(paths.len());
                for (signer, path) in signers.iter().zip(paths.iter()) {
                    let mut effective_path = Vec::with_capacity(signer.path.len() + path.len());
                    effective_path.extend_from_slice(&signer.path);
                    effective_path.extend_from_slice(path);
                    xpubs.push(signer.xpub);
                    effective_paths.push(effective_path);
                }
                (xpubs, effective_paths)
            }
            None => (details.address_xpubs.clone(), paths),
        };

        let variant = crypto_multisig_variant(details.summary.variant);
        let address = match network {
            MultisigAddressNetwork::Bitcoin(network) => {
                jade_crypto::pure_rust::bitcoin_multisig_address_from_xpubs(
                    &xpubs,
                    &effective_paths,
                    network,
                    variant,
                    details.summary.sorted,
                    details.summary.threshold,
                )
            }
            MultisigAddressNetwork::LiquidUnconfidential(network) => {
                jade_crypto::pure_rust::liquid_unconfidential_multisig_address_from_xpubs(
                    &xpubs,
                    &effective_paths,
                    network,
                    variant,
                    details.summary.sorted,
                    details.summary.threshold,
                )
            }
            MultisigAddressNetwork::LiquidConfidential {
                network,
                master_unblinding_key,
            } => jade_crypto::pure_rust::liquid_confidential_multisig_address_from_xpubs(
                &xpubs,
                &effective_paths,
                network,
                variant,
                details.summary.sorted,
                details.summary.threshold,
                &master_unblinding_key,
            ),
        };
        let Some(address) = address else {
            return bad_parameters(
                "Unexpected number of signer paths or invalid path for multisig",
            );
        };

        V1Outcome::TextResult { result: address }
    }

    fn register_otp_result(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let name = match params.str("name") {
            Ok(Some(name)) if key_name_valid(name) => name,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to fetch valid otp name from parameters");
            }
        };
        let uri = match params.str("uri") {
            Ok(Some(uri)) if !uri.is_empty() => uri,
            Ok(_) | Err(_) => return bad_parameters("Failed to fetch otp uri from parameters"),
        };

        if self.platform.wallet_seed().is_none() {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Feature requires resetting Jade".to_string(),
            };
        }

        let mut existing_otp = Vec::new();
        if self
            .storage
            .get_record(StorageRecord::OtpData { name }, &mut existing_otp)
            .is_err()
            && self.storage.count(StorageNamespace::Otp).unwrap_or(0)
                >= jade_crypto::OTP_MAX_RECORDS
        {
            return bad_parameters("Already have maximum number of otp records");
        }

        let otp = match jade_crypto::OtpUri::parse(uri) {
            Ok(otp) => otp,
            Err(_) => return bad_parameters("Failed to parse otp record"),
        };
        if otp.auth_code(0).is_err() {
            return bad_parameters("Failed to calculate otp token");
        }

        if self.storage.set_otp_data(name, uri.as_bytes()).is_err() {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to persist otp details".to_string(),
            };
        }
        if let Some(counter) = otp.initial_hotp_counter() {
            if self.storage.set_otp_hotp_counter(name, counter).is_err() {
                let _ = self.storage.erase_otp(name);
                return V1Outcome::Reject {
                    code: ErrorCode::InternalError,
                    message: "Failed to persist otp counter".to_string(),
                };
            }
        }

        V1Outcome::BoolResult { result: true }
    }

    fn otp_code_result(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let name = match params.str("name") {
            Ok(Some(name)) if !name.is_empty() => name,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to fetch valid otp name from parameters");
            }
        };

        if self.platform.wallet_seed().is_none() {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Feature requires resetting Jade".to_string(),
            };
        }

        let mut uri = Vec::new();
        if self
            .storage
            .get_record(StorageRecord::OtpData { name }, &mut uri)
            .is_err()
            || uri.is_empty()
        {
            return bad_parameters("Cannot find or load named otp record");
        }
        let uri = match str::from_utf8(&uri) {
            Ok(uri) => uri,
            Err(_) => return bad_parameters("Failed to parse otp record"),
        };
        let otp = match jade_crypto::OtpUri::parse(uri) {
            Ok(otp) => otp,
            Err(_) => return bad_parameters("Failed to parse otp record"),
        };

        let value = match otp.kind {
            jade_crypto::OtpKind::Hotp { .. } => {
                let current = match self.storage.otp_hotp_counter(name) {
                    Ok(counter) => counter,
                    Err(_) => {
                        return V1Outcome::Reject {
                            code: ErrorCode::InternalError,
                            message: "Failed to set OTP counter".to_string(),
                        };
                    }
                };
                if self
                    .storage
                    .set_otp_hotp_counter(name, current.saturating_add(1))
                    .is_err()
                {
                    return V1Outcome::Reject {
                        code: ErrorCode::InternalError,
                        message: "Failed to set OTP counter".to_string(),
                    };
                }
                current
            }
            jade_crypto::OtpKind::Totp { .. } => self
                .platform
                .current_epoch()
                .unwrap_or_else(current_unix_epoch),
        };

        let override_value = params.u64("override").ok().flatten();
        let value = override_value.unwrap_or(value);

        if override_value.is_none()
            && matches!(otp.kind, jade_crypto::OtpKind::Totp { .. })
            && value < 1_577_836_800
        {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to set OTP counter".to_string(),
            };
        }

        match otp.auth_code(value) {
            Ok(result) => V1Outcome::TextResult { result },
            Err(_) => V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to calculate otp token".to_string(),
            },
        }
    }

    fn sign_message_result(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };

        if params.contains("message_file").unwrap_or(false) {
            let message_file = match params.str("message_file") {
                Ok(Some(message_file)) if !message_file.is_empty() => message_file,
                Ok(_) | Err(_) => return bad_parameters("Invalid sign message file data"),
            };
            return self.sign_message_file_result(message_file);
        }

        let message = match params.str("message") {
            Ok(Some(message)) if !message.is_empty() => message,
            Ok(_) | Err(_) => return bad_parameters("Failed to extract message from parameters"),
        };
        let path = match params.u32_array("path", MAX_PATH_LEN) {
            Ok(Some(path)) if !path.is_empty() => path,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid path from parameters")
            }
        };
        let message_hash = match jade_crypto::bitcoin_message_hash(message.as_bytes()) {
            Some(hash) => hash,
            None => {
                return V1Outcome::Reject {
                    code: ErrorCode::InternalError,
                    message: "Failed to convert message to btc hex format".to_string(),
                };
            }
        };

        if params.contains("ae_host_commitment").unwrap_or(false) {
            match params.bytes("ae_host_commitment") {
                Ok(Some(commitment)) if commitment.len() == 32 => {
                    let host_commitment: [u8; jade_crypto::SHA256_LEN] =
                        commitment.try_into().expect("checked commitment length");
                    let Some(seed) = self.platform.wallet_seed() else {
                        return V1Outcome::Reject {
                            code: ErrorCode::InternalError,
                            message: "Wallet seed is not available".to_string(),
                        };
                    };
                    let signer_commitment =
                        match jade_crypto::pure_rust::anti_exfil_signer_commitment_from_seed(
                            seed,
                            &path,
                            &message_hash,
                            &host_commitment,
                        ) {
                            Some(commitment) => commitment,
                            None => {
                                return V1Outcome::Reject {
                                    code: ErrorCode::InternalError,
                                    message: "Failed to make ae signer commitment".to_string(),
                                };
                            }
                        };
                    self.sign_message_ae = Some(BitcoinSignMessageAeSession {
                        message: message.as_bytes().to_vec(),
                        path,
                    });
                    return V1Outcome::BytesResult {
                        result: signer_commitment.to_vec(),
                    };
                }
                Ok(_) | Err(_) => {
                    return bad_parameters(
                        "Failed to extract valid host commitment from parameters",
                    );
                }
            }
        }

        self.sign_message_ae = None;
        self.sign_message_bytes(message.as_bytes(), &path)
    }

    fn sign_message_file_result(&self, message_file: &str) -> V1Outcome {
        let Some((prefix, rest)) = split_once_byte(message_file, b' ') else {
            return bad_parameters("Invalid prefix");
        };
        if !prefix.eq_ignore_ascii_case("signmessage") {
            return bad_parameters("Invalid prefix");
        }

        let Some((path_str, rest)) = split_once_byte(rest, b' ') else {
            return bad_parameters("Invalid bip32 path");
        };
        let path = match JadeDerivationPath::parse(path_str) {
            Ok(path) => path.to_u32_vec(),
            Err(_) => return bad_parameters("Invalid bip32 path"),
        };

        let Some((label, message)) = split_once_byte(rest, b':') else {
            return bad_parameters("Invalid message prefix");
        };
        if !label.eq_ignore_ascii_case("ascii") {
            return bad_parameters("Invalid message prefix");
        }
        if message.is_empty() {
            return bad_parameters("Invalid message bytes");
        }

        self.sign_message_bytes(message.as_bytes(), &path)
    }

    fn sign_message_bytes(&self, message: &[u8], path: &[u32]) -> V1Outcome {
        let Some(seed) = self.platform.wallet_seed() else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Feature requires resetting Jade".to_string(),
            };
        };
        let Some(signature) =
            jade_crypto::pure_rust::sign_bitcoin_message_from_seed(seed, path, message)
        else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to sign message".to_string(),
            };
        };

        V1Outcome::TextResult { result: signature }
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

    fn sign_identity_result(&self, request: &Request<'_>) -> V1Outcome {
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
        let challenge = match params.bytes("challenge") {
            Ok(Some(challenge)) if !challenge.is_empty() => challenge,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid challenge from parameters");
            }
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Feature requires resetting Jade".to_string(),
            };
        };
        let Some(signature) =
            jade_crypto::pure_rust::sign_identity_from_seed(seed, identity, index, challenge)
        else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to sign identity".to_string(),
            };
        };

        V1Outcome::OwnedMapResult {
            entries: vec![
                OwnedResultMapEntry {
                    key: "signature".to_string(),
                    value: OwnedV1Value::Bytes(signature.signature.to_vec()),
                },
                OwnedResultMapEntry {
                    key: "pubkey".to_string(),
                    value: OwnedV1Value::Bytes(signature.pubkey.to_vec()),
                },
            ],
        }
    }

    fn bip85_bip39_entropy_result(&self, request: &Request<'_>) -> V1Outcome {
        match self.bip85_bip39_entropy_data(request) {
            Ok(data) => V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "pubkey".to_string(),
                        value: OwnedV1Value::Bytes(data.pubkey.to_vec()),
                    },
                    OwnedResultMapEntry {
                        key: "encrypted".to_string(),
                        value: OwnedV1Value::Bytes(data.encrypted),
                    },
                ],
            },
            Err(outcome) => outcome,
        }
    }

    fn bip85_bip39_entropy_data(
        &self,
        request: &Request<'_>,
    ) -> Result<jade_crypto::Bip85EncryptedEntropy, V1Outcome> {
        let Some(params) = request.params() else {
            return Err(V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            });
        };
        let nwords = match params.u64("num_words") {
            Ok(Some(12)) => 12,
            Ok(Some(24)) => 24,
            Ok(_) | Err(_) => {
                return Err(bad_parameters(
                    "Failed to fetch valid number of words from message",
                ));
            }
        };
        let index = match params.u64("index") {
            Ok(Some(index)) if index <= 0x7fff_ffff => index as u32,
            Ok(_) | Err(_) => {
                return Err(bad_parameters("Failed to fetch valid index from message"));
            }
        };
        let host_pubkey = match params.bytes("pubkey") {
            Ok(Some(bytes)) => {
                match <&[u8; jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN]>::try_from(bytes) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Err(bad_parameters("Failed to fetch valid pubkey from message"));
                    }
                }
            }
            Ok(None) | Err(_) => {
                return Err(bad_parameters("Failed to fetch valid pubkey from message"));
            }
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return Err(V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to calculate bip85 entropy from parameters".to_string(),
            });
        };
        jade_crypto::pure_rust::bip85_bip39_encrypted_entropy_from_seed(
            seed,
            nwords,
            index,
            host_pubkey,
            &self.platform.bip85_ephemeral_private_key,
            &self.platform.bip85_iv,
        )
        .ok_or_else(|| V1Outcome::Reject {
            code: ErrorCode::InternalError,
            message: "Failed to encrypt bip85 entropy".to_string(),
        })
    }

    fn bip85_rsa_entropy_result(&self, request: &Request<'_>) -> V1Outcome {
        match self.bip85_rsa_entropy_data(request) {
            Ok(data) => V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "pubkey".to_string(),
                        value: OwnedV1Value::Bytes(data.pubkey.to_vec()),
                    },
                    OwnedResultMapEntry {
                        key: "encrypted".to_string(),
                        value: OwnedV1Value::Bytes(data.encrypted),
                    },
                ],
            },
            Err(outcome) => outcome,
        }
    }

    fn bip85_rsa_entropy_data(
        &self,
        request: &Request<'_>,
    ) -> Result<jade_crypto::Bip85EncryptedEntropy, V1Outcome> {
        let Some(params) = request.params() else {
            return Err(V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            });
        };
        let key_bits = match params.u64("key_bits") {
            Ok(Some(key_bits)) if valid_rsa_key_bits(key_bits) => key_bits as u32,
            Ok(_) | Err(_) => {
                return Err(bad_parameters(
                    "Failed to fetch valid number of key_bits from message",
                ));
            }
        };
        let index = match params.u64("index") {
            Ok(Some(index)) if index <= 0x7fff_ffff => index as u32,
            Ok(_) | Err(_) => {
                return Err(bad_parameters("Failed to fetch valid index from message"));
            }
        };
        let host_pubkey = match params.bytes("pubkey") {
            Ok(Some(bytes)) => {
                match <&[u8; jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN]>::try_from(bytes) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Err(bad_parameters("Failed to fetch valid pubkey from message"));
                    }
                }
            }
            Ok(None) | Err(_) => {
                return Err(bad_parameters("Failed to fetch valid pubkey from message"));
            }
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return Err(V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to calculate bip85 entropy from parameters".to_string(),
            });
        };
        jade_crypto::pure_rust::bip85_rsa_encrypted_entropy_from_seed(
            seed,
            key_bits,
            index,
            host_pubkey,
            &self.platform.bip85_ephemeral_private_key,
            &self.platform.bip85_iv,
        )
        .ok_or_else(|| V1Outcome::Reject {
            code: ErrorCode::InternalError,
            message: "Failed to encrypt bip85 entropy".to_string(),
        })
    }

    fn bip85_rsa_pubkey_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        if let Err(message) = parse_bip85_rsa_key_params(params) {
            return bad_parameters(message);
        }

        V1Outcome::DeferredToCore {
            method: "get_bip85_pubkey RSA generation".to_string(),
        }
    }

    fn sign_bip85_digests_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let key = match parse_bip85_rsa_key_params(params) {
            Ok(key) => key,
            Err(message) => return bad_parameters(message),
        };
        let digests = match cbor_map_field(params.raw(), "digests").and_then(decode_digest_array) {
            Ok(digests) if !digests.is_empty() => digests,
            Ok(_) | Err(()) => {
                return bad_parameters("Failed to extract digests from parameters");
            }
        };
        let max_digests = if key.key_bits <= 2048 {
            8
        } else if key.key_bits < 4096 {
            6
        } else {
            4
        };
        if digests.len() > max_digests {
            return bad_parameters("Unsupported number of digests");
        }

        V1Outcome::DeferredToCore {
            method: "sign_bip85_digests RSA generation".to_string(),
        }
    }

    fn sign_tx_result(&mut self, request: &Request<'_>) -> V1Outcome {
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
        if bitcoin_network_for_name(network_name).is_none() {
            return bad_parameters("Network/transaction type mismatch");
        }
        let txn = match params.bytes("txn") {
            Ok(Some(txn)) if !txn.is_empty() => txn.to_vec(),
            Ok(_) | Err(_) => return bad_parameters("Failed to extract txn from parameters"),
        };
        let expected_inputs = match params.u64("num_inputs") {
            Ok(Some(num_inputs)) if num_inputs <= usize::MAX as u64 => num_inputs as usize,
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract num_inputs from parameters")
            }
        };
        let actual_inputs = match jade_crypto::pure_rust::bitcoin_tx_input_count(&txn) {
            Ok(count) => count,
            Err(_) => return bad_parameters("Failed to extract txn from parameters"),
        };
        if actual_inputs != expected_inputs {
            return bad_parameters("Wrong number of inputs");
        }
        let flow = if optional_bool(params, "use_ae_signatures") {
            BitcoinSignTxFlow::Staged
        } else {
            BitcoinSignTxFlow::Legacy
        };

        self.sign_tx = Some(BitcoinSignTxSession {
            txn,
            expected_inputs,
            received_inputs: 0,
            next_signature: 0,
            flow,
            inputs: Vec::with_capacity(expected_inputs),
        });
        V1Outcome::BoolResult { result: true }
    }

    fn tx_input_result(&mut self, request: &Request<'_>) -> V1Outcome {
        if self.sign_tx.is_none() {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Unexpected method".to_string(),
            };
        }
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let input = match parse_bitcoin_tx_input_params(params) {
            Ok(input) => input,
            Err(message) => return bad_parameters(message),
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Wallet seed is not available".to_string(),
            };
        };
        let session = self
            .sign_tx
            .as_mut()
            .expect("checked active sign_tx session");
        if session.received_inputs >= session.expected_inputs {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Too many tx_input messages".to_string(),
            };
        }
        let tx_input_index = session.received_inputs;
        let ae_signer_commitment = if let Some(host_commitment) = input.ae_host_commitment.as_ref()
        {
            if session.flow != BitcoinSignTxFlow::Staged {
                return bad_parameters("Failed to extract valid host commitment from parameters");
            }
            match bitcoin_tx_signer_commitment(
                &session.txn,
                seed,
                tx_input_index,
                &input,
                host_commitment,
            ) {
                Ok(commitment) => commitment,
                Err(jade_crypto::TxSignError::Invalid) => {
                    return bad_parameters("Failed to extract tx input from parameters");
                }
                Err(jade_crypto::TxSignError::Unsupported) => {
                    return V1Outcome::DeferredToCore {
                        method: "sign_tx signing".to_string(),
                    };
                }
            }
        } else {
            Vec::new()
        };
        session.received_inputs += 1;

        match session.flow {
            BitcoinSignTxFlow::Legacy => {
                let signature = sign_bitcoin_tx_input(&session.txn, seed, tx_input_index, &input)
                    .map_err(|err| match err {
                        jade_crypto::TxSignError::Invalid => {
                            bad_parameters("Failed to extract tx input from parameters")
                        }
                        jade_crypto::TxSignError::Unsupported => V1Outcome::DeferredToCore {
                            method: "sign_tx signing".to_string(),
                        },
                    });
                if session.received_inputs == session.expected_inputs {
                    self.sign_tx = None;
                }
                match signature {
                    Ok(signature) => V1Outcome::BytesResult { result: signature },
                    Err(outcome) => outcome,
                }
            }
            BitcoinSignTxFlow::Staged => {
                session.inputs.push(input);
                V1Outcome::BytesResult {
                    result: ae_signer_commitment,
                }
            }
        }
    }

    fn get_signature_result(&mut self, request: &Request<'_>) -> V1Outcome {
        if self.sign_tx.is_none() && self.sign_message_ae.is_some() {
            return self.get_message_signature_result(request);
        }

        let Some(session) = self.sign_tx.as_ref() else {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Unexpected method".to_string(),
            };
        };
        if session.flow != BitcoinSignTxFlow::Staged
            || session.received_inputs < session.expected_inputs
        {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Unexpected method".to_string(),
            };
        }
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let ae_host_entropy = match cbor_map_bytes_or_null(params.raw(), "ae_host_entropy") {
            Ok(value) => value,
            Err(()) => {
                return V1Outcome::Reject {
                    code: ErrorCode::ProtocolError,
                    message: "Failed to extract valid host entropy from parameters".to_string(),
                };
            }
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Wallet seed is not available".to_string(),
            };
        };
        let session = self
            .sign_tx
            .as_mut()
            .expect("checked active sign_tx session");
        let signature_index = session.next_signature;
        let Some(input) = session.inputs.get(signature_index).cloned() else {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Unexpected method".to_string(),
            };
        };
        if input.path.is_some()
            && ae_host_entropy.is_some_and(|entropy| {
                !entropy.is_empty() && entropy.len() != jade_crypto::SHA256_LEN
            })
        {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Failed to extract valid host entropy from parameters".to_string(),
            };
        }
        let signature = if input.path.is_none() {
            Vec::new()
        } else if input.ae_host_commitment.is_some() {
            let host_entropy = match ae_host_entropy {
                Some(entropy) if entropy.len() == jade_crypto::SHA256_LEN => {
                    let mut bytes = [0u8; jade_crypto::SHA256_LEN];
                    bytes.copy_from_slice(entropy);
                    bytes
                }
                _ => {
                    return V1Outcome::Reject {
                        code: ErrorCode::ProtocolError,
                        message:
                            "Failed to extract valid host commitment and entropy from parameters"
                                .to_string(),
                    };
                }
            };
            match sign_bitcoin_tx_input_anti_exfil(
                &session.txn,
                seed,
                signature_index,
                &input,
                &host_entropy,
            ) {
                Ok(signature) => signature,
                Err(jade_crypto::TxSignError::Invalid) => {
                    return bad_parameters("Failed to extract tx input from parameters");
                }
                Err(jade_crypto::TxSignError::Unsupported) => {
                    return V1Outcome::DeferredToCore {
                        method: "sign_tx signing".to_string(),
                    };
                }
            }
        } else {
            if ae_host_entropy.is_some_and(|entropy| !entropy.is_empty()) {
                return V1Outcome::Reject {
                    code: ErrorCode::ProtocolError,
                    message: "Failed to extract valid host commitment and entropy from parameters"
                        .to_string(),
                };
            }
            let signatures = match sign_bitcoin_tx_inputs(&session.txn, seed, &session.inputs) {
                Ok(signatures) => signatures,
                Err(jade_crypto::TxSignError::Invalid) => {
                    return bad_parameters("Failed to extract tx input from parameters");
                }
                Err(jade_crypto::TxSignError::Unsupported) => {
                    return V1Outcome::DeferredToCore {
                        method: "sign_tx signing".to_string(),
                    };
                }
            };
            let Some(signature) = signatures.get(signature_index).cloned() else {
                return V1Outcome::Reject {
                    code: ErrorCode::ProtocolError,
                    message: "Unexpected method".to_string(),
                };
            };
            signature
        };
        session.next_signature += 1;
        if session.next_signature == session.expected_inputs {
            self.sign_tx = None;
        }

        V1Outcome::BytesResult { result: signature }
    }

    fn get_message_signature_result(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            self.sign_message_ae = None;
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let host_entropy = match params.bytes("ae_host_entropy") {
            Ok(Some(entropy)) if entropy.len() == jade_crypto::SHA256_LEN => {
                let mut bytes = [0u8; jade_crypto::SHA256_LEN];
                bytes.copy_from_slice(entropy);
                bytes
            }
            Ok(_) | Err(_) => {
                self.sign_message_ae = None;
                return bad_parameters("Failed to extract host entropy from parameters");
            }
        };
        let Some(session) = self.sign_message_ae.take() else {
            return V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Unexpected method".to_string(),
            };
        };
        let Some(seed) = self.platform.wallet_seed() else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Wallet seed is not available".to_string(),
            };
        };

        match jade_crypto::pure_rust::sign_bitcoin_message_anti_exfil_from_seed(
            seed,
            &session.path,
            &session.message,
            &host_entropy,
        ) {
            Some(result) => V1Outcome::TextResult { result },
            None => V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to sign message".to_string(),
            },
        }
    }

    fn sign_psbt_result(&self, request: &Request<'_>) -> V1Outcome {
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
        let psbt = match psbt_param_bytes(params) {
            Ok(psbt) if !psbt.is_empty() => psbt,
            Ok(_) | Err(()) => return bad_parameters("Failed to extract psbt from parameters"),
        };
        match jade_crypto::psbt_envelope(&psbt) {
            Some(jade_crypto::PsbtEnvelope::Bitcoin) if !is_liquid => {}
            Some(jade_crypto::PsbtEnvelope::Liquid) if is_liquid => {}
            Some(_) => return bad_parameters("Network/psbt type mismatch"),
            None => return bad_parameters("Failed to extract psbt from parameters"),
        }

        let Some(seed) = self.platform.wallet_seed() else {
            return V1Outcome::BytesResult { result: psbt };
        };
        let Some(fingerprint) = wallet_fingerprint_from_seed(seed) else {
            return V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Failed to inspect psbt signing paths".to_string(),
            };
        };
        if !is_liquid {
            match jade_crypto::pure_rust::sign_bitcoin_psbt_singlesig_from_seed(
                &psbt,
                seed,
                &fingerprint,
            ) {
                Ok(Some(result)) => return V1Outcome::BytesResult { result },
                Ok(None) => return V1Outcome::BytesResult { result: psbt },
                Err(jade_crypto::PsbtSignError::Invalid) => {
                    return bad_parameters("Failed to extract psbt from parameters");
                }
                Err(jade_crypto::PsbtSignError::Unsupported) => {}
            }
        }
        match jade_crypto::psbt_needs_wallet_signature(&psbt, &fingerprint) {
            Ok(false) => V1Outcome::BytesResult { result: psbt },
            Ok(true) => V1Outcome::DeferredToCore {
                method: "sign_psbt signing".to_string(),
            },
            Err(_) => bad_parameters("Failed to extract psbt from parameters"),
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

    fn commitments_result(&self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };
        let _asset_id = match params.bytes("asset_id") {
            Ok(Some(asset_id)) if asset_id.len() == jade_crypto::SHA256_LEN => {
                let mut bytes = [0u8; jade_crypto::SHA256_LEN];
                bytes.copy_from_slice(asset_id);
                bytes
            }
            Ok(_) | Err(_) => return bad_parameters("Failed to extract asset_id from parameters"),
        };
        let _value = match params.u64("value") {
            Ok(Some(value)) => value,
            Ok(None) | Err(_) => return bad_parameters("Failed to extract value from parameters"),
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
        let vbf = match cbor_map_bytes_or_null(params.raw(), "vbf") {
            Ok(Some(vbf)) if vbf.len() == jade_crypto::SHA256_LEN => {
                let mut bytes = [0u8; jade_crypto::SHA256_LEN];
                bytes.copy_from_slice(vbf);
                Some(bytes)
            }
            Ok(Some(_)) | Err(()) => {
                return bad_parameters("Failed to extract vbf from parameters")
            }
            Ok(None) => None,
        };
        let master_unblinding_key = match self.master_unblinding_key_for_params(params) {
            Ok(key) => key,
            Err(outcome) => return outcome,
        };
        let kind = if vbf.is_some() {
            jade_crypto::BlindingFactorKind::Asset
        } else {
            jade_crypto::BlindingFactorKind::AssetAndValue
        };
        let Some(_blinding_factor) = jade_crypto::pure_rust::deterministic_blinding_factor(
            &master_unblinding_key,
            &hash_prevouts,
            output_index,
            kind,
        ) else {
            return bad_parameters("Failed to compute abf/vbf from the parameters");
        };

        V1Outcome::DeferredToCore {
            method: "get_commitments commitments".to_string(),
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

    fn register_attestation_result(&self, request: &Request<'_>) -> V1Outcome {
        if request.params().is_none() {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        }

        V1Outcome::Reject {
            code: ErrorCode::InternalError,
            message: "Attestation not supported".to_string(),
        }
    }

    fn sign_attestation_result(&self, request: &Request<'_>) -> V1Outcome {
        if request.params().is_none() {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        }

        V1Outcome::Reject {
            code: ErrorCode::InternalError,
            message: "Attestation not supported".to_string(),
        }
    }

    fn auth_user_result(&mut self, request: &Request<'_>) -> V1Outcome {
        let Some(params) = request.params() else {
            return V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            };
        };

        match params.str("network") {
            Ok(Some(network)) if valid_network_name(network) => {}
            Ok(_) | Err(_) => {
                return bad_parameters("Failed to extract valid network from parameters");
            }
        }
        if params.contains("epoch").unwrap_or(false) {
            let epoch = match params.u64("epoch") {
                Ok(Some(epoch)) => epoch,
                Ok(None) | Err(_) => {
                    return bad_parameters("Failed to extract valid epoch value from parameters");
                }
            };
            if let Err(err) = self.state.set_epoch(&mut self.platform, epoch) {
                return reject_core_error(err);
            }
        }
        let _suppress_pin_change_confirmation =
            optional_bool(params, "suppress_pin_change_confirmation");

        if self.platform.wallet_seed().is_some() {
            if self.state.wallet != WalletLifecycle::Temporary {
                self.state.wallet = WalletLifecycle::Ready;
            }
            V1Outcome::BoolResult { result: true }
        } else {
            V1Outcome::BoolResult { result: false }
        }
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

fn current_unix_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn split_once_byte(value: &str, byte: u8) -> Option<(&str, &str)> {
    let index = value.as_bytes().iter().position(|item| *item == byte)?;
    Some((&value[..index], &value[index + 1..]))
}

fn parse_decimal_u64(value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }

    value.bytes().try_fold(0u64, |acc, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        acc.checked_mul(10)?.checked_add((byte - b'0') as u64)
    })
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

fn psbt_param_bytes(params: jade_protocol_v1::Params<'_>) -> Result<Vec<u8>, ()> {
    if let Ok(Some(bytes)) = params.bytes("psbt") {
        return Ok(bytes.to_vec());
    }
    if let Ok(Some(text)) = params.str("psbt") {
        return base64_decode(text);
    }
    Err(())
}

fn base64_decode(text: &str) -> Result<Vec<u8>, ()> {
    if text.is_empty() || text.len() % 4 != 0 {
        return Err(());
    }
    let mut output = Vec::with_capacity(text.len() / 4 * 3);
    let num_chunks = text.len() / 4;
    for (chunk_index, chunk) in text.as_bytes().chunks_exact(4).enumerate() {
        let mut values = [0u8; 4];
        let mut padding = 0usize;
        for (index, byte) in chunk.iter().copied().enumerate() {
            values[index] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if index >= 2 => {
                    padding += 1;
                    0
                }
                _ => return Err(()),
            };
        }
        if padding > 2
            || (padding > 0 && chunk[3] != b'=')
            || (padding > 0 && chunk_index + 1 != num_chunks)
        {
            return Err(());
        }
        let bits = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | values[3] as u32;
        output.push((bits >> 16) as u8);
        if padding < 2 {
            output.push((bits >> 8) as u8);
        }
        if padding == 0 {
            output.push(bits as u8);
        }
    }
    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedMultisigFile {
    name: String,
    variant: MultisigVariant,
    sorted: bool,
    threshold: u8,
    master_blinding_key: Option<[u8; jade_storage::MULTISIG_MASTER_BLINDING_KEY_SIZE]>,
    signers: Vec<MultisigSignerDetails>,
}

const MULTISIG_FILE_FIELD_NAME: u8 = 0x01;
const MULTISIG_FILE_FIELD_POLICY: u8 = 0x02;
const MULTISIG_FILE_FIELD_FORMAT: u8 = 0x04;
const MULTISIG_FILE_FIELD_SORTED: u8 = 0x08;
const MULTISIG_FILE_FIELD_BLINDING_KEY: u8 = 0x10;
const MULTISIG_FILE_FIELD_DERIVATION: u8 = 0x20;
const MULTISIG_FILE_REQUIRED_FIELDS: u8 = MULTISIG_FILE_FIELD_NAME
    | MULTISIG_FILE_FIELD_POLICY
    | MULTISIG_FILE_FIELD_FORMAT
    | MULTISIG_FILE_FIELD_DERIVATION;

fn parse_multisig_file(
    multisig_file: &str,
    network: jade_crypto::BitcoinNetwork,
) -> Result<ParsedMultisigFile, &'static str> {
    let mut fields_read = 0u8;
    let mut name = String::new();
    let mut variant = None;
    let mut sorted = true;
    let mut threshold = 0u8;
    let mut expected_signers = 0usize;
    let mut master_blinding_key = None;
    let mut derivation = Vec::new();
    let mut signers = Vec::new();

    for line in multisig_file.split('\n') {
        if line.is_empty() || line.as_bytes().first() == Some(&b'#') {
            continue;
        }

        let (field, value) = split_multisig_file_line(line)?;
        if field.eq_ignore_ascii_case("Name") {
            if fields_read & MULTISIG_FILE_FIELD_NAME != 0 {
                return Err("Invalid multisig file");
            }
            name = parse_multisig_file_name(value)?;
            fields_read |= MULTISIG_FILE_FIELD_NAME;
        } else if field.eq_ignore_ascii_case("Policy") {
            if fields_read & MULTISIG_FILE_FIELD_POLICY != 0 {
                return Err("Invalid multisig file");
            }
            (threshold, expected_signers) = parse_multisig_file_policy(value)?;
            fields_read |= MULTISIG_FILE_FIELD_POLICY;
        } else if field.eq_ignore_ascii_case("Format") {
            if fields_read & MULTISIG_FILE_FIELD_FORMAT != 0 {
                return Err("Invalid multisig file");
            }
            variant = Some(parse_multisig_file_format(value)?);
            fields_read |= MULTISIG_FILE_FIELD_FORMAT;
        } else if field.eq_ignore_ascii_case("Sorted") {
            if fields_read & MULTISIG_FILE_FIELD_SORTED != 0 {
                return Err("Invalid multisig file");
            }
            sorted = parse_multisig_file_sorted(value)?;
            fields_read |= MULTISIG_FILE_FIELD_SORTED;
        } else if field.eq_ignore_ascii_case("BlindingKey") {
            if fields_read & MULTISIG_FILE_FIELD_BLINDING_KEY != 0 {
                return Err("Invalid multisig file");
            }
            master_blinding_key = Some(
                decode_hex_fixed::<{ jade_storage::MULTISIG_MASTER_BLINDING_KEY_SIZE }>(value)
                    .ok_or("Invalid master blinding key")?,
            );
            fields_read |= MULTISIG_FILE_FIELD_BLINDING_KEY;
        } else if field.eq_ignore_ascii_case("Derivation") {
            derivation = JadeDerivationPath::parse(value)
                .map_err(|_| "Invalid derivation path")?
                .to_u32_vec();
            fields_read |= MULTISIG_FILE_FIELD_DERIVATION;
        } else if field.len() == 8 {
            if fields_read & MULTISIG_FILE_REQUIRED_FIELDS != MULTISIG_FILE_REQUIRED_FIELDS {
                return Err("Insufficient information records");
            }
            if signers.len() >= expected_signers || expected_signers == 0 {
                return Err("Invalid number of signers");
            }
            let fingerprint = decode_hex_fixed::<4>(field).ok_or("Invalid signer fingerprint")?;
            let xpub = parse_multisig_file_xpub(value, network).ok_or("Invalid signer xpub")?;
            signers.push(MultisigSignerDetails {
                fingerprint,
                derivation: derivation.clone(),
                xpub,
                path: Vec::new(),
            });
        } else {
            return Err("Invalid multisig file");
        }
    }

    if fields_read & MULTISIG_FILE_REQUIRED_FIELDS != MULTISIG_FILE_REQUIRED_FIELDS {
        return Err("Insufficient information records");
    }
    if signers.len() != expected_signers || expected_signers == 0 {
        return Err("Invalid number of signers");
    }

    Ok(ParsedMultisigFile {
        name,
        variant: variant.ok_or("Insufficient information records")?,
        sorted,
        threshold,
        master_blinding_key,
        signers,
    })
}

fn split_multisig_file_line(line: &str) -> Result<(&str, &str), &'static str> {
    let Some(delimiter) = line.as_bytes().iter().position(|byte| *byte == b':') else {
        return Err("Invalid multisig file");
    };
    if delimiter == 0 {
        return Err("Invalid multisig file");
    }

    let mut value_start = delimiter + 1;
    while value_start < line.len() && line.as_bytes()[value_start].is_ascii_whitespace() {
        value_start += 1;
    }
    let value = &line[value_start..];
    if value.is_empty() || value.len() >= 128 {
        return Err("Invalid multisig file");
    }

    Ok((&line[..delimiter], value))
}

fn parse_multisig_file_name(value: &str) -> Result<String, &'static str> {
    let mut sanitized = Vec::with_capacity(value.len().min(jade_storage::MAX_KEY_NAME_LEN));
    for byte in value
        .as_bytes()
        .iter()
        .copied()
        .take(jade_storage::MAX_KEY_NAME_LEN)
    {
        sanitized.push(if byte.is_ascii_whitespace() {
            b'_'
        } else {
            byte
        });
    }
    let name = String::from_utf8(sanitized).map_err(|_| "Invalid multisig name")?;
    if key_name_valid(&name) {
        Ok(name)
    } else {
        Err("Invalid multisig name")
    }
}

fn parse_multisig_file_policy(value: &str) -> Result<(u8, usize), &'static str> {
    let parts: Vec<&str> = value.split(' ').collect();
    if parts.len() != 3 || !parts[1].eq_ignore_ascii_case("of") {
        return Err("Invalid multisig policy");
    }
    let threshold = parse_decimal_u64(parts[0]).ok_or("Invalid multisig policy")?;
    let signers = parse_decimal_u64(parts[2]).ok_or("Invalid multisig policy")?;
    if threshold == 0
        || signers == 0
        || threshold > signers
        || signers > jade_storage::MAX_ALLOWED_SIGNERS as u64
    {
        return Err("Invalid multisig policy");
    }
    Ok((threshold as u8, signers as usize))
}

fn parse_multisig_file_format(value: &str) -> Result<MultisigVariant, &'static str> {
    if value.eq_ignore_ascii_case("P2WSH") {
        Ok(MultisigVariant::P2wsh)
    } else if value.eq_ignore_ascii_case("P2SH") {
        Ok(MultisigVariant::P2sh)
    } else if value.eq_ignore_ascii_case("P2WSH-P2SH") || value.eq_ignore_ascii_case("P2SH-P2WSH") {
        Ok(MultisigVariant::P2wshP2sh)
    } else {
        Err("Invalid multisig format")
    }
}

fn parse_multisig_file_sorted(value: &str) -> Result<bool, &'static str> {
    if value.eq_ignore_ascii_case("TRUE") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("FALSE") {
        Ok(false)
    } else {
        Err("Invalid sorted flag")
    }
}

fn parse_multisig_file_xpub(
    value: &str,
    network: jade_crypto::BitcoinNetwork,
) -> Option<[u8; jade_storage::BIP32_SERIALIZED_LEN]> {
    let mut xpub: [u8; jade_storage::BIP32_SERIALIZED_LEN] =
        base58ck::decode_check(value).ok()?.try_into().ok()?;
    xpub[..4].copy_from_slice(&xpub_version_bytes(network));
    Some(xpub)
}

fn xpub_version_bytes(network: jade_crypto::BitcoinNetwork) -> [u8; 4] {
    match network {
        jade_crypto::BitcoinNetwork::Main => 0x0488_b21eu32.to_be_bytes(),
        jade_crypto::BitcoinNetwork::Test | jade_crypto::BitcoinNetwork::Regtest => {
            0x0435_87cfu32.to_be_bytes()
        }
    }
}

fn decode_hex_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex_nibble_value(value.as_bytes()[index * 2])?;
        let low = hex_nibble_value(value.as_bytes()[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Some(out)
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BitcoinTxInputParams {
    path: Option<Vec<u32>>,
    script: Option<Vec<u8>>,
    sighash: u32,
    is_witness: bool,
    satoshi: Option<u64>,
    input_tx: Option<Vec<u8>>,
    ae_host_commitment: Option<[u8; jade_crypto::SHA256_LEN]>,
}

fn parse_bitcoin_tx_input_params(
    params: jade_protocol_v1::Params<'_>,
) -> Result<BitcoinTxInputParams, &'static str> {
    let is_witness = match params.bool("is_witness") {
        Ok(Some(value)) => value,
        Ok(None) | Err(_) => return Err("Failed to extract is_witness from parameters"),
    };
    let path = match params.u32_array("path", MAX_PATH_LEN) {
        Ok(Some(path)) if !path.is_empty() => Some(path),
        Ok(Some(_)) | Err(_) => return Err("Failed to extract path from parameters"),
        Ok(None) => None,
    };
    let script = if path.is_some() {
        match params.bytes("script") {
            Ok(Some(script)) if !script.is_empty() => Some(script.to_vec()),
            Ok(_) | Err(_) => return Err("Failed to extract script from parameters"),
        }
    } else {
        None
    };
    let sighash = match params.u64("sighash") {
        Ok(Some(sighash)) if sighash <= u32::MAX as u64 => sighash as u32,
        Ok(None) if script.as_deref().is_some_and(is_taproot_script_pubkey) => 0,
        Ok(None) => 1,
        Ok(Some(_)) | Err(_) => return Err("Failed to extract sighash from parameters"),
    };
    let satoshi = match params.u64("satoshi") {
        Ok(value) => value,
        Err(_) => return Err("Failed to extract satoshi from parameters"),
    };
    let input_tx = match cbor_map_bytes_or_null(params.raw(), "input_tx") {
        Ok(Some(input_tx)) if !input_tx.is_empty() => Some(input_tx.to_vec()),
        Ok(Some(_)) | Ok(None) => None,
        Err(()) => return Err("Failed to extract input_tx from parameters"),
    };
    let ae_host_commitment = if path.is_some() {
        match cbor_map_bytes_or_null(params.raw(), "ae_host_commitment") {
            Ok(Some(commitment)) if commitment.len() == jade_crypto::SHA256_LEN => {
                let mut bytes = [0u8; jade_crypto::SHA256_LEN];
                bytes.copy_from_slice(commitment);
                Some(bytes)
            }
            Ok(Some(commitment)) if commitment.is_empty() => None,
            Ok(Some(_)) | Err(()) => {
                return Err("Failed to extract valid host commitment from parameters")
            }
            Ok(None) => None,
        }
    } else {
        None
    };
    if ae_host_commitment.is_some() && script.as_deref().is_some_and(is_taproot_script_pubkey) {
        return Err("Invalid non-empty taproot host commitment");
    }

    Ok(BitcoinTxInputParams {
        path,
        script,
        sighash,
        is_witness,
        satoshi,
        input_tx,
        ae_host_commitment,
    })
}

fn sign_bitcoin_tx_input(
    txn: &[u8],
    seed: &[u8],
    tx_input_index: usize,
    input: &BitcoinTxInputParams,
) -> Result<Vec<u8>, jade_crypto::TxSignError> {
    let Some(signing_input) = bitcoin_tx_sign_input(txn, tx_input_index, input)? else {
        return Ok(Vec::new());
    };
    let mut signatures =
        jade_crypto::pure_rust::sign_bitcoin_tx_from_seed(txn, seed, &[signing_input])?;
    Ok(signatures.remove(0))
}

fn bitcoin_tx_signer_commitment(
    txn: &[u8],
    seed: &[u8],
    tx_input_index: usize,
    input: &BitcoinTxInputParams,
    host_commitment: &[u8; jade_crypto::SHA256_LEN],
) -> Result<Vec<u8>, jade_crypto::TxSignError> {
    let Some(signing_input) = bitcoin_tx_sign_input(txn, tx_input_index, input)? else {
        return Ok(Vec::new());
    };
    jade_crypto::pure_rust::bitcoin_tx_anti_exfil_signer_commitment_from_seed(
        txn,
        seed,
        &signing_input,
        host_commitment,
    )
}

fn sign_bitcoin_tx_input_anti_exfil(
    txn: &[u8],
    seed: &[u8],
    tx_input_index: usize,
    input: &BitcoinTxInputParams,
    host_entropy: &[u8; jade_crypto::SHA256_LEN],
) -> Result<Vec<u8>, jade_crypto::TxSignError> {
    let Some(signing_input) = bitcoin_tx_sign_input(txn, tx_input_index, input)? else {
        return Ok(Vec::new());
    };
    jade_crypto::pure_rust::sign_bitcoin_tx_anti_exfil_from_seed(
        txn,
        seed,
        &signing_input,
        host_entropy,
    )
}

fn sign_bitcoin_tx_inputs(
    txn: &[u8],
    seed: &[u8],
    inputs: &[BitcoinTxInputParams],
) -> Result<Vec<Vec<u8>>, jade_crypto::TxSignError> {
    let mut signing_inputs = Vec::with_capacity(inputs.len());
    let mut signing_indexes = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        if let Some(signing_input) = bitcoin_tx_sign_input(txn, index, input)? {
            signing_indexes.push(index);
            signing_inputs.push(signing_input);
        }
    }
    if signing_inputs.is_empty() {
        return Ok(vec![Vec::new(); inputs.len()]);
    }
    let signatures = jade_crypto::pure_rust::sign_bitcoin_tx_from_seed(txn, seed, &signing_inputs)?;
    if signatures.len() != signing_indexes.len() {
        return Err(jade_crypto::TxSignError::Invalid);
    }

    let mut ordered = vec![Vec::new(); inputs.len()];
    for (index, signature) in signing_indexes.into_iter().zip(signatures) {
        ordered[index] = signature;
    }
    Ok(ordered)
}

fn bitcoin_tx_sign_input<'a>(
    txn: &[u8],
    tx_input_index: usize,
    input: &'a BitcoinTxInputParams,
) -> Result<Option<jade_crypto::pure_rust::BitcoinTxSignInput<'a>>, jade_crypto::TxSignError> {
    let Some(path) = input.path.as_deref() else {
        return Ok(None);
    };
    let script = input
        .script
        .as_deref()
        .ok_or(jade_crypto::TxSignError::Invalid)?;
    let satoshi = match (input.satoshi, input.input_tx.as_deref()) {
        (Some(satoshi), _) => Some(satoshi),
        (None, Some(input_tx)) => Some(jade_crypto::pure_rust::bitcoin_prevout_amount(
            txn,
            tx_input_index,
            input_tx,
        )?),
        (None, None) => None,
    };
    Ok(Some(jade_crypto::pure_rust::BitcoinTxSignInput {
        tx_input_index,
        path,
        script_code: script,
        sighash: input.sighash,
        is_witness: input.is_witness,
        satoshi,
    }))
}

fn is_taproot_script_pubkey(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x51 && script[1] == jade_crypto::SHA256_LEN as u8
}

fn cbor_map_field<'a>(raw: &'a [u8], field: &str) -> Result<Option<&'a [u8]>, ()> {
    let mut decoder = Decoder::new(raw);
    let Some(len) = decoder.map().map_err(|_| ())? else {
        return Err(());
    };

    for _ in 0..len {
        match decoder.datatype().map_err(|_| ())? {
            Type::String => {
                let key = decoder.str().map_err(|_| ())?;
                let start = decoder.position();
                decoder.skip().map_err(|_| ())?;
                if key == field {
                    return Ok(Some(&raw[start..decoder.position()]));
                }
            }
            _ => {
                decoder.skip().map_err(|_| ())?;
                decoder.skip().map_err(|_| ())?;
            }
        }
    }

    Ok(None)
}

fn cbor_map_bool(raw: &[u8], field: &str) -> Result<Option<bool>, ()> {
    cbor_map_field(raw, field)?.map(cbor_bool).transpose()
}

fn cbor_map_u64(raw: &[u8], field: &str) -> Result<Option<u64>, ()> {
    cbor_map_field(raw, field)?.map(cbor_u64).transpose()
}

fn cbor_map_str<'a>(raw: &'a [u8], field: &str) -> Result<Option<&'a str>, ()> {
    cbor_map_field(raw, field)?.map(cbor_str).transpose()
}

fn cbor_map_bytes<'a>(raw: &'a [u8], field: &str) -> Result<Option<&'a [u8]>, ()> {
    cbor_map_field(raw, field)?.map(cbor_bytes).transpose()
}

fn cbor_map_bytes_or_null<'a>(raw: &'a [u8], field: &str) -> Result<Option<&'a [u8]>, ()> {
    match cbor_map_field(raw, field)? {
        Some(value) => cbor_bytes_or_null(value),
        None => Ok(None),
    }
}

fn cbor_bool(raw: &[u8]) -> Result<bool, ()> {
    let mut decoder = Decoder::new(raw);
    let value = decoder.bool().map_err(|_| ())?;
    if decoder.position() == raw.len() {
        Ok(value)
    } else {
        Err(())
    }
}

fn cbor_u64(raw: &[u8]) -> Result<u64, ()> {
    let mut decoder = Decoder::new(raw);
    let value = decoder.u64().map_err(|_| ())?;
    if decoder.position() == raw.len() {
        Ok(value)
    } else {
        Err(())
    }
}

fn cbor_str(raw: &[u8]) -> Result<&str, ()> {
    let mut decoder = Decoder::new(raw);
    let value = decoder.str().map_err(|_| ())?;
    if decoder.position() == raw.len() {
        Ok(value)
    } else {
        Err(())
    }
}

fn cbor_bytes(raw: &[u8]) -> Result<&[u8], ()> {
    let mut decoder = Decoder::new(raw);
    let value = decoder.bytes().map_err(|_| ())?;
    if decoder.position() == raw.len() {
        Ok(value)
    } else {
        Err(())
    }
}

fn cbor_bytes_or_null(raw: &[u8]) -> Result<Option<&[u8]>, ()> {
    let mut decoder = Decoder::new(raw);
    let value = match decoder.datatype().map_err(|_| ())? {
        Type::Null => {
            decoder.null().map_err(|_| ())?;
            None
        }
        Type::Bytes => Some(decoder.bytes().map_err(|_| ())?),
        _ => return Err(()),
    };
    if decoder.position() == raw.len() {
        Ok(value)
    } else {
        Err(())
    }
}

fn cbor_u32_array(raw: &[u8], max_len: usize) -> Result<Vec<u32>, ()> {
    let mut decoder = Decoder::new(raw);
    let Some(len) = decoder.array().map_err(|_| ())? else {
        return Err(());
    };
    if len as usize > max_len {
        return Err(());
    }

    let mut values = Vec::with_capacity(len as usize);
    for _ in 0..len {
        values.push(decoder.u32().map_err(|_| ())?);
    }
    if decoder.position() == raw.len() {
        Ok(values)
    } else {
        Err(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bip85RsaKeyParams {
    key_bits: u32,
}

fn parse_bip85_rsa_key_params(
    params: jade_protocol_v1::Params<'_>,
) -> Result<Bip85RsaKeyParams, &'static str> {
    match params.str("key_type") {
        Ok(Some("RSA")) => {}
        Ok(_) | Err(_) => return Err("Cannot extract valid key_type from parameters"),
    }
    let key_bits = match params.u64("key_bits") {
        Ok(Some(key_bits)) if valid_rsa_generation_key_bits(key_bits) => key_bits as u32,
        Ok(_) | Err(_) => return Err("Failed to fetch valid key length from message"),
    };
    match params.u64("index") {
        Ok(Some(index)) if index <= 0x7fff_ffff => {}
        Ok(_) | Err(_) => return Err("Failed to fetch valid index from message"),
    };

    Ok(Bip85RsaKeyParams { key_bits })
}

fn decode_digest_array(
    digests_raw: Option<&[u8]>,
) -> Result<Vec<[u8; jade_crypto::SHA256_LEN]>, ()> {
    let digests_raw = digests_raw.ok_or(())?;
    let mut decoder = Decoder::new(digests_raw);
    let Some(len) = decoder.array().map_err(|_| ())? else {
        return Err(());
    };
    if len == 0 {
        return Err(());
    }

    let mut digests = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let bytes = decoder.bytes().map_err(|_| ())?;
        let digest: [u8; jade_crypto::SHA256_LEN] = bytes.try_into().map_err(|_| ())?;
        digests.push(digest);
    }
    if decoder.position() != digests_raw.len() {
        return Err(());
    }

    Ok(digests)
}

fn decode_registration_signers(
    signers_raw: Option<&[u8]>,
) -> Result<Vec<MultisigSignerDetails>, ()> {
    let signers_raw = signers_raw.ok_or(())?;
    let mut decoder = Decoder::new(signers_raw);
    let Some(len) = decoder.array().map_err(|_| ())? else {
        return Err(());
    };
    if len == 0 || len as usize > jade_storage::MAX_ALLOWED_SIGNERS {
        return Err(());
    }

    let mut signers = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let start = decoder.position();
        decoder.skip().map_err(|_| ())?;
        let raw = &signers_raw[start..decoder.position()];
        let fingerprint = cbor_map_bytes(raw, "fingerprint")?
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(())?;
        let derivation = cbor_map_field(raw, "derivation")?
            .map(|raw| cbor_u32_array(raw, MAX_PATH_LEN))
            .transpose()?
            .ok_or(())?;
        let xpub = cbor_map_str(raw, "xpub")?
            .and_then(|xpub| base58ck::decode_check(xpub).ok())
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(())?;
        let path = cbor_map_field(raw, "path")?
            .map(|raw| cbor_u32_array(raw, MAX_PATH_LEN))
            .transpose()?
            .ok_or(())?;
        signers.push(MultisigSignerDetails {
            fingerprint,
            derivation,
            xpub,
            path,
        });
    }
    if decoder.position() != signers_raw.len() {
        return Err(());
    }

    Ok(signers)
}

fn decode_descriptor_datavalues(raw: Option<&[u8]>) -> Result<Vec<DescriptorDataValue>, ()> {
    let raw = raw.ok_or(())?;
    let mut decoder = Decoder::new(raw);
    let Some(len) = decoder.map().map_err(|_| ())? else {
        return Err(());
    };
    if len == 0 || len as usize > jade_storage::MAX_ALLOWED_SIGNERS {
        return Err(());
    }

    let mut datavalues = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let key = decoder.str().map_err(|_| ())?;
        let value = decoder.str().map_err(|_| ())?;
        if key.is_empty() || key.len() >= 16 || value.is_empty() || value.len() >= 160 {
            return Err(());
        }
        datavalues.push(DescriptorDataValue {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
    if decoder.position() != raw.len() {
        return Err(());
    }

    Ok(datavalues)
}

fn nested_u32_arrays(
    params: jade_protocol_v1::Params<'_>,
    field: &str,
    max_outer_len: usize,
    max_inner_len: usize,
) -> Result<Option<Vec<Vec<u32>>>, ()> {
    let mut decoder = Decoder::new(params.raw());
    let Some(len) = decoder.map().map_err(|_| ())? else {
        return Err(());
    };

    for _ in 0..len {
        match decoder.datatype().map_err(|_| ())? {
            Type::String => {
                let key = decoder.str().map_err(|_| ())?;
                if key != field {
                    decoder.skip().map_err(|_| ())?;
                    continue;
                }

                let Some(outer_len) = decoder.array().map_err(|_| ())? else {
                    return Err(());
                };
                if outer_len as usize > max_outer_len {
                    return Err(());
                }

                let mut outer = Vec::with_capacity(outer_len as usize);
                for _ in 0..outer_len {
                    let Some(inner_len) = decoder.array().map_err(|_| ())? else {
                        return Err(());
                    };
                    if inner_len == 0 || inner_len as usize > max_inner_len {
                        return Err(());
                    }

                    let mut inner = Vec::with_capacity(inner_len as usize);
                    for _ in 0..inner_len {
                        inner.push(decoder.u32().map_err(|_| ())?);
                    }
                    outer.push(inner);
                }
                return Ok(Some(outer));
            }
            _ => {
                decoder.skip().map_err(|_| ())?;
                decoder.skip().map_err(|_| ())?;
            }
        }
    }

    Ok(None)
}

fn crypto_multisig_variant(variant: MultisigVariant) -> jade_crypto::MultisigScriptVariant {
    match variant {
        MultisigVariant::P2wsh => jade_crypto::MultisigScriptVariant::P2wsh,
        MultisigVariant::P2sh => jade_crypto::MultisigScriptVariant::P2sh,
        MultisigVariant::P2wshP2sh => jade_crypto::MultisigScriptVariant::P2wshP2sh,
    }
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

fn liquid_network_for_name(network: &str) -> Option<jade_crypto::LiquidNetwork> {
    match network {
        "liquid" => Some(jade_crypto::LiquidNetwork::Main),
        "testnet-liquid" => Some(jade_crypto::LiquidNetwork::Test),
        "localtest-liquid" => Some(jade_crypto::LiquidNetwork::Regtest),
        _ => None,
    }
}

fn descriptor_receive_address(
    details: &DescriptorDetails,
    branch: u32,
    pointer: u32,
    network: jade_crypto::BitcoinNetwork,
) -> Option<String> {
    let inner = descriptor_function_body(&details.descriptor, "wsh")?;
    let script = descriptor_script(inner, &details.datavalues, branch, pointer, network)?;
    jade_crypto::pure_rust::bitcoin_wsh_address_from_script(&script, network)
}

fn descriptor_script(
    expression: &str,
    datavalues: &[DescriptorDataValue],
    branch: u32,
    pointer: u32,
    network: jade_crypto::BitcoinNetwork,
) -> Option<Vec<u8>> {
    let expression = expression.trim();
    if let Some(inner) = expression.strip_prefix("v:") {
        let mut script = descriptor_script(inner, datavalues, branch, pointer, network)?;
        descriptor_script_push_verify(&mut script);
        return Some(script);
    }
    if let Some(inner) = expression.strip_prefix("c:") {
        let mut script = descriptor_script(inner, datavalues, branch, pointer, network)?;
        script.push(OP_CHECKSIG);
        return Some(script);
    }

    let (name, args) = descriptor_function_call(expression)?;
    match name {
        "and_v" => {
            if args.len() != 2 {
                return None;
            }
            let mut script = descriptor_script(args[0], datavalues, branch, pointer, network)?;
            script.extend_from_slice(&descriptor_script(
                args[1], datavalues, branch, pointer, network,
            )?);
            Some(script)
        }
        "or_d" => {
            if args.len() != 2 {
                return None;
            }
            let mut script = descriptor_script(args[0], datavalues, branch, pointer, network)?;
            script.extend_from_slice(&[OP_IFDUP, OP_NOTIF]);
            script.extend_from_slice(&descriptor_script(
                args[1], datavalues, branch, pointer, network,
            )?);
            script.push(OP_ENDIF);
            Some(script)
        }
        "pk" => {
            if args.len() != 1 {
                return None;
            }
            let mut script = descriptor_pk_script(args[0], datavalues, branch, pointer, network)?;
            script.push(OP_CHECKSIG);
            Some(script)
        }
        "pk_k" => {
            if args.len() != 1 {
                return None;
            }
            descriptor_pk_script(args[0], datavalues, branch, pointer, network)
        }
        "pkh" => {
            if args.len() != 1 {
                return None;
            }
            let mut script = descriptor_pkh_script(args[0], datavalues, branch, pointer, network)?;
            script.push(OP_CHECKSIG);
            Some(script)
        }
        "pk_h" => {
            if args.len() != 1 {
                return None;
            }
            descriptor_pkh_script(args[0], datavalues, branch, pointer, network)
        }
        "older" => {
            if args.len() != 1 {
                return None;
            }
            let value = parse_decimal_u64(args[0])?;
            if value > i32::MAX as u64 {
                return None;
            }
            let mut script = Vec::new();
            descriptor_script_push_int(&mut script, value as i64)?;
            script.push(OP_CSV);
            Some(script)
        }
        "multi" | "sortedmulti" => {
            if args.len() < 2 {
                return None;
            }
            let threshold = parse_decimal_u64(args[0])?;
            if threshold == 0 || threshold > 16 || threshold as usize >= args.len() {
                return None;
            }

            let mut pubkeys = Vec::with_capacity(args.len() - 1);
            for key_expression in &args[1..] {
                pubkeys.push(descriptor_public_key(
                    key_expression,
                    datavalues,
                    branch,
                    pointer,
                    network,
                )?);
            }
            if name == "sortedmulti" {
                pubkeys.sort();
            }
            let mut script = Vec::new();
            descriptor_script_push_int(&mut script, threshold as i64)?;
            for pubkey in &pubkeys {
                descriptor_script_push_slice(&mut script, pubkey)?;
            }
            descriptor_script_push_int(&mut script, pubkeys.len() as i64)?;
            script.push(OP_CHECKMULTISIG);
            Some(script)
        }
        _ => None,
    }
}

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_1: u8 = 0x51;
const OP_DUP: u8 = 0x76;
const OP_IFDUP: u8 = 0x73;
const OP_NOTIF: u8 = 0x64;
const OP_ENDIF: u8 = 0x68;
const OP_VERIFY: u8 = 0x69;
const OP_HASH160: u8 = 0xa9;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const OP_CSV: u8 = 0xb2;

fn descriptor_function_body<'a>(expression: &'a str, expected_name: &str) -> Option<&'a str> {
    let (name, args) = descriptor_function_call(expression)?;
    if name == expected_name && args.len() == 1 {
        Some(args[0])
    } else {
        None
    }
}

fn descriptor_function_call(expression: &str) -> Option<(&str, Vec<&str>)> {
    let expression = expression.trim();
    let open = expression.find('(')?;
    if !expression.ends_with(')') {
        return None;
    }
    let name = expression[..open].trim();
    if name.is_empty() {
        return None;
    }

    let mut depth = 0usize;
    let mut close = None;
    for (offset, byte) in expression.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'(' => depth = depth.checked_add(1)?,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    if close? != expression.len() - 1 {
        return None;
    }

    Some((
        name,
        descriptor_split_args(&expression[open + 1..expression.len() - 1])?,
    ))
}

fn descriptor_split_args(args: &str) -> Option<Vec<&str>> {
    if args.trim().is_empty() {
        return Some(Vec::new());
    }

    let mut output = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, ch) in args.char_indices() {
        match ch {
            '(' => paren_depth = paren_depth.checked_add(1)?,
            ')' => paren_depth = paren_depth.checked_sub(1)?,
            '<' => angle_depth = angle_depth.checked_add(1)?,
            '>' => angle_depth = angle_depth.checked_sub(1)?,
            '[' => bracket_depth = bracket_depth.checked_add(1)?,
            ']' => bracket_depth = bracket_depth.checked_sub(1)?,
            ',' if paren_depth == 0 && angle_depth == 0 && bracket_depth == 0 => {
                output.push(args[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if paren_depth != 0 || angle_depth != 0 || bracket_depth != 0 {
        return None;
    }
    output.push(args[start..].trim());
    if output.iter().any(|arg| arg.is_empty()) {
        return None;
    }
    Some(output)
}

fn descriptor_pk_script(
    key_expression: &str,
    datavalues: &[DescriptorDataValue],
    branch: u32,
    pointer: u32,
    network: jade_crypto::BitcoinNetwork,
) -> Option<Vec<u8>> {
    let pubkey = descriptor_public_key(key_expression, datavalues, branch, pointer, network)?;
    let mut script = Vec::new();
    descriptor_script_push_slice(&mut script, &pubkey)?;
    Some(script)
}

fn descriptor_pkh_script(
    key_expression: &str,
    datavalues: &[DescriptorDataValue],
    branch: u32,
    pointer: u32,
    network: jade_crypto::BitcoinNetwork,
) -> Option<Vec<u8>> {
    let pubkey = descriptor_public_key(key_expression, datavalues, branch, pointer, network)?;
    let pubkey_hash = jade_crypto::pure_rust::hash160_digest(&pubkey);
    let mut script = Vec::new();
    script.extend_from_slice(&[OP_DUP, OP_HASH160]);
    descriptor_script_push_slice(&mut script, &pubkey_hash)?;
    script.push(OP_EQUALVERIFY);
    Some(script)
}

fn descriptor_public_key(
    key_expression: &str,
    datavalues: &[DescriptorDataValue],
    branch: u32,
    pointer: u32,
    network: jade_crypto::BitcoinNetwork,
) -> Option<[u8; jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN]> {
    let key_expression = key_expression.trim();
    if let Some(pubkey) = descriptor_raw_public_key(key_expression) {
        return Some(pubkey);
    }

    let (key_name, suffix) = split_descriptor_key_suffix(key_expression);
    let value = datavalues
        .iter()
        .find(|item| item.key == key_name)
        .map(|item| item.value.as_str())?;
    let xpub = descriptor_xpub(value, network)?;
    let path = descriptor_key_suffix_path(suffix, branch, pointer)?;
    jade_crypto::pure_rust::public_key_from_serialized_xpub_path(&xpub, &path)
}

fn split_descriptor_key_suffix(key_expression: &str) -> (&str, &str) {
    match key_expression.find('/') {
        Some(index) => (&key_expression[..index], &key_expression[index..]),
        None => (key_expression, ""),
    }
}

fn descriptor_xpub(
    value: &str,
    network: jade_crypto::BitcoinNetwork,
) -> Option<[u8; jade_storage::BIP32_SERIALIZED_LEN]> {
    let value = value.trim();
    let value = if let Some(rest) = value.strip_prefix('[') {
        let (_, xpub) = split_once_byte(rest, b']')?;
        xpub
    } else {
        value
    };
    let xpub_end = value.find('/').unwrap_or(value.len());
    let xpub = &value[..xpub_end];
    let bytes = base58ck::decode_check(xpub).ok()?;
    let bytes: [u8; jade_storage::BIP32_SERIALIZED_LEN] = bytes.try_into().ok()?;
    let prefix = u32::from_be_bytes(bytes[..4].try_into().ok()?);
    let expected_prefix = match network {
        jade_crypto::BitcoinNetwork::Main => 0x0488_b21e,
        jade_crypto::BitcoinNetwork::Test | jade_crypto::BitcoinNetwork::Regtest => 0x0435_87cf,
    };
    if prefix == expected_prefix {
        Some(bytes)
    } else {
        None
    }
}

fn descriptor_key_suffix_path(suffix: &str, branch: u32, pointer: u32) -> Option<Vec<u32>> {
    let mut path = Vec::new();
    let mut rest = suffix;
    let mut saw_multipath = false;
    while !rest.is_empty() {
        rest = rest.strip_prefix('/')?;
        if let Some(after_open) = rest.strip_prefix('<') {
            let (choices, after_choices) = split_once_byte(after_open, b'>')?;
            let choices: Vec<&str> = choices.split(';').collect();
            let choice = choices.get(branch as usize)?;
            path.push(parse_descriptor_path_index(choice)?);
            saw_multipath = true;
            rest = after_choices;
            continue;
        }
        if let Some(after_wildcard) = rest.strip_prefix('*') {
            path.push(pointer);
            rest = after_wildcard;
            continue;
        }

        let segment_end = rest.find('/').unwrap_or(rest.len());
        path.push(parse_descriptor_path_index(&rest[..segment_end])?);
        rest = &rest[segment_end..];
    }
    if !saw_multipath && branch != 0 {
        return None;
    }
    Some(path)
}

fn parse_descriptor_path_index(value: &str) -> Option<u32> {
    if value.is_empty() || value.ends_with('\'') || value.ends_with('h') {
        return None;
    }
    let value = parse_decimal_u64(value)?;
    if value <= 0x7fff_ffff {
        Some(value as u32)
    } else {
        None
    }
}

fn descriptor_raw_public_key(
    key_expression: &str,
) -> Option<[u8; jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN]> {
    if key_expression.len() != jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN * 2 {
        return None;
    }
    let mut pubkey = [0u8; jade_crypto::EC_PUBLIC_KEY_COMPRESSED_LEN];
    for (index, item) in pubkey.iter_mut().enumerate() {
        let high = hex_nibble_value(key_expression.as_bytes()[index * 2])?;
        let low = hex_nibble_value(key_expression.as_bytes()[index * 2 + 1])?;
        *item = (high << 4) | low;
    }
    if valid_compressed_secp256k1_pubkey(&pubkey) {
        Some(pubkey)
    } else {
        None
    }
}

fn hex_nibble_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn descriptor_script_push_slice(script: &mut Vec<u8>, data: &[u8]) -> Option<()> {
    match data.len() {
        0..=75 => script.push(data.len() as u8),
        76..=255 => {
            script.push(OP_PUSHDATA1);
            script.push(data.len() as u8);
        }
        _ => return None,
    }
    script.extend_from_slice(data);
    Some(())
}

fn descriptor_script_push_int(script: &mut Vec<u8>, value: i64) -> Option<()> {
    match value {
        0 => {
            script.push(OP_0);
            Some(())
        }
        1..=16 => {
            script.push(OP_1 + value as u8 - 1);
            Some(())
        }
        17..=i64::MAX => {
            let mut encoded = Vec::new();
            let mut remaining = value as u64;
            while remaining > 0 {
                encoded.push((remaining & 0xff) as u8);
                remaining >>= 8;
            }
            if encoded.last().copied().unwrap_or(0) & 0x80 != 0 {
                encoded.push(0);
            }
            descriptor_script_push_slice(script, &encoded)
        }
        _ => None,
    }
}

fn descriptor_script_push_verify(script: &mut Vec<u8>) {
    match script.last_mut() {
        Some(last) if *last == OP_EQUAL => *last = OP_EQUALVERIFY,
        Some(last) if *last == OP_CHECKSIG => *last = OP_CHECKSIGVERIFY,
        Some(last) if *last == OP_CHECKMULTISIG => *last = OP_CHECKMULTISIGVERIFY,
        _ => script.push(OP_VERIFY),
    }
}

fn multisig_registration_record(
    variant: MultisigVariant,
    sorted: bool,
    threshold: u8,
    master_blinding_key: Option<[u8; jade_storage::MULTISIG_MASTER_BLINDING_KEY_SIZE]>,
    signers: &[MultisigSignerDetails],
) -> Option<Vec<u8>> {
    if signers.is_empty()
        || signers.len() > jade_storage::MAX_ALLOWED_SIGNERS
        || threshold == 0
        || threshold as usize > signers.len()
    {
        return None;
    }

    let path_elements = signers.iter().try_fold(0usize, |acc, signer| {
        if signer.derivation.len() > MAX_PATH_LEN || signer.path.len() > MAX_PATH_LEN {
            None
        } else {
            acc.checked_add(signer.derivation.len())?
                .checked_add(signer.path.len())
        }
    })?;
    let master_blinding_len = master_blinding_key.as_ref().map(|_| 32).unwrap_or(0);
    let mut payload = Vec::with_capacity(
        6 + master_blinding_len
            + signers.len() * (6 + jade_storage::BIP32_SERIALIZED_LEN)
            + path_elements * 4,
    );
    payload.push(3);
    payload.push(variant as u8);
    payload.push(u8::from(sorted));
    payload.push(threshold);
    payload.push(master_blinding_len as u8);
    if let Some(master_blinding_key) = master_blinding_key {
        payload.extend_from_slice(&master_blinding_key);
    }
    payload.push(signers.len() as u8);
    for signer in signers {
        payload.extend_from_slice(&signer.fingerprint);
        payload.push(signer.derivation.len() as u8);
        push_le_u32s(&mut payload, &signer.derivation);
        payload.extend_from_slice(&signer.xpub);
        payload.push(signer.path.len() as u8);
        push_le_u32s(&mut payload, &signer.path);
    }

    Some(host_authenticated_record(payload))
}

fn descriptor_registration_record(details: &DescriptorDetails) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        4 + details.descriptor.len()
            + 1
            + details
                .datavalues
                .iter()
                .map(|item| 4 + item.key.len() + item.value.len())
                .sum::<usize>(),
    );
    payload.push(0);
    payload.push(details.descriptor_type);
    payload.extend_from_slice(&(details.descriptor.len() as u16).to_le_bytes());
    payload.extend_from_slice(details.descriptor.as_bytes());
    payload.push(details.datavalues.len() as u8);
    for item in &details.datavalues {
        payload.extend_from_slice(&(item.key.len() as u16).to_le_bytes());
        payload.extend_from_slice(item.key.as_bytes());
        payload.extend_from_slice(&(item.value.len() as u16).to_le_bytes());
        payload.extend_from_slice(item.value.as_bytes());
    }

    host_authenticated_record(payload)
}

fn host_authenticated_record(mut payload: Vec<u8>) -> Vec<u8> {
    payload.extend_from_slice(&[0xa5; HMAC_SHA256_LEN]);
    payload
}

fn push_le_u32s(output: &mut Vec<u8>, values: &[u32]) {
    for value in values {
        output.extend_from_slice(&value.to_le_bytes());
    }
}

fn wallet_fingerprint_from_seed(seed: &[u8]) -> Option<[u8; 4]> {
    let pubkey = jade_crypto::pure_rust::public_key_from_seed_path(seed, &[])?;
    let hash = jade_crypto::pure_rust::hash160_digest(&pubkey);
    hash[..4].try_into().ok()
}

#[cfg(test)]
fn valid_serialized_xpub_for_network(
    xpub: &[u8; jade_storage::BIP32_SERIALIZED_LEN],
    network: jade_crypto::BitcoinNetwork,
) -> bool {
    let prefix = match network {
        jade_crypto::BitcoinNetwork::Main => jade_crypto::XpubPrefix::Main,
        jade_crypto::BitcoinNetwork::Test | jade_crypto::BitcoinNetwork::Regtest => {
            jade_crypto::XpubPrefix::Test
        }
    };
    valid_serialized_xpub_for_prefix(xpub, prefix)
}

fn valid_serialized_xpub_for_prefix(
    xpub: &[u8; jade_storage::BIP32_SERIALIZED_LEN],
    xpub_prefix: jade_crypto::XpubPrefix,
) -> bool {
    let prefix = u32::from_be_bytes(xpub[..4].try_into().expect("fixed prefix len"));
    match xpub_prefix {
        jade_crypto::XpubPrefix::Main => prefix == 0x0488_b21e,
        jade_crypto::XpubPrefix::Test => prefix == 0x0435_87cf,
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

fn decode_xpub_for_prefix(
    xpub: &str,
    xpub_prefix: jade_crypto::XpubPrefix,
) -> Option<[u8; jade_storage::BIP32_SERIALIZED_LEN]> {
    let bytes = base58ck::decode_check(xpub).ok()?;
    let bytes: [u8; jade_storage::BIP32_SERIALIZED_LEN] = bytes.try_into().ok()?;
    if valid_serialized_xpub_for_prefix(&bytes, xpub_prefix) {
        Some(bytes)
    } else {
        None
    }
}

fn green_service_xpub_for_network(
    network: &str,
) -> Option<[u8; jade_storage::BIP32_SERIALIZED_LEN]> {
    let xpub = match network {
        "mainnet" => MAINNET_SERVICE_XPUB,
        "liquid" => LIQUID_SERVICE_XPUB,
        "testnet" | "localtest" | "localtest-liquid" => TESTNET_SERVICE_XPUB,
        "testnet-liquid" => TESTNET_LIQUID_SERVICE_XPUB,
        _ => return None,
    };
    let prefix = xpub_prefix_for_network(network)?;
    decode_xpub_for_prefix(xpub, prefix)
}

fn network_allows_csv_blocks(network: &str, csv_blocks: u32) -> bool {
    let Some(minimum) = (match network {
        "mainnet" => Some(25_920),
        "testnet" | "localtest" => Some(144),
        "liquid" => Some(65_535),
        "testnet-liquid" | "localtest-liquid" => Some(1_440),
        _ => None,
    }) else {
        return false;
    };
    csv_blocks >= minimum && csv_blocks <= 65_535
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

fn valid_rsa_key_bits(key_bits: u64) -> bool {
    matches!(key_bits, 1024 | 2048 | 3072 | 4096 | 8192)
}

fn valid_rsa_generation_key_bits(key_bits: u64) -> bool {
    matches!(key_bits, 1024 | 2048 | 3072 | 4096)
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
    bip85_ephemeral_private_key: [u8; jade_crypto::EC_PRIVATE_KEY_LEN],
    bip85_iv: [u8; 16],
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
            bip85_ephemeral_private_key: [
                0x0b, 0x6b, 0x3d, 0xc9, 0x0d, 0x20, 0x3d, 0x85, 0x41, 0x00, 0x11, 0x07, 0x88, 0xac,
                0x87, 0xd4, 0x3a, 0xa0, 0x06, 0x20, 0xc9, 0xcd, 0xb3, 0x61, 0xb2, 0x81, 0xb0, 0x90,
                0x22, 0xef, 0x4b, 0x53,
            ],
            bip85_iv: [
                0xbd, 0x5d, 0x47, 0x24, 0x24, 0x38, 0x80, 0x73, 0x8e, 0x7e, 0x8b, 0x0c, 0x02, 0x65,
                0x87, 0x00,
            ],
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

    pub fn current_epoch(&self) -> Option<u64> {
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

    fn descriptor_registration_payload(
        descriptor_type: u8,
        descriptor: &str,
        datavalues: &[(&str, &str)],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0, descriptor_type]);
        payload.extend_from_slice(&(descriptor.len() as u16).to_le_bytes());
        payload.extend_from_slice(descriptor.as_bytes());
        payload.push(datavalues.len() as u8);
        for (key, value) in datavalues {
            payload.extend_from_slice(&(key.len() as u16).to_le_bytes());
            payload.extend_from_slice(key.as_bytes());
            payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
            payload.extend_from_slice(value.as_bytes());
        }
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

    fn decode_hex_vec(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        let mut output = Vec::with_capacity(input.len() / 2);
        for pair in input.as_bytes().chunks_exact(2) {
            output.push((hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]));
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

    fn test_mnemonic_seed() -> [u8; 64] {
        decode_hex(
            "f1d56befd46eddfc31cda129dc76cd4a2b41d2cf86f10a5ccf0787617afa3869\
             967aab0224742ccc002056747ea09b68598ddf79c027c37a7c3ec923004593da",
        )
    }

    fn test_mnemonic_single_sig_seed() -> [u8; 64] {
        decode_hex(
            "5eff11cb0a00759be57e20d20d8076b80e8954df54318967116269909b501c10\
             99c27239c6e1cc1e9211a9b8157f150d58fc3f88ba79fd7c1515f3f317732337",
        )
    }

    fn fixture_psbt_base64(fixture: &str) -> &str {
        let marker = "\"psbt\": \"";
        let start = fixture.find(marker).unwrap() + marker.len();
        let rest = &fixture[start..];
        let end = rest.find('"').unwrap();
        &rest[..end]
    }

    fn fixture_network(fixture: &str) -> &str {
        let marker = "\"network\": \"";
        let start = fixture.find(marker).unwrap() + marker.len();
        let rest = &fixture[start..];
        let end = rest.find('"').unwrap();
        &rest[..end]
    }

    fn fixture_expected_output_psbt_base64(fixture: &str) -> &str {
        let marker = "\"expected_output\":";
        let start = fixture.find(marker).unwrap() + marker.len();
        fixture_psbt_base64(&fixture[start..])
    }

    fn fixture_hex_values<'a>(fixture: &'a str, field: &str) -> Vec<&'a str> {
        let marker = format!("\"{field}\": \"");
        let mut values = Vec::new();
        let mut rest = fixture;
        while let Some(start) = rest.find(&marker) {
            let value_start = start + marker.len();
            let value_rest = &rest[value_start..];
            let value_end = value_rest.find('"').unwrap();
            values.push(&value_rest[..value_end]);
            rest = &value_rest[value_end..];
        }
        values
    }

    fn fixture_legacy_signatures(fixture: &str) -> Vec<&str> {
        let marker = "\"expected_legacy_output\"";
        let start = fixture.find(marker).unwrap();
        let legacy_block = &fixture[start..];
        let end = legacy_block.find(']').unwrap();
        quoted_hex_strings(&legacy_block[..end])
    }

    fn fixture_expected_output_signatures(fixture: &str) -> Vec<&str> {
        let marker = "\"expected_output\"";
        let start = fixture.find(marker).unwrap();
        let expected_block = &fixture[start..];
        let end = expected_block
            .find("\"expected_legacy_output\"")
            .unwrap_or(expected_block.len());
        quoted_hex_strings(&expected_block[..end])
    }

    fn quoted_hex_strings(block: &str) -> Vec<&str> {
        let mut values = Vec::new();
        let mut rest = block;
        while let Some(start) = rest.find('"') {
            let value_rest = &rest[start + 1..];
            let value_end = value_rest.find('"').unwrap();
            let value = &value_rest[..value_end];
            if !value.is_empty() && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
                values.push(value);
            }
            rest = &value_rest[value_end + 1..];
        }
        values
    }

    fn sign_tx_start_params(txn: &[u8], num_inputs: u64, use_ae_signatures: bool) -> Vec<u8> {
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest")
            .unwrap()
            .str("txn")
            .unwrap()
            .bytes(txn)
            .unwrap()
            .str("num_inputs")
            .unwrap()
            .u64(num_inputs)
            .unwrap()
            .str("use_ae_signatures")
            .unwrap()
            .bool(use_ae_signatures)
            .unwrap();
        params
    }

    fn get_signature_params() -> Vec<u8> {
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("ae_host_entropy")
            .unwrap()
            .null()
            .unwrap();
        params
    }

    fn sign_tx_input_params(
        is_witness: bool,
        path: &[u32],
        script: &[u8],
        satoshi: Option<u64>,
        input_tx: Option<&[u8]>,
    ) -> Vec<u8> {
        sign_tx_input_params_with_sighash(is_witness, path, script, 1, satoshi, input_tx)
    }

    fn sign_tx_input_params_with_sighash(
        is_witness: bool,
        path: &[u32],
        script: &[u8],
        sighash: u64,
        satoshi: Option<u64>,
        input_tx: Option<&[u8]>,
    ) -> Vec<u8> {
        let field_count = 4 + u64::from(satoshi.is_some()) + u64::from(input_tx.is_some());
        let mut params = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut params);
        encoder
            .map(field_count)
            .unwrap()
            .str("is_witness")
            .unwrap()
            .bool(is_witness)
            .unwrap()
            .str("path")
            .unwrap()
            .array(path.len() as u64)
            .unwrap();
        for child in path {
            encoder.u32(*child).unwrap();
        }
        encoder
            .str("script")
            .unwrap()
            .bytes(script)
            .unwrap()
            .str("sighash")
            .unwrap()
            .u64(sighash)
            .unwrap();
        if let Some(satoshi) = satoshi {
            encoder.str("satoshi").unwrap().u64(satoshi).unwrap();
        }
        if let Some(input_tx) = input_tx {
            encoder.str("input_tx").unwrap().bytes(input_tx).unwrap();
        }
        params
    }

    fn sign_tx_input_params_with_ae(
        is_witness: bool,
        path: &[u32],
        script: &[u8],
        satoshi: Option<u64>,
        input_tx: Option<&[u8]>,
        ae_host_commitment: &[u8; jade_crypto::SHA256_LEN],
    ) -> Vec<u8> {
        sign_tx_input_params_with_ae_sighash(
            is_witness,
            path,
            script,
            1,
            satoshi,
            input_tx,
            ae_host_commitment,
        )
    }

    fn sign_tx_input_params_with_ae_sighash(
        is_witness: bool,
        path: &[u32],
        script: &[u8],
        sighash: u64,
        satoshi: Option<u64>,
        input_tx: Option<&[u8]>,
        ae_host_commitment: &[u8; jade_crypto::SHA256_LEN],
    ) -> Vec<u8> {
        let field_count = 5 + u64::from(satoshi.is_some()) + u64::from(input_tx.is_some());
        let mut params = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut params);
        encoder
            .map(field_count)
            .unwrap()
            .str("is_witness")
            .unwrap()
            .bool(is_witness)
            .unwrap()
            .str("path")
            .unwrap()
            .array(path.len() as u64)
            .unwrap();
        for child in path {
            encoder.u32(*child).unwrap();
        }
        encoder
            .str("script")
            .unwrap()
            .bytes(script)
            .unwrap()
            .str("sighash")
            .unwrap()
            .u64(sighash)
            .unwrap()
            .str("ae_host_commitment")
            .unwrap()
            .bytes(ae_host_commitment)
            .unwrap();
        if let Some(satoshi) = satoshi {
            encoder.str("satoshi").unwrap().u64(satoshi).unwrap();
        }
        if let Some(input_tx) = input_tx {
            encoder.str("input_tx").unwrap().bytes(input_tx).unwrap();
        }
        params
    }

    fn get_signature_params_with_entropy(host_entropy: &[u8; jade_crypto::SHA256_LEN]) -> Vec<u8> {
        get_signature_params_with_raw_entropy(host_entropy)
    }

    fn get_signature_params_with_raw_entropy(host_entropy: &[u8]) -> Vec<u8> {
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("ae_host_entropy")
            .unwrap()
            .bytes(host_entropy)
            .unwrap();
        params
    }

    fn sign_tx_unsigned_input_params(
        is_witness: bool,
        satoshi: Option<u64>,
        input_tx: Option<&[u8]>,
    ) -> Vec<u8> {
        let field_count = 1 + u64::from(satoshi.is_some()) + u64::from(input_tx.is_some());
        let mut params = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut params);
        encoder
            .map(field_count)
            .unwrap()
            .str("is_witness")
            .unwrap()
            .bool(is_witness)
            .unwrap();
        if let Some(satoshi) = satoshi {
            encoder.str("satoshi").unwrap().u64(satoshi).unwrap();
        }
        if let Some(input_tx) = input_tx {
            encoder.str("input_tx").unwrap().bytes(input_tx).unwrap();
        }
        params
    }

    fn decode_xpub(input: &str) -> [u8; BIP32_SERIALIZED_LEN] {
        let bytes = base58ck::decode_check(input).unwrap();
        bytes.try_into().unwrap()
    }

    fn register_multisig_file(emulator: &mut Emulator, multisig_file: &str) -> V1Outcome {
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("multisig_file")
            .unwrap()
            .str(multisig_file)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("mf"),
            method: Cow::Borrowed("register_multisig"),
            params: Some(&params),
        };
        emulator.handle_v1_request(&request)
    }

    fn stored_multisig_details(emulator: &Emulator, name: &str) -> MultisigDetails {
        let mut record = Vec::new();
        emulator
            .storage
            .get_record(StorageRecord::MultisigRegistration { name }, &mut record)
            .unwrap();
        parse_multisig_details(&record, &HostRecordAuthenticator).unwrap()
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
    fn sign_tx_rejects_missing_start_params() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("2"),
            method: Cow::Borrowed("sign_tx"),
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
    fn sign_tx_legacy_flow_signs_p2pkh_wallet_inputs() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let txn = decode_hex_vec(
            "020000000283dbdaaee275d2910cd17f65187ea3f20fe37a553b16df398160f14b84ff49a3000000006b483045022100ff7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f02207f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f01210268246c0462037aefb8611a9cebf313ee2430c22a4f3644e6460f4e88d73b54f4fdffffff4c3f7d4310d8d679d89a8af18094bb29be7de8cbfdb4b466c400fd41bf11d9af000000006b483045022100ff7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f02207f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f0121027eeb53798c29e1d19ad9c4948fce7f4fd13f65ba25a3100130ec5d4747bf1d54fdffffff02983a000000000000160014c153947d38dccc7238947edb2ecea9a420a9fd1e15120000000000001976a914c4e6c152268f755afbd8e70b8aa07f9c3aa0b4c888ac72000000",
        );
        let start_params = sign_tx_start_params(&txn, 2, false);
        let start_request = Request {
            id: Cow::Borrowed("tx"),
            method: Cow::Borrowed("sign_tx"),
            params: Some(&start_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&start_request),
            V1Outcome::BoolResult { result: true }
        );

        for (path, script, expected) in [
            (
                &[2_147_483_692, 2_147_483_649, 2_147_483_648, 0, 3][..],
                "76a9146f16cf9c04a990dcc10f97366b617c9b93f40a6088ac",
                "3044022077ba475ddd478e786788e7f79e1b3196edfbe4b754914e883c69a6ac9711aa4e02201fdae82d1363f08bbcc7bce82af264f9ac58795b6551288e4edebf2ab788413f01",
            ),
            (
                &[2_147_483_692, 2_147_483_649, 2_147_483_648, 0, 2][..],
                "76a914fd9015522dbafda0b33ad66b24d0ee75507a2c1588ac",
                "304402201a1942a4002c7d1112e54a1d5b068a2d504cc10464d59775c08ff1128c0061fe022000da1b6d41732db58e6cb2e308cebedf5d989ced9fe1782833fa0358862f231301",
            ),
        ] {
            let input_params = sign_tx_input_params(false, path, &decode_hex_vec(script), None, None);
            let input_request = Request {
                id: Cow::Borrowed("input"),
                method: Cow::Borrowed("tx_input"),
                params: Some(&input_params),
            };
            assert_eq!(
                emulator.handle_v1_request(&input_request),
                V1Outcome::BytesResult {
                    result: decode_hex_vec(expected)
                }
            );
        }
    }

    #[test]
    fn sign_tx_legacy_flow_signs_single_input_p2wpkh() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let txn = decode_hex_vec(
            "02000000000101962675e3082c9df574155ea8a005a4d2888e8f6a68769e0fef1ca1fff24b23190000000000fdffffff028813000000000000160014c153947d38dccc7238947edb2ecea9a420a9fd1efb12000000000000160014fd02dc9ef3aa06200e215f8a16ff56241ac3077f02002102151478c7a51abb39dc80bc35231ebb6e4d681f68a955c7c2a37ea0aa4415fe6934000000",
        );
        let start_params = sign_tx_start_params(&txn, 1, false);
        let start_request = Request {
            id: Cow::Borrowed("tx"),
            method: Cow::Borrowed("sign_tx"),
            params: Some(&start_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&start_request),
            V1Outcome::BoolResult { result: true }
        );

        let input_params = sign_tx_input_params(
            true,
            &[2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 2],
            &decode_hex_vec("76a914faaba4d82b92371198437bc6fc7f995834fdf25a88ac"),
            Some(10_000),
            None,
        );
        let input_request = Request {
            id: Cow::Borrowed("input"),
            method: Cow::Borrowed("tx_input"),
            params: Some(&input_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&input_request),
            V1Outcome::BytesResult {
                result: decode_hex_vec(
                    "304402206bebf8a137c9447e60ea079497ffc2e5d6fdd267e70a5742d1f4beb91a47ee7b02204fc4779b1293b53e5c32903943b6b12f9f3c46d8df559097aefb95be04a0836001"
                )
            }
        );
    }

    #[test]
    fn sign_tx_staged_flow_returns_empty_commitment_then_signature() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let txn = decode_hex_vec(
            "02000000000101962675e3082c9df574155ea8a005a4d2888e8f6a68769e0fef1ca1fff24b23190000000000fdffffff028813000000000000160014c153947d38dccc7238947edb2ecea9a420a9fd1efb12000000000000160014fd02dc9ef3aa06200e215f8a16ff56241ac3077f02002102151478c7a51abb39dc80bc35231ebb6e4d681f68a955c7c2a37ea0aa4415fe6934000000",
        );
        let start_params = sign_tx_start_params(&txn, 1, true);
        let start_request = Request {
            id: Cow::Borrowed("tx"),
            method: Cow::Borrowed("sign_tx"),
            params: Some(&start_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&start_request),
            V1Outcome::BoolResult { result: true }
        );

        let input_params = sign_tx_input_params(
            true,
            &[2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 2],
            &decode_hex_vec("76a914faaba4d82b92371198437bc6fc7f995834fdf25a88ac"),
            Some(10_000),
            None,
        );
        let input_request = Request {
            id: Cow::Borrowed("input"),
            method: Cow::Borrowed("tx_input"),
            params: Some(&input_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&input_request),
            V1Outcome::BytesResult { result: Vec::new() }
        );

        let signature_params = get_signature_params();
        let signature_request = Request {
            id: Cow::Borrowed("sig"),
            method: Cow::Borrowed("get_signature"),
            params: Some(&signature_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&signature_request),
            V1Outcome::BytesResult {
                result: decode_hex_vec(
                    "304402206bebf8a137c9447e60ea079497ffc2e5d6fdd267e70a5742d1f4beb91a47ee7b02204fc4779b1293b53e5c32903943b6b12f9f3c46d8df559097aefb95be04a0836001"
                )
            }
        );
    }

    #[test]
    fn sign_tx_staged_flow_signs_anti_exfil_p2wsh_input() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
        let fixture = include_str!("../../../test_data/txn_segwit_ae.json");
        let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
        let script = decode_hex_vec(fixture_hex_values(fixture, "script")[0]);
        let expected = fixture_expected_output_signatures(fixture);
        assert_eq!(expected.len(), 2);

        let start_params = sign_tx_start_params(&txn, 1, true);
        let start_request = Request {
            id: Cow::Borrowed("tx"),
            method: Cow::Borrowed("sign_tx"),
            params: Some(&start_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&start_request),
            V1Outcome::BoolResult { result: true }
        );

        let host_commitment =
            decode_hex("71df1b3c631a0209b58e5ba3103a8f84ec5a2addb2a2993fa99a65d98cd933ae");
        let input_params = sign_tx_input_params_with_ae(
            true,
            &[1, 674],
            &script,
            Some(2_200_000),
            None,
            &host_commitment,
        );
        let input_request = Request {
            id: Cow::Borrowed("input"),
            method: Cow::Borrowed("tx_input"),
            params: Some(&input_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&input_request),
            V1Outcome::BytesResult {
                result: decode_hex_vec(expected[0])
            }
        );

        let host_entropy =
            decode_hex("854003465b0f98e3216d893a2d3eec7445ae802994fc3efbc9471e5338d37aad");
        let signature_params = get_signature_params_with_entropy(&host_entropy);
        let signature_request = Request {
            id: Cow::Borrowed("sig"),
            method: Cow::Borrowed("get_signature"),
            params: Some(&signature_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&signature_request),
            V1Outcome::BytesResult {
                result: decode_hex_vec(expected[1])
            }
        );
    }

    #[test]
    fn sign_tx_staged_flow_signs_anti_exfil_singlesig_inputs() {
        let fixtures = [
            (
                include_str!("../../../test_data/tx_ss_p2pkh.json"),
                false,
                &[
                    &[2_147_483_692, 2_147_483_649, 2_147_483_648, 0, 3][..],
                    &[2_147_483_692, 2_147_483_649, 2_147_483_648, 0, 2][..],
                ][..],
            ),
            (
                include_str!("../../../test_data/tx_ss_p2wpkh.json"),
                true,
                &[
                    &[2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 2][..],
                    &[2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 1][..],
                ][..],
            ),
            (
                include_str!("../../../test_data/tx_ss_p2sh_p2wpkh.json"),
                true,
                &[
                    &[2_147_483_697, 2_147_483_649, 2_147_483_648, 0, 2][..],
                    &[2_147_483_697, 2_147_483_649, 2_147_483_648, 0, 1][..],
                ][..],
            ),
        ];

        for (fixture, is_witness, paths) in fixtures {
            let mut emulator = Emulator::new();
            emulator
                .platform_mut()
                .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
            let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
            let scripts: Vec<_> = fixture_hex_values(fixture, "script")
                .into_iter()
                .map(decode_hex_vec)
                .collect();
            let input_txs: Vec<_> = fixture_hex_values(fixture, "input_tx")
                .into_iter()
                .map(decode_hex_vec)
                .collect();
            let host_commitments: Vec<_> = fixture_hex_values(fixture, "ae_host_commitment")
                .into_iter()
                .map(decode_hex)
                .collect();
            let host_entropies: Vec<_> = fixture_hex_values(fixture, "ae_host_entropy")
                .into_iter()
                .map(decode_hex)
                .collect();
            let expected = fixture_expected_output_signatures(fixture);
            assert_eq!(paths.len(), scripts.len());
            assert_eq!(paths.len(), input_txs.len());
            assert_eq!(paths.len(), host_commitments.len());
            assert_eq!(paths.len(), host_entropies.len());
            assert_eq!(paths.len() * 2, expected.len());

            let start_params = sign_tx_start_params(&txn, paths.len() as u64, true);
            let start_request = Request {
                id: Cow::Borrowed("tx"),
                method: Cow::Borrowed("sign_tx"),
                params: Some(&start_params),
            };
            assert_eq!(
                emulator.handle_v1_request(&start_request),
                V1Outcome::BoolResult { result: true }
            );

            for index in 0..paths.len() {
                let input_params = sign_tx_input_params_with_ae(
                    is_witness,
                    paths[index],
                    &scripts[index],
                    None,
                    Some(&input_txs[index]),
                    &host_commitments[index],
                );
                let input_request = Request {
                    id: Cow::Borrowed("input"),
                    method: Cow::Borrowed("tx_input"),
                    params: Some(&input_params),
                };
                assert_eq!(
                    emulator.handle_v1_request(&input_request),
                    V1Outcome::BytesResult {
                        result: decode_hex_vec(expected[index * 2])
                    }
                );
            }

            for index in 0..paths.len() {
                let signature_params = get_signature_params_with_entropy(&host_entropies[index]);
                let signature_request = Request {
                    id: Cow::Borrowed("sig"),
                    method: Cow::Borrowed("get_signature"),
                    params: Some(&signature_params),
                };
                assert_eq!(
                    emulator.handle_v1_request(&signature_request),
                    V1Outcome::BytesResult {
                        result: decode_hex_vec(expected[index * 2 + 1])
                    }
                );
            }
        }
    }

    #[test]
    fn sign_tx_staged_flow_signs_anti_exfil_legacy_p2pkh_inputs() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
        let fixture = include_str!("../../../test_data/txn_legacy_ae.json");
        let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
        let input_txs: Vec<_> = fixture_hex_values(fixture, "input_tx")
            .into_iter()
            .map(decode_hex_vec)
            .collect();
        let scripts: Vec<_> = fixture_hex_values(fixture, "script")
            .into_iter()
            .map(decode_hex_vec)
            .collect();
        let expected = fixture_expected_output_signatures(fixture);
        assert_eq!(input_txs.len(), 3);
        assert_eq!(scripts.len(), 2);
        assert_eq!(expected.len(), 4);

        let start_params = sign_tx_start_params(&txn, 3, true);
        let start_request = Request {
            id: Cow::Borrowed("tx"),
            method: Cow::Borrowed("sign_tx"),
            params: Some(&start_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&start_request),
            V1Outcome::BoolResult { result: true }
        );

        let first_host_commitment =
            decode_hex("adac3ae3f3934fa2ed2475849588fba68c34a01dcc421e80abcf635a23f06fbd");
        let first_input_params = sign_tx_input_params_with_ae(
            false,
            &[2147483692, 0, 1, 2],
            &scripts[0],
            None,
            Some(&input_txs[0]),
            &first_host_commitment,
        );
        let first_input_request = Request {
            id: Cow::Borrowed("input-0"),
            method: Cow::Borrowed("tx_input"),
            params: Some(&first_input_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&first_input_request),
            V1Outcome::BytesResult {
                result: decode_hex_vec(expected[0])
            }
        );

        let unsigned_input_params = sign_tx_unsigned_input_params(false, None, Some(&input_txs[1]));
        let unsigned_input_request = Request {
            id: Cow::Borrowed("input-1"),
            method: Cow::Borrowed("tx_input"),
            params: Some(&unsigned_input_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&unsigned_input_request),
            V1Outcome::BytesResult { result: Vec::new() }
        );

        let second_host_commitment =
            decode_hex("d8af4e5415461fb586a40c8c0a6cecda6a66adb19bf7cf27f7a40d468b97576f");
        let second_input_params = sign_tx_input_params_with_ae(
            false,
            &[2147483692, 0, 2, 5],
            &scripts[1],
            None,
            Some(&input_txs[2]),
            &second_host_commitment,
        );
        let second_input_request = Request {
            id: Cow::Borrowed("input-2"),
            method: Cow::Borrowed("tx_input"),
            params: Some(&second_input_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&second_input_request),
            V1Outcome::BytesResult {
                result: decode_hex_vec(expected[2])
            }
        );

        let first_host_entropy =
            decode_hex("49aa539ecf1ee2713379e736ed8937e79cb44bcdb5f0115228002274862e429f");
        let first_signature_params = get_signature_params_with_entropy(&first_host_entropy);
        let first_signature_request = Request {
            id: Cow::Borrowed("sig-0"),
            method: Cow::Borrowed("get_signature"),
            params: Some(&first_signature_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&first_signature_request),
            V1Outcome::BytesResult {
                result: decode_hex_vec(expected[1])
            }
        );

        let unsigned_signature_params = get_signature_params();
        let unsigned_signature_request = Request {
            id: Cow::Borrowed("sig-1"),
            method: Cow::Borrowed("get_signature"),
            params: Some(&unsigned_signature_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&unsigned_signature_request),
            V1Outcome::BytesResult { result: Vec::new() }
        );

        let second_host_entropy =
            decode_hex("ba30dcf11df43b3dc1c78e34f013de047a1c2752bf089c62534eefcd48021a1b");
        let second_signature_params = get_signature_params_with_entropy(&second_host_entropy);
        let second_signature_request = Request {
            id: Cow::Borrowed("sig-2"),
            method: Cow::Borrowed("get_signature"),
            params: Some(&second_signature_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&second_signature_request),
            V1Outcome::BytesResult {
                result: decode_hex_vec(expected[3])
            }
        );
    }

    #[test]
    fn sign_tx_staged_flow_rejects_wrong_size_anti_exfil_entropy() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/tx_ss_bad_ae_4.json");
        let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
        let script = decode_hex_vec(fixture_hex_values(fixture, "script")[0]);
        let host_commitment =
            decode_hex("ee3dfd0944dcfb10b6ecf8ae4df1ba2c179cfb4a0cf0e4f20c39317891862c8a");

        let start_params = sign_tx_start_params(&txn, 1, true);
        let start_request = Request {
            id: Cow::Borrowed("tx"),
            method: Cow::Borrowed("sign_tx"),
            params: Some(&start_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&start_request),
            V1Outcome::BoolResult { result: true }
        );

        let input_params = sign_tx_input_params_with_ae(
            true,
            &[2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 2],
            &script,
            Some(10_000),
            None,
            &host_commitment,
        );
        let input_request = Request {
            id: Cow::Borrowed("input"),
            method: Cow::Borrowed("tx_input"),
            params: Some(&input_params),
        };
        assert!(matches!(
            emulator.handle_v1_request(&input_request),
            V1Outcome::BytesResult { result } if result.len() == 33
        ));

        let wrong_size_entropy =
            decode_hex_vec("9e02c7553f61576b17df8983fefd0f3dcbca289c34ebb52e1b9e67f9d4f549");
        let signature_params = get_signature_params_with_raw_entropy(&wrong_size_entropy);
        let signature_request = Request {
            id: Cow::Borrowed("sig"),
            method: Cow::Borrowed("get_signature"),
            params: Some(&signature_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&signature_request),
            V1Outcome::Reject {
                code: ErrorCode::ProtocolError,
                message: "Failed to extract valid host entropy from parameters".to_string()
            }
        );
    }

    #[test]
    fn sign_tx_legacy_flow_extracts_witness_amounts_from_input_tx() {
        for (fixture, paths) in [
            (
                include_str!("../../../test_data/tx_ss_p2wpkh.json"),
                &[
                    &[2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 2][..],
                    &[2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 1][..],
                ][..],
            ),
            (
                include_str!("../../../test_data/tx_ss_p2sh_p2wpkh.json"),
                &[
                    &[2_147_483_697, 2_147_483_649, 2_147_483_648, 0, 2][..],
                    &[2_147_483_697, 2_147_483_649, 2_147_483_648, 0, 1][..],
                ][..],
            ),
        ] {
            let mut emulator = Emulator::new();
            emulator
                .platform_mut()
                .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
            let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
            let scripts = fixture_hex_values(fixture, "script");
            let input_txs = fixture_hex_values(fixture, "input_tx");
            let expected = fixture_legacy_signatures(fixture);
            assert_eq!(paths.len(), scripts.len());
            assert_eq!(paths.len(), input_txs.len());
            assert_eq!(paths.len(), expected.len());

            let start_params = sign_tx_start_params(&txn, paths.len() as u64, false);
            let start_request = Request {
                id: Cow::Borrowed("tx"),
                method: Cow::Borrowed("sign_tx"),
                params: Some(&start_params),
            };
            assert_eq!(
                emulator.handle_v1_request(&start_request),
                V1Outcome::BoolResult { result: true }
            );

            for index in 0..paths.len() {
                let script = decode_hex_vec(scripts[index]);
                let input_tx = decode_hex_vec(input_txs[index]);
                let input_params =
                    sign_tx_input_params(true, paths[index], &script, None, Some(&input_tx));
                let input_request = Request {
                    id: Cow::Borrowed("input"),
                    method: Cow::Borrowed("tx_input"),
                    params: Some(&input_params),
                };
                assert_eq!(
                    emulator.handle_v1_request(&input_request),
                    V1Outcome::BytesResult {
                        result: decode_hex_vec(expected[index])
                    }
                );
            }
        }
    }

    #[test]
    fn sign_tx_legacy_flow_returns_empty_for_unowned_inputs() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
        let fixture = include_str!("../../../test_data/txn_segwit_no_signing.json");
        let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
        let start_params = sign_tx_start_params(&txn, 1, false);
        let start_request = Request {
            id: Cow::Borrowed("tx"),
            method: Cow::Borrowed("sign_tx"),
            params: Some(&start_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&start_request),
            V1Outcome::BoolResult { result: true }
        );

        let input_params = sign_tx_unsigned_input_params(true, Some(2_200_000), None);
        let input_request = Request {
            id: Cow::Borrowed("input"),
            method: Cow::Borrowed("tx_input"),
            params: Some(&input_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&input_request),
            V1Outcome::BytesResult { result: Vec::new() }
        );
    }

    #[test]
    fn sign_tx_legacy_flow_signs_green_multisig_witness_scripts() {
        for (fixture, path, satoshi) in [
            (
                include_str!("../../../test_data/txn_2of2_change.json"),
                &[1, 2][..],
                500_000_000,
            ),
            (
                include_str!("../../../test_data/txn_2of3_change.json"),
                &[2_147_483_651, 2_147_483_649, 1, 1][..],
                4_883_121,
            ),
            (
                include_str!("../../../test_data/txn_2of2csv_change.json"),
                &[1, 1][..],
                100_000_000,
            ),
        ] {
            let mut emulator = Emulator::new();
            emulator
                .platform_mut()
                .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
            let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
            let script = decode_hex_vec(fixture_hex_values(fixture, "script")[0]);
            let expected = fixture_expected_output_signatures(fixture);

            let start_params = sign_tx_start_params(&txn, 1, false);
            let start_request = Request {
                id: Cow::Borrowed("tx"),
                method: Cow::Borrowed("sign_tx"),
                params: Some(&start_params),
            };
            assert_eq!(
                emulator.handle_v1_request(&start_request),
                V1Outcome::BoolResult { result: true }
            );

            let input_params = sign_tx_input_params(true, path, &script, Some(satoshi), None);
            let input_request = Request {
                id: Cow::Borrowed("input"),
                method: Cow::Borrowed("tx_input"),
                params: Some(&input_params),
            };
            assert_eq!(
                emulator.handle_v1_request(&input_request),
                V1Outcome::BytesResult {
                    result: decode_hex_vec(expected[0])
                }
            );
        }
    }

    #[test]
    fn sign_tx_legacy_flow_signs_green_multisig_prevout_transactions() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
        let fixture = include_str!("../../../test_data/txn_segwit_multi_input.json");
        let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
        let scripts = fixture_hex_values(fixture, "script");
        let input_txs = fixture_hex_values(fixture, "input_tx");
        let expected = fixture_expected_output_signatures(fixture);
        assert_eq!(scripts.len(), 2);
        assert_eq!(input_txs.len(), 2);
        assert_eq!(expected.len(), 2);

        let start_params = sign_tx_start_params(&txn, expected.len() as u64, false);
        let start_request = Request {
            id: Cow::Borrowed("tx"),
            method: Cow::Borrowed("sign_tx"),
            params: Some(&start_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&start_request),
            V1Outcome::BoolResult { result: true }
        );

        for index in 0..expected.len() {
            let script = decode_hex_vec(scripts[index]);
            let input_tx = decode_hex_vec(input_txs[index]);
            let input_params = sign_tx_input_params(true, &[1, 1], &script, None, Some(&input_tx));
            let input_request = Request {
                id: Cow::Borrowed("input"),
                method: Cow::Borrowed("tx_input"),
                params: Some(&input_params),
            };
            assert_eq!(
                emulator.handle_v1_request(&input_request),
                V1Outcome::BytesResult {
                    result: decode_hex_vec(expected[index])
                }
            );
        }
    }

    #[test]
    fn sign_tx_staged_flow_signs_taproot_keypath_inputs() {
        for (fixture, sighash) in [
            (include_str!("../../../test_data/tx_ss_p2tr.json"), 0),
            (
                include_str!("../../../test_data/tx_ss_p2tr_sighash_all.json"),
                1,
            ),
        ] {
            let mut emulator = Emulator::new();
            emulator
                .platform_mut()
                .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
            let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
            let scripts = fixture_hex_values(fixture, "script");
            let input_txs = fixture_hex_values(fixture, "input_tx");
            let expected = fixture_expected_output_signatures(fixture);
            let paths = [
                &[2_147_483_734, 2_147_483_649, 2_147_483_648, 0, 2][..],
                &[2_147_483_734, 2_147_483_649, 2_147_483_648, 0, 1][..],
            ];
            assert_eq!(paths.len(), scripts.len());
            assert_eq!(paths.len(), input_txs.len());
            assert_eq!(paths.len(), expected.len());

            let start_params = sign_tx_start_params(&txn, paths.len() as u64, true);
            let start_request = Request {
                id: Cow::Borrowed("tx"),
                method: Cow::Borrowed("sign_tx"),
                params: Some(&start_params),
            };
            assert_eq!(
                emulator.handle_v1_request(&start_request),
                V1Outcome::BoolResult { result: true }
            );

            for index in 0..paths.len() {
                let script = decode_hex_vec(scripts[index]);
                let input_tx = decode_hex_vec(input_txs[index]);
                let input_params = sign_tx_input_params_with_sighash(
                    true,
                    paths[index],
                    &script,
                    sighash,
                    None,
                    Some(&input_tx),
                );
                let input_request = Request {
                    id: Cow::Borrowed("input"),
                    method: Cow::Borrowed("tx_input"),
                    params: Some(&input_params),
                };
                assert_eq!(
                    emulator.handle_v1_request(&input_request),
                    V1Outcome::BytesResult { result: Vec::new() }
                );
            }

            for expected_signature in expected {
                let signature_params = get_signature_params();
                let signature_request = Request {
                    id: Cow::Borrowed("sig"),
                    method: Cow::Borrowed("get_signature"),
                    params: Some(&signature_params),
                };
                assert_eq!(
                    emulator.handle_v1_request(&signature_request),
                    V1Outcome::BytesResult {
                        result: decode_hex_vec(expected_signature)
                    }
                );
            }
        }
    }

    #[test]
    fn sign_tx_staged_flow_rejects_non_empty_taproot_anti_exfil_commitment() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/tx_ss_bad_ae_p2tr_1.json");
        let txn = decode_hex_vec(fixture_hex_values(fixture, "txn")[0]);
        let script = decode_hex_vec(fixture_hex_values(fixture, "script")[0]);
        let input_tx = decode_hex_vec(fixture_hex_values(fixture, "input_tx")[0]);
        let host_commitment =
            decode_hex("4dc3fdadce5758c96c1a31fb8b4cbae97c89e70dd2bae33a78e6b7463d3122f9");

        let start_params = sign_tx_start_params(&txn, 1, true);
        let start_request = Request {
            id: Cow::Borrowed("tx"),
            method: Cow::Borrowed("sign_tx"),
            params: Some(&start_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&start_request),
            V1Outcome::BoolResult { result: true }
        );

        let input_params = sign_tx_input_params_with_ae_sighash(
            true,
            &[2_147_483_734, 2_147_483_649, 2_147_483_648, 0, 1],
            &script,
            0,
            None,
            Some(&input_tx),
            &host_commitment,
        );
        let input_request = Request {
            id: Cow::Borrowed("input"),
            method: Cow::Borrowed("tx_input"),
            params: Some(&input_params),
        };
        assert_eq!(
            emulator.handle_v1_request(&input_request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Invalid non-empty taproot host commitment".to_string()
            }
        );
    }

    #[test]
    fn sign_psbt_returns_noop_psbt_when_no_wallet_input_matches() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
        let psbt = fixture_psbt_base64(include_str!("../../../test_data/psbt_ss_not_us.json"));
        let expected = base64_decode(psbt).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_returns_already_signed_wallet_psbt_unchanged() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
        let psbt = fixture_psbt_base64(include_str!(
            "../../../test_data/psbt_ss_p2wpkh_already_signed.json"
        ));
        let expected = base64_decode(psbt).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_signs_p2pkh_v2_wallet_input() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/psbt_ss_p2pkh_v2.json");
        let psbt = fixture_psbt_base64(fixture);
        let expected = base64_decode(fixture_expected_output_psbt_base64(fixture)).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_signs_p2pkh_v0_wallet_input() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/psbt_ss_p2pkh.json");
        let psbt = fixture_psbt_base64(fixture);
        let expected = base64_decode(fixture_expected_output_psbt_base64(fixture)).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_signs_p2wpkh_wallet_inputs() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/psbt_ss_p2wpkh.json");
        let psbt = fixture_psbt_base64(fixture);
        let expected = base64_decode(fixture_expected_output_psbt_base64(fixture)).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_signs_p2sh_p2wpkh_wallet_inputs() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/psbt_ss_p2sh_p2wpkh.json");
        let psbt = fixture_psbt_base64(fixture);
        let expected = base64_decode(fixture_expected_output_psbt_base64(fixture)).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_signs_p2tr_keypath_wallet_inputs() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/psbt_ss_p2tr_default_all.json");
        let psbt = fixture_psbt_base64(fixture);
        let expected = base64_decode(fixture_expected_output_psbt_base64(fixture)).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_signs_p2sh_multisig_wallet_input() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/psbt_ss_p2sh_multisig.json");
        let psbt = fixture_psbt_base64(fixture);
        let expected = base64_decode(fixture_expected_output_psbt_base64(fixture)).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_signs_p2wsh_multisig_wallet_input() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/psbt_ss_p2wsh_multisig.json");
        let psbt = fixture_psbt_base64(fixture);
        let expected = base64_decode(fixture_expected_output_psbt_base64(fixture)).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_signs_p2sh_p2wsh_multisig_wallet_input() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let fixture = include_str!("../../../test_data/psbt_ss_p2sh_p2wsh_multisig.json");
        let psbt = fixture_psbt_base64(fixture);
        let expected = base64_decode(fixture_expected_output_psbt_base64(fixture)).unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult { result: expected }
        );
    }

    #[test]
    fn sign_psbt_signs_green_multisig_wallet_inputs() {
        for fixture in [
            include_str!("../../../test_data/psbt_tm_green_multisig_2of2csv.json"),
            include_str!("../../../test_data/psbt_tm_green_multisig_2of3.json"),
            include_str!("../../../test_data/psbt_tm_green_multisig_2of3_recovery_signing.json"),
            include_str!(
                "../../../test_data/psbt_tm_green_multisig_2of3_recovery_signing_full_path.json"
            ),
            include_str!("../../../test_data/psbt_tm_multisig_segwit_many_inputs.json"),
            include_str!("../../../test_data/psbt_tm_multisig_segwit_many_inputs_2.json"),
        ] {
            let mut emulator = Emulator::new();
            emulator
                .platform_mut()
                .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
            let psbt = fixture_psbt_base64(fixture);
            let expected = base64_decode(fixture_expected_output_psbt_base64(fixture)).unwrap();

            let mut params = Vec::new();
            minicbor::Encoder::new(&mut params)
                .map(2)
                .unwrap()
                .str("network")
                .unwrap()
                .str(fixture_network(fixture))
                .unwrap()
                .str("psbt")
                .unwrap()
                .str(psbt)
                .unwrap();
            let request = Request {
                id: Cow::Borrowed("psbt"),
                method: Cow::Borrowed("sign_psbt"),
                params: Some(&params),
            };

            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::BytesResult { result: expected }
            );
        }
    }

    #[test]
    fn sign_psbt_defers_for_unsupported_wallet_signature() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_single_sig_seed().to_vec());
        let psbt = fixture_psbt_base64(include_str!("../../../test_data/pset_ss_p2wpkh.json"));

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest-liquid")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::DeferredToCore {
                method: "sign_psbt signing".to_string()
            }
        );
    }

    #[test]
    fn sign_psbt_rejects_network_type_mismatch() {
        let mut emulator = Emulator::new();
        let psbt = fixture_psbt_base64(include_str!(
            "../../../test_data/psbt_tm_wrong_network_type.json"
        ));

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("liquid")
            .unwrap()
            .str("psbt")
            .unwrap()
            .str(psbt)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("psbt"),
            method: Cow::Borrowed("sign_psbt"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Network/psbt type mismatch".to_string()
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
    fn register_otp_and_get_hotp_codes_use_rust_storage() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(vec![0x11; jade_crypto::SHA512_LEN]);
        let uri = "otpauth://hotp/ACME%20Co:john.doe@email.com\
                   ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&counter=0";

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("name")
            .unwrap()
            .str("test_hotp")
            .unwrap()
            .str("uri")
            .unwrap()
            .str(uri)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("otp"),
            method: Cow::Borrowed("register_otp"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("name")
            .unwrap()
            .str("test_hotp")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("otp"),
            method: Cow::Borrowed("get_otp_code"),
            params: Some(&params),
        };

        for expected in ["755224", "287082", "359152"] {
            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::TextResult {
                    result: expected.to_string(),
                }
            );
        }

        assert_eq!(emulator.storage.otp_hotp_counter("test_hotp").unwrap(), 3);
    }

    #[test]
    fn get_otp_code_honors_debug_override_for_totp() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(vec![0x22; jade_crypto::SHA512_LEN]);
        let uri = "otpauth://totp/ACME%20Co:john.doe@email.com\
                   ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&digits=8&algorithm=SHA256";

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("name")
            .unwrap()
            .str("test_totp")
            .unwrap()
            .str("uri")
            .unwrap()
            .str(uri)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("otp"),
            method: Cow::Borrowed("register_otp"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("name")
            .unwrap()
            .str("test_totp")
            .unwrap()
            .str("override")
            .unwrap()
            .u64(59)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("otp"),
            method: Cow::Borrowed("get_otp_code"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "46119246".to_string(),
            }
        );
    }

    #[test]
    fn register_otp_rejects_missing_seed_and_bad_uri() {
        let mut emulator = Emulator::new();
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("name")
            .unwrap()
            .str("otp")
            .unwrap()
            .str("uri")
            .unwrap()
            .str("otpauth://totp/Foo?secret=VM")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("otp"),
            method: Cow::Borrowed("register_otp"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::InternalError,
                message: "Feature requires resetting Jade".to_string(),
            }
        );

        emulator
            .platform_mut()
            .set_debug_wallet_seed(vec![0x11; jade_crypto::SHA512_LEN]);
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("name")
            .unwrap()
            .str("otp")
            .unwrap()
            .str("uri")
            .unwrap()
            .str("otpauth://hotp/Foo?secret=VM")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("otp"),
            method: Cow::Borrowed("register_otp"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to parse otp record".to_string(),
            }
        );
    }

    #[test]
    fn sign_message_returns_legacy_recoverable_signature() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("path")
            .unwrap()
            .array(1)
            .unwrap()
            .u32(0)
            .unwrap()
            .str("message")
            .unwrap()
            .str("Jade is cool")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("msg"),
            method: Cow::Borrowed("sign_message"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "IHd2/Y65d1P7Gq6I6gTDoRql9eEsFEh7B8RtAJm+g+AdHuxT5hbMKN28Jlotxfp0LO3WLxPlJh61BQYPYL1uikw=".to_string(),
            }
        );
    }

    #[test]
    fn sign_message_file_parses_specter_style_payload() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("message_file")
            .unwrap()
            .str("signmessage M/0 ascii:Jade is cool")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("msg"),
            method: Cow::Borrowed("sign_message"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "IHd2/Y65d1P7Gq6I6gTDoRql9eEsFEh7B8RtAJm+g+AdHuxT5hbMKN28Jlotxfp0LO3WLxPlJh61BQYPYL1uikw=".to_string(),
            }
        );
    }

    #[test]
    fn sign_message_rejects_bad_params_and_handles_anti_exfil() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("path")
            .unwrap()
            .array(0)
            .unwrap()
            .str("message")
            .unwrap()
            .str("XYZ")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("msg"),
            method: Cow::Borrowed("sign_message"),
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
            .map(3)
            .unwrap()
            .str("path")
            .unwrap()
            .array(3)
            .unwrap()
            .u32(1)
            .unwrap()
            .u32(2)
            .unwrap()
            .u32(3)
            .unwrap()
            .str("message")
            .unwrap()
            .str("Message to test Anti-Exfil signatures work as expected.")
            .unwrap()
            .str("ae_host_commitment")
            .unwrap()
            .bytes(&decode_hex::<32>(
                "953c84f6fc33c14938899b1ecca09c6a3848951fbd48b472004d4377b73b7046",
            ))
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("msg"),
            method: Cow::Borrowed("sign_message"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BytesResult {
                result: decode_hex_vec(
                    "020a5522522ffa999669e140095d40eb6e7fd047375654ce589ce83b6786c3eea7"
                ),
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("ae_host_entropy")
            .unwrap()
            .bytes(&decode_hex::<32>(
                "c2e58dc572a47c579f539cfb8dc09501c128d193919fef8945199b12ce778c89",
            ))
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("sig"),
            method: Cow::Borrowed("get_signature"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "ewh7wY10jyK3C5xyqtedw6zOKM3wYp5PDo6s6jLvFos+pMD7pdnFekTCBC9jnvLOnFd58JGw85MuXUvMcb3IbA=="
                    .to_string(),
            }
        );
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
    fn get_receive_address_derives_default_green_addresses() {
        let seed = decode_hex::<64>(
            "f1d56befd46eddfc31cda129dc76cd4a2b41d2cf86f10a5ccf0787617afa3869\
             967aab0224742ccc002056747ea09b68598ddf79c027c37a7c3ec923004593da",
        );
        let mut emulator = Emulator::new();
        emulator.platform_mut().set_debug_wallet_seed(seed.to_vec());
        emulator.platform_mut().set_master_unblinding_key(
            jade_crypto::slip77_master_unblinding_key_from_seed(&seed).unwrap(),
        );

        for (network, subaccount, branch, pointer, recovery_xpub, csv_blocks, confidential, expected) in [
            (
                "localtest",
                0,
                1,
                345,
                None,
                0,
                None,
                "2MyMy6Ey7a5dmWJW1D9M7RFwjmXD1ECrgy4",
            ),
            (
                "testnet",
                0,
                1,
                568,
                None,
                51_840,
                None,
                "2MxbBuvnRvgL3uTDtTkufPTdzuwuXE9HCNj",
            ),
            (
                "mainnet",
                3,
                1,
                88,
                Some(""),
                0,
                None,
                "36kTtrBFR5NQmzBxAuNWcmLk22WsuhRq2S",
            ),
            (
                "mainnet",
                0,
                1,
                568,
                Some(
                    "xpub6BYx1MizD2XPpY6EuF5Pso8cG5fVHJEWniziGqXcrrcqH96MUiPcuNQkfKSnGx9tCvBJBZx35fiZE3zBbVkZqH89TU4W6HkyE9fSUx9QHNX",
                ),
                0,
                None,
                "338M4PG24m1gZggrzQV1s9vr3dZZ31kLsU",
            ),
            (
                "localtest-liquid",
                6,
                1,
                345,
                None,
                65_535,
                None,
                "Azpx2UGRpzEQ6pt6yCbPYGnjqNaTtxN2ZdLmMMjWMVvJdzd5uD9cysaRc4Es5auve68RAwijQqReG3AT",
            ),
            (
                "testnet-liquid",
                3,
                1,
                244,
                None,
                65_535,
                None,
                "vjU6NdME2viTa8BzBA6qNG5jQKLfGfLvC93f4fRwZ9SR4pE7KBWQNbGUi2bodfxiMACFDombViiC5Vej",
            ),
            (
                "liquid",
                10,
                1,
                122,
                None,
                65_535,
                None,
                "VJLGotGqjthW3NY7JFZ7EaJZo8rnuRi23waPVY7FwJTYxtFNrNLy6CC4VEQoKRmd5VkL2mmuo64LfZNy",
            ),
            (
                "testnet-liquid",
                0,
                1,
                9,
                None,
                65_535,
                Some(false),
                "8z6YuTaMWRf4UeqAGKmQ64Bi4wPWtw7pqm",
            ),
        ] {
            let mut params = Vec::new();
            let entry_count = 5 + usize::from(recovery_xpub.is_some())
                + usize::from(confidential.is_some());
            let mut encoder = minicbor::Encoder::new(&mut params);
            encoder.map(entry_count as u64).unwrap();
            encoder.str("network").unwrap().str(network).unwrap();
            encoder.str("subaccount").unwrap().u64(subaccount).unwrap();
            encoder.str("branch").unwrap().u64(branch).unwrap();
            encoder.str("pointer").unwrap().u64(pointer).unwrap();
            encoder.str("csv_blocks").unwrap().u64(csv_blocks).unwrap();
            if let Some(recovery_xpub) = recovery_xpub {
                encoder
                    .str("recovery_xpub")
                    .unwrap()
                    .str(recovery_xpub)
                    .unwrap();
            }
            if let Some(confidential) = confidential {
                encoder
                    .str("confidential")
                    .unwrap()
                    .bool(confidential)
                    .unwrap();
            }
            let request = Request {
                id: Cow::Borrowed("a"),
                method: Cow::Borrowed("get_receive_address"),
                params: Some(&params),
            };

            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::TextResult {
                    result: expected.to_string()
                },
                "{network} {subaccount}/{branch}/{pointer}"
            );
        }
    }

    #[test]
    fn get_receive_address_derives_liquid_unconfidential_singlesig_address() {
        let mut emulator = Emulator::new();
        emulator.platform_mut().set_debug_wallet_seed(
            decode_hex::<32>("b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c")
                .to_vec(),
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest-liquid")
            .unwrap()
            .str("variant")
            .unwrap()
            .str("pkh(k)")
            .unwrap()
            .str("confidential")
            .unwrap()
            .bool(false)
            .unwrap()
            .str("path")
            .unwrap()
            .array(3)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap()
            .u32(0x8000_0009)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "2dafKNiCKbRum9S1u5BYqTByZT5R9zSqcWy".to_string()
            }
        );
    }

    #[test]
    fn get_receive_address_derives_liquid_confidential_singlesig_address() {
        let mut emulator = Emulator::new();
        emulator.platform_mut().set_debug_wallet_seed(
            decode_hex::<32>("b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c")
                .to_vec(),
        );
        let master_unblinding_key = jade_crypto::slip77_master_unblinding_key_from_seed(
            &decode_hex::<32>("b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c"),
        )
        .unwrap();
        emulator
            .platform_mut()
            .set_master_unblinding_key(master_unblinding_key);

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest-liquid")
            .unwrap()
            .str("variant")
            .unwrap()
            .str("wpkh(k)")
            .unwrap()
            .str("path")
            .unwrap()
            .array(3)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap()
            .u32(0x8000_0002)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "el1qqwud2rtjxwgfxc9wrey504mtjqujrmzsc442zway65gkuj2f0mm4xfv8h3sqfz223jxjrj307zyqln2dywxmsvpvs9x2tvufj".to_string()
            }
        );
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
    fn get_receive_address_derives_registered_multisig_address() {
        let mut emulator = Emulator::new();
        let xpub = decode_xpub(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe\
             PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        );
        let mut payload = Vec::new();
        payload.extend_from_slice(&[3, MultisigVariant::P2wsh as u8, 0, 2]);
        payload.push(0);
        payload.push(2);
        for signer in 0..2u8 {
            payload.extend_from_slice(&[signer; 4]);
            payload.push(0);
            payload.extend_from_slice(&xpub);
            payload.push(0);
        }
        emulator
            .storage_mut()
            .set_multisig_registration("wallet-a", &authenticated_record(payload))
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("wallet-a")
            .unwrap()
            .str("paths")
            .unwrap()
            .array(2)
            .unwrap()
            .array(1)
            .unwrap()
            .u32(0)
            .unwrap()
            .array(1)
            .unwrap()
            .u32(1)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "bc1qyjkdrj9rr6uzt46fgr7j7kelx92n0lu99ex2zsxlmlvcsaf3yy3qaxune3"
                    .to_string()
            }
        );
    }

    #[test]
    fn get_receive_address_derives_legacy_registered_multisig_address() {
        let mut emulator = Emulator::new();
        let xpub = decode_xpub(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe\
             PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        );
        let mut payload = Vec::new();
        payload.extend_from_slice(&[2, MultisigVariant::P2wsh as u8, 0, 2, 0]);
        payload.extend_from_slice(&xpub);
        payload.extend_from_slice(&xpub);
        emulator
            .storage_mut()
            .set_multisig_registration("legacy-a", &authenticated_record(payload))
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("legacy-a")
            .unwrap()
            .str("paths")
            .unwrap()
            .array(2)
            .unwrap()
            .array(1)
            .unwrap()
            .u32(0)
            .unwrap()
            .array(1)
            .unwrap()
            .u32(1)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "bc1qyjkdrj9rr6uzt46fgr7j7kelx92n0lu99ex2zsxlmlvcsaf3yy3qaxune3"
                    .to_string()
            }
        );
    }

    #[test]
    fn get_receive_address_derives_registered_descriptor_address() {
        let mut emulator = Emulator::new();
        let descriptor =
            "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:pkh(@2/<0;1>/*),older(100))))";
        let datavalues = [
            (
                "@0",
                "[7897b5b3/48'/1'/0'/2']\
                 tpubDE8B47dY4JuGLnXVyDzG76UuhBM5hTjc6sXeJjG6ThbPsryiAnKqQY8CmxWcYjM6eVvkyH7CNTVrmPMxSWP9ZzCfHVHo6preHp6Xhgd42JH",
            ),
            (
                "@1",
                "[1bf12fe0/48'/1'/0'/2']\
                 tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P6BqREemaqrFsC96Fy",
            ),
            (
                "@2",
                "[7897b5b3/48'/1'/1'/2']\
                 tpubDFf2ES1oUSZRgiCFT4mvBQ4jC2xTfRzVwfa6KewXZthgtL83UquqirWXzo1EKi4et3bx2wQz9QFKLDeu6vXoKpgQnJHyV8DomjCjJRT3d57",
            ),
        ];
        emulator
            .storage_mut()
            .set_descriptor_registration(
                "liana-a",
                &authenticated_record(descriptor_registration_payload(2, descriptor, &datavalues)),
            )
            .unwrap();

        let expected = [
            [
                "tb1q0ddn2fn5y66gt2r69dv6el32lw44lupa2ry9enlm8zduxhpwk6aqen88zh",
                "tb1qfj66kfjk98cfcays67c9rvkzals7tnxz2dkxnwrjslwk5tzcd8ysgx9ahf",
            ],
            [
                "tb1qu6j64q9kezc0dxgfl67fgnm2z9yycc55c0fa09uresf65w6py04s4qwgul",
                "tb1qkmr7qpxagfn7mafmsrt6e3qzzc599w28cl037cktjjegenfnhyysllxj5p",
            ],
        ];
        for (branch, branch_expected) in expected.iter().enumerate() {
            for (pointer, expected_address) in branch_expected.iter().enumerate() {
                let mut params = Vec::new();
                minicbor::Encoder::new(&mut params)
                    .map(4)
                    .unwrap()
                    .str("network")
                    .unwrap()
                    .str("testnet")
                    .unwrap()
                    .str("descriptor_name")
                    .unwrap()
                    .str("liana-a")
                    .unwrap()
                    .str("branch")
                    .unwrap()
                    .u64(branch as u64)
                    .unwrap()
                    .str("pointer")
                    .unwrap()
                    .u64(pointer as u64)
                    .unwrap();
                let request = Request {
                    id: Cow::Borrowed("a"),
                    method: Cow::Borrowed("get_receive_address"),
                    params: Some(&params),
                };

                assert_eq!(
                    emulator.handle_v1_request(&request),
                    V1Outcome::TextResult {
                        result: (*expected_address).to_string()
                    }
                );
            }
        }
    }

    #[test]
    fn get_receive_address_rejects_invalid_registered_descriptor_inputs() {
        let mut emulator = Emulator::new();
        let descriptor = "wsh(@0/<0;1>/*)";
        let datavalues = [(
            "@0",
            "[7897b5b3/48'/1'/0'/2']\
             tpubDE8B47dY4JuGLnXVyDzG76UuhBM5hTjc6sXeJjG6ThbPsryiAnKqQY8CmxWcYjM6eVvkyH7CNTVrmPMxSWP9ZzCfHVHo6preHp6Xhgd42JH",
        )];
        emulator
            .storage_mut()
            .set_descriptor_registration(
                "desc-a",
                &authenticated_record(descriptor_registration_payload(2, descriptor, &datavalues)),
            )
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("bad name")
            .unwrap()
            .str("pointer")
            .unwrap()
            .u64(0)
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
                message: "Invalid descriptor name parameter".to_string()
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("missing")
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
                message: "Cannot find named descriptor wallet".to_string()
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("desc-a")
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
                message: "Failed to extract path elements from parameters".to_string()
            }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("liquid")
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("desc-a")
            .unwrap()
            .str("pointer")
            .unwrap()
            .u64(0)
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
                message: "Descriptor wallets not supported on liquid network".to_string()
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
            .str("descriptor_name")
            .unwrap()
            .str("desc-a")
            .unwrap()
            .str("pointer")
            .unwrap()
            .u64(0)
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
                message: "Failed to generate valid descriptor script".to_string()
            }
        );
    }

    #[test]
    fn get_receive_address_rejects_invalid_registered_multisig_paths() {
        let mut emulator = Emulator::new();
        let xpub = decode_xpub(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe\
             PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        );
        let mut payload = Vec::new();
        payload.extend_from_slice(&[3, MultisigVariant::P2wsh as u8, 0, 2]);
        payload.push(0);
        payload.push(2);
        for signer in 0..2u8 {
            payload.extend_from_slice(&[signer; 4]);
            payload.push(0);
            payload.extend_from_slice(&xpub);
            payload.push(0);
        }
        emulator
            .storage_mut()
            .set_multisig_registration("wallet-a", &authenticated_record(payload))
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("wallet-a")
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
                message: "Failed to extract signer paths from parameters".to_string()
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
            .str("multisig_name")
            .unwrap()
            .str("wallet-a")
            .unwrap()
            .str("paths")
            .unwrap()
            .array(2)
            .unwrap()
            .array(1)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap()
            .array(1)
            .unwrap()
            .u32(1)
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
                message: "Unexpected number of signer paths or invalid path for multisig"
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
    fn sign_identity_returns_jade_signature_and_slip13_pubkey() {
        let mut emulator = Emulator::new();
        let mnemonic = bip39::Mnemonic::parse(
            "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
        )
        .unwrap();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(mnemonic.to_seed("").to_vec());

        let challenge =
            decode_hex::<32>("cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2");
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
            .str("challenge")
            .unwrap()
            .bytes(&challenge)
            .unwrap()
            .str("index")
            .unwrap()
            .u64(47)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("sign_identity"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "signature".to_string(),
                        value: OwnedV1Value::Bytes(
                            decode_hex::<65>(
                                "005122cebabb852cdd32103b602662afa88e54c0c0c1b38d7099c64dcd49efe908288114e66ed2d8c82f23a70b769a4db723173ec53840c08aafb840d3f09a18d3"
                            )
                            .to_vec()
                        ),
                    },
                    OwnedResultMapEntry {
                        key: "pubkey".to_string(),
                        value: OwnedV1Value::Bytes(
                            decode_hex::<65>(
                                "0473f21a3da3d0e96fc2189f81dd826658c3d76b2d55bd1da349bc6c3573b13ae4d564710ca0bf84b81c6850e916cb94ae9c397b550589da476ace7aee39ebcb37"
                            )
                            .to_vec()
                        ),
                    },
                ],
            }
        );
    }

    #[test]
    fn get_bip85_bip39_entropy_returns_encrypted_reply() {
        let mut emulator = Emulator::new();
        let mnemonic = bip39::Mnemonic::parse(
            "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
        )
        .unwrap();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(mnemonic.to_seed("").to_vec());

        let host_pubkey =
            decode_hex::<33>("03e581be89d1ef8ce11d60746d08e4f8aedf934d1d861dd436042ee2e3b16db918");
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("num_words")
            .unwrap()
            .u64(12)
            .unwrap()
            .str("index")
            .unwrap()
            .u64(0)
            .unwrap()
            .str("pubkey")
            .unwrap()
            .bytes(&host_pubkey)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("get_bip85_bip39_entropy"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::OwnedMapResult {
                entries: vec![
                    OwnedResultMapEntry {
                        key: "pubkey".to_string(),
                        value: OwnedV1Value::Bytes(
                            decode_hex::<33>(
                                "03ff06999ad61c0f3a733b93fc1e6b75ecfb1439b326e840de590a56454f0eeb0d"
                            )
                            .to_vec()
                        ),
                    },
                    OwnedResultMapEntry {
                        key: "encrypted".to_string(),
                        value: OwnedV1Value::Bytes(vec![
                            0xbd, 0x5d, 0x47, 0x24, 0x24, 0x38, 0x80, 0x73, 0x8e, 0x7e, 0x8b,
                            0x0c, 0x02, 0x65, 0x87, 0x00, 0xa9, 0x05, 0x2e, 0xdf, 0xad, 0xb5,
                            0x0f, 0xf7, 0xa8, 0x42, 0x69, 0x69, 0x8a, 0x08, 0xd3, 0x35, 0x8f,
                            0xb4, 0x06, 0xe8, 0xfa, 0xd7, 0xac, 0x1e, 0x90, 0xb0, 0x82, 0x6f,
                            0xcd, 0xc8, 0xfd, 0xd3, 0xb8, 0x55, 0x68, 0xd9, 0x58, 0x5d, 0xf6,
                            0xe4, 0x1c, 0x87, 0x7b, 0x11, 0x9f, 0xd5, 0xdb, 0x72, 0x6b, 0x21,
                            0x70, 0xdf, 0xf8, 0x66, 0x99, 0xe7, 0x58, 0x5e, 0x5a, 0x35, 0x39,
                            0xbe, 0x5d, 0x4f,
                        ]),
                    },
                ],
            }
        );
    }

    #[test]
    fn show_bip85_bip39_entropy_returns_ok_after_generating_payload() {
        let mut emulator = Emulator::new();
        let mnemonic = bip39::Mnemonic::parse(
            "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
        )
        .unwrap();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(mnemonic.to_seed("").to_vec());

        let host_pubkey =
            decode_hex::<33>("03e581be89d1ef8ce11d60746d08e4f8aedf934d1d861dd436042ee2e3b16db918");
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("num_words")
            .unwrap()
            .u64(24)
            .unwrap()
            .str("index")
            .unwrap()
            .u64(0)
            .unwrap()
            .str("pubkey")
            .unwrap()
            .bytes(&host_pubkey)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("show_bip85_bip39_entropy"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );
    }

    #[test]
    fn get_bip85_rsa_entropy_returns_encrypted_reply() {
        let mut emulator = Emulator::new();
        let mnemonic = bip39::Mnemonic::parse(
            "fish inner face ginger orchard permit useful method fence kidney chuckle party \
             favorite sunset draw limb science crane oval letter slot invite sadness banana",
        )
        .unwrap();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(mnemonic.to_seed("").to_vec());

        let host_pubkey =
            decode_hex::<33>("03e581be89d1ef8ce11d60746d08e4f8aedf934d1d861dd436042ee2e3b16db918");
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("key_bits")
            .unwrap()
            .u64(1024)
            .unwrap()
            .str("index")
            .unwrap()
            .u64(0)
            .unwrap()
            .str("pubkey")
            .unwrap()
            .bytes(&host_pubkey)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("id"),
            method: Cow::Borrowed("get_bip85_rsa_entropy"),
            params: Some(&params),
        };

        let V1Outcome::OwnedMapResult { entries } = emulator.handle_v1_request(&request) else {
            panic!("expected encrypted entropy map");
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "pubkey");
        assert_eq!(
            entries[0].value,
            OwnedV1Value::Bytes(
                decode_hex::<33>(
                    "03ff06999ad61c0f3a733b93fc1e6b75ecfb1439b326e840de590a56454f0eeb0d"
                )
                .to_vec()
            )
        );
        assert_eq!(entries[1].key, "encrypted");
        let OwnedV1Value::Bytes(encrypted) = &entries[1].value else {
            panic!("expected encrypted bytes");
        };
        assert_eq!(encrypted.len(), 128);
        assert_eq!(
            &encrypted[..16],
            &[
                0xbd, 0x5d, 0x47, 0x24, 0x24, 0x38, 0x80, 0x73, 0x8e, 0x7e, 0x8b, 0x0c, 0x02, 0x65,
                0x87, 0x00,
            ]
        );
    }

    #[test]
    fn bip85_rsa_pubkey_validates_key_parameters_before_core_generation() {
        let mut emulator = Emulator::new();

        let request = Request {
            id: Cow::Borrowed("rsa"),
            method: Cow::Borrowed("get_bip85_pubkey"),
            params: None,
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Expecting parameters map".to_string(),
            }
        );

        let invalid_cases = [
            (
                {
                    let mut params = Vec::new();
                    minicbor::Encoder::new(&mut params)
                        .map(1)
                        .unwrap()
                        .str("key_type")
                        .unwrap()
                        .str("bad")
                        .unwrap();
                    params
                },
                "Cannot extract valid key_type from parameters",
            ),
            (
                {
                    let mut params = Vec::new();
                    minicbor::Encoder::new(&mut params)
                        .map(2)
                        .unwrap()
                        .str("key_type")
                        .unwrap()
                        .str("RSA")
                        .unwrap()
                        .str("key_bits")
                        .unwrap()
                        .u64(8192)
                        .unwrap();
                    params
                },
                "Failed to fetch valid key length from message",
            ),
            (
                {
                    let mut params = Vec::new();
                    minicbor::Encoder::new(&mut params)
                        .map(2)
                        .unwrap()
                        .str("key_type")
                        .unwrap()
                        .str("RSA")
                        .unwrap()
                        .str("key_bits")
                        .unwrap()
                        .u64(2048)
                        .unwrap();
                    params
                },
                "Failed to fetch valid index from message",
            ),
        ];

        for (params, expected) in invalid_cases {
            let request = Request {
                id: Cow::Borrowed("rsa"),
                method: Cow::Borrowed("get_bip85_pubkey"),
                params: Some(&params),
            };
            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::Reject {
                    code: ErrorCode::BadParameters,
                    message: expected.to_string(),
                }
            );
        }

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("key_type")
            .unwrap()
            .str("RSA")
            .unwrap()
            .str("key_bits")
            .unwrap()
            .u64(4096)
            .unwrap()
            .str("index")
            .unwrap()
            .u64(0)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("rsa"),
            method: Cow::Borrowed("get_bip85_pubkey"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::DeferredToCore {
                method: "get_bip85_pubkey RSA generation".to_string(),
            }
        );
    }

    #[test]
    fn sign_bip85_digests_validates_digest_arrays_before_core_generation() {
        let mut emulator = Emulator::new();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("key_type")
            .unwrap()
            .str("RSA")
            .unwrap()
            .str("key_bits")
            .unwrap()
            .u64(2048)
            .unwrap()
            .str("index")
            .unwrap()
            .u64(0)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("rsa"),
            method: Cow::Borrowed("sign_bip85_digests"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract digests from parameters".to_string(),
            }
        );

        let digest = [0xab; jade_crypto::SHA256_LEN];
        let mut params = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut params);
        encoder
            .map(4)
            .unwrap()
            .str("key_type")
            .unwrap()
            .str("RSA")
            .unwrap()
            .str("key_bits")
            .unwrap()
            .u64(4096)
            .unwrap()
            .str("index")
            .unwrap()
            .u64(0)
            .unwrap()
            .str("digests")
            .unwrap()
            .array(5)
            .unwrap();
        for _ in 0..5 {
            encoder.bytes(&digest).unwrap();
        }
        let request = Request {
            id: Cow::Borrowed("rsa"),
            method: Cow::Borrowed("sign_bip85_digests"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Unsupported number of digests".to_string(),
            }
        );

        let mut params = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut params);
        encoder
            .map(4)
            .unwrap()
            .str("key_type")
            .unwrap()
            .str("RSA")
            .unwrap()
            .str("key_bits")
            .unwrap()
            .u64(3072)
            .unwrap()
            .str("index")
            .unwrap()
            .u64(0)
            .unwrap()
            .str("digests")
            .unwrap()
            .array(1)
            .unwrap()
            .bytes(&digest)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("rsa"),
            method: Cow::Borrowed("sign_bip85_digests"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::DeferredToCore {
                method: "sign_bip85_digests RSA generation".to_string(),
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
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract path elements from parameters".to_string()
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
            .str("multisig_name")
            .unwrap()
            .str("missing")
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
                message: "Cannot find named multisig wallet".to_string()
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
    fn register_multisig_persists_current_record_for_address_derivation() {
        let mut emulator = Emulator::new();
        let seed = test_mnemonic_seed();
        emulator.platform_mut().set_debug_wallet_seed(seed.to_vec());
        let fingerprint = wallet_fingerprint_from_seed(&seed).unwrap();
        let xpub =
            jade_crypto::pure_rust::xpub_from_seed(&seed, &[], jade_crypto::XpubPrefix::Main)
                .unwrap();
        let xpub_bytes: [u8; BIP32_SERIALIZED_LEN] =
            base58ck::decode_check(&xpub).unwrap().try_into().unwrap();
        let expected = jade_crypto::pure_rust::bitcoin_multisig_address_from_xpubs(
            &[xpub_bytes],
            &[vec![0]],
            jade_crypto::BitcoinNetwork::Main,
            jade_crypto::MultisigScriptVariant::P2wsh,
            true,
            1,
        )
        .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("wallet-r")
            .unwrap()
            .str("descriptor")
            .unwrap()
            .map(4)
            .unwrap()
            .str("variant")
            .unwrap()
            .str("wsh(multi(k))")
            .unwrap()
            .str("sorted")
            .unwrap()
            .bool(true)
            .unwrap()
            .str("threshold")
            .unwrap()
            .u64(1)
            .unwrap()
            .str("signers")
            .unwrap()
            .array(1)
            .unwrap()
            .map(4)
            .unwrap()
            .str("fingerprint")
            .unwrap()
            .bytes(&fingerprint)
            .unwrap()
            .str("derivation")
            .unwrap()
            .array(0)
            .unwrap()
            .str("xpub")
            .unwrap()
            .str(&xpub)
            .unwrap()
            .str("path")
            .unwrap()
            .array(0)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("r"),
            method: Cow::Borrowed("register_multisig"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("wallet-r")
            .unwrap()
            .str("paths")
            .unwrap()
            .array(1)
            .unwrap()
            .array(1)
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
            V1Outcome::TextResult { result: expected }
        );
    }

    #[test]
    fn register_multisig_accepts_liquid_network_and_derives_unconfidential_address() {
        let mut emulator = Emulator::new();
        let seed = test_mnemonic_seed();
        emulator.platform_mut().set_debug_wallet_seed(seed.to_vec());
        let fingerprint = wallet_fingerprint_from_seed(&seed).unwrap();
        let xpub =
            jade_crypto::pure_rust::xpub_from_seed(&seed, &[], jade_crypto::XpubPrefix::Test)
                .unwrap();
        let xpub_bytes: [u8; BIP32_SERIALIZED_LEN] =
            base58ck::decode_check(&xpub).unwrap().try_into().unwrap();
        let expected = jade_crypto::pure_rust::liquid_unconfidential_multisig_address_from_xpubs(
            &[xpub_bytes],
            &[vec![0]],
            jade_crypto::LiquidNetwork::Regtest,
            jade_crypto::MultisigScriptVariant::P2wsh,
            true,
            1,
        )
        .unwrap();
        let mut record_master_unblinding_key = [0u8; jade_crypto::SHA512_LEN];
        record_master_unblinding_key[32..]
            .copy_from_slice(&[0x33; MULTISIG_MASTER_BLINDING_KEY_SIZE]);
        let expected_confidential =
            jade_crypto::pure_rust::liquid_confidential_multisig_address_from_xpubs(
                &[xpub_bytes],
                &[vec![0]],
                jade_crypto::LiquidNetwork::Regtest,
                jade_crypto::MultisigScriptVariant::P2wsh,
                true,
                1,
                &record_master_unblinding_key,
            )
            .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest-liquid")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("liquid-r")
            .unwrap()
            .str("descriptor")
            .unwrap()
            .map(5)
            .unwrap()
            .str("variant")
            .unwrap()
            .str("wsh(multi(k))")
            .unwrap()
            .str("sorted")
            .unwrap()
            .bool(true)
            .unwrap()
            .str("threshold")
            .unwrap()
            .u64(1)
            .unwrap()
            .str("master_blinding_key")
            .unwrap()
            .bytes(&[0x33; MULTISIG_MASTER_BLINDING_KEY_SIZE])
            .unwrap()
            .str("signers")
            .unwrap()
            .array(1)
            .unwrap()
            .map(4)
            .unwrap()
            .str("fingerprint")
            .unwrap()
            .bytes(&fingerprint)
            .unwrap()
            .str("derivation")
            .unwrap()
            .array(0)
            .unwrap()
            .str("xpub")
            .unwrap()
            .str(&xpub)
            .unwrap()
            .str("path")
            .unwrap()
            .array(0)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("r"),
            method: Cow::Borrowed("register_multisig"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest-liquid")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("liquid-r")
            .unwrap()
            .str("confidential")
            .unwrap()
            .bool(false)
            .unwrap()
            .str("paths")
            .unwrap()
            .array(1)
            .unwrap()
            .array(1)
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
            V1Outcome::TextResult { result: expected }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("localtest-liquid")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("liquid-r")
            .unwrap()
            .str("paths")
            .unwrap()
            .array(1)
            .unwrap()
            .array(1)
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
                result: expected_confidential
            }
        );
    }

    #[test]
    fn register_multisig_file_persists_fixture_records() {
        let fixtures = [
            (
                include_str!("../../../test_data/multisig_file_jade.dat"),
                "Jade_File_Test",
                MultisigVariant::P2wsh,
                false,
                1,
                2,
                Some(decode_hex::<32>(
                    "3172ae4169b206645a52df2ef79dff7a8c23412e6c0f129ef92e3ec570c5e2d1",
                )),
            ),
            (
                include_str!("../../../test_data/multisig_file_bw.dat"),
                "Jade_File_Test",
                MultisigVariant::P2wsh,
                true,
                1,
                3,
                None,
            ),
            (
                include_str!("../../../test_data/multisig_file_p2sh-p2wsh.dat"),
                "Test_17characte",
                MultisigVariant::P2wshP2sh,
                false,
                2,
                2,
                None,
            ),
        ];

        for (file, name, variant, sorted, threshold, num_signers, master_blinding_key) in fixtures {
            let mut emulator = Emulator::new();
            emulator
                .platform_mut()
                .set_debug_wallet_seed(test_mnemonic_seed().to_vec());

            assert_eq!(
                register_multisig_file(&mut emulator, file),
                V1Outcome::BoolResult { result: true }
            );

            let details = stored_multisig_details(&emulator, name);
            assert_eq!(details.summary.variant, variant);
            assert_eq!(details.summary.sorted, sorted);
            assert_eq!(details.summary.threshold, threshold);
            assert_eq!(details.summary.num_signers, num_signers);
            assert_eq!(details.summary.master_blinding_key, master_blinding_key);
            assert_eq!(
                details.signers.as_ref().unwrap().len(),
                num_signers as usize
            );
            assert!(details.signers.as_ref().unwrap().iter().all(|signer| {
                valid_serialized_xpub_for_network(&signer.xpub, jade_crypto::BitcoinNetwork::Main)
            }));
        }
    }

    #[test]
    fn register_multisig_file_roundtrips_exported_record() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());

        assert_eq!(
            register_multisig_file(
                &mut emulator,
                include_str!("../../../test_data/multisig_file_sparrow.dat")
            ),
            V1Outcome::BoolResult { result: true }
        );
        let first = stored_multisig_details(&emulator, "Jade_File_Test");
        let exported = multisig_export_file("Roundtrip_File", &first).unwrap();

        assert_eq!(
            register_multisig_file(&mut emulator, &exported),
            V1Outcome::BoolResult { result: true }
        );
        let second = stored_multisig_details(&emulator, "Roundtrip_File");
        assert_eq!(first.summary, second.summary);
        assert_eq!(first.signers, second.signers);
    }

    #[test]
    fn register_multisig_file_rejects_fixture_errors() {
        let fixtures = [
            (
                include_str!("../../../test_data/multisig_bad_file_derivation.dat"),
                "Invalid derivation path",
            ),
            (
                include_str!("../../../test_data/multisig_bad_file_duplicate_field1.dat"),
                "Invalid multisig file",
            ),
            (
                include_str!("../../../test_data/multisig_bad_file_field_missing1.dat"),
                "Insufficient information records",
            ),
            (
                include_str!("../../../test_data/multisig_bad_file_format.dat"),
                "Invalid multisig format",
            ),
            (
                include_str!("../../../test_data/multisig_bad_file_not_in.dat"),
                "Failed to validate co-signers",
            ),
            (
                include_str!("../../../test_data/multisig_bad_file_policy.dat"),
                "Invalid multisig policy",
            ),
            (
                include_str!("../../../test_data/multisig_bad_file_signers1.dat"),
                "Invalid number of signers",
            ),
            (
                include_str!("../../../test_data/multisig_bad_file_sorted.dat"),
                "Invalid sorted flag",
            ),
        ];

        for (file, expected_error) in fixtures {
            let mut emulator = Emulator::new();
            emulator
                .platform_mut()
                .set_debug_wallet_seed(test_mnemonic_seed().to_vec());

            assert_eq!(
                register_multisig_file(&mut emulator, file),
                V1Outcome::Reject {
                    code: ErrorCode::BadParameters,
                    message: expected_error.to_string(),
                }
            );
        }
    }

    #[test]
    fn register_multisig_rejects_invalid_or_unowned_signers() {
        let mut emulator = Emulator::new();
        let seed = test_mnemonic_seed();
        let xpub =
            jade_crypto::pure_rust::xpub_from_seed(&seed, &[], jade_crypto::XpubPrefix::Main)
                .unwrap();

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(3)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap()
            .str("multisig_name")
            .unwrap()
            .str("wallet-r")
            .unwrap()
            .str("descriptor")
            .unwrap()
            .map(4)
            .unwrap()
            .str("variant")
            .unwrap()
            .str("wsh(multi(k))")
            .unwrap()
            .str("threshold")
            .unwrap()
            .u64(1)
            .unwrap()
            .str("sorted")
            .unwrap()
            .bool(false)
            .unwrap()
            .str("signers")
            .unwrap()
            .array(1)
            .unwrap()
            .map(4)
            .unwrap()
            .str("fingerprint")
            .unwrap()
            .bytes(&[0u8; 4])
            .unwrap()
            .str("derivation")
            .unwrap()
            .array(0)
            .unwrap()
            .str("xpub")
            .unwrap()
            .str(&xpub)
            .unwrap()
            .str("path")
            .unwrap()
            .array(1)
            .unwrap()
            .u32(0x8000_0000)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("r"),
            method: Cow::Borrowed("register_multisig"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to validate co-signers".to_string(),
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
    fn register_descriptor_persists_record_for_address_derivation() {
        let mut emulator = Emulator::new();
        let descriptor =
            "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:pkh(@2/<0;1>/*),older(100))))";
        let datavalues = [
            (
                "@0",
                "[7897b5b3/48'/1'/0'/2']\
                 tpubDE8B47dY4JuGLnXVyDzG76UuhBM5hTjc6sXeJjG6ThbPsryiAnKqQY8CmxWcYjM6eVvkyH7CNTVrmPMxSWP9ZzCfHVHo6preHp6Xhgd42JH",
            ),
            (
                "@1",
                "[1bf12fe0/48'/1'/0'/2']\
                 tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P6BqREemaqrFsC96Fy",
            ),
            (
                "@2",
                "[7897b5b3/48'/1'/1'/2']\
                 tpubDFf2ES1oUSZRgiCFT4mvBQ4jC2xTfRzVwfa6KewXZthgtL83UquqirWXzo1EKi4et3bx2wQz9QFKLDeu6vXoKpgQnJHyV8DomjCjJRT3d57",
            ),
        ];

        let mut params = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut params);
        encoder
            .map(4)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("desc-r")
            .unwrap()
            .str("descriptor")
            .unwrap()
            .str(descriptor)
            .unwrap()
            .str("datavalues")
            .unwrap()
            .map(datavalues.len() as u64)
            .unwrap();
        for (key, value) in datavalues {
            encoder.str(key).unwrap().str(value).unwrap();
        }
        let request = Request {
            id: Cow::Borrowed("r"),
            method: Cow::Borrowed("register_descriptor"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("desc-r")
            .unwrap()
            .str("branch")
            .unwrap()
            .u64(1)
            .unwrap()
            .str("pointer")
            .unwrap()
            .u64(1)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("a"),
            method: Cow::Borrowed("get_receive_address"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::TextResult {
                result: "tb1qkmr7qpxagfn7mafmsrt6e3qzzc599w28cl037cktjjegenfnhyysllxj5p"
                    .to_string(),
            }
        );
    }

    #[test]
    fn register_descriptor_rejects_liquid_network() {
        let mut emulator = Emulator::new();
        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(4)
            .unwrap()
            .str("network")
            .unwrap()
            .str("liquid")
            .unwrap()
            .str("descriptor_name")
            .unwrap()
            .str("desc-r")
            .unwrap()
            .str("descriptor")
            .unwrap()
            .str("wsh(@0/<0;1>/*)")
            .unwrap()
            .str("datavalues")
            .unwrap()
            .map(0)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("r"),
            method: Cow::Borrowed("register_descriptor"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Descriptor wallets not supported on liquid network".to_string(),
            }
        );
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
    fn auth_user_rejects_bad_parameters() {
        let mut emulator = Emulator::new();
        let request = Request {
            id: Cow::Borrowed("auth"),
            method: Cow::Borrowed("auth_user"),
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
            .str("network")
            .unwrap()
            .str("notanetwork")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("auth"),
            method: Cow::Borrowed("auth_user"),
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
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("epoch")
            .unwrap()
            .str("notanumber")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("auth"),
            method: Cow::Borrowed("auth_user"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract valid epoch value from parameters".to_string(),
            }
        );
    }

    #[test]
    fn auth_user_updates_epoch_and_unlocks_host_wallet() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
        emulator.state.wallet = WalletLifecycle::Locked;

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(2)
            .unwrap()
            .str("network")
            .unwrap()
            .str("testnet")
            .unwrap()
            .str("epoch")
            .unwrap()
            .u64(1_700_000_123)
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("auth"),
            method: Cow::Borrowed("auth_user"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );
        assert_eq!(emulator.platform().epoch(), Some(1_700_000_123));
        assert_eq!(emulator.state.wallet, WalletLifecycle::Ready);
    }

    #[test]
    fn auth_user_preserves_temporary_wallet_and_fails_without_keys() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_debug_wallet_seed(test_mnemonic_seed().to_vec());
        emulator.state.wallet = WalletLifecycle::Temporary;

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(1)
            .unwrap()
            .str("network")
            .unwrap()
            .str("mainnet")
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("auth"),
            method: Cow::Borrowed("auth_user"),
            params: Some(&params),
        };
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: true }
        );
        assert_eq!(emulator.state.wallet, WalletLifecycle::Temporary);

        let mut emulator = Emulator::new();
        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::BoolResult { result: false }
        );
        assert_eq!(emulator.state.wallet, WalletLifecycle::Uninit);
    }

    #[test]
    fn attestation_methods_are_explicit_platform_boundaries_on_host() {
        let mut emulator = Emulator::new();

        for method in ["register_attestation", "sign_attestation"] {
            let request = Request {
                id: Cow::Borrowed("att"),
                method: Cow::Borrowed(method),
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
            minicbor::Encoder::new(&mut params).map(0).unwrap();
            let request = Request {
                id: Cow::Borrowed("att"),
                method: Cow::Borrowed(method),
                params: Some(&params),
            };
            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::Reject {
                    code: ErrorCode::InternalError,
                    message: "Attestation not supported".to_string(),
                }
            );
        }
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
    fn get_commitments_validates_inputs_before_zkp_defer() {
        let mut emulator = Emulator::new();
        emulator
            .platform_mut()
            .set_master_unblinding_key([0x99; 64]);
        let asset_id = [0x11; jade_crypto::SHA256_LEN];
        let hash_prevouts = [0x22; jade_crypto::SHA256_LEN];
        let vbf = [0x33; jade_crypto::SHA256_LEN];

        for maybe_vbf in [None, Some(&vbf[..])] {
            let mut params = Vec::new();
            let field_count = if maybe_vbf.is_some() { 5 } else { 4 };
            let mut encoder = minicbor::Encoder::new(&mut params);
            encoder
                .map(field_count)
                .unwrap()
                .str("asset_id")
                .unwrap()
                .bytes(&asset_id)
                .unwrap()
                .str("value")
                .unwrap()
                .u64(9_000_000)
                .unwrap()
                .str("hash_prevouts")
                .unwrap()
                .bytes(&hash_prevouts)
                .unwrap()
                .str("output_index")
                .unwrap()
                .u8(1)
                .unwrap();
            if let Some(vbf) = maybe_vbf {
                encoder.str("vbf").unwrap().bytes(vbf).unwrap();
            }
            let request = Request {
                id: Cow::Borrowed("commitments"),
                method: Cow::Borrowed("get_commitments"),
                params: Some(&params),
            };

            assert_eq!(
                emulator.handle_v1_request(&request),
                V1Outcome::DeferredToCore {
                    method: "get_commitments commitments".to_string()
                }
            );
        }
    }

    #[test]
    fn get_commitments_rejects_bad_parameters_before_zkp_defer() {
        let mut emulator = Emulator::new();
        let asset_id = [0x11; jade_crypto::SHA256_LEN];
        let hash_prevouts = [0x22; jade_crypto::SHA256_LEN];

        let mut params = Vec::new();
        minicbor::Encoder::new(&mut params)
            .map(5)
            .unwrap()
            .str("asset_id")
            .unwrap()
            .bytes(&asset_id)
            .unwrap()
            .str("value")
            .unwrap()
            .u64(9_000_000)
            .unwrap()
            .str("hash_prevouts")
            .unwrap()
            .bytes(&hash_prevouts)
            .unwrap()
            .str("output_index")
            .unwrap()
            .u8(1)
            .unwrap()
            .str("vbf")
            .unwrap()
            .bytes(&[0x33; jade_crypto::SHA256_LEN - 1])
            .unwrap();
        let request = Request {
            id: Cow::Borrowed("commitments"),
            method: Cow::Borrowed("get_commitments"),
            params: Some(&params),
        };

        assert_eq!(
            emulator.handle_v1_request(&request),
            V1Outcome::Reject {
                code: ErrorCode::BadParameters,
                message: "Failed to extract vbf from parameters".to_string()
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
