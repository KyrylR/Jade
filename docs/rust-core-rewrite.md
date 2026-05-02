# Rust Core Rewrite

This document is the implementation checkpoint for the Rust rewrite. It keeps
the current C firmware intact while creating a host-first Rust boundary that can
be expanded under differential tests.

## Architecture

- `jade-core`: `no_std + alloc` state and core errors.
- `jade-protocol-v1`: current CBOR-RPC compatibility catalog and v1 wire limits.
- `jade-protocol-v2`: typed canonical request/response model.
- `jade-crypto`: backend traits for secp256k1, P-256, and BIP85 RSA behavior.
- `jade-storage`: storage trait boundary for NVS/host backends.
- `jade-emulator`: host-side Rust emulator entrypoint.
- `jade-fw-esp32s3`: Jade v2/v2c platform shell.
- `jade-fw-esp32`: Jade v1/v1.1 platform shell.

The core is intentionally not tied to ESP-IDF, `esp-hal`, Embassy, radio, USB,
camera, or OTA implementations. Those remain platform shims until each subsystem
has parity evidence.

## State Domains

The Rust core models state as orthogonal domains:

- wallet lifecycle: `Uninit`, `Unsaved`, `Locked`, `Ready`, `Temporary`
- interface/session state: serial, BLE, QEMU TCP, internal
- operation state: idle, client message, UI navigation, signing, OTA

The v1 adapter is responsible for collapsing this into current public protocol
values where older clients expect them.

## RPC Classification

Classification is seeded from `main/process/dashboard.c`, `main/process/*`, and
the continuation methods used by multi-message flows.

| Class | RPCs | Parity |
| --- | --- | --- |
| Immediate | `ping` | must-parity |
| Pre-auth | `get_version_info`, `add_entropy`, `set_epoch`, `logout`, `register_attestation`, `sign_attestation`, `update_pinserver`, `auth_user`, `cancel`, `ota`, `ota_delta` | must-parity |
| Authenticated | `register_otp`, `get_otp_code`, `get_xpub`, `get_registered_multisigs`, `get_registered_multisig`, `register_multisig`, `get_registered_descriptors`, `get_registered_descriptor`, `register_descriptor`, `get_receive_address`, `get_identity_pubkey`, `get_identity_shared_key`, `sign_identity`, `sign_message`, `sign_psbt`, `sign_tx`, `get_master_blinding_key`, `get_bip85_pubkey`, `sign_bip85_digests`, `show_bip85_bip39_entropy` | must-parity |
| Liquid | `get_blinding_factor`, `get_blinding_key`, `get_shared_nonce` | must-parity |
| Liquid TX | `sign_liquid_tx`, `get_commitments` | deferred until audited pure-Rust Liquid transaction milestone |
| Continuation | `ota_data`, `ota_complete`, `tx_input`, `get_extended_data`, `get_signature`, `pin` | must-parity |
| Debug/CI | `debug_selfcheck`, `debug_clean_reset`, `debug_set_mnemonic`, `debug_handshake`, `debug_scan_qr`, `debug_capture_image_data`, `get_bip85_bip39_entropy`, `get_bip85_rsa_entropy` | adapter-only unless promoted by release policy |

## Dependency Policy

- Prefer maintained `no_std + alloc` crates over in-repo rewrites.
- Keep secp256k1 and P-256 behind narrow backend traits until side-channel,
  determinism, performance, and audit gates are complete.
- Freeze BIP85 RSA against golden behavior before swapping implementations.
- Do not introduce C-linked core dependencies. Temporary C/ESP-IDF use belongs
  only in platform shims.
- Liquid address encoding uses a minimal pure-Rust Blech32/address encoder in
  `jade-crypto`, adapted from the local rust-elements implementation under
  `/Users/inter/Desktop/Simpl/rust-elements`. The C++ Elements tree at
  `/Users/inter/Desktop/Simpl/elements` was checked for Blech32 constants and
  network HRPs, but it is not copied into the Rust core. The full `elements`
  crate remains a later decision because its transaction stack brings
  `secp256k1-zkp` concerns that must be audited separately for the no-C-core
  rule.

## Elements Copy/Paste Evaluation

The C++ Elements tree is useful as an oracle, not as a source to paste into the
Rust core. Its Blech32 code is small and isolated, so the Rust rewrite only
ports the constants/checksum shape needed for address parity and validates it
against Jade vectors. The rest of full Liquid parity is spread across C++ wallet,
script, primitive transaction, confidential asset/value, rangeproof, sighash,
and validation code. Copying that into this project would move a large C++/Core
architecture into `jade-core`, violate the no-C-application/core target, and
make bounded-allocation/no-panic review harder.

Liquid transaction completion should therefore use the Elements implementation
as a differential reference and pull behavior across as small Rust modules:
PSET/transaction parsing, issuance/reissuance commitments, confidential
value/asset handling, rangeproof/surjection-proof boundaries, Elements sighash,
anti-exfil signing, and golden vector compatibility. Any temporary dependency
on `secp256k1-zkp` belongs behind the cryptographic backend traits until there
is a reviewed pure-Rust replacement or an explicit release exception.

## Implemented Rust Parity

- v1 management and debug basics: `ping`, `get_version_info`, entropy/epoch,
  logout, OTA metadata flow, pinserver update/reset, and debug seed/mnemonic
  injection.
- Host wallet exports and identity: xpub derivation, BIP39/BIP85 entropy,
  BIP85 RSA validation boundary, P-256 identity pubkey/sign/ECDH, OTP storage,
  and legacy message signing.
- Wallet registration and enumeration: current/legacy multisig records,
  multisig setup-file import/export, descriptor registration for Bitcoin
  networks, and registered wallet listing/details.
- Receive addresses: Bitcoin singlesig, Bitcoin multisig, Bitcoin descriptors,
  Liquid singlesig confidential and unconfidential addresses, and Liquid
  multisig confidential and unconfidential addresses. Liquid Taproot remains
  deferred because Elements uses a different taproot tweak.
- Liquid key helpers: master blinding key export, script blinding key, shared
  nonce, and deterministic blinding factors.
- PSBT/PSET signing front door: Rust now validates PSBT vs. PSET envelope
  compatibility, scans BIP32 derivations for wallet-owned inputs, returns
  no-op PSBT/PSET payloads unchanged when there is nothing to sign or wallet
  inputs are already signed, and defers only when new signatures must be
  produced. Full sighash/signature insertion remains in the transaction-signing
  milestone.

## First Parity Gates

1. `cargo check --workspace --all-targets` passes.
2. v1 method catalog matches current dispatch and continuation methods.
3. `jade-emulator` routes immediate/pre-auth/authenticated calls through Rust
   where parity is implemented and keeps explicit defers for remaining signing
   and Liquid transaction flows.
4. Existing Python/libjade tests remain the oracle for subsequent ports.

## C/C++ Removal Rule

The first enforceable boundary is `crates/`: no C or C++ source/header files are
allowed there. The legacy firmware remains available outside `crates/` only as
the production implementation and differential oracle until Rust parity is
proven subsystem by subsystem.
