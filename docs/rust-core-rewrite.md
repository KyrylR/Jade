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
| Liquid | `sign_liquid_tx`, `get_commitments`, `get_blinding_factor`, `get_blinding_key`, `get_shared_nonce` | deferred until audited pure-Rust Liquid milestone |
| Continuation | `ota_data`, `ota_complete`, `tx_input`, `get_extended_data`, `get_signature`, `pin` | must-parity |
| Debug/CI | `debug_selfcheck`, `debug_clean_reset`, `debug_set_mnemonic`, `debug_handshake`, `debug_scan_qr`, `debug_capture_image_data`, `get_bip85_bip39_entropy`, `get_bip85_rsa_entropy` | adapter-only unless promoted by release policy |

## Dependency Policy

- Prefer maintained `no_std + alloc` crates over in-repo rewrites.
- Keep secp256k1 and P-256 behind narrow backend traits until side-channel,
  determinism, performance, and audit gates are complete.
- Freeze BIP85 RSA against golden behavior before swapping implementations.
- Do not introduce C-linked core dependencies. Temporary C/ESP-IDF use belongs
  only in platform shims.

## First Parity Gates

1. `cargo check --workspace --all-targets` passes.
2. v1 method catalog matches current dispatch and continuation methods.
3. `jade-emulator` can route `ping` immediately and defer non-immediate methods.
4. Existing Python/libjade tests remain the oracle for subsequent ports.

## C/C++ Removal Rule

The first enforceable boundary is `crates/`: no C or C++ source/header files are
allowed there. The legacy firmware remains available outside `crates/` only as
the production implementation and differential oracle until Rust parity is
proven subsystem by subsystem.
