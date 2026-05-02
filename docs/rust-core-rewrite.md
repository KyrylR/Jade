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
  network HRPs, but it is not copied into the Rust core. The Rust `elements`
  crate was also evaluated: it is useful as an oracle and may be acceptable
  behind a temporary platform/research boundary, but its transaction stack
  depends directly on `secp256k1-zkp`, so it is not a final no-C-core dependency
  until a pure-Rust ZKP backend or an explicit release exception exists.

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
  and legacy plus anti-exfil message signing. Message anti-exfil now implements
  host commitment validation, signer commitment generation, and the
  `get_signature` continuation using pure-Rust sign-to-contract secp256k1
  primitives matched against libsecp/Jade vectors.
- Wallet registration and enumeration: current/legacy multisig records,
  multisig setup-file import/export, descriptor registration for Bitcoin
  networks, and registered wallet listing/details.
- Receive addresses: Bitcoin singlesig, Bitcoin multisig, Bitcoin descriptors,
  Liquid singlesig confidential and unconfidential addresses, and Liquid
  multisig confidential and unconfidential addresses. Liquid Taproot remains
  deferred because Elements uses a different taproot tweak.
- Liquid key helpers: master blinding key export, script blinding key, shared
  nonce, and deterministic blinding factors. `get_commitments` now performs
  v1-compatible request validation and deterministic ABF/VBF derivation before
  deferring the final asset-generator/value-commitment construction, which
  remains blocked on an audited pure-Rust Elements/ZKP commitment backend.
- PSBT/PSET signing front door: Rust now validates PSBT vs. PSET envelope
  compatibility, scans BIP32 derivations for wallet-owned inputs, returns
  no-op PSBT/PSET payloads unchanged when there is nothing to sign or wallet
  inputs are already signed, and produces pure-Rust ECDSA signatures for the
  first Bitcoin signing paths: single-sig legacy P2PKH, native P2WPKH,
  P2SH-wrapped P2WPKH, Taproot key-path DEFAULT/ALL, and one-device multisig
  partial signatures for P2SH, P2WSH, P2SH-P2WSH, Green 2-of-2 CSV, and
  Green 2-of-3 fixtures, including multi-input Green PSBT byte-order golden
  parity. PSBT anti-exfil, Green recovery policy cases, script-path Taproot,
  full multisig finalization, and Liquid/PSET signing still defer to the
  transaction-signing milestone.
- Bitcoin `sign_tx` flow: Rust now has stateful v1 `sign_tx` / `tx_input` /
  `get_signature` continuation paths for non-anti-exfil Bitcoin transactions
  and a pure-Rust transaction parser/sighash signer that matches the existing
  single-sig P2PKH and single-input P2WPKH legacy-output fixtures. The staged
  non-anti-exfil flow returns an empty signer commitment from `tx_input` and
  the signature from `get_signature`, matching the current client protocol.
  Rust also validates full Bitcoin `input_tx` prevouts by txid, extracts
  witness amounts from them, and matches the multi-input P2WPKH and
  P2SH-P2WPKH legacy-output fixtures. It now preserves the v1 empty-signature
  behavior for unowned inputs and signs Green 2-of-2, Green 2-of-3, CSV, and
  multi-input Green multisig witness-script fixtures, including low-R ECDSA
  grinding compatible with libwally. Taproot key-path `sign_tx` signs
  SIGHASH_DEFAULT and SIGHASH_ALL staged fixtures, and rejects non-empty
  Taproot anti-exfil host commitments with the v1-compatible error. Non-Taproot
  Bitcoin anti-exfil `sign_tx` now returns signer commitments from `tx_input`
  and DER signatures from `get_signature`, matching P2PKH, P2WPKH,
  P2SH-P2WPKH, P2WSH, and multi-input legacy P2PKH anti-exfil fixtures,
  including empty responses for pathless inputs. Bad anti-exfil host-entropy
  lengths now return the v1-compatible protocol error before the
  commitment/entropy consistency check. PSBT anti-exfil, Taproot anti-exfil
  signing, registered/generic multisig policy validation, and Liquid
  `sign_liquid_tx` remain explicit defers.

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
