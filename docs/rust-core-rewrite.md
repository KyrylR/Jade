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
| Liquid TX | `sign_liquid_tx`, `get_commitments` | `get_commitments` commitment construction implemented with the permanent public `elements` Liquid backend; `sign_liquid_tx` now starts a Rust v1 session, validates Liquid `tx_input` continuations, signs non-Taproot legacy/segwit ECDSA inputs, including anti-exfil continuations, and signs staged Liquid Taproot key-path inputs through the public `elements` sighash API |
| Continuation | `ota_data`, `ota_complete`, `tx_input`, `get_extended_data`, `get_signature`, `pin` | must-parity |
| Debug/CI | `debug_selfcheck`, `debug_clean_reset`, `debug_set_mnemonic`, `debug_handshake`, `debug_scan_qr`, `debug_capture_image_data`, `get_bip85_bip39_entropy`, `get_bip85_rsa_entropy` | adapter-only unless promoted by release policy |

## Dependency Policy

- Prefer maintained `no_std + alloc` crates over in-repo rewrites.
- Keep secp256k1 and P-256 behind narrow backend traits until side-channel,
  determinism, performance, and audit gates are complete.
- BIP85 RSA entropy, RSA key generation, public-key PEM export, and RSA-PSS
  digest signing now have a functional RustCrypto-backed implementation. Exact
  mbedTLS historical-vector parity remains a release comparison, not a reason
  to leave the RPCs deferred.
- Final production core must not contain Jade-owned C/C++ application or core
  code. Temporary C/ESP-IDF use belongs only in platform shims. The public
  `elements` crate and its upstream `secp256k1-zkp` backend are the permanent
  Liquid dependency boundary because this is the official Rust Elements stack;
  they are tracked separately from Jade-owned C/C++ removal.
- Liquid address encoding uses a minimal pure-Rust Blech32/address encoder in
  `jade-crypto`, aligned with the public ElementsProject `rust-elements`
  implementation. The C++ Elements tree is not copied into the Rust core. The
  public crates.io `elements` crate now backs host-side Liquid commitment
  construction and Elements transaction parsing unconditionally in
  `jade-crypto`. This is better than depending directly on `secp256k1-zkp`
  because `elements` re-exports the ZKP types and also provides Elements-native
  asset, value, PSET, sighash, transaction, and address structures needed by
  Liquid signing and PSET work. Its
  `secp256k1-zkp-sys` and `secp256k1-sys` dependencies are accepted as the
  permanent upstream Liquid cryptography backend, while Jade-owned C/C++ core
  code remains out of scope for the Rust crates.

## Elements Copy/Paste Evaluation

The C++ Elements tree is useful as an oracle, not as a source to paste into the
Rust core. Its Blech32 code is small and isolated, so the Rust rewrite only
ports the constants/checksum shape needed for address parity and validates it
against Jade vectors. The rest of full Liquid parity is spread across C++ wallet,
script, primitive transaction, confidential asset/value, rangeproof, sighash,
and validation code. Copying that into this project would move a large C++/Core
architecture into `jade-core`, violate the no-C-application/core target, and
make bounded-allocation/no-panic review harder.

Liquid transaction completion uses the public Elements implementation as the
production dependency and the C firmware/libjade behavior as the differential
reference. The Rust `sign_liquid_tx` signer covers non-Taproot legacy/segwit
ECDSA inputs by parsing Elements transactions with `elements`, constructing
Elements legacy/BIP143 sighashes with `SighashCache`, parsing confidential or
explicit value commitments, and reusing Jade's low-R and anti-exfil ECDSA
signers. It also covers staged Liquid Taproot key-path inputs by collecting the
full prevout set from `tx_input`, using the Jade-compatible Liquid
main/testnet/regtest genesis hashes for ELIP-0101 Taproot sighashes, verifying
Elements Taproot tweaked output keys against the supplied script pubkeys, and
producing DEFAULT/ALL Schnorr signatures. Remaining Liquid work is now narrower:
script-path Taproot, PSET mutation, and full confidential transaction proof
validation. Direct `secp256k1-zkp` usage should still stay behind narrow Liquid
helper APIs unless there is a reason to expose the lower-level backend.

The hard parts are hard for concrete compatibility reasons:

- BIP85 RSA follows the same pragmatic rule as Liquid: use the smallest backend
  boundary that gets working Jade behavior. The first implementation is pure
  Rust: BIP85 RSA entropy feeds a SHAKE256 deterministic RNG for RustCrypto RSA
  key generation, PEM export, and RSA-PSS signing. If downstream compatibility
  requires byte-for-byte matching against historical mbedTLS public-key or
  signature vectors, add a narrowly scoped `bip85-rsa-compat` backend for only
  `get_bip85_pubkey` and `sign_bip85_digests`; keep it behind `jade-crypto`
  traits and do not reintroduce libwally or broad C application logic into the
  Rust crates.

## Implemented Rust Parity

- v1 management and debug basics: `ping`, `get_version_info`, entropy/epoch,
  logout, OTA metadata flow, pinserver update/reset, and debug seed/mnemonic
  injection.
- Host wallet exports and identity: xpub derivation, BIP39/BIP85 entropy,
  BIP85 RSA public-key PEM export and RSA-PSS digest signing, P-256 identity
  pubkey/sign/ECDH, OTP storage,
  and legacy plus anti-exfil message signing. Message anti-exfil now implements
  host commitment validation, signer commitment generation, and the
  `get_signature` continuation using pure-Rust sign-to-contract secp256k1
  primitives matched against libsecp/Jade vectors.
- Wallet registration and enumeration: current/legacy multisig records,
  multisig setup-file import/export, descriptor registration for Bitcoin
  networks, and registered wallet listing/details.
- Receive addresses: default Green 2-of-2, Green 2-of-3 recovery-xpub, and
  Green CSV p2sh-p2wsh addresses for Bitcoin and Liquid, plus Bitcoin
  singlesig, Bitcoin multisig, Bitcoin descriptors, Liquid singlesig
  confidential and unconfidential addresses, and Liquid multisig confidential
  and unconfidential addresses. Liquid singlesig Taproot now uses the Elements
  taproot tweak and Blech32m confidential address encoding.
- Liquid key helpers: master blinding key export, script blinding key, shared
  nonce, deterministic blinding factors, and `get_commitments` asset-generator
  plus value-commitment construction. Host `get_commitments` now matches Jade
  Liquid commitment vectors through the permanent public `elements` backend.
- PSBT/PSET signing front door: Rust now validates PSBT vs. PSET envelope
  compatibility, scans BIP32 derivations for wallet-owned inputs, returns
  no-op PSBT/PSET payloads unchanged when there is nothing to sign or wallet
  inputs are already signed, and produces pure-Rust ECDSA signatures for the
  first Bitcoin signing paths: single-sig legacy P2PKH, native P2WPKH,
  P2SH-wrapped P2WPKH, Taproot key-path DEFAULT/ALL, and one-device multisig
  partial signatures for P2SH, P2WSH, P2SH-P2WSH, Green 2-of-2 CSV, and
  Green 2-of-3 fixtures, including multi-input Green PSBT byte-order golden
  parity plus Green 2-of-3 recovery signing with both short parent-fingerprint
  and full-path derivations. Raw v1 CBOR responses now chunk large signed PSBT
  byte results with `seqnum`/`seqlen` and validate `get_extended_data`
  continuation requests against the originating id and method. PSBT
  anti-exfil, script-path Taproot, full multisig finalization, Liquid PSET
  signing/mutation, and full Liquid proof validation remain active
  transaction-signing implementation work.
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
  commitment/entropy consistency check. Liquid `sign_liquid_tx` now enters the
  Rust v1 adapter for network validation, public `elements` transaction
  parsing, input-count validation, trusted-commitment array checks, change
  output metadata checks, and asset-info shape validation, then starts a
  stateful Liquid legacy or anti-exfil signing session. Liquid `tx_input`
  continuations now use Jade-compatible validation for signing paths, scripts,
  witness value commitments, sighash values, and anti-exfil host commitments,
  including empty byte replies for pathless no-sign inputs. Non-Taproot
  legacy/segwit ECDSA Liquid inputs now produce DER+sighash signatures through
  the `elements` sighash backend in both immediate legacy signing and staged
  anti-exfil signing: `tx_input` returns the signer commitment and
  `get_signature` returns the final DER+sighash signature. Staged Liquid
  Taproot key-path inputs now collect all prevouts, compute genesis-aware
  Elements Taproot sighashes, reject non-matching output keys, and return
  DEFAULT/ALL Schnorr signatures matching the Jade fixture. PSBT anti-exfil,
  Liquid script-path Taproot, registered/generic multisig policy validation,
  PSET mutation, and full confidential transaction proof validation remain
  active implementation work.

## First Parity Gates

1. `cargo check --workspace --all-targets` passes.
2. v1 method catalog matches current dispatch and continuation methods.
3. `jade-emulator` routes immediate/pre-auth/authenticated calls through Rust
   where parity is implemented and tracks remaining signing and Liquid
   transaction flows as active implementation work.
4. Existing Python/libjade tests remain the oracle for subsequent ports.

## C/C++ Removal Rule

The first enforceable boundary is `crates/`: no Jade-owned C or C++
source/header files are allowed there. The CI helper rejects unrelated C
build/FFI dependencies, while allowing the permanent upstream
`elements`/`secp256k1-zkp` Liquid backend. The legacy firmware remains
available outside `crates/` only as the production implementation and
differential oracle until Rust parity is proven subsystem by subsystem.
