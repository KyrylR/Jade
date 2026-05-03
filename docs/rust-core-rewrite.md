# Rust Core Rewrite

This document is the implementation checkpoint for the Rust rewrite. It keeps
the current C firmware intact while creating a host-first Rust boundary that can
be expanded under differential tests.

## Architecture

- `jade-core`: `no_std + alloc` state, core errors, device runtime, and
  firmware frame dispatch.
- `jade-protocol-v1`: current CBOR-RPC compatibility catalog and v1 wire limits.
- `jade-protocol-v2`: typed canonical request/response model.
- `jade-crypto`: backend traits for secp256k1, P-256, and BIP85 RSA behavior.
- `jade-storage`: storage trait boundary for NVS/host backends.
- `jade-emulator`: Rust v1 behavior engine and host emulator entrypoint. The
  library now exposes `JadeRuntime<P, B>` over platform and storage backend
  types, supports `no_std + alloc` with `default-features = false`, and keeps
  the CLI binary on the default `std` feature for host conveniences.
- `jade-fw-esp32s3`: Jade v2/v2c platform shell with official target
  manifests, partition/OTA slot budgets, runtime constructor, and ESP32-S3
  capability traits for serial, BLE, USB, camera QR, touch, rollback, and
  hardware attestation.
- `jade-fw-esp32`: Jade v1/v1.1 platform shell with official target
  manifests, partition/OTA slot budgets, runtime constructor, and ESP32
  capability traits for serial, BLE, camera QR, rollback, and release security
  gates.

The core is intentionally not tied to ESP-IDF, `esp-hal`, Embassy, radio, USB,
camera, or OTA implementations. Those remain platform shims until each subsystem
has parity evidence.

## Real-Device Firmware Boundary

The first real-device Rust boundary now exists in code rather than just in this
plan. `jade-core::DeviceRuntime` owns the shared `CoreState`, accepts any
target platform that implements `DevicePlatform`, performs boot readiness
checks, exposes the target `DeviceManifest`, and dispatches typed v2 requests
through the same core path used by host tests. `jade-core::FirmwareProtocol`
and `DeviceRuntime::handle_firmware_frame` process v1 CBOR compatibility frames
and v2 typed CBOR frames after boot, returning `BootRequired` before the
platform is ready. The target firmware crates bind that generic runtime to the
official Jade targets:

| Crate | Official targets | SoC | Partition baseline | Required platform shims |
| --- | --- | --- | --- | --- |
| `jade-fw-esp32s3` | `jade_v2`, `jade_v2c` | ESP32-S3 | `partitionss3.csv`, dual 4024K OTA slots, 64K NVS, attest partition | serial, BLE, USB, camera QR, touch, entropy, storage, OTA/rollback, hardware attestation |
| `jade-fw-esp32` | `jade`, `jade_v1_1` | ESP32 | `partitions.csv`, dual 1984K OTA slots, 16K NVS | serial, BLE, camera QR, entropy, storage, OTA/rollback |

Both firmware crates now assert their manifests against shipping partition
sizes and release gates: dual OTA slots, secure boot, flash encryption,
anti-rollback, required user I/O, and the correct ESP32 vs. ESP32-S3 capability
split. They also expose transport pollers for the real links:
`jade-fw-esp32s3` has serial, USB, and BLE pollers for v1/v2 CBOR frames, while
`jade-fw-esp32` has serial and BLE pollers. The boot/core pollers dispatch
through `DeviceRuntime`; the full-v1 pollers dispatch through
`JadeRuntime<P, B>::handle_v1_cbor`, so board code can now wire the full Rust
wallet/signing/auth/management v1 engine directly to serial/BLE/USB shims and
write replies back through the same link.

Both firmware crates also expose constructors for the full generic v1 runtime:
`jade-fw-esp32s3::v1_runtime_for_v2` and `jade-fw-esp32::v1_runtime_for_v1`.
Those constructors instantiate `JadeRuntime<P, B>` with `jade-emulator`
compiled as `no_std + alloc` and default features disabled, so board code can
wire the full Rust v1 behavior engine to ESP platform hooks and NVS storage
without pulling in host `std`.

Both firmware crates now also expose bootable full-v1 board runtimes:
`Esp32V1BoardRuntime<P, B>` for Jade v1/v1.1 and
`Esp32s3V1BoardRuntime<P, B>` for Jade v2/v2c. These wrappers own the generic
Rust v1 runtime, call the platform boot report before accepting traffic, return
`BootRequired` until the hardware readiness checks pass, and then dispatch
serial/BLE/USB traffic through the full Rust v1 behavior engine. This is the
entrypoint shape expected by a real board event loop.

This does not yet flash a board, but it gives the pure-Rust firmware bring-up a
concrete target API: implement the platform shim traits for an `esp-hal` or
conservative ESP-IDF-hosted transitional backend, boot `DeviceRuntime`, create
the full board runtime over the same hardware-facing state and NVS backend, and
call the v1/v2 transport pollers from the board event loop.

The large v1 wallet/signing implementation is also no longer intrinsically
host-only: `cargo check -p jade-emulator --no-default-features --lib` passes,
and the implementation now has `JadeRuntime<P, B>` with a host `Emulator` alias
for `JadeRuntime<HostPlatform, MemoryStorage>`. The full `handle_v1_request`
implementation is generic over `RuntimePlatform` and `StorageBackend`, so the
same wallet/signing/auth/management handler can be instantiated with device
platform hooks instead of the host emulator platform. `jade-emulator` now also
exports `RuntimePlatformState` and a `RuntimePlatformStateAccess` blanket
implementation, so production ESP32/ESP32-S3 platform structs can reuse the
same transient wallet/PIN/attestation/debug state holder and only provide
hardware-specific epoch, entropy, UI, camera, transport, OTA, attestation, and
NVS behavior. A device-style storage backend test instantiates the generic
runtime without `MemoryStorage`, which is the first step toward using
NVS-backed storage on hardware. The firmware crate tests now instantiate
full-v1 runtimes with platform types that implement both the real-device
transport shims and `RuntimePlatformStateAccess`, proving that the same type
boundary can serve board I/O and the Rust v1 behavior engine. The remaining
extraction work is to implement production ESP32/ESP32-S3 hardware hook methods
for entropy, clock, display, camera, confirmation, OTA, and attestation, plus
the concrete ESP NVS driver behind the storage shim.

The storage crate now includes an `NvsKeyValueBackend` + `NvsStorage<B>`
adapter. It maps Jade's typed `StorageNamespace` values to fixed NVS namespace
names, validates Jade/NVS key constraints before platform I/O, and lets the
existing `JadeStorage` record, PIN-counter, registration, OTP, and pinserver
helpers run unchanged over an ESP NVS backend.

The device manifest now validates OTA requests against the target partition
layout. `DeviceManifest::validate_ota_request` rejects full firmware images,
compressed uploads, and delta patches that do not fit the configured OTA slot,
making partition fit a shared core release gate instead of a late board-script
check.

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
| Liquid TX | `sign_liquid_tx`, `get_commitments` | `get_commitments` commitment construction implemented with the permanent public `elements` Liquid backend; `sign_liquid_tx` now starts a Rust v1 session, verifies supplied factor-backed or explicit-proof trusted commitments against transaction outputs, preserves v1-compatible null trusted-commitment entries, validates Liquid `tx_input` continuations, signs non-Taproot legacy/segwit ECDSA inputs, including anti-exfil continuations and standard Elements ECDSA sighash flags, and signs staged Liquid Taproot key-path inputs through the public `elements` sighash API |
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
explicit value commitments, verifying supplied trusted commitments against the
transaction asset/value commitments when the host provides ABF/VBF material or
explicit rangeproof/surjection-proof data, and reusing Jade's low-R and
anti-exfil ECDSA signers. Null or empty trusted-commitment entries remain
accepted for v1 compatibility and are treated as unverified entries, matching
current firmware behavior. The v1 adapter now accepts the standard Elements
ECDSA sighash set, including `SIGHASH_SINGLE|ANYONECANPAY`, and matches the
Jade single-sig Liquid anti-exfil fixtures for P2PKH, P2WPKH, P2SH-P2WPKH, and
the Liquidex partial-swap maker flow. Fixture coverage now also includes legacy
low-R, large-amount, ledger-compare, no-signing, explicit-sighash, testnet,
non-confidential-input, non-CSV, tx-commitment, random-blinder/proof-shape,
asset-info, and swap maker/taker flows, including null no-sign input slots. It
also covers staged Liquid Taproot key-path inputs by collecting the full
prevout set from `tx_input`, using the Jade-compatible Liquid
main/testnet/regtest genesis hashes for ELIP-0101 Taproot sighashes, verifying
Elements Taproot tweaked output keys against the supplied script pubkeys, and
producing DEFAULT/ALL Schnorr signatures. Liquid PSET signing now covers
singlesig, the Liquidex partial-swap maker PSET, and the current Green
witness-script fixtures, and returns Liquid PSET payloads unchanged when the
wallet has no matching signing input. The PSBT/PSET Taproot signer and
fallback scanner now match Jade's current Taproot policy boundary: single-key
key-path Taproot is eligible for Rust signing, while script-path Taproot
markers, merkle roots, multiple Taproot derivations, and already-signed
key-path inputs do not keep a request on the legacy C-core boundary. Remaining
Liquid work is now narrower: generic PSET policy validation beyond the covered
send, swap, singlesig, and Green cases. Direct `secp256k1-zkp` usage should
still stay behind narrow Liquid helper APIs unless there is a reason to expose
the lower-level backend.

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
  logout, OTA metadata flow, pinserver update/reset, attestation
  registration/signing request validation plus RustCrypto RSA PKCS#1 v1.5
  SHA-256 signing behind host platform state, and debug seed/mnemonic
  injection. The blind PIN oracle client now has Rust request assembly,
  replay-counter handling, recoverable payload signing, AES-CBC/HMAC
  ECDH-envelope compatibility, server-reply validation, final AES-key
  derivation, AES-CBC/HMAC wallet seed blob encryption/decryption, retry
  counter restore/decrement semantics, and host-first `auth_user` -> `pin`
  continuation paths for both `set_pin` wallet persistence and `get_pin`
  wallet unlock. `get_version_info` now derives `jade_has_pin` and `LOCKED`
  state from the Rust encrypted wallet blob when no seed is loaded, matching
  the public keychain state without the C keychain globals. These routes emit
  the existing `http_request`/`on-reply` shape while keeping HTTP transport and
  PIN entry as platform boundaries. Adapter-only debug handshake, QR image
  capture, and QR scan calls now route through Rust host platform byte hooks
  instead of the C debug handlers. The Rust QR adapter now references every
  original QVGA JSON/DAT fixture pair and validates the expected text/hex
  payload shape through the host scanner hook. ESP32-S3 eFuse/DS burning and
  real camera/QR decoder backends remain target firmware platform shims, but
  the v1 core response shapes and request validation no longer require
  Jade-owned C application code.
- Host wallet exports and identity: xpub derivation, BIP39/BIP85 entropy,
  BIP85 RSA public-key PEM export and RSA-PSS digest signing, P-256 identity
  pubkey/sign/ECDH, OTP storage,
  and legacy plus anti-exfil message signing. Message anti-exfil now implements
  host commitment validation, signer commitment generation, and the
  `get_signature` continuation using pure-Rust sign-to-contract secp256k1
  primitives matched against libsecp/Jade vectors. Rust emulator coverage now
  directly imports the original message JSON fixtures, valid and invalid
  message-file fixtures, and the full identity JSON fixture set, including
  SLIP-0013 public keys/signatures, SLIP-0017 public keys, and ECDH symmetry
  checks against the Trezor-compatible fixture.
- Wallet registration and enumeration: current/legacy multisig records,
  multisig setup-file import/export, descriptor registration for Bitcoin
  networks, and registered wallet listing/details. The Rust descriptor shell
  now covers all original descriptor address fixtures for `wsh(...)`,
  `sh(wsh(...))`, Taproot `tr(...)`, Jade's `/**` branch/pointer wildcard
  form, and the Miniscript `or_i(...)`, `thresh(...)`, and `a:` wrappers used
  by the long Liana/P2SH fixtures through the v1 `register_descriptor` and
  `get_receive_address` APIs. Multisig setup-file import now references every
  original accepted and rejected JSON/DAT fixture pair, including Jade,
  BlueWallet, Nunchuk, Sparrow, Specter, P2SH, P2WSH, wrapped P2WSH, bad
  derivation, duplicate-field, missing-field, format, policy, signer-count,
  signer-membership, and sorted-flag cases. Direct multisig registration now
  covers all original `multisig_reg_*` fixtures, including 15-of-15,
  1-of-1, Green/GA-compatible 2-of-2 and 2-of-3, singlesig Liquid 1-of-2,
  P2SH, sorted P2WSH, QR-example, Liquid blinding-key/shared-nonce, and
  Liquid commitment vectors.
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
  The v1 method catalog now marks these Liquid helper RPCs and
  `sign_liquid_tx` as must-parity Rust routes; unsupported subcases defer
  inside the relevant transaction policy handlers rather than at method
  dispatch.
- PSBT/PSET signing front door: Rust now validates PSBT vs. PSET envelope
  compatibility, scans BIP32 derivations for wallet-owned inputs, returns
  no-op Bitcoin PSBT and Liquid PSET payloads unchanged when there is nothing
  to sign, no wallet-owned input matches, or wallet inputs are already signed,
  and produces pure-Rust ECDSA signatures for Bitcoin signing paths:
  single-sig legacy P2PKH, native P2WPKH including the original coinbase-spend
  fixture, P2SH-wrapped P2WPKH, Taproot key-path DEFAULT/ALL, and one-device
  multisig partial signatures for P2SH, P2WSH, P2SH-P2WSH, Green 2-of-2 CSV,
  and all original Green/native/wrapped/partial multisig PSBT fixtures,
  including multi-input Green PSBT byte-order golden parity plus Green 2-of-3
  recovery signing with both short parent-fingerprint and full-path
  derivations. Raw v1 CBOR responses now chunk large signed PSBT byte results
  with `seqnum`/`seqlen` and validate `get_extended_data` continuation
  requests against the originating id and method. Liquid PSET
  signing now uses the permanent public `elements` PSET and sighash APIs to
  mutate singlesig P2PKH, P2WPKH, P2SH-P2WPKH, Liquidex partial-swap
  `SIGHASH_SINGLE|ANYONECANPAY`, Taproot key-path, and Green witness-script
  CSV/no-recovery P2WSH fixtures byte-for-byte against Jade `test_data`,
  preserving raw map ordering and inserting only the new partial signatures.
  Bitcoin PSBT and Liquid PSET multisig script-code selection now accepts only
  recognized standard multisig scripts or Jade Green CSV script forms, so
  arbitrary scripts that merely contain the wallet public key are rejected
  before sighash construction.
  Unsupported Liquid PSET policy/finalization cases still defer explicitly to
  the legacy core boundary until their parity is implemented.
  `sign_psbt` itself has no staged anti-exfil subprotocol in the current Jade
  client or C handler; anti-exfil parity belongs to `sign_tx`,
  `sign_liquid_tx`, and message signing. Script-path Taproot is not a pending
  C-removal dependency because current Jade signing is key-path-only; Rust now
  treats script-path Taproot signing/fallback scans as unsupported-by-policy
  rather than deferred-to-C. Broader multisig policy validation beyond
  recognized standard and Green script forms, plus generic Liquid PSET policy
  validation, remain active transaction-signing implementation work.
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
  grinding compatible with libwally. Bitcoin `sign_tx` start now validates
  declared `change` entries against the actual transaction output scripts for
  Green 2-of-2, Green 2-of-3 recovery-xpub, Green CSV, and singlesig
  P2PKH/P2WPKH/P2SH-P2WPKH/Taproot key-path change outputs. It also validates
  registered multisig and registered descriptor change entries by loading the
  authenticated storage record, deriving the exact receive scriptPubKey from
  the stored policy and supplied path/branch/pointer metadata, and comparing it
  with the raw transaction output script before any input signature is
  requested. Mismatched Green CSV, registered multisig, and registered
  descriptor change metadata now reject with `Receive script cannot be
  validated`. Taproot key-path `sign_tx` signs
  SIGHASH_DEFAULT and SIGHASH_ALL staged fixtures, and rejects non-empty
  Taproot anti-exfil host commitments with the v1-compatible error. Non-Taproot
  Bitcoin anti-exfil `sign_tx` now returns signer commitments from `tx_input`
  and DER signatures from `get_signature`, matching P2PKH, P2WPKH,
  P2SH-P2WPKH, P2WSH, and multi-input legacy P2PKH anti-exfil fixtures,
  including empty responses for pathless inputs. All original Bitcoin
  transaction JSON fixtures are now referenced directly from Rust tests,
  including large/pathless inputs, OP_RETURN and pay-to-Taproot output cases,
  no-output-script segwit, explicit sighashes, malformed anti-exfil requests,
  missing `input_tx`, and total-input-less-than-output rejection. Bad
  anti-exfil host-entropy lengths now return the v1-compatible protocol error
  before the commitment/entropy consistency check. Liquid `sign_liquid_tx` now enters the
  Rust v1 adapter for network validation, public `elements` transaction
  parsing, input-count validation, trusted-commitment array checks, factor
  or explicit-proof verification against output asset/value commitments, change
  output metadata checks, and asset-info shape validation, then starts a
  stateful Liquid legacy or anti-exfil signing session. Liquid `tx_input`
  continuations now use Jade-compatible validation for signing paths, scripts,
  witness value commitments, standard Elements ECDSA sighash values, and
  anti-exfil host commitments, including empty byte replies for pathless
  no-sign inputs. Non-Taproot legacy/segwit ECDSA Liquid inputs now produce
  DER+sighash signatures through the `elements` sighash backend in both
  immediate legacy signing and staged anti-exfil signing: `tx_input` returns
  the signer commitment and `get_signature` returns the final DER+sighash
  signature. This matches the P2PKH, P2WPKH, P2SH-P2WPKH, and Liquidex partial
  swap anti-exfil fixtures, including `SIGHASH_SINGLE|ANYONECANPAY`, and the
  broader Liquid fixture corpus for low-R legacy signing, large amounts,
  no-signing inputs, ledger comparison, testnet anti-exfil, explicit sighashes,
  non-confidential inputs, non-CSV scripts, tx commitments, random blinder
  proof-shape variants, including explicit rangeproof/surjection-proof trusted
  commitments, asset metadata, and swap maker/taker flows with null no-sign
  input slots. Staged Liquid Taproot key-path inputs now collect all
  prevouts, compute genesis-aware Elements Taproot sighashes, reject
  non-matching output keys, and return DEFAULT/ALL Schnorr signatures matching
  the Jade fixture. Liquid PSET signing now covers p2pkh, p2wpkh,
  p2sh-p2wpkh, the Liquidex partial-swap maker PSET, Taproot key-path, Green
  CSV witness-script, Green no-recovery P2WSH, and no-wallet-input Liquid PSET
  fixtures through `sign_psbt`, with PSBT/PSET multisig script-code selection
  restricted to recognized standard multisig or Jade Green CSV script forms
  rather than arbitrary pubkey-containing scripts. Unsupported Liquid PSET
  policy/finalization cases return the explicit core-defer outcome.
  `sign_psbt` has no staged anti-exfil continuation in current Jade. The
  PSBT/PSET Taproot signer and fallback scanner now mirror Jade's
  key-path-only Taproot signer: script-path Taproot markers, merkle roots,
  multiple Taproot derivations, and already-signed key-path inputs do not
  create a legacy C-core defer. Broader multisig policy validation beyond
  recognized standard and Green script forms, plus generic Liquid PSET policy
  validation, remain active implementation work.

## First Parity Gates

1. `cargo check --workspace --all-targets` passes.
2. v1 method catalog matches current dispatch and continuation methods.
3. `jade-emulator` routes immediate/pre-auth/authenticated calls through Rust
   where parity is implemented and tracks remaining signing and Liquid
   transaction flows as active implementation work.
4. Existing Python/libjade tests remain the oracle for subsequent ports. The
   Rust fixture gate now directly references all 210 original `test_data`
   files. QR image recognition remains a platform-backend responsibility, but
   the Rust v1 debug adapter and all non-image fixture payloads are covered by
   host tests.

## C/C++ Removal Rule

The first enforceable boundary is `crates/`: no Jade-owned C or C++
source/header files are allowed there. The CI helper rejects unrelated C
build/FFI dependencies, while allowing the permanent upstream
`elements`/`secp256k1-zkp` Liquid backend. The legacy firmware remains
available outside `crates/` only as the production implementation and
differential oracle until Rust parity is proven subsystem by subsystem.
