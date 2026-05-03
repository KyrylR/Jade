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

Both firmware crates now also provide reusable device platform adapters for
production bring-up: `Esp32DevicePlatform<H>` over `Esp32Hardware`, and
`Esp32s3DevicePlatform<H>` over `Esp32s3Hardware`. These adapters own the
shared `RuntimePlatformState` exported by `jade-emulator`, implement
`Platform`, `DevicePlatform`, `RuntimePlatform`, and the target-specific board
shim traits, and leave the concrete backend responsible only for raw hardware
operations: manifest/boot report, RNG, clock, rollback counter, serial/BLE/USB
I/O, camera QR input, display/user confirmation, touch, and ESP32-S3 hardware
attestation. This is the intended real-device contract for replacing C/C++
application code: board support code implements the small hardware trait, then
the Rust firmware crate supplies the runtime state glue, version metadata,
boot-gated board runtime, and stream-loop dispatch.
`jade-core::DeviceBootReadiness` now gives those hardware backends a shared
boot-readiness shape for entropy, storage, OTA state, transport, display, and
rollback checks. The ESP32/ESP32-S3 hardware traits can derive the public
`DeviceBootReport` from those booleans by default, so real board code does not
need to hand-assemble the report or duplicate the first-failure ordering used
by the boot gate.
Secure boot and flash-encryption readiness are also part of that boot gate,
not only manifest metadata. A production backend must report the actual eFuse
state, and the Rust runtime now fails closed with explicit boot errors before
accepting traffic if secure boot or flash encryption is not enabled.
The boot gate also models the ESP OTA running-image validation path that the C
firmware currently performs during startup. `DevicePlatform` can now report the
running OTA image state and secure version; when the state is pending verify,
`DeviceRuntime::boot` calls the platform hook that maps to
`esp_ota_mark_app_valid_cancel_rollback` before accepting client traffic, and
invalid or aborted running images fail closed as `OtaStateInvalid`. The ESP32
and ESP32-S3 reusable hardware adapters forward those hooks, so a production
backend only needs to bind them to the concrete ESP OTA APIs.

Both firmware crates also expose constructors for the full generic v1 runtime:
`jade-fw-esp32s3::v1_runtime_for_v2` and `jade-fw-esp32::v1_runtime_for_v1`.
Those constructors instantiate `JadeRuntime<P, B>` with `jade-emulator`
compiled as `no_std + alloc` and default features disabled, so board code can
wire the full Rust v1 behavior engine to ESP platform hooks and storage
without pulling in host `std`. The boot-path tests now cover all official
manifest identities through these constructors: `jade`, `jade_v1_1`, `jade_v2`,
and `jade_v2c`. Each target crate now also has an NVS-specific constructor,
`nvs_runtime_for_v1` or `nvs_runtime_for_v2`, plus
`Esp32V1BoardRuntime::new_with_nvs` and
`Esp32s3V1BoardRuntime::new_with_nvs`, so a real ESP NVS driver only needs to
implement `jade_storage::NvsKeyValueBackend` to become the runtime storage
backend.

Both firmware crates now also expose bootable full-v1 board runtimes:
`Esp32V1BoardRuntime<P, B>` for Jade v1/v1.1 and
`Esp32s3V1BoardRuntime<P, B>` for Jade v2/v2c. These wrappers own the generic
Rust v1 runtime, call the platform boot report before accepting traffic, return
`BootRequired` until the hardware readiness checks pass, and then dispatch
serial/BLE/USB traffic through the full Rust v1 behavior engine. They also
offer a single boot-gated `poll_v1_transports` helper per target, returning a
small report of which links handled frames in that board-loop tick. They also
offer a higher-level `tick` API that performs one board-loop iteration over
v1 transports, QR, display status, user confirmation, monotonic time, rollback
state, and ESP32-S3 touch events. The individual methods still expose
boot-gated hardware RNG, monotonic clock, rollback secure-version, and camera
QR polling over caller-owned buffers, returning
`Ok(None)` when no QR payload is ready and surfacing platform buffer/transport
failures without panicking. Both target families now expose boot-gated display
status and user-confirmation hooks for address, message, transaction, and
export prompts, and the ESP32-S3 board runtime exposes the same boot-gated
boundary for touch press/release events and hardware attestation challenge
signing. OTA start is also exposed on the board runtimes, so firmware event
loops now begin OTA through the boot-gated runtime wrapper before streaming
chunks through `OtaWriteSession<W>`. This is the entrypoint shape expected by a
real board event loop. Tests also verify that the board runtime and both
board-app owner shapes preserve the alternate shipping variants,
`jade_v1_1` and `jade_v2c`, rather than silently normalizing them to the base
ESP32 or ESP32-S3 target.

The firmware crates now also provide board-app owners for the real entrypoint
shape: `Esp32BoardApp<'_, P, B>` and `Esp32s3BoardApp<'_, P, B>` for legacy
one-shot receive buffers, plus `Esp32BoardStreamApp<'_, P, B>` and
`Esp32s3BoardStreamApp<'_, P, B>` for the production stream path. These types
own the bootable full-v1 runtime and borrow fixed transport/QR scratch buffers
supplied by board startup code. They validate those buffers before boot using
the target allocation budgets (`17 KiB` per ESP32 transport buffer,
`401 KiB` per ESP32-S3/SPIRAM transport buffer, and `1024` bytes for QR
payloads), then expose a single `boot` + `tick` flow. This keeps the production
`app_main` boundary concrete without forcing the Rust core to know whether the
buffers came from static memory, heap, or a HAL allocator.
`jade-core::CborFrameBuffer` now mirrors the important `main/wire.c` buffering
behavior in pure Rust: append transport bytes, detect the first complete CBOR
object without allocation, leave trailing bytes pending for the next frame, and
surface full-buffer invalid/incomplete data so the board loop can reject stale
or oversized input explicitly. The ESP32 and ESP32-S3 firmware wrappers expose
boot-gated stream pollers over those buffers for serial/BLE and serial/USB/BLE
respectively, so the real board transport adapters can hand over arbitrary byte
chunks and drain every complete v1 CBOR-RPC request without losing partial or
back-to-back frames. The stream board-app owners now keep those persistent
`CborFrameBuffer`s inside the app object, so firmware glue can allocate the
storage once at startup while still running display, user confirmation, QR,
touch, clock, and rollback checks through the same event-loop tick.
The firmware boundary now also enforces each target manifest's allocation
budget before dispatching a request or sending a response. Oversized request
frames and oversized handler replies return explicit allocation errors instead
of being forwarded to serial, BLE, or USB, which is a required step before the
Rust transport path can run against fixed real-device buffers.
The ESP32 and ESP32-S3 crates now also expose stream board-loop runners,
`Esp32BoardStreamLoop` and `Esp32s3BoardStreamLoop`, which wrap the production
stream app owners with a boot-once/tick-many loop, hook-supplied UI inputs,
per-tick reports, and explicit tick-error surfacing. A real `app_main` can now
own platform drivers, static buffers, NVS, and a small hook object while
delegating the repeated boot/tick/stop policy to the Rust firmware crate.
The runners support both bounded host/test execution with `run_until_stop` and
unbounded firmware execution with `run_until_hook_stop`, so production glue can
run until the hook layer requests shutdown without inventing a synthetic tick
limit. Boot failures are also routed through `on_boot_error` before the loop
returns, allowing a real device hook layer to show recovery UI or retry
hardware readiness checks while keeping the default fail-stop behavior.
The target crates also expose `run_board_stream_loop_from_storage` and
`run_board_stream_loop_with_nvs_storage` helpers, which are the current
Rust-side `app_main` contract: pass the concrete platform shim, concrete NVS
backend, target stream storage, and loop hooks, then let the firmware crate
construct and run the boot-gated stream loop.
For production backends that use the reusable device platform adapters, the
target crates also expose
`run_board_stream_loop_with_hardware_and_nvs_storage`. That helper accepts raw
`Esp32Hardware` or `Esp32s3Hardware`, wraps it in the Rust
`Esp32DevicePlatform` or `Esp32s3DevicePlatform`, attaches the NVS adapter, and
then runs the same boot-gated stream loop. A real `app_main` can therefore be
reduced to board driver construction, static stream storage, NVS backend
construction, hook construction, and one Rust entrypoint call.
Those runners also have startup constructors over named buffer bundles,
`Esp32BoardStreamBuffers` and `Esp32s3BoardStreamBuffers`, plus NVS-backed
`new_with_nvs` constructors. This gives board startup code one typed object
for the static serial/BLE/USB/QR buffers and keeps the positional buffer
ordering out of the final hardware entrypoint.
For firmware targets that want the Rust crate to own the exact static buffer
layout, the crates also provide `Esp32BoardStreamStorage` and
`Esp32s3BoardStreamStorage`. These storage structs contain target-sized
transport and QR arrays, expose borrow-only buffer bundles, and can be passed
directly to the NVS-backed stream-loop constructors. The ESP32-S3 storage is
large enough that it is intended for static or SPIRAM-backed firmware placement,
not host-test stack allocation.

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
runtime without `MemoryStorage`, and both firmware crates now instantiate the
bootable board runtime directly over `NvsStorage<B>`, proving the same type
boundary can serve board I/O, NVS-backed records, and the Rust v1 behavior
engine. The remaining extraction work is to implement production
ESP32/ESP32-S3 hardware hook methods for entropy, clock, display driver
rendering, camera decoding, confirmation input policy, OTA, and attestation,
plus the concrete ESP NVS driver behind the storage shim.

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

`jade-core::OtaWriteSession<W>` now provides the generic Rust OTA writer
lifecycle over a platform `OtaImageWriter`: begin, stream compressed chunks with
offset and byte-count checks, finalize only after the declared compressed size
has arrived, and abort unfinished uploads. Unfinished sessions now also abort
the writer when dropped, so early-return error paths cannot leave a real flash
writer open after a partial upload. It also accepts an optional
`OtaUploadVerifier` so production OTA code can stream the compressed-image hash
alongside flash writes and abort before finalization when the uploaded bytes do
not match the declared compressed hash. The ESP32 and ESP32-S3 firmware crates
expose `begin_ota_update` and `begin_ota_update_verified` helpers that first
assert the official target manifest and OTA partition fit, then start the
platform writer. The remaining board runtimes and both one-shot and stream
board-app owners now expose that same boot-gated path, including the verified
variant. The remaining board work is the concrete ESP OTA writer/verifier that
maps these traits to the device OTA slot APIs and signed-image verification
path.

`jade-fw-esp32s3` now has a hardware-attestation platform boundary for the real
device-specific key path: `sign_hardware_attestation` asks the platform shim
for the hardware public key PEM, external attestation signature, and a device
signature over the challenge, all written into caller-provided buffers. The
Rust board runtime boot-gates that operation and returns `Ok(None)` when a
platform reports that hardware attestation is unavailable, so v2/v2c bring-up
can wire eFuse/DS-backed signing without putting attestation request handling
back into C.

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
  to keep the RPCs outside the Rust implementation.
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
key-path inputs do not keep a request on a C fallback boundary. Remaining
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
  payload shape through the host scanner hook. The ESP32 and ESP32-S3 board
  runtimes now expose the same QR byte boundary through boot-gated firmware
  polling helpers, so a real camera decoder can feed the Rust v1/debug scan
  paths without adding C-owned request handling. The ESP32-S3 board runtime
  also exposes boot-gated touch events for the UI event loop, both target
families expose boot-gated hardware RNG, monotonic clock, rollback
secure-version, and display/confirmation calls, and v2/v2c has a
device-attestation signing hook for the eFuse/DS-backed key path. ESP32-S3
eFuse/DS burning and real RNG/clock/rollback/camera/QR/display/input backends
remain target firmware platform shims, but
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
  `sign_liquid_tx` as must-parity Rust routes; unsupported subcases return
  explicit Rust-core errors inside the relevant transaction policy handlers
  rather than falling through at method dispatch.
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
  Unsupported Liquid PSET policy/finalization cases now return explicit
  Rust-core unsupported errors until their parity is implemented.
  `sign_psbt` itself has no staged anti-exfil subprotocol in the current Jade
  client or C handler; anti-exfil parity belongs to `sign_tx`,
  `sign_liquid_tx`, and message signing. Script-path Taproot is not a pending
  C-removal dependency because current Jade signing is key-path-only; Rust now
  treats script-path Taproot signing/fallback scans as unsupported-by-policy
  rather than C-fallback work. Broader multisig policy validation beyond
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
  policy/finalization cases return the explicit Rust-core unsupported outcome.
  `sign_psbt` has no staged anti-exfil continuation in current Jade. The
  PSBT/PSET Taproot signer and fallback scanner now mirror Jade's
  key-path-only Taproot signer: script-path Taproot markers, merkle roots,
  multiple Taproot derivations, and already-signed key-path inputs do not
  create a C fallback. Broader multisig policy validation beyond
  recognized standard and Green script forms, plus generic Liquid PSET policy
  validation, remain active implementation work.

## First Parity Gates

1. Rust CI gates pass locally: `cargo fmt --all --check`,
   `./tools/check_rust_core_no_c.sh`, `cargo check --workspace --all-targets`,
   `cargo test --workspace`, `cargo clippy --workspace --all-targets
   --all-features -- -D warnings`, and `cargo check -p jade-emulator
   --no-default-features --lib`.
2. v1 method catalog matches current dispatch and continuation methods.
3. `jade-emulator` routes immediate/pre-auth/authenticated calls through Rust
   where parity is implemented and tracks remaining signing and Liquid
   transaction flows as active implementation work.
4. Existing Python/libjade tests remain the oracle for subsequent ports. The
   Rust fixture gate now directly references all 210 original `test_data`
   files. QR image recognition remains a platform-backend responsibility, but
   the Rust v1 debug adapter, firmware RNG/clock/rollback/QR/touch/display/
   confirmation polling boundaries, and all non-image fixture payloads are
   covered by host tests.

## C/C++ Removal Rule

The first enforceable boundary is `crates/`: no Jade-owned C or C++
source/header files are allowed there. The CI helper rejects unrelated C
build/FFI dependencies, while allowing the permanent upstream
`elements`/`secp256k1-zkp` Liquid backend. The legacy firmware remains
available outside `crates/` only as the production implementation and
differential oracle until Rust parity is proven subsystem by subsystem.
