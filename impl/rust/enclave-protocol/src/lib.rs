//! Enclave Protocol — canonical wire format for the 2D TEE signing service.
//!
//! This crate defines the length-prefixed CBOR protocol spoken over vsock
//! between the untrusted 2D host and the minimal PQ signing service inside
//! a TEE (Nitro Enclave / SEV-SNP).
//!
//! **High-risk component**: Any change here directly affects the ability
//! to sign AuthorizationTickets (including hard-fork announcements) and
//! to arm the enclave with correct network state.
//!
//! Review gate: Every non-trivial change must go through the 3:3 roborev
//! matrix + compact before being considered reviewed (see AGENTS.md).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// В Phase 1 мы оставляем часть публичных полей без документации,
// чтобы не раздувать скелет. На более поздних фазах документацию нужно будет довести до высокого уровня.
#![allow(missing_docs)]

#[cfg(all(feature = "ml-dsa-65", feature = "test-support"))]
compile_error!(
    "features `ml-dsa-65` and `test-support` are mutually exclusive; do not use --all-features"
);

// Production role isolation (vsock spec §10.2): a signer binary is EITHER the producer (ML-DSA
// AuthorizationTicket signer) OR the Agent Gateway secp256k1 signer — never both. Enforcing it at
// compile time makes a single instance structurally incapable of cross-role command execution
// (e.g. an agent instance signing a producer AuthorizationTicket), so the runtime profile gate
// never has to defend a both-roles binary that should not exist.
#[cfg(all(feature = "ml-dsa-65", feature = "agent-gateway"))]
compile_error!(
    "features `ml-dsa-65` (producer role) and `agent-gateway` (Agent Gateway role) are mutually \
     exclusive — a signer binary serves exactly one role (production role isolation, vsock §10.2)"
);

#[cfg(all(
    release_build,
    any(
        feature = "staging-host",
        feature = "reference-test-key",
        feature = "reference-seal-v1-root"
    )
))]
compile_error!(
    "reference/staging PQ features (staging-host, reference-test-key, reference-seal-v1-root) \
     must not be enabled in release builds; use ml-dsa-65 with platform set_pq_seal_v1_provisioning_root"
);

#[cfg(all(
    release_build,
    any(
        feature = "platform-provisioning-from-file",
        feature = "lab-pq-seal-from-file"
    )
))]
compile_error!("lab file provisioning features are for debug/integration builds only, not release");

// TASK-7.7 5b-2d: the agent sealed-keystore FILE loader + agent file provisioning root are lab/integration
// surfaces only — they accept the sealed keystore + provisioning root from operator-supplied files, which
// belongs to debug/integration images, never a production agent binary (production sources the sealed
// keystore over the attested host-vsock install/restore channel, a deferred slice). Hard-ban from release.
#[cfg(all(release_build, feature = "lab-agent-keystore-from-file"))]
compile_error!(
    "`lab-agent-keystore-from-file` (agent sealed-keystore file loader) is for debug/integration builds \
     only, not release"
);

// (4c) in-guest quote smoke (TASK-7.7 5b-2b-ii (d-ii)/4c): a diagnostic surface for lab/debug guest
// images only — it deliberately stages a vsock black-hole lapse, configfs entry seeding and a
// nonzero-exit child, none of which belongs in a production binary.
#[cfg(all(release_build, feature = "lab-quote-smoke"))]
compile_error!(
    "`lab-quote-smoke` is the (4c) in-guest smoke surface — debug/lab builds only, never release"
);

// 5b-2c-iii live-smoke surface (TASK-7.7): the lab anchor stub (TEST-KEYS-ONLY Ed25519 seed in
// source) + the host-side 0x40 smoke-client cores + the minted smoke keystore fixture — lab/debug
// HOST tooling only, never a production binary surface. Hard-ban from release (mirrors
// lab-quote-smoke).
#[cfg(all(release_build, feature = "lab-agent-smoke"))]
compile_error!(
    "`lab-agent-smoke` (5b-2c-iii lab anchor stub + smoke client; TEST KEYS ONLY) is for \
     debug/lab builds only, never release"
);

// AGENT_K1_PROVE_IDENTITY signing — UN-GATED. 2D PR #144 (type-0x19 reservation) MERGED
// (commit f3908deb in 2D main, 2026-06). The collision concern is resolved; the compile_error! ban
// is REMOVED.

// Live AGENT_K1_GENERATE_KEYS execution — UN-GATED (TASK-18 18-6, 2026-06-22). The three prerequisites
// are ALL DONE + reviewed: (1) anti-rollback durable commit (TASK-7.7 commit_before_emit seal→anchor→swap);
// (2) scope_target-binding (TASK-18 18-2 signed scope_identity byte-compare vs sealed enclave_scope_id);
// (3) AC#14 audit record (record_audit in the GENERATE_KEYS handler). The G3 precondition (TASK-25 AC#1/#3:
// in-TEE enclave_scope_id RNG provenance via the attested provisioning channel) is DONE + verified.
// The compile_error! release ban is REMOVED; the feature can be enabled in release builds.

// Live AGENT_K1_SIGN_TRANSFER signing — UN-GATED (TASK-18 18-7). NOT rollback-sensitive (mutates no
// sealed state); the AC#5 funding profile is a runtime provisioning concern (not a compile gate).

// Live AGENT_K1_SIGN_FAUCET_DISPENSE signing — UN-GATED (TASK-18 18-8). Rollback-sensitive (debits
// sealed spend counters); anti-rollback (commit_before_emit) + scope_identity (18-2) + G3 (TASK-25) DONE.

// Live AGENT_K1_CONFIGURE_TREASURY execution — UN-GATED (TASK-18 18-7). Mutates sealed faucet config
// (Structural). scope_identity binding (18-2) + recovery-counter + AC#14 audit + G3 provenance all DONE.

// TASK-23: the deviceless UDS 0x40 contract-test server stays release-banned (PUBLIC keys, no SNP).
#[cfg(all(release_build, feature = "agent-contract-server"))]
compile_error!(
    "`agent-contract-server` (deviceless UDS 0x40 contract-test server) is test/dev-only and must never \
     ship in a release build — it installs a reference keystore with PUBLIC keys, runs no SNP \
     attestation, and has no anti-rollback durability"
);

// TASK-13b/TASK-24: EXPORT_BACKUP(7) / RESTORE_BACKUP(8) — UN-GATED (TASK-18 18-9). The EXPORT handler
// + audit drain (TASK-13b), the RESTORE handler + AC#6 (TASK-24), + Structural anti-rollback all DONE.

mod boot_input;
pub mod boot_lab_pq_seal;
pub use boot_lab_pq_seal::LAB_PROD_MEASUREMENT as PRODUCTION_PLACEHOLDER_MEASUREMENT;
mod chain_proof_crypto;
pub mod enclave_serve;
pub mod env_config;
// Reference agent keystore for the deviceless contract-test server (TASK-23). Compiled only for the
// contract-server bin or tests, and only when `agent-gateway` provides the keystore types.
#[cfg(all(
    feature = "agent-gateway",
    any(test, feature = "agent-contract-server")
))]
pub mod reference_keystore;
// Deviceless cross-platform 0x40 serve loop for the contract-test server (TASK-23). UDS-only, so
// `unix`-gated (it uses std::os::unix UnixListener / UnixStream); the crate's targets are Linux + macOS.
/// Shared cancellable-boundary primitives (deadline-bounded `poll`) for the agent boot-relay hard bounds
/// (TASK-7.7 5b-2b-ii (a')/(d)). Linux + vsock-transport gated (backed by `nix::poll`).
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
mod cancellable_boundary;
#[cfg(all(
    unix,
    feature = "agent-gateway",
    any(test, feature = "agent-contract-server")
))]
pub mod contract_server;
#[cfg(feature = "ml-dsa-65")]
pub mod platform_provisioning_boot;
/// Killable-subprocess hard bound for the SNP quote fetch (TASK-7.7 5b-2b-ii(d) — invariants/design in
/// the module header + §8). Triple-gated: needs nix (vsock-transport) AND the quote/boot types
/// (agent-gateway). Also home of `HardBoundedQuoteProducer` — the (d-ii)/2 structural serve-gate
/// producer (plain-backtick reference for CONSISTENCY with the trait-side references in
/// `agent_boot_relay`, where the rule is load-bearing: that module exists in agent-gateway-without-
/// vsock builds where this type does not, so a link THERE breaks `cargo doc`; HERE the doc is an
/// attribute of the triple-gated item itself and is compiled out with it, so a link could never
/// dangle — the uniform rule just keeps the next editor from copying a link to a site where it does).
#[cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway"
))]
mod quote_subprocess;
mod uds_listen;
/// AF_VSOCK address/port resolution + validation (pure, gate-free so it is CI-tested without the
/// Linux-only `vsock` crate). The socket-binding leaf is the gated [`vsock_listen`] module.
pub mod vsock_addr;
#[cfg(feature = "vsock-transport")]
pub mod vsock_listen;
#[cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway"
))]
pub use quote_subprocess::agent_quote_child_dispatch;
// Agent Gateway (4b) boot wiring (TASK-7.7 5b-2b-ii (d-ii)/4b): the wired boot-handshake composition
// (`run_boot_handshake_wired`) + the typed boot-event seam. Triple-gated like `quote_subprocess` — the
// cfg intersection of its dependencies (`ValidatedBootBudget`/`HardBoundedQuoteProducer`), never wider
// (§8 hard rule). (5b-2c) NOW EXPORTS the sole `pub` boot bridge `run_agent_gateway_boot` — every other
// wired type stays `pub(crate)`; the bin reaches ONLY this entrypoint.
#[cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway"
))]
mod agent_gateway_boot;
// (5b-2c) The agent-gateway serve-bin boot entrypoint — MUST live in-crate (the wired types it composes
// are crate-private) and stay under the SAME triple gate, NEVER wider; require_real hardcodes
// cfg!(release_build) (THIS crate's build.rs cfg — a copy out-of-crate fails OPEN).
#[cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway"
))]
pub use agent_gateway_boot::run_agent_gateway_boot;
// (4c) in-guest quote smoke (TASK-7.7 5b-2b-ii (d-ii)/4c). QUADRUPLE-gated: the triple gate of the
// consumed items (`quote_subprocess`/`agent_boot_relay` vsock leaves) ∩ the bare `lab-quote-smoke`
// marker — narrower than every consumed item, never wider (§8 hard rule). NOT the 5b-2c serve
// wrapper: no handshake, no `decide_serve`, no listener; `agent_gateway_boot` stays crate-private
// and unexported (the pin above is untouched) — live serve remains gated on 5b-2c.
#[cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway",
    feature = "lab-quote-smoke"
))]
mod quote_smoke;
#[cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway",
    feature = "lab-quote-smoke"
))]
pub use quote_smoke::run_quote_smoke;
/// (b) host-relay daemon (TASK-7.7 5b-2b-ii(b)) — untrusted host process bridging the SNP guest to the
/// external anchor over TCP. Triple-gated: the cfg-INTERSECTION of the vsock leaf
/// (`linux`+`vsock-transport`) and the agent-gateway cores (`relay_forward_once` lives in the
/// agent-gateway-gated `agent_boot_relay`). NEVER wider. Same intersection-gate discipline as
/// `quote_subprocess`/`agent_gateway_boot`.
#[cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway"
))]
mod host_anchor_relay;
#[cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway"
))]
pub use host_anchor_relay::run_host_anchor_relay;
#[cfg(any(
    feature = "test-support",
    feature = "staging-host",
    feature = "reference-test-key"
))]
mod host_test_fixtures;
#[cfg(feature = "ml-dsa-65")]
mod mldsa65;
mod pq_signer;
// Shared platform provisioning root (producer pq-seal-v1 + agent pq-agent-keystore-v1). Compiled only
// for the seal-capable profiles — it uses the optional `zeroize` dep that only those features pull in,
// so the bare no-feature build must not include it.
#[cfg(any(feature = "ml-dsa-65", feature = "agent-gateway"))]
mod seal_root;
/// SEV-SNP attestation report fetch (configfs-tsm) + launch-measurement extraction (TASK-5 Phase 3).
pub mod snp_report;
/// Reference relying-party SNP attestation verifier (TASK-1 AC#3/#12). Off by default — not part
/// of the enclave signing path; enable with `--features snp-verify`.
#[cfg(feature = "snp-verify")]
pub mod snp_verify;
// Agent Gateway secp256k1 signer primitives (TASK-7.6.1). Compiled only under `agent-gateway`,
// keeping it out of the producer ML-DSA signing path.
#[cfg(feature = "agent-gateway")]
pub mod secp256k1;
// Agent Gateway sealed keystore envelope (TASK-7.6.2). `pq-agent-keystore-v1` seal/unseal,
// mirroring the producer `pq-seal-v1` primitives with distinct magic + KDF/measurement domains.
#[cfg(feature = "agent-gateway")]
pub mod agent_keystore;
// TASK-13b: the pq-agent-backup-v1 DR-backup KEM-DEM primitive (ML-KEM-1024 Encaps → SHA3-256 KDF →
// ChaCha20Poly1305) wrapping an opaque payload to the operator's offline recovery public key. Pure crypto,
// no dispatch coupling; compiled only under the un-gated `agent-backup-export-preview` (TASK-18 18-9,
// which pulls the `ml-kem` crate). The EXPORT_BACKUP handler + audit drain + golden vector land in later 13b slices.
#[cfg(feature = "agent-backup-export-preview")]
pub(crate) mod agent_backup;
// Agent Gateway sealed-keystore unseal-at-boot loader (TASK-7.7 5b-2d): the agent twin of
// `boot_lab_pq_seal` — sources the sealed agent keystore + the agent provisioning root (lab file source)
// and unseals it via `agent_keystore::unseal_body`, fail-closed. A PURE source→unseal→return seam: it does
// NOT install and does NOT judge freshness (the 5b-2c bin installs; the handshake reconciles). The lab file
// source is release-banned above. agent-gateway-gated.
#[cfg(feature = "agent-gateway")]
mod boot_agent_keystore;
#[cfg(feature = "agent-gateway")]
pub use boot_agent_keystore::{
    boot_configure_agent_seal_root, unseal_agent_keystore_at_boot,
    AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
};
// Agent Gateway identity proof (TASK-7.6.3). EIP-191 0x19 PROVE_IDENTITY preimage + signer.
#[cfg(feature = "agent-gateway")]
pub mod agent_identity;
// Minimal hand-rolled RLP encoder (TASK-7.6.4). Encode-only; no new crate. The byte-exact 2D
// `Chain.Crypto.Envelope` preimage builder for the structured EIP-155 transfer signer.
#[cfg(feature = "agent-gateway")]
mod rlp;
// Checked 256-bit arithmetic over big-endian [u8;32] (TASK-15, TASK-7.4 §2). Pure, no new crate;
// checked add/mul fail closed on overflow so the faucet worst-case cost (composed in slice 15-3, the
// consumer) can never wrap a spend under a sealed cap.
#[cfg(feature = "agent-gateway")]
mod u256;
// Agent Gateway structured ordinary-transfer signing (TASK-7.6.4). EIP-155 RLP preimage + signer,
// mirroring `agent_identity`. The SIGN_TRANSFER dispatch handler is `agent-sign-transfer-preview`-gated.
#[cfg(feature = "agent-gateway")]
pub mod agent_transfer;
// Agent Gateway key generation (TASK-7.6.3). GENERATE_KEYS keystore-mutation core.
#[cfg(feature = "agent-gateway")]
pub mod agent_keygen;
// Agent Gateway 0x40 dispatch router (TASK-7.6.3). Envelope decode + profile/opcode gates +
// privilege routing + read opcodes; privileged opcodes via a fail-closed capability seam.
#[cfg(feature = "agent-gateway")]
pub mod agent_dispatch;
// Agent Gateway capability verification (TASK-7.6.x). Ed25519 over canonical-CBOR(1..12) +
// contiguous-counter CHECK for privileged opcodes (verify-only; advance/payload-binding deferred).
#[cfg(feature = "agent-gateway")]
pub mod agent_capability;
// Agent Gateway anti-rollback anchor (TASK-7.7). Verify-only slice: Ed25519 freshness-response
// verify against the sealed `anchor_root` + boot reconcile (Variant C: enclave is anchor-agnostic).
#[cfg(feature = "agent-gateway")]
pub mod agent_anchor;
// Shared CBOR helpers for host-supplied agent-gateway wire maps (int-key accessors + strict
// canonical decode). Crate-private; consumed by agent_capability/agent_dispatch/agent_anchor.
#[cfg(feature = "agent-gateway")]
mod agent_cbor;
// Agent Gateway provisioning channel wire-format codec (TASK-25, slice 25-2b-i). Pure encode/decode
// of the frozen `provision_wire_version = 1` format; cert-chain verify, transcript/Sig_PROV verify,
// mint+seal, and golden-regen land in slices ii–v. Crate-private; `agent-gateway`-gated (mirrors
// agent_cbor/agent_anchor — no crypto deps beyond the shared CBOR + keystore-validators).
#[cfg(feature = "agent-gateway")]
mod agent_provision;
// Runtime driver for the one-shot provisioning bootstrap ceremony (TASK-25). Connects
// ProvisionSession to a transport stream (vsock/stdio) + a SNP report-producer seam.
// Crate-private; `agent-gateway`-gated. The vsock binding adds `vsock-transport` + `target_os="linux"`.
#[cfg(feature = "agent-gateway")]
pub(crate) mod provision_bootstrap;
// Agent Gateway anti-rollback freshness-challenge (nonce) state machine (TASK-7.7). CSPRNG issue +
// single-use lifecycle + handshake report_data binding. Crate-private; dead-code until boot wiring.
#[cfg(feature = "agent-gateway")]
mod agent_challenge;
// Agent Gateway anti-rollback boot reconcile orchestration (TASK-7.7, slice 5a). Pure glue:
// verify_outstanding_response -> compute_local_marks_digest -> reconcile -> install the runtime binding
// ONLY on the Fresh arm. Crate-private; UNWIRED (dead-code) until the slice-5b boot caller lands.
#[cfg(feature = "agent-gateway")]
mod agent_boot;
// Agent Gateway anti-rollback boot-handshake driver + serve-gate (TASK-7.7, slice 5b-1). Bounded retry
// loop over the AnchorBootTransport seam around boot_reconcile_anti_rollback; only transport errors
// retry, every reconcile verdict + AdoptForward is terminal (anti-grind). Crate-private; UNWIRED
// (dead-code) until the slice-5b-2 agent bin + concrete transport land (aya/SNP validation).
#[cfg(feature = "agent-gateway")]
mod agent_boot_driver;
// Agent Gateway anti-rollback boot-relay wire protocol + transport seam (TASK-7.7, slice 5b-2a). The
// request CBOR codec (MessageType::AgentBootRelay 0x41), the bounded raw-response read, the
// BootRelayChannel + BootQuoteProducer seams, and RelayAnchorTransport (the concrete
// `impl AnchorBootTransport`). Pure/CI-testable; the real vsock channel landed in 5b-2b-ii(a)/(c) and
// the producer that wires is `HardBoundedQuoteProducer` (`quote_subprocess`, (d-ii)/2); the agent bin
// lands in 5b-2c. UNWIRED (dead-code) until then.
#[cfg(feature = "agent-gateway")]
mod agent_boot_relay;
// 5b-2c-iii lab SNP live-smoke surface (TASK-7.7): the TEST-KEYS-ONLY minted smoke keystore +
// (follow-on commits of the slice) the lab anchor stub + host-side 0x40 smoke-client cores.
// Compiles under cfg(test) so the freeze/cross-validation tests run in the normal agent-gateway
// lanes, and under the release-banned `lab-agent-smoke` feature for the host-side lab bins.
#[cfg(all(feature = "agent-gateway", any(test, feature = "lab-agent-smoke")))]
mod lab_agent_smoke;
// The lab smoke bins reach ONLY these three items (the quote_smoke `pub use` precedent); every
// other lab item stays `pub(crate)`. Exported only under the release-banned feature — a cfg(test)
// build keeps the module fully private.
#[cfg(all(feature = "agent-gateway", feature = "lab-agent-smoke"))]
pub use lab_agent_smoke::{
    run_agent_smoke_client, run_lab_anchor_stub, SMOKE_CLIENT_IDLE_READ_TIMEOUT,
};
// slice 6-7b WRITE-PATH client — additionally gated on `agent-keygen-exec-preview` (the only build
// where the enclave executes GENERATE_KEYS), so the `twod-hsm-agent-keygen-smoke-client` bin reaches it.
#[cfg(all(
    feature = "agent-gateway",
    feature = "lab-agent-smoke",
    feature = "agent-keygen-exec-preview"
))]
pub use lab_agent_smoke::run_agent_keygen_smoke_client;
// TASK-15 combined faucet write-path smoke client — needs all three preview gates (mint treasury +
// configure budget + dispense).
#[cfg(all(
    feature = "agent-gateway",
    feature = "lab-agent-smoke",
    feature = "agent-keygen-exec-preview",
    feature = "agent-configure-treasury-preview",
    feature = "agent-sign-faucet-preview"
))]
pub use lab_agent_smoke::run_agent_faucet_smoke_client;
mod wire;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

pub use chain_proof_crypto::{
    build_proof_data_v1, build_signed_recent_chain_proof, compute_recovery_tail_digest,
    parse_proof_data_v1, sign_recent_chain_proof, verify_recent_chain_proof_crypto,
    ProducerAttestationTrust, ProofDataV1, PRODUCER_ATTESTATION_SIGNATURE_LEN,
    PROOF_DATA_FORMAT_V1, PROOF_DATA_V1_LEN,
};
#[cfg(any(
    test,
    feature = "test-support",
    feature = "staging-host",
    feature = "reference-test-key"
))]
pub use chain_proof_crypto::{
    reference_test_attestation_signing_key, reference_test_attestation_trust,
};
#[cfg(any(
    feature = "test-support",
    feature = "staging-host",
    feature = "reference-test-key"
))]
pub use host_test_fixtures::{
    sample_arm_for_production_frame, sample_arm_for_production_frame_with_pubkey,
    sample_hardfork_sign_frame, sample_recovery_sign_frame, sample_second_hardfork_sign_frame,
};
#[cfg(feature = "ml-dsa-65")]
pub use mldsa65::MlDsa65Signer;
#[cfg(feature = "ml-dsa-65")]
pub use platform_provisioning_boot::boot_configure_pq_seal_v1_platform_root;
pub use pq_signer::{
    install_sealed_pq_signer, is_sealed_signer_installed, ML_DSA65_SECRETKEY_LEN,
    SEALED_BLOB_V0_VERSION,
};
pub use uds_listen::{bind_unix_listener, default_dev_socket_dir};
pub use wire::{
    decode_arm_for_production_request, decode_arm_for_production_response,
    decode_get_measurement_request, decode_get_measurement_response, decode_get_status_request,
    decode_get_status_response, decode_sign_authorization_ticket_request,
    decode_sign_authorization_ticket_response, decode_wire_error,
    encode_arm_for_production_request, encode_arm_for_production_response,
    encode_get_measurement_request, encode_get_measurement_response, encode_get_status_request,
    encode_get_status_response, encode_sign_authorization_ticket_request,
    encode_sign_authorization_ticket_response, encode_wire_error, is_wire_error_payload,
};
// Shared provisioning-root API — available to both the producer and the agent profile so each can
// set/check the platform root at boot (the secret + KDFs stay role-separated; see `seal_root`).
#[cfg(feature = "ml-dsa-65")]
pub use pq_signer::{
    pq_seal_v1_expected_blob_len, pq_seal_v1_measurement_digest, SEALED_BLOB_V1_HEADER_LEN,
    SEALED_BLOB_V1_MAGIC, SEALED_BLOB_V1_VERSION,
};
#[cfg(all(feature = "ml-dsa-65", test))]
pub use pq_signer::{seal_mldsa65_keypair_v0, unseal_mldsa65_keypair_v0};
#[cfg(all(feature = "ml-dsa-65", any(test, feature = "pq-seal-provisioning")))]
pub use pq_signer::{
    seal_mldsa65_keypair_v1, seal_mldsa65_keypair_v1_with_root, verify_sealed_blob_v1_with_root,
};
#[cfg(any(feature = "ml-dsa-65", feature = "agent-gateway"))]
pub use seal_root::{
    is_platform_pq_seal_v1_provisioning_root_set, is_pq_seal_v1_provisioning_root_configured,
    set_pq_seal_v1_provisioning_root,
};

/// Protocol version (bumped on breaking changes to the framing or core messages).
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum allowed message size (1 MiB).
///
/// Reduced from 64 MiB after Gemini security review on 2026-06-05:
/// In a TEE (Nitro Enclaves / SEV-SNP) memory is strictly limited.
/// A 64 MiB limit allows an untrusted host to force large allocations
/// via the length prefix, leading to resource exhaustion / OOM.
/// 1 MiB is more than sufficient for PQ signatures, attestations and tickets.
pub const MAX_MESSAGE_SIZE: u32 = 1 * 1024 * 1024;

/// Errors that can occur while (de)serializing or framing messages.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("message too large: {0} bytes (max {MAX_MESSAGE_SIZE})")]
    MessageTooLarge(u32),

    #[error("invalid protocol version: got {got}, expected {expected}")]
    InvalidVersion { got: u8, expected: u8 },

    #[error("cbor decode error: {0}")]
    CborDecode(#[from] ciborium::de::Error<std::io::Error>),

    #[error("cbor encode error: {0}")]
    CborEncode(#[from] ciborium::ser::Error<std::io::Error>),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unknown message type: {0}")]
    UnknownMessageType(u8),

    #[error("invalid ticket payload: {0}")]
    InvalidTicket(&'static str),

    /// Validation of the mandatory recent chain freshness proof failed.
    /// This error is security-critical: it prevents the enclave from arming
    /// under a stale, replayed, or attacker-supplied view of the chain.
    #[error("recent chain proof validation failed: {0}")]
    RecentChainProofValidation(&'static str),

    #[error("wire protocol error: {0}")]
    WireProtocol(&'static str),

    #[error("PQ signing unavailable: {0}")]
    PqSigningUnavailable(&'static str),

    #[error("PQ signature invalid: {0}")]
    PqSignatureInvalid(&'static str),
}

/// ML-DSA-65 wire sizes (FIPS 204, vsock spec §2.1).
pub const ML_DSA65_PUBKEY_LEN: usize = 1952;
pub const ML_DSA65_SIGNATURE_LEN: usize = 3309;

/// Wire message types (keep in sync with the spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    GetMeasurement = 0x01,
    SignAuthorizationTicket = 0x10,
    ArmForProduction = 0x20,
    GetStatus = 0x30,
    /// Agent Gateway secp256k1 namespace (TASK-7.1). Outer envelope under frame v1;
    /// the inner CBOR payload carries its own agent_version + opcode. Reserved
    /// outer band 0x40..0x4F. Command handling lands in TASK-7.6.
    AgentGateway = 0x40,
    /// Agent Gateway anti-rollback **boot-relay** request frame (TASK-7.7 slice 5b-2). Reserved
    /// outer band `0x40..0x4F`. ENCLAVE-INITIATED: the enclave opens an outbound connection to a host
    /// relay and writes this frame (SNP quote + public challenge); it is NEVER serve-dispatched, so
    /// `decode_wire_command` rejects it fail-closed (a hostile inbound `0x41` cannot reach a handler).
    AgentBootRelay = 0x41,
    /// Agent Gateway anti-rollback **raw-marks-relay** request frame (TASK-7.7 slice 5b-2e). Reserved
    /// outer band `0x40..0x4F` (`0x42`/`0x43` are inner `AgentError` codes — a DISJOINT namespace from
    /// this outer-frame byte). The SECOND enclave-initiated leg: on `AdoptForward` the enclave writes
    /// this (scope + the same fresh nonce + the adopted epoch — NO SNP quote; the attestation was bound
    /// on the `0x41` leg) and the anchor returns the signed raw marks. Like `0x41` it is NEVER
    /// serve-dispatched — a hostile inbound `0x44` fails closed in `decode_wire_command`.
    AgentAnchorMarksRelay = 0x44,
    /// Agent Gateway anti-rollback **per-op commit-relay** request frame (TASK-7.7 slice 6). Reserved
    /// outer band `0x40..0x4F`. The inner `AgentError` status codes `0x42`/`0x43`/`0x44`/`0x45`
    /// (`0x45` = `AGENT_NOT_CONFIGURED`) are a DISJOINT namespace from these OUTER-frame bytes — an outer
    /// `0x45 AgentAnchorCommitRelay` frame and an inner `0x45` CBOR status key never coexist on one wire
    /// position (outer = frame type byte; inner = a CBOR map value), so the reuse is unambiguous. The
    /// THIRD enclave-initiated leg and the first MUTATING one: on a
    /// rollback-sensitive op the enclave writes this (scope + the proposed new `epoch`/`structural_version`
    /// + the post-op `marks_digest` + a fresh per-op nonce + the op's `request_id` — NO SNP quote) and the
    /// anchor durably records the commit and returns a signed ACK. Like `0x41`/`0x44` it is NEVER
    /// serve-dispatched — a hostile inbound `0x45` fails closed in `decode_wire_command`.
    AgentAnchorCommitRelay = 0x45,
}

/// Простой диспетчер команд (скелет).
///
/// В реальном enclave здесь будет основная логика обработки входящих сообщений
/// от хоста. Пока оставлено как демонстрация структуры.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    GetMeasurement(GetMeasurementRequest),
    SignAuthorizationTicket(SignAuthorizationTicketRequest),
    ArmForProduction(ArmForProductionRequest),
    GetStatus(GetStatusRequest),
    /// Agent Gateway (0x40) — carries the raw inner-envelope CBOR; decoded/routed by
    /// `agent_dispatch` (the envelope is self-describing: opcode is inside).
    #[cfg(feature = "agent-gateway")]
    AgentGateway(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    GetMeasurement(GetMeasurementResponse),
    SignAuthorizationTicket(SignAuthorizationTicketResponse),
    ArmForProduction(ArmForProductionResponse),
    GetStatus(GetStatusResponse),
    Error(String),
    /// Agent Gateway (0x40) — the already-encoded response body (a per-opcode success map or a
    /// §10.9 `{code, reason}` error map, built by `agent_dispatch`).
    #[cfg(feature = "agent-gateway")]
    AgentGateway(Vec<u8>),
}

/// Top-level framed message.
///
/// This struct represents a single message on the wire after length-prefix decoding.
#[derive(Debug, Clone)]
pub struct FramedMessage {
    pub version: u8,
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

/// Encode a message with length-prefixed framing.
///
/// Format (big-endian):
/// [u32 total_len] [u8 version] [u8 msg_type] [CBOR payload]
pub fn encode_message(msg_type: MessageType, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    encode_message_raw(msg_type as u8, payload)
}

/// Like [`encode_message`] but with a raw message-type byte. Used to echo an
/// *unrecognized* request type in an error frame without falling back to a known
/// (producer) variant — fail-closed routing per TASK-7.1 AC#20.
fn encode_message_raw(type_byte: u8, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let total_len = 2 + payload.len(); // version + type + payload
    if total_len > MAX_MESSAGE_SIZE as usize {
        return Err(ProtocolError::MessageTooLarge(total_len as u32));
    }

    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_be_bytes());
    buf.push(PROTOCOL_VERSION);
    buf.push(type_byte);
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// Decode a length-prefixed framed message.
pub fn decode_message(data: &[u8]) -> Result<FramedMessage, ProtocolError> {
    if data.len() < 6 {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "frame too short",
        )));
    }

    let total_len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    if total_len > MAX_MESSAGE_SIZE as usize {
        return Err(ProtocolError::MessageTooLarge(total_len as u32));
    }
    if data.len() != 4 + total_len {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame length mismatch",
        )));
    }

    let version = data[4];
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::InvalidVersion {
            got: version,
            expected: PROTOCOL_VERSION,
        });
    }

    let msg_type = match data[5] {
        0x01 => MessageType::GetMeasurement,
        0x10 => MessageType::SignAuthorizationTicket,
        0x20 => MessageType::ArmForProduction,
        0x30 => MessageType::GetStatus,
        0x40 => MessageType::AgentGateway,
        0x41 => MessageType::AgentBootRelay,
        0x44 => MessageType::AgentAnchorMarksRelay,
        0x45 => MessageType::AgentAnchorCommitRelay,
        other => return Err(ProtocolError::UnknownMessageType(other)),
    };

    let payload = data[6..].to_vec();

    Ok(FramedMessage {
        version,
        msg_type,
        payload,
    })
}

// -----------------------------------------------------------------------------
// Payload types (CBOR, using integer keys for compactness and determinism)
// -----------------------------------------------------------------------------

/// Request for GET_MEASUREMENT (empty for now).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetMeasurementRequest {
    pub version: u8, // protocol version inside CBOR for extra safety
}

/// Response for GET_MEASUREMENT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetMeasurementResponse {
    pub measurement: Vec<u8>,
    pub attestation: Vec<u8>,
    pub pq_pubkey: Vec<u8>,
    /// **Static capability list** — ticket types this enclave image can ever sign
    /// when all preconditions are met. Does not reflect current readiness
    /// (e.g. type=1 additionally requires armed state; see `GET_STATUS.armed`).
    pub supported_ticket_types: Vec<u8>,
    /// ML-DSA-65 signing operational in this build (true only with sealed key or explicit `ml-dsa-65` test key).
    pub pq_signing_ready: bool,
    /// SNP VCEK→ASK→ARK certificate chain (configfs-tsm `auxblob`) for verifying `attestation` to
    /// the AMD root (wire key 7). Empty when no chain was captured (non-SNP/dev, or a provider that
    /// doesn't populate `auxblob` — the verifier then fetches it from AMD KDS by VCEK serial). See
    /// `backlog/docs/snp-attestation-verifier-policy.md`.
    pub cert_chain: Vec<u8>,
}

/// Whether this build can produce valid on-chain ML-DSA-65 signatures right now.
pub fn pq_signing_ready() -> bool {
    if cfg!(feature = "test-support") {
        return false;
    }
    pq_signer::is_sealed_signer_installed()
}

/// Active PQ signing public key when operational (after sealed-key install at boot).
fn active_signing_public_key_bytes() -> Option<Vec<u8>> {
    if cfg!(feature = "test-support") {
        return None;
    }
    pq_signer::sealed_signer_public_key_bytes()
}

/// When a real ML-DSA signer is installed, `pq_pubkey` must match the enclave key (no-op otherwise).
fn expect_pq_pubkey_matches_active_signer(pq_pubkey: &[u8]) -> Result<(), ProtocolError> {
    let Some(expected) = active_signing_public_key_bytes() else {
        return Ok(());
    };
    // Unit tests still use short placeholder pubkeys for arm/status fixtures.
    #[cfg(test)]
    if pq_pubkey.len() < 128 {
        return Ok(());
    }
    if pq_pubkey != expected {
        return Err(ProtocolError::InvalidTicket(
            "pq_pubkey must match the enclave PQ signing key",
        ));
    }
    Ok(())
}

/// Ticket `pq_pubkey` must match the enclave signer when a real ML-DSA key is active.
fn validate_ticket_pq_pubkey_matches_signer(
    ticket: &AuthorizationTicketPayload,
) -> Result<(), ProtocolError> {
    expect_pq_pubkey_matches_active_signer(&ticket.pq_pubkey)
}

/// Boot hook (production / AC#4): capture the real SEV-SNP launch measurement bound to the
/// installed PQ key so `GET_MEASUREMENT` can return it. Best-effort — returns the fetch error so
/// the caller logs and continues; `measurement_response` then falls back to the placeholder on
/// non-SNP/dev hosts (no `sev-guest` / KVM).
pub fn boot_capture_snp_measurement() -> Result<(), ProtocolError> {
    let pq_pubkey = active_signing_public_key_bytes().ok_or(
        ProtocolError::PqSigningUnavailable("no installed PQ signer to bind the SNP report to"),
    )?;
    snp_report::boot_fetch_and_cache(&pq_pubkey)
}

/// Boot-time fail-closed decision (pure / testable). Production (`require_real`, i.e. release
/// builds) must refuse to start when an operational PQ signer is installed but the real SNP
/// measurement could not be captured — otherwise a host that blocks SNP/configfs could make an
/// operational signer appear attested with a placeholder. Dev/lab (debug) builds, and the
/// transport-only case (no operational signer), are allowed to continue with the placeholder.
///
/// The cached report's `report_data` is verified against the installed key at capture time
/// (`snp_report::fetch_measurement_and_report`); the sealed signer is install-once
/// (`pq_signer`), so the advertised `pq_pubkey` cannot change after capture and the binding holds
/// for the enclave's lifetime.
pub fn snp_attestation_boot_gate(
    require_real: bool,
    signer_installed: bool,
    measurement_captured: bool,
) -> Result<(), ProtocolError> {
    if require_real && signer_installed && !measurement_captured {
        return Err(ProtocolError::PqSigningUnavailable(
            "operational PQ signer without a real SNP measurement (production refuses to serve)",
        ));
    }
    Ok(())
}

fn measurement_response() -> GetMeasurementResponse {
    let pq_pubkey = active_signing_public_key_bytes().unwrap_or_default();
    let (measurement, attestation, cert_chain) = resolve_measurement_and_attestation();
    GetMeasurementResponse {
        measurement,
        attestation,
        pq_pubkey,
        supported_ticket_types: vec![0, 1],
        pq_signing_ready: pq_signing_ready(),
        cert_chain,
    }
}

/// `(measurement, attestation, cert_chain)` for `GET_MEASUREMENT`. Staging/reference advertise the
/// sealed label (no cert chain). Production returns the boot-captured SNP launch measurement + raw
/// report + VCEK cert chain when available, else gracefully falls back to the placeholder label
/// (keeps KVM/dev/transport smokes working).
fn resolve_measurement_and_attestation() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    #[cfg(any(feature = "staging-host", feature = "reference-test-key"))]
    {
        (
            REFERENCE_STAGING_MEASUREMENT.to_vec(),
            b"attestation-placeholder".to_vec(),
            Vec::new(),
        )
    }
    #[cfg(not(any(feature = "staging-host", feature = "reference-test-key")))]
    {
        match snp_report::cached_attestation() {
            Some((measurement, report, cert_chain)) => (measurement.to_vec(), report, cert_chain),
            None => (
                boot_lab_pq_seal::LAB_PROD_MEASUREMENT.to_vec(),
                b"attestation-placeholder".to_vec(),
                Vec::new(),
            ),
        }
    }
}

#[cfg(all(
    test,
    not(any(feature = "staging-host", feature = "reference-test-key"))
))]
mod measurement_wiring_tests {
    use super::*;

    #[test]
    fn production_measurement_prefers_cached_snp_then_falls_back() {
        snp_report::reset_cached_attestation_for_tests();
        // No SNP report cached -> placeholder label + placeholder attestation + empty cert chain.
        let (m, att, certs) = resolve_measurement_and_attestation();
        assert_eq!(m, boot_lab_pq_seal::LAB_PROD_MEASUREMENT.to_vec());
        assert_eq!(att, b"attestation-placeholder".to_vec());
        assert!(certs.is_empty());

        // With a boot-captured SNP report -> real 48-byte measurement + raw report + cert chain.
        let meas = [0x5au8; snp_report::SNP_MEASUREMENT_LEN];
        let report = vec![0xa5u8; 1184];
        let cert_chain = vec![0xc7u8; 64];
        snp_report::set_cached_attestation_for_tests(meas, report.clone(), cert_chain.clone());
        let (m2, att2, certs2) = resolve_measurement_and_attestation();
        assert_eq!(m2, meas.to_vec());
        assert_eq!(att2, report);
        assert_eq!(certs2, cert_chain);

        snp_report::reset_cached_attestation_for_tests();
    }

    #[test]
    fn snp_attestation_boot_gate_refusal_matrix() {
        use crate::snp_attestation_boot_gate as gate;
        // release + operational signer + NOT captured -> refuse (fail-closed).
        assert!(gate(true, true, false).is_err());
        // release + operational + captured -> ok.
        assert!(gate(true, true, true).is_ok());
        // release + no operational signer (transport-only) -> ok.
        assert!(gate(true, false, false).is_ok());
        // dev/lab (not release) + operational + not captured -> graceful continue.
        assert!(gate(false, true, false).is_ok());
    }
}

// -----------------------------------------------------------------------------
// SignAuthorizationTicket (core for both recovery and hard forks)
// -----------------------------------------------------------------------------

/// Request to sign an AuthorizationTicket.
///
/// The enclave must:
/// - Verify it is currently armed as the authorized producer (for hard-fork tickets especially).
///
///   Hard-fork (type=1) requires `handle_sign_authorization_ticket_with_state`
///   after arming with a cryptographically verified `RecentChainProof` (TASK-3).
///   Stateless `handle_sign_authorization_ticket` still rejects type=1.
///
///   Recovery tickets (type 0) are currently allowed (bootstrap path).
///
/// - Compute the exact canonical `ticket_hash` (see below).
/// - Sign it with the PQ private key.
/// - Return the signature + the hash that was signed.
///
/// Recovery tickets (type 0) have a somewhat relaxed policy in early phases
/// (they are the bootstrap path), but even they benefit from the proof tail
/// checks inside `validate_recent_chain_proof` to limit replay windows.
///
/// **Important**: The actual state machine ("am I armed with a fresh-enough proof?")
/// and the exact gating logic live in the enclave implementation, **not** in this
/// protocol crate's request types. Do not add dispatch or handler code here
/// (that is Track A). This comment exists purely to make the security coupling
/// explicit for reviewers and future implementers.
///
/// This is the implementation of the canonical signed payload rules
/// fixed after the first roborev matrix (Codex HIGH + Claude confirmation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignAuthorizationTicketRequest {
    pub ticket: AuthorizationTicketPayload,
}

/// The payload that goes into the canonical hash for signing.
///
/// This must exactly match what the on-chain precompile will validate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationTicketPayload {
    pub ticket_type: u8, // 0 = Recovery, 1 = HardFork
    pub nonce: u64,
    pub context_hash: [u8; 32],
    pub activation_height: u64,
    pub new_measurement: Vec<u8>,
    pub pq_pubkey: Vec<u8>,
    // For HARD_FORK_ACTIVATION these are mandatory in the signed preimage
    pub fork_spec_hash: Option<[u8; 32]>,
    pub new_header_version: Option<u32>,
}

/// Response after successful signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignAuthorizationTicketResponse {
    pub signature: Vec<u8>,
    pub ticket_hash: [u8; 32], // The exact canonical hash that was signed
}

// -----------------------------------------------------------------------------
// ArmForProduction (with mandatory freshness proof) — Track B
// -----------------------------------------------------------------------------

/// Typed, verifiable structure carrying a recent chain freshness proof.
///
/// This replaces the previous opaque `Vec<u8>` for `recent_chain_proof`.
///
/// ## Security Rationale (critical for "network as second factor")
///
/// The host (block producer) is **untrusted**. A compromised or malicious host
/// must not be able to:
/// - Arm the enclave under a completely stale view of the chain.
/// - Replay an old `AuthorizationTicket` (especially RECOVERY) that was valid
///   at some past height but is no longer the live authorized producer.
/// - Convince the enclave that a hard-fork or recovery action is fresh when
///   the on-chain reality has moved on (long-range / replay attacks).
///
/// Therefore in a real implementation `ARM_FOR_PRODUCTION` should require a
/// cryptographically fresh proof that the claimed `AuthorizedProducerState`
/// is consistent with a recent finalized prefix of the canonical chain.
///
/// Cryptographic verification uses Producer Chain Attestation v1 in
/// `proof_data` plus `signature_from_recent_producer` (see `chain_proof_crypto`).
/// Full light-client proofs may extend or replace this format later.
///
/// Fields are intentionally minimal. A future light-client proof
/// (e.g. Tendermint/Beacon chain header + validator signatures, or 2D-specific
/// equivalent) will later live inside `proof_data` or replace parts of the
/// struct. We do **not** implement the full verifier here (explicitly out of
/// scope for this track).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentChainProof {
    /// Height of the most recent finalized block the proof attests to.
    /// Must be strictly monotonic and greater than or equal to the height at
    /// which the `authorized_state` was activated on-chain.
    pub finalized_height: u64,

    /// Hash of the finalized header (or state root, depending on final design).
    /// Non-zero value is a basic structural requirement.
    pub finalized_header_hash: [u8; 32],

    /// Hashes of the most recent RECOVERY and HARD_FORK_ACTIVATION tickets
    /// that were accepted on-chain and are visible in the recent history.
    ///
    /// Purpose: allow the enclave to detect whether the `source_ticket_hash`
    /// of the claimed `AuthorizedProducerState` is still part of the live
    /// tail, or whether a newer recovery/hard-fork has superseded it.
    /// This directly mitigates replay of old recovery tickets.
    pub recovery_history_tail: Vec<[u8; 32]>,

    /// Cryptographic proof material. **MVP (TASK-3):** Producer Chain
    /// Attestation v1 — see `chain_proof_crypto` (`0x01` || 32-byte tail digest).
    pub proof_data: Vec<u8>,

    /// Mandatory Ed25519 signature (64 bytes) over the domain-separated
    /// preimage defined in `chain_proof_crypto::recent_chain_proof_signing_preimage`.
    pub signature_from_recent_producer: Option<Vec<u8>>,
}

/// Request to arm the enclave for production under a specific authorized state.
///
/// Per review findings (Codex HIGH + Claude + Gemini, 5a0e3e2 matrix):
/// - `recent_chain_proof` is now **mandatory** and **typed** (not raw bytes).
/// - In the real enclave, `validate_recent_chain_proof` (or its future
///   cryptographic successor) **must** be called before arming.
///
///   Cryptographic verification of `RecentChainProof` is required (TASK-3).
///
/// After a successful arming the enclave records that it has seen a fresh proof.
/// Subsequent `SIGN_AUTHORIZATION_TICKET` for type=1 (HARD_FORK) **must** only
/// succeed if the enclave is currently armed under a proof whose
/// `finalized_height` is sufficiently recent relative to the ticket's
/// `activation_height` (exact policy to be enforced in the real enclave state
/// machine — see comments below; handler logic itself is Track A).
///
/// The previous raw `Vec<u8>` representation made it impossible for the type
/// system and reviewers to reason about the required fields and invariants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmForProductionRequest {
    pub authorized_state: AuthorizedProducerState,
    pub recent_chain_proof: RecentChainProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedProducerState {
    pub pq_pubkey: Vec<u8>,
    pub measurement: Vec<u8>,
    pub activated_at_height: u64,
    pub source_ticket_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmForProductionResponse {
    pub status: String, // "armed" or "refused"
    pub reason: Option<String>,
}

// -----------------------------------------------------------------------------
// Enclave State (for AC #7 - ArmForProduction with actual state tracking)
// -----------------------------------------------------------------------------

/// Represents the state of the enclave after a successful `ARM_FOR_PRODUCTION`.
///
/// This is a minimal skeleton type used in Phase 1 to track authorization state.
/// In a real TEE implementation this information would be sealed inside the
/// enclave, protected by the TEE, and never exposed to the untrusted host
/// except through carefully controlled queries (e.g. `GET_STATUS`).
#[derive(Debug, Clone)]
pub struct EnclaveArmedState {
    /// The `RecentChainProof` that was successfully validated during arming.
    pub proof: RecentChainProof,

    /// Pinned producer attestation identity used to verify this session's proof.
    pub attestation_trust: ProducerAttestationTrust,

    /// On-chain activation height of the authorized producer (from
    /// `AuthorizedProducerState.activated_at_height` at arming time).
    /// Not the chain tip height at arming — see `proof.finalized_height` / GET_STATUS.
    pub authorized_activated_at_height: u64,

    /// The measurement that was authorized during this arming.
    /// Exposed via GET_STATUS so the host can know what code is considered active.
    pub authorized_measurement: Vec<u8>,

    /// The PQ pubkey that was authorized.
    pub authorized_pq_pubkey: Vec<u8>,

    /// The source ticket hash from the AuthorizedProducerState used at arming.
    /// Useful for auditing and future sign-time anti-replay checks.
    pub source_ticket_hash: [u8; 32],

    /// If a HARD_FORK_ACTIVATION ticket was signed while armed, records its
    /// `activation_height` for observability via `GET_STATUS`.
    pub pending_hard_fork_height: Option<u64>,
}

/// Current authorization state of the enclave.
///
/// This enum allows the skeleton (and future real enclave) to track whether
/// it has been successfully armed for production and with which proof.
#[derive(Debug, Clone, Default)]
pub enum EnclaveState {
    /// The enclave has not yet been armed (or has been reset).
    #[default]
    Unarmed,

    /// The enclave is currently armed with a validated proof.
    Armed(EnclaveArmedState),
}

/// Validates a `RecentChainProof` against the `AuthorizedProducerState` that
/// the caller wishes to arm the enclave with.
///
/// ## Security Invariants (MUST hold — fail closed on any violation)
///
/// 1. The proof must demonstrate that the chain has progressed at least to the
///    activation height of the authorized state (or beyond). This prevents
///    arming the enclave with an ancient "authorized producer" that has long
///    been replaced on-chain.
/// 2. Structural sanity: heights positive, header hash non-zero, etc.
/// 3. If `recovery_history_tail` is non-empty, the `source_ticket_hash` from
///    the authorized state **must** appear in it. Failure to contain it when
///    the tail is non-empty is now a hard error (see code below).
/// 4. `proof_data` and `signature_from_recent_producer` must pass Producer
///    Chain Attestation v1 verification (`verify_recent_chain_proof_crypto`).
///
/// Called at `ARM_FOR_PRODUCTION` and again at hard-fork sign time.
///
/// Returns `Ok(())` only when structural and cryptographic checks pass.
pub fn validate_recent_chain_proof(
    proof: &RecentChainProof,
    current_authorized: &AuthorizedProducerState,
    trust: &ProducerAttestationTrust,
) -> Result<(), ProtocolError> {
    if proof.finalized_header_hash == [0u8; 32] {
        return Err(ProtocolError::RecentChainProofValidation(
            "finalized_header_hash must not be zero",
        ));
    }

    if proof.finalized_height == 0 {
        return Err(ProtocolError::RecentChainProofValidation(
            "finalized_height must be positive",
        ));
    }

    if proof.finalized_height < current_authorized.activated_at_height {
        return Err(ProtocolError::RecentChainProofValidation(
            "finalized_height is older than the authorized state's activation height (stale/replay)",
        ));
    }

    // Basic anti-replay: if the tail is non-empty, the claimed source ticket
    // must be present in it. This is now a hard error (post-matrix fix).
    if !proof.recovery_history_tail.is_empty() {
        let source_in_tail = proof
            .recovery_history_tail
            .iter()
            .any(|h| h == &current_authorized.source_ticket_hash);
        if !source_in_tail {
            return Err(ProtocolError::RecentChainProofValidation(
                "recovery_history_tail is non-empty but does not contain the claimed source_ticket_hash (possible replay or superseded state)",
            ));
        }
    }

    // Reject obviously malformed tail entries
    for hash in &proof.recovery_history_tail {
        if *hash == [0u8; 32] {
            return Err(ProtocolError::RecentChainProofValidation(
                "recovery_history_tail contains zero hash",
            ));
        }
    }

    verify_recent_chain_proof_crypto(proof, current_authorized, trust)?;

    Ok(())
}

/// Attempts to arm (or re-arm) the enclave with the provided authorization.
///
/// This is the core pure function for AC #7. It:
/// - Validates the supplied `RecentChainProof` against the claimed `AuthorizedProducerState`
/// - On success, produces a new `EnclaveState::Armed(...)`
///
/// In a real enclave this function would be called by the vsock handler,
/// and the resulting state would be sealed inside the TEE.
///
pub fn arm_for_production(
    current_state: &EnclaveState,
    req: ArmForProductionRequest,
    trust: ProducerAttestationTrust,
) -> Result<EnclaveState, ProtocolError> {
    if let EnclaveState::Armed(ref armed) = current_state {
        if req.recent_chain_proof.finalized_height <= armed.proof.finalized_height {
            return Err(ProtocolError::RecentChainProofValidation(
                "re-arm requires strictly greater finalized_height than the current session proof",
            ));
        }
        if armed.attestation_trust.attestation_verifying_key.to_bytes()
            != trust.attestation_verifying_key.to_bytes()
        {
            return Err(ProtocolError::RecentChainProofValidation(
                "re-arm attestation trust must match the current session trust anchor",
            ));
        }
    }

    if !pq_signing_ready() {
        return Err(ProtocolError::PqSigningUnavailable(
            "ARM_FOR_PRODUCTION requires operational PQ signing (pq_signing_ready)",
        ));
    }

    validate_recent_chain_proof(&req.recent_chain_proof, &req.authorized_state, &trust)?;

    expect_pq_pubkey_matches_active_signer(&req.authorized_state.pq_pubkey)?;

    let armed_state = EnclaveArmedState {
        proof: req.recent_chain_proof,
        attestation_trust: trust,
        authorized_activated_at_height: req.authorized_state.activated_at_height,
        authorized_measurement: req.authorized_state.measurement,
        authorized_pq_pubkey: req.authorized_state.pq_pubkey,
        source_ticket_hash: req.authorized_state.source_ticket_hash,
        pending_hard_fork_height: None,
    };

    Ok(EnclaveState::Armed(armed_state))
}

/// Reconstructs the `AuthorizedProducerState` that was used when the enclave armed.
fn authorized_state_from_armed(armed: &EnclaveArmedState) -> AuthorizedProducerState {
    AuthorizedProducerState {
        pq_pubkey: armed.authorized_pq_pubkey.clone(),
        measurement: armed.authorized_measurement.clone(),
        activated_at_height: armed.authorized_activated_at_height,
        source_ticket_hash: armed.source_ticket_hash,
    }
}

/// Sign-time checks for HARD_FORK_ACTIVATION (type=1).
///
/// Re-runs full `validate_recent_chain_proof` (structural + cryptographic) on the
/// armed proof snapshot and enforces activation-height ordering.
fn validate_hard_fork_sign_preconditions(
    ticket: &AuthorizationTicketPayload,
    armed: &EnclaveArmedState,
) -> Result<(), ProtocolError> {
    if armed.pending_hard_fork_height.is_some() {
        return Err(ProtocolError::InvalidTicket(
            "only one HARD_FORK_ACTIVATION ticket may be signed per armed session; re-arm to announce another fork",
        ));
    }

    if ticket.pq_pubkey != armed.authorized_pq_pubkey {
        return Err(ProtocolError::InvalidTicket(
            "pq_pubkey in hard-fork ticket must match the currently armed producer key",
        ));
    }

    let authorized = authorized_state_from_armed(armed);
    validate_recent_chain_proof(&armed.proof, &authorized, &armed.attestation_trust)?;

    if ticket.activation_height <= armed.proof.finalized_height {
        return Err(ProtocolError::InvalidTicket(
            "activation_height must be strictly greater than the finalized height from the armed RecentChainProof (stale chain view)",
        ));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// GetStatus
// -----------------------------------------------------------------------------

/// Пустой запрос на статус (пока не несёт полезной нагрузки).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStatusRequest {
    pub version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStatusResponse {
    pub armed: bool,

    /// The measurement that was authorized when the enclave was armed.
    /// In Phase 1 this is the value captured at arming time.
    pub authorized_measurement: Vec<u8>,

    /// The PQ public key that was authorized when the enclave was armed.
    pub authorized_pq_pubkey: Vec<u8>,

    /// On-chain activation height of the authorized producer captured at arming.
    /// None when unarmed. Distinct from `proof_finalized_height` (chain view at arm).
    pub authorized_activated_at_height: Option<u64>,

    /// The finalized height from the proof that was used during arming.
    /// This gives the host visibility into how fresh the chain view was
    /// at the moment of arming.
    /// None when unarmed.
    pub proof_finalized_height: Option<u64>,

    /// The source ticket hash from the AuthorizedProducerState that was used
    /// during this arming. Useful for auditing and for future sign-time
    /// anti-replay checks (see AC #8).
    /// None when unarmed.
    pub source_ticket_hash: Option<[u8; 32]>,

    pub pending_hard_fork_height: Option<u64>,
    pub last_known_block: Option<u64>,
}

// -----------------------------------------------------------------------------
// Canonical hash computation (must be identical on enclave and precompile side)
// -----------------------------------------------------------------------------

/// Computes the **canonical** `ticketHash` that the enclave must sign,
/// using the **normative** preimage defined in the spec:
///
/// `keccak256(abi.encode(ticketType, nonce, contextHash, activationHeight,
///                       newMeasurement, pqPubkey, forkSpecHash, newHeaderVersion))`
///
/// This function now implements the exact layout that Solidity `abi.encode`
/// produces for the tuple `(uint8, uint64, bytes32, uint64, bytes, bytes, bytes32, uint32)`.
///
/// This is the implementation that must be used for all future ticket signing
/// (both in the enclave and eventually mirrored in the on-chain precompile verification).
pub fn compute_canonical_ticket_hash(payload: &AuthorizationTicketPayload) -> [u8; 32] {
    let mut hasher = Keccak256::new();

    // --- Head (static part, exactly 8 × 32 bytes for the 8-tuple) ---
    //
    // Tuple: (uint8, uint64, bytes32, uint64, bytes, bytes, bytes32, uint32)
    // This must produce bit-for-bit identical preimage to Solidity's
    // `abi.encode(...)` + `keccak256` as defined in the normative spec.
    //
    // Head layout (words 0-7):
    // 0: ticketType
    // 1: nonce
    // 2: contextHash
    // 3: activationHeight
    // 4: offset(newMeasurement) = 256
    // 5: offset(pqPubkey) = 256 + 32 + padded(newMeasurement)
    // 6: forkSpecHash (0 for recovery per script)
    // 7: newHeaderVersion (0 for recovery per script)

    // 0. ticketType as uint8 (right-padded to 32 bytes)
    let mut word = [0u8; 32];
    word[31] = payload.ticket_type;
    hasher.update(word);

    // 1. nonce as uint64
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&payload.nonce.to_be_bytes());
    hasher.update(word);

    // 2. contextHash (bytes32)
    hasher.update(payload.context_hash);

    // 3. activationHeight as uint64
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&payload.activation_height.to_be_bytes());
    hasher.update(word);

    // 4. offset for first dynamic (newMeasurement): always 256 (after 8-word head)
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&(256u64).to_be_bytes());
    hasher.update(word);

    // 5. offset for second dynamic (pqPubkey)
    // Data for newMeasurement starts at 256, consists of: 32-byte length word + actual data bytes + right-zero padding to 32
    let meas_len = payload.new_measurement.len() as u64;
    let meas_data_padded = 32 + meas_len + ((32 - (meas_len % 32)) % 32);
    let pq_offset: u64 = 256 + meas_data_padded;
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&pq_offset.to_be_bytes());
    hasher.update(word);

    // 6. forkSpecHash — for recovery (type 0) the canonical script forces bytes32(0)
    // even if the JSON had a value; for hard-fork use the provided value.
    let fork_hash = if payload.ticket_type == 0 {
        [0u8; 32]
    } else {
        payload.fork_spec_hash.unwrap_or([0u8; 32])
    };
    hasher.update(fork_hash);

    // 7. newHeaderVersion — same rule: 0 for recovery, real value for hard-fork.
    let ver = if payload.ticket_type == 0 {
        0u32
    } else {
        payload.new_header_version.unwrap_or(0)
    };
    let mut word = [0u8; 32];
    word[28..32].copy_from_slice(&ver.to_be_bytes());
    hasher.update(word);

    // --- Tail (dynamic data section, in declaration order) ---

    // newMeasurement (bytes): length word + data + right-zero padding to 32
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&meas_len.to_be_bytes());
    hasher.update(word);
    hasher.update(&payload.new_measurement);
    let padding = (32 - (meas_len % 32)) % 32;
    if padding > 0 {
        hasher.update(&[0u8; 32][..padding as usize]);
    }

    // pqPubkey (bytes): length word + data + padding
    let pq_len = payload.pq_pubkey.len() as u64;
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&pq_len.to_be_bytes());
    hasher.update(word);
    hasher.update(&payload.pq_pubkey);
    let padding = (32 - (pq_len % 32)) % 32;
    if padding > 0 {
        hasher.update(&[0u8; 32][..padding as usize]);
    }

    let result = hasher.finalize();
    result.into()
}

/// Validates that a ticket payload is well-formed before hashing/signing.
///
/// Returns error for hard-fork tickets that are missing required fields.
/// This was added to address the MEDIUM finding from the matrix.
pub fn validate_ticket_payload(payload: &AuthorizationTicketPayload) -> Result<(), ProtocolError> {
    match payload.ticket_type {
        0 => {
            // Recovery
            if payload.fork_spec_hash.is_some() || payload.new_header_version.is_some() {
                return Err(ProtocolError::InvalidTicket(
                    "Non-hard-fork tickets must not include hard-fork specific fields",
                ));
            }
        }
        1 => {
            // HARD_FORK_ACTIVATION (must match precompile skeleton §4 decoder table)
            let fork_spec = payload.fork_spec_hash.ok_or(ProtocolError::InvalidTicket(
                "Hard-fork tickets must include fork_spec_hash",
            ))?;
            if fork_spec == [0u8; 32] {
                return Err(ProtocolError::InvalidTicket(
                    "Hard-fork fork_spec_hash must be non-zero",
                ));
            }
            let header_version = payload
                .new_header_version
                .ok_or(ProtocolError::InvalidTicket(
                    "Hard-fork tickets must include new_header_version",
                ))?;
            if header_version == 0 {
                return Err(ProtocolError::InvalidTicket(
                    "Hard-fork new_header_version must be non-zero",
                ));
            }
        }
        _ => {
            // Strict allow-list: only 0 and 1 are supported.
            // This addresses the Medium finding from the matrix on 402fdba
            // (default-allow for unknown ticket_type values creates a signing oracle risk).
            return Err(ProtocolError::InvalidTicket(
                "Unsupported ticket_type (only 0 = Recovery and 1 = HardFork are allowed)",
            ));
        }
    }
    Ok(())
}

/// High-level helper: validates the payload and returns the canonical hash
/// that should be signed.
///
/// This is the function the TEE signing service will most likely call
/// before producing a signature over an AuthorizationTicket.
pub fn prepare_ticket_for_signing(
    payload: &AuthorizationTicketPayload,
) -> Result<[u8; 32], ProtocolError> {
    validate_ticket_payload(payload)?;
    Ok(compute_canonical_ticket_hash(payload))
}

// =============================================================================
// Track A: Real command dispatch + SignAuthorizationTicket handler
// =============================================================================
//
// This is the first production-grade implementation of the vsock command
// handlers on top of the already-reviewed framing and canonical hash logic.
//
// Security notes (references to prior roborev work):
// - The only path that may produce a signature over an AuthorizationTicket
//   is `handle_sign_authorization_ticket` → `prepare_ticket_for_signing`.
// - For HARD_FORK_ACTIVATION tickets, the real enclave must additionally
//   check that it is currently armed under a *fresh* RecentChainProof
//   (see Track B coupling comments on SignAuthorizationTicketRequest).
// - The mock signature below is obviously fake and contains a clear
//   "DO-NOT-USE-IN-REAL-ENCLAVE" marker. It will be replaced by real
//   ML-DSA (or SLH-DSA) inside the TEE.
//
// All future changes to this module must go through the 3:3 process
// defined in AGENTS.md / .roborev.toml.
// =============================================================================

/// Production PQ signature (installed sealed key only).
#[cfg(all(feature = "ml-dsa-65", not(feature = "test-support")))]
fn produce_pq_signature(ticket_hash: &[u8; 32], nonce: u64) -> Result<Vec<u8>, ProtocolError> {
    if pq_signing_ready() {
        return pq_signer::sign_ticket_hash_sealed(ticket_hash);
    }
    #[cfg(test)]
    {
        #[cfg(feature = "reference-test-key")]
        {
            let _ = (ticket_hash, nonce);
            return Err(ProtocolError::PqSigningUnavailable(
                "ML-DSA-65 signer not provisioned (reference-test-key: install sealed key at boot)",
            ));
        }
        #[cfg(not(feature = "reference-test-key"))]
        return Ok(compute_mock_pq_signature(ticket_hash, nonce));
    }
    #[cfg(not(test))]
    {
        let _ = (ticket_hash, nonce);
        Err(ProtocolError::PqSigningUnavailable(
            "ML-DSA-65 signer not provisioned (install sealed key at enclave boot)",
        ))
    }
}

#[cfg(all(not(feature = "ml-dsa-65"), not(feature = "test-support"), not(test)))]
fn produce_pq_signature(_ticket_hash: &[u8; 32], _nonce: u64) -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::PqSigningUnavailable(
        "ML-DSA-65 signing disabled (build with ml-dsa-65 and install sealed key at boot)",
    ))
}

/// Deterministic mock for a post-quantum signature (`test-support` / unit tests without `ml-dsa-65`).
#[cfg(any(test, feature = "test-support"))]
fn compute_mock_pq_signature(ticket_hash: &[u8; 32], nonce: u64) -> Vec<u8> {
    const MOCK_SECRET: &[u8] = b"2d-hsm-track-a-deterministic-mock-pq-sig-secret--DO-NOT-USE-IN-REAL-ENCLAVE--THIS-IS-ONLY-FOR-TESTING-THE-PROTOCOL-LAYER--";

    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(MOCK_SECRET);
    hasher.update(ticket_hash);
    hasher.update(nonce.to_be_bytes());
    let first = hasher.finalize();

    // Second round for "length"
    let mut hasher2 = Sha3_256::new();
    hasher2.update(&first);
    hasher2.update(b"second-round-for-64-byte-mock");
    let second = hasher2.finalize();

    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&first);
    sig.extend_from_slice(&second);
    sig
}

#[cfg(feature = "test-support")]
fn produce_pq_signature(ticket_hash: &[u8; 32], nonce: u64) -> Result<Vec<u8>, ProtocolError> {
    #[cfg(feature = "demo-mock-sign")]
    {
        return Ok(compute_mock_pq_signature(ticket_hash, nonce));
    }
    #[cfg(not(feature = "demo-mock-sign"))]
    {
        let _ = (ticket_hash, nonce);
        Err(ProtocolError::PqSigningUnavailable(
            "PQ signing disabled (test-support without demo-mock-sign)",
        ))
    }
}

#[cfg(all(not(feature = "test-support"), not(feature = "ml-dsa-65"), test))]
fn produce_pq_signature(ticket_hash: &[u8; 32], nonce: u64) -> Result<Vec<u8>, ProtocolError> {
    Ok(compute_mock_pq_signature(ticket_hash, nonce))
}

/// Signs a PRODUCER_RECOVERY ticket (type=0) without requiring armed state.
///
/// HARD_FORK_ACTIVATION (type=1) must use `handle_sign_authorization_ticket_with_state`.
fn sign_recovery_ticket(
    ticket: &AuthorizationTicketPayload,
) -> Result<SignAuthorizationTicketResponse, ProtocolError> {
    validate_ticket_pq_pubkey_matches_signer(ticket)?;
    let ticket_hash = prepare_ticket_for_signing(ticket)?;
    let signature = produce_pq_signature(&ticket_hash, ticket.nonce)?;
    Ok(SignAuthorizationTicketResponse {
        signature,
        ticket_hash,
    })
}

/// The stateless signing entry point (legacy / host paths without enclave state).
///
/// Recovery tickets (type=0) are allowed. Hard-fork tickets (type=1) are rejected
/// here by design — they require `handle_sign_authorization_ticket_with_state`.
pub fn handle_sign_authorization_ticket(
    req: SignAuthorizationTicketRequest,
) -> Result<SignAuthorizationTicketResponse, ProtocolError> {
    if req.ticket.ticket_type == 1 {
        return Err(ProtocolError::InvalidTicket(
            "Hard-fork (type=1) ticket signing requires armed enclave state. \
             Use dispatch_command_with_state after ARM_FOR_PRODUCTION with a validated RecentChainProof.",
        ));
    }

    sign_recovery_ticket(&req.ticket)
}

/// Stateful signing entry point — the recommended path for all ticket types.
///
/// - type=0 (recovery): allowed when armed or unarmed.
/// - type=1 (hard fork): requires `EnclaveState::Armed`, full proof validation
///   (structural + crypto), activation-height ordering, one hard-fork per session.
pub fn handle_sign_authorization_ticket_with_state(
    req: SignAuthorizationTicketRequest,
    state: &mut EnclaveState,
) -> Result<SignAuthorizationTicketResponse, ProtocolError> {
    match req.ticket.ticket_type {
        0 => sign_recovery_ticket(&req.ticket),
        1 => {
            let EnclaveState::Armed(ref mut armed) = state else {
                return Err(ProtocolError::InvalidTicket(
                    "Hard-fork signing requires the enclave to be armed via ARM_FOR_PRODUCTION with a validated RecentChainProof",
                ));
            };

            validate_hard_fork_sign_preconditions(&req.ticket, armed)?;
            validate_ticket_pq_pubkey_matches_signer(&req.ticket)?;

            let ticket_hash = prepare_ticket_for_signing(&req.ticket)?;
            let signature = produce_pq_signature(&ticket_hash, req.ticket.nonce)?;

            armed.pending_hard_fork_height = Some(req.ticket.activation_height);

            Ok(SignAuthorizationTicketResponse {
                signature,
                ticket_hash,
            })
        }
        _ => {
            validate_ticket_payload(&req.ticket)?;
            unreachable!("validate_ticket_payload only accepts ticket types 0 and 1");
        }
    }
}

/// Host-side session state for stateful vsock / UDS / stdio-session transports.
///
/// `attestation_trust` must come from enclave provisioning (§9.3), not from the host
/// payload. The reference `enclave-stdio-session` / `enclave-uds-server` binaries load
/// test trust only under `test-support`.
pub struct HostSession {
    /// Enclave authorization state (arming, pending hard fork).
    pub state: EnclaveState,
    /// Pinned Producer Chain Attestation trust (Ed25519 verify key).
    pub attestation_trust: ProducerAttestationTrust,
}

impl HostSession {
    /// New unarmed session with caller-supplied trust (production enclave entry).
    pub fn new(attestation_trust: ProducerAttestationTrust) -> Self {
        Self {
            state: EnclaveState::Unarmed,
            attestation_trust,
        }
    }

    /// Reference dev session (requires `test-support` feature).
    #[cfg(feature = "test-support")]
    pub fn reference_test() -> Self {
        Self::new(reference_test_attestation_trust())
    }

    /// Staging session trust (requires `staging-host` / `reference-test-key` attestation vectors).
    #[cfg(feature = "staging-host")]
    pub fn reference_staging() -> Self {
        Self::new(reference_test_attestation_trust())
    }
}

/// Measurement bytes shared by staging install + `host_test_fixtures` ARM frames.
#[cfg(all(
    feature = "ml-dsa-65",
    any(feature = "reference-test-key", feature = "staging-host")
))]
pub const REFERENCE_STAGING_MEASUREMENT: &[u8] = b"prod-enclave-v1";

#[cfg(all(
    feature = "ml-dsa-65",
    any(feature = "reference-test-key", feature = "staging-host")
))]
static REFERENCE_MLDSA65_SK: &[u8] = include_bytes!("../testvectors/mldsa65_reference_sk.bin");

#[cfg(all(
    feature = "ml-dsa-65",
    any(feature = "reference-test-key", feature = "staging-host")
))]
static REFERENCE_MLDSA65_PK: &[u8] = include_bytes!("../testvectors/mldsa65_reference_pk.bin");

/// Install the NIST reference ML-DSA-65 keypair as a v1 sealed signer (embedded at build time).
///
/// **Staging/CI only** — not for production deployment.
#[cfg(all(
    feature = "ml-dsa-65",
    any(feature = "reference-test-key", feature = "staging-host")
))]
fn install_reference_sealed_signer_from_embedded() -> Result<(), ProtocolError> {
    let sk = REFERENCE_MLDSA65_SK.to_vec();
    let pk = REFERENCE_MLDSA65_PK.to_vec();
    let blob = seal_mldsa65_keypair_v1(&sk, &pk, REFERENCE_STAGING_MEASUREMENT)?;
    pq_signer::install_sealed_pq_signer(&blob, REFERENCE_STAGING_MEASUREMENT)
}

/// Boot-time install for `enclave-uds-staging` (requires `staging-host`).
#[cfg(feature = "staging-host")]
pub fn install_reference_sealed_signer_staging() -> Result<(), ProtocolError> {
    install_reference_sealed_signer_from_embedded()
}

fn decode_wire_command(msg_type: MessageType, payload: &[u8]) -> Result<Command, ProtocolError> {
    match msg_type {
        MessageType::GetMeasurement => Ok(Command::GetMeasurement(decode_get_measurement_request(
            payload,
        )?)),
        MessageType::SignAuthorizationTicket => Ok(Command::SignAuthorizationTicket(
            decode_sign_authorization_ticket_request(payload)?,
        )),
        MessageType::ArmForProduction => Ok(Command::ArmForProduction(
            decode_arm_for_production_request(payload)?,
        )),
        MessageType::GetStatus => Ok(Command::GetStatus(decode_get_status_request(payload)?)),
        // Agent Gateway (0x40): carry the raw inner envelope; agent_dispatch decodes + routes it
        // (self-describing — opcode is inside). Built only under the `agent-gateway` feature; a
        // build without it keeps the fail-closed reserved behavior.
        #[cfg(feature = "agent-gateway")]
        MessageType::AgentGateway => Ok(Command::AgentGateway(payload.to_vec())),
        #[cfg(not(feature = "agent-gateway"))]
        MessageType::AgentGateway => Err(ProtocolError::WireProtocol(
            "agent gateway commands require the agent-gateway feature (reserved by TASK-7.1)",
        )),
        // AGENT_BOOT_RELAY (0x41) is ENCLAVE-INITIATED (the enclave writes it outbound to a host relay
        // during the anti-rollback boot handshake); it is never a serve-loop command. A hostile inbound
        // 0x41 to the serve dispatcher fails closed here (TASK-7.7 slice 5b-2).
        MessageType::AgentBootRelay => Err(ProtocolError::WireProtocol(
            "AGENT_BOOT_RELAY is enclave-initiated; not serve-dispatchable",
        )),
        // AGENT_ANCHOR_MARKS_RELAY (0x44) is likewise ENCLAVE-INITIATED (the AdoptForward marks fetch);
        // a hostile inbound 0x44 to the serve dispatcher fails closed here (TASK-7.7 slice 5b-2e).
        MessageType::AgentAnchorMarksRelay => Err(ProtocolError::WireProtocol(
            "AGENT_ANCHOR_MARKS_RELAY is enclave-initiated; not serve-dispatchable",
        )),
        // AGENT_ANCHOR_COMMIT_RELAY (0x45) is likewise ENCLAVE-INITIATED (the per-op seal-before-emit
        // commit); a hostile inbound 0x45 to the serve dispatcher fails closed here (TASK-7.7 slice 6).
        MessageType::AgentAnchorCommitRelay => Err(ProtocolError::WireProtocol(
            "AGENT_ANCHOR_COMMIT_RELAY is enclave-initiated; not serve-dispatchable",
        )),
    }
}

fn encode_wire_response(
    msg_type: MessageType,
    response: &Response,
) -> Result<Vec<u8>, ProtocolError> {
    match (msg_type, response) {
        (MessageType::GetMeasurement, Response::GetMeasurement(r)) => {
            encode_get_measurement_response(r)
        }
        (MessageType::ArmForProduction, Response::ArmForProduction(r)) => {
            encode_arm_for_production_response(r)
        }
        (MessageType::GetStatus, Response::GetStatus(r)) => encode_get_status_response(r),
        (MessageType::SignAuthorizationTicket, Response::SignAuthorizationTicket(r)) => {
            encode_sign_authorization_ticket_response(r)
        }
        // Agent Gateway body is pre-encoded by agent_dispatch (success map or §10.9 error map).
        #[cfg(feature = "agent-gateway")]
        (MessageType::AgentGateway, Response::AgentGateway(body)) => Ok(body.clone()),
        (_, Response::Error(msg)) => encode_wire_error(1, msg),
        (expected, other) => encode_wire_error(
            1,
            &format!(
                "unexpected response {:?} for message type {:?}",
                other, expected
            ),
        ),
    }
}

/// Best-effort message type from a frame prefix (for error responses when decode fails).
///
/// Returns `None` for an unrecognized type byte — callers must NOT fall back to a
/// producer message type (that was a fail-**open** routing bug; TASK-7.1 AC#20).
pub fn peek_msg_type_from_frame(frame: &[u8]) -> Option<MessageType> {
    match frame.get(5) {
        Some(0x01) => Some(MessageType::GetMeasurement),
        Some(0x10) => Some(MessageType::SignAuthorizationTicket),
        Some(0x20) => Some(MessageType::ArmForProduction),
        Some(0x30) => Some(MessageType::GetStatus),
        Some(0x40) => Some(MessageType::AgentGateway),
        Some(0x41) => Some(MessageType::AgentBootRelay),
        Some(0x44) => Some(MessageType::AgentAnchorMarksRelay),
        Some(0x45) => Some(MessageType::AgentAnchorCommitRelay),
        _ => None,
    }
}

fn protocol_error_to_wire_body(e: &ProtocolError) -> Result<Vec<u8>, ProtocolError> {
    let (code, reason) = match e {
        ProtocolError::MessageTooLarge(n) => (1, format!("message too large: {n}")),
        ProtocolError::InvalidVersion { got, expected } => (
            1,
            format!("invalid version: got {got}, expected {expected}"),
        ),
        ProtocolError::UnknownMessageType(b) => (1, format!("unknown message type: {b}")),
        ProtocolError::WireProtocol(s) => (1, (*s).to_string()),
        ProtocolError::InvalidTicket(s) => (2, (*s).to_string()),
        ProtocolError::RecentChainProofValidation(s) => (2, (*s).to_string()),
        ProtocolError::PqSigningUnavailable(s) => (2, (*s).to_string()),
        ProtocolError::PqSignatureInvalid(s) => (2, (*s).to_string()),
        ProtocolError::CborDecode(err) => (1, format!("cbor decode error: {err}")),
        ProtocolError::CborEncode(err) => (1, format!("cbor encode error: {err}")),
        ProtocolError::Io(_) => {
            return Err(ProtocolError::WireProtocol(
                "internal: Io errors must not be encoded as wire errors",
            ));
        }
    };
    encode_wire_error(code, &reason)
}

pub(crate) fn encode_wire_error_frame(
    msg_type: MessageType,
    e: ProtocolError,
) -> Result<Vec<u8>, ProtocolError> {
    let body = protocol_error_to_wire_body(&e)?;
    encode_message(msg_type, &body)
}

/// Encode an error frame echoing the *request's* message type. A recognized type
/// is echoed as itself; an unrecognized type byte is echoed raw rather than
/// defaulting to a producer type (fail-closed routing, TASK-7.1 AC#20).
pub(crate) fn encode_wire_error_frame_for_frame(
    frame: &[u8],
    e: ProtocolError,
) -> Result<Vec<u8>, ProtocolError> {
    // Call-site invariant: only reached after `decode_message` accepted the 6-byte framing
    // prefix — sub-6-byte frames surface as Io errors the callers propagate before here.
    // Make the layered invariant self-checking in debug/test builds (no release impact).
    debug_assert!(
        frame.len() >= 6,
        "error-frame echo expects the 6-byte framing prefix"
    );
    match peek_msg_type_from_frame(frame) {
        Some(t) => encode_wire_error_frame(t, e),
        None => {
            // Echo the original (unrecognized) type byte rather than a producer type.
            // Frames shorter than 6 bytes surface as Io errors that propagate *before*
            // this path, so frame[5] is present in practice; unwrap_or(0) is defensive.
            let type_byte = frame.get(5).copied().unwrap_or(0);
            let body = protocol_error_to_wire_body(&e)?;
            encode_message_raw(type_byte, &body)
        }
    }
}

/// Process one framed host request with session state (all commands, integer-key wire).
///
/// Decode/dispatch failures return a wire error frame on the **same** `msg_type` (connection stays up).
/// I/O errors still propagate to the transport layer.
pub fn process_framed_with_session(
    frame: &[u8],
    session: &mut HostSession,
) -> Result<Vec<u8>, ProtocolError> {
    process_framed_with_shared_state(frame, &mut session.state, session.attestation_trust)
}

/// Process one framed request against **shared** enclave state (one `EnclaveState` per enclave process).
///
/// Use for production vsock and for `enclave-uds-server` (all UDS connections must share state so
/// hard-fork anti-equivocation holds). `HostSession` is a convenience wrapper for a single connection.
pub fn process_framed_with_shared_state(
    frame: &[u8],
    state: &mut EnclaveState,
    attestation_trust: ProducerAttestationTrust,
) -> Result<Vec<u8>, ProtocolError> {
    match try_process_framed_with_shared_state(frame, state, attestation_trust) {
        Ok(resp) => Ok(resp),
        Err(e @ ProtocolError::Io(_)) => Err(e),
        Err(e) => encode_wire_error_frame_for_frame(frame, e),
    }
}

fn try_process_framed_with_shared_state(
    frame: &[u8],
    state: &mut EnclaveState,
    attestation_trust: ProducerAttestationTrust,
) -> Result<Vec<u8>, ProtocolError> {
    let framed = decode_message(frame)?;
    let cmd = decode_wire_command(framed.msg_type, &framed.payload)?;
    let response = dispatch_command_with_state(cmd, state, attestation_trust);
    let body = encode_wire_response(framed.msg_type, &response)?;
    encode_message(framed.msg_type, &body)
}

/// Stateless one-shot bridge: **GET_MEASUREMENT only** (no `test-support` required).
pub fn process_framed_bytes(frame: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    match try_process_framed_bytes(frame) {
        Ok(resp) => Ok(resp),
        Err(e @ ProtocolError::Io(_)) => Err(e),
        Err(e) => encode_wire_error_frame_for_frame(frame, e),
    }
}

fn try_process_framed_bytes(frame: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let framed = decode_message(frame)?;
    if framed.msg_type != MessageType::GetMeasurement {
        return Err(ProtocolError::WireProtocol(
            "stateless stdio bridge supports GET_MEASUREMENT only; use enclave-stdio-session for ARM/STATUS/SIGN",
        ));
    }
    let req = decode_get_measurement_request(&framed.payload)?;
    let body = match dispatch_command(Command::GetMeasurement(req)) {
        Response::GetMeasurement(resp) => encode_get_measurement_response(&resp)?,
        Response::Error(msg) => encode_wire_error(1, &msg)?,
        other => encode_wire_error(
            1,
            &format!(
                "unexpected dispatch response for GET_MEASUREMENT: {:?}",
                other
            ),
        )?,
    };
    encode_message(MessageType::GetMeasurement, &body)
}

// `pub(crate)` so the agent boot-relay channel (TASK-7.7 5b-2) reuses the same deadline-bounded read
// for its bounded anchor-response read helper.
pub(crate) fn read_exact_with_idle_deadline<R: std::io::Read>(
    reader: &mut R,
    buf: &mut [u8],
    idle_deadline: Option<std::time::Instant>,
) -> Result<(), ProtocolError> {
    use std::io::ErrorKind;

    let mut off = 0;
    while off < buf.len() {
        if let Some(deadline) = idle_deadline {
            if std::time::Instant::now() >= deadline {
                return Err(ProtocolError::Io(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "session idle timeout exceeded",
                )));
            }
        }
        match reader.read(&mut buf[off..]) {
            Ok(0) => {
                return Err(ProtocolError::Io(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "connection closed while reading frame",
                )));
            }
            Ok(n) => off += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e)
                if (e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock)
                    && idle_deadline.is_some_and(|d| std::time::Instant::now() < d) =>
            {
                continue
            }
            Err(e)
                if (e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock)
                    && idle_deadline.is_some_and(|d| std::time::Instant::now() >= d) =>
            {
                return Err(ProtocolError::Io(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "session idle timeout exceeded",
                )));
            }
            Err(e) => return Err(ProtocolError::from(e)),
        }
    }
    Ok(())
}

/// Read one length-prefixed frame from a stream.
///
/// When `idle_deadline` is [`Some`], each `read` is bounded by that instant (inter-frame
/// slowloris defense). When [`None`], uses blocking `read_exact` (stdio and legacy callers).
pub fn read_framed_message_with_idle_deadline<R: std::io::Read>(
    reader: &mut R,
    idle_deadline: Option<std::time::Instant>,
) -> Result<Vec<u8>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    read_exact_with_idle_deadline(reader, &mut len_buf, idle_deadline)?;
    let total_len = u32::from_be_bytes(len_buf);
    if total_len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge(total_len));
    }
    let total_len = total_len as usize;
    let mut body = vec![0u8; total_len];
    read_exact_with_idle_deadline(reader, &mut body, idle_deadline)?;
    let mut frame = Vec::with_capacity(4 + total_len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Read one length-prefixed frame from a stream (blocking, no inter-read idle deadline).
pub fn read_framed_message<R: std::io::Read>(reader: &mut R) -> Result<Vec<u8>, ProtocolError> {
    read_framed_message_with_idle_deadline(reader, None)
}

/// Write one length-prefixed frame to a stream.
pub fn write_framed_message<W: std::io::Write>(
    writer: &mut W,
    frame: &[u8],
) -> Result<(), ProtocolError> {
    use std::io::Write;
    writer.write_all(frame).map_err(ProtocolError::from)?;
    writer.flush().map_err(ProtocolError::from)?;
    Ok(())
}

/// Stateless dispatcher — **recovery tickets (type 0) and GET_MEASUREMENT only**.
///
/// Hard-fork signing, `ARM_FOR_PRODUCTION`, and `GET_STATUS` require
/// [`dispatch_command_with_state`] with an enclave-held [`ProducerAttestationTrust`]
/// (see §9.3 in the vsock spec — the host must not choose the trust anchor).
pub fn dispatch_command(cmd: Command) -> Response {
    match cmd {
        Command::SignAuthorizationTicket(req) => {
            match handle_sign_authorization_ticket(req) {
                Ok(resp) => Response::SignAuthorizationTicket(resp),
                Err(e) => Response::Error(format!("sign_authorization_ticket failed: {}", e)),
            }
        }
        Command::GetMeasurement(_req) => Response::GetMeasurement(measurement_response()),
        Command::ArmForProduction(_) => Response::Error(
            "ARM_FOR_PRODUCTION requires dispatch_command_with_state and an enclave-held ProducerAttestationTrust (host cannot supply the trust anchor)".to_string(),
        ),
        Command::GetStatus(_) => Response::Error(
            "GET_STATUS requires dispatch_command_with_state".to_string(),
        ),
        // Agent Gateway uses its own installed-keystore slot (not EnclaveState), so it routes the
        // same in both dispatchers; the body is built (success or §10.9 error) by agent_dispatch.
        #[cfg(feature = "agent-gateway")]
        Command::AgentGateway(payload) => {
            Response::AgentGateway(agent_dispatch::handle_agent_gateway_frame(&payload))
        }
    }
}

/// Stateful dispatcher — **required** for arming, status, and hard-fork signing.
///
/// `attestation_trust` must be loaded inside the TEE from sealed configuration or
/// an attested provisioning channel (PCR/policy-bound manifest). The untrusted
/// host must **never** pass the trust anchor over vsock; only the enclave binary
/// or attested bootstrapping code may call this with the pinned verifying key.
pub fn dispatch_command_with_state(
    cmd: Command,
    state: &mut EnclaveState,
    attestation_trust: ProducerAttestationTrust,
) -> Response {
    match cmd {
        Command::SignAuthorizationTicket(req) => {
            match handle_sign_authorization_ticket_with_state(req, state) {
                Ok(resp) => Response::SignAuthorizationTicket(resp),
                Err(e) => Response::Error(format!("sign_authorization_ticket failed: {}", e)),
            }
        }
        Command::GetMeasurement(_req) => Response::GetMeasurement(measurement_response()),
        Command::ArmForProduction(req) => match arm_for_production(state, req, attestation_trust) {
            Ok(new_state) => {
                *state = new_state;
                Response::ArmForProduction(ArmForProductionResponse {
                    status: "armed".to_string(),
                    reason: None,
                })
            }
            Err(e) => Response::ArmForProduction(ArmForProductionResponse {
                status: "refused".to_string(),
                reason: Some(e.to_string()),
            }),
        },
        Command::GetStatus(_req) => Response::GetStatus(build_get_status_response(state)),
        #[cfg(feature = "agent-gateway")]
        Command::AgentGateway(payload) => {
            Response::AgentGateway(agent_dispatch::handle_agent_gateway_frame(&payload))
        }
    }
}

/// Builds the logical GET_STATUS payload (encode on the wire with [`encode_get_status_response`]).
pub fn build_get_status_response(state: &EnclaveState) -> GetStatusResponse {
    match state {
        EnclaveState::Armed(s) => GetStatusResponse {
            armed: true,
            authorized_measurement: s.authorized_measurement.clone(),
            authorized_pq_pubkey: s.authorized_pq_pubkey.clone(),
            authorized_activated_at_height: Some(s.authorized_activated_at_height),
            proof_finalized_height: Some(s.proof.finalized_height),
            source_ticket_hash: Some(s.source_ticket_hash),
            pending_hard_fork_height: s.pending_hard_fork_height,
            last_known_block: Some(s.proof.finalized_height),
        },
        EnclaveState::Unarmed => GetStatusResponse {
            armed: false,
            authorized_measurement: vec![],
            authorized_pq_pubkey: vec![],
            authorized_activated_at_height: None,
            proof_finalized_height: None,
            source_ticket_hash: None,
            pending_hard_fork_height: None,
            last_known_block: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_attestation_signing_key() -> ed25519_dalek::SigningKey {
        crate::chain_proof_crypto::reference_test_attestation_signing_key()
    }

    fn test_attestation_trust() -> ProducerAttestationTrust {
        crate::chain_proof_crypto::reference_test_attestation_trust()
    }

    /// Tests that arm/sign with 48-byte placeholder `pq_pubkey` must not run while a sealed signer is installed.
    #[cfg(feature = "ml-dsa-65")]
    fn clear_sealed_signer_for_mock_pubkey_tests() -> pq_signer::SealedSignerTestGuard {
        let guard = pq_signer::SealedSignerTestGuard::acquire();
        pq_signer::reset_installed_pq_signer_for_tests();
        guard
    }

    /// Installs the reference sealed signer when needed. `None` = skip test (`ml-dsa-65` without `reference-test-key`).
    /// Caller must keep `_guard` alive through `ARM_FOR_PRODUCTION`.
    #[cfg(feature = "ml-dsa-65")]
    fn arm_test_pq_setup() -> Option<(pq_signer::SealedSignerTestGuard, Vec<u8>)> {
        #[cfg(not(feature = "reference-test-key"))]
        {
            return None;
        }
        #[cfg(feature = "reference-test-key")]
        {
            let guard = install_reference_sealed_signer_for_tests();
            let pk = pq_signer::sealed_signer_public_key_bytes().expect("sealed pk");
            Some((guard, pk))
        }
    }

    fn signed_recent_chain_proof(
        finalized_height: u64,
        finalized_header_hash: [u8; 32],
        recovery_history_tail: Vec<[u8; 32]>,
        authorized: &AuthorizedProducerState,
    ) -> RecentChainProof {
        build_signed_recent_chain_proof(
            finalized_height,
            finalized_header_hash,
            recovery_history_tail,
            authorized,
            &test_attestation_signing_key(),
        )
        .expect("test proof signing must succeed")
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn get_status_wire_roundtrip_matches_spec_integer_keys() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq,
            measurement: b"m".to_vec(),
            activated_at_height: 5,
            source_ticket_hash: [0x02; 32],
        };
        let state = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: signed_recent_chain_proof(
                    10,
                    [0x03; 32],
                    vec![[0x02; 32]],
                    &authorized,
                ),
            },
            test_attestation_trust(),
        )
        .unwrap();
        let logical = build_get_status_response(&state);
        let wire = encode_get_status_response(&logical).unwrap();
        let decoded = decode_get_status_response(&wire).unwrap();
        assert!(decoded.armed);
        assert_eq!(decoded.proof_finalized_height, Some(10));
    }

    #[test]
    fn arm_request_wire_roundtrip_structured_recent_chain_proof() {
        let authorized = AuthorizedProducerState {
            pq_pubkey: vec![7],
            measurement: b"meas".to_vec(),
            activated_at_height: 1,
            source_ticket_hash: [0x08; 32],
        };
        let req = ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(2, [0x09; 32], vec![], &authorized),
        };
        let wire = encode_arm_for_production_request(&req).unwrap();
        let decoded = decode_arm_for_production_request(&wire).unwrap();
        assert_eq!(decoded.recent_chain_proof.finalized_height, 2);
    }

    #[test]
    fn stateless_dispatch_rejects_arm_with_actionable_error() {
        let resp = dispatch_command(Command::ArmForProduction(ArmForProductionRequest {
            authorized_state: AuthorizedProducerState {
                pq_pubkey: vec![],
                measurement: vec![],
                activated_at_height: 0,
                source_ticket_hash: [0; 32],
            },
            recent_chain_proof: RecentChainProof {
                finalized_height: 1,
                finalized_header_hash: [1; 32],
                recovery_history_tail: vec![],
                proof_data: vec![0x01],
                signature_from_recent_producer: None,
            },
        }));
        match resp {
            Response::Error(msg) => {
                assert!(msg.contains("dispatch_command_with_state"));
                assert!(msg.contains("ProducerAttestationTrust"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn roundtrip_get_measurement() {
        let req = GetMeasurementRequest { version: 1 };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&req, &mut payload).unwrap();

        let framed = encode_message(MessageType::GetMeasurement, &payload).unwrap();
        let decoded = decode_message(&framed).unwrap();

        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.msg_type, MessageType::GetMeasurement);

        let decoded_req: GetMeasurementRequest =
            ciborium::de::from_reader(&decoded.payload[..]).unwrap();
        assert_eq!(decoded_req.version, 1);
    }

    #[test]
    fn process_framed_get_measurement_wire_roundtrip() {
        #[cfg(feature = "ml-dsa-65")]
        let _guard = pq_signer::SealedSignerTestGuard::acquire();
        #[cfg(feature = "ml-dsa-65")]
        pq_signer::reset_installed_pq_signer_for_tests();
        let req_payload =
            encode_get_measurement_request(&GetMeasurementRequest { version: 1 }).unwrap();
        let request_frame = encode_message(MessageType::GetMeasurement, &req_payload).unwrap();
        let response_frame = process_framed_bytes(&request_frame).unwrap();
        let decoded = decode_message(&response_frame).unwrap();
        assert_eq!(decoded.msg_type, MessageType::GetMeasurement);
        let resp = decode_get_measurement_response(&decoded.payload).unwrap();
        assert_eq!(resp.supported_ticket_types, vec![0, 1]);
        assert!(!resp.pq_signing_ready);
        assert!(!resp.measurement.is_empty());
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn process_framed_with_session_returns_wire_error_on_unknown_msg_type() {
        let mut session = HostSession::reference_test();
        let payload =
            encode_get_measurement_request(&GetMeasurementRequest { version: 1 }).unwrap();
        let mut bad_frame = encode_message(MessageType::GetMeasurement, &payload).unwrap();
        bad_frame[5] = 0xFF;
        let resp = process_framed_with_session(&bad_frame, &mut session).unwrap();
        // Fail-closed routing (TASK-7.1 AC#20): the error frame echoes the original
        // unknown type byte and does NOT default to a producer type (0x01). The body
        // (after the 6-byte header) is still a wire error payload.
        assert_eq!(resp[5], 0xFF);
        assert_ne!(resp[5], MessageType::GetMeasurement as u8);
        assert!(is_wire_error_payload(&resp[6..]));
    }

    #[test]
    fn read_framed_message_rejects_oversized_length_prefix() {
        use std::io::Cursor;
        let oversized = (MAX_MESSAGE_SIZE + 1).to_be_bytes();
        let mut reader = Cursor::new(oversized);
        let err = read_framed_message(&mut reader).unwrap_err();
        assert!(matches!(err, ProtocolError::MessageTooLarge(_)));
    }

    #[cfg(all(feature = "test-support", feature = "demo-mock-sign"))]
    #[test]
    fn process_framed_session_rejects_arm_when_pq_signing_not_ready() {
        use crate::host_test_fixtures::sample_arm_for_production_frame;
        use crate::{
            decode_arm_for_production_response, decode_get_status_response,
            encode_get_status_request, is_wire_error_payload,
        };

        assert!(!pq_signing_ready());
        let mut session = HostSession::reference_test();
        let arm_frame = sample_arm_for_production_frame();
        let arm_resp_frame = process_framed_with_session(&arm_frame, &mut session).unwrap();
        let arm_decoded = decode_message(&arm_resp_frame).unwrap();
        let arm_body = decode_arm_for_production_response(&arm_decoded.payload).unwrap();
        assert_eq!(arm_body.status, "refused");

        let status_payload = encode_get_status_request(&GetStatusRequest { version: 1 }).unwrap();
        let status_frame = encode_message(MessageType::GetStatus, &status_payload).unwrap();
        let status_resp_frame = process_framed_with_session(&status_frame, &mut session).unwrap();
        let status_decoded = decode_message(&status_resp_frame).unwrap();
        let status = decode_get_status_response(&status_decoded.payload).unwrap();
        assert!(!status.armed);
    }

    #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
    #[test]
    fn staging_framed_arm_sign_hardfork_uses_mldsa_signature_len() {
        use crate::host_test_fixtures::sample_arm_for_production_frame_with_pubkey;
        use crate::{
            decode_sign_authorization_ticket_response, encode_message,
            encode_sign_authorization_ticket_request, is_wire_error_payload,
            AuthorizationTicketPayload, MessageType, SignAuthorizationTicketRequest,
        };

        let _guard = install_reference_sealed_signer_for_tests();
        let pk = pq_signer::sealed_signer_public_key_bytes().expect("staging signer");
        let trust = reference_test_attestation_trust();
        let mut state = EnclaveState::Unarmed;

        process_framed_with_shared_state(
            &sample_arm_for_production_frame_with_pubkey(pk.clone()),
            &mut state,
            trust,
        )
        .unwrap();

        let ticket = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 99,
            context_hash: [0xAB; 32],
            activation_height: 10_500_100,
            new_measurement: b"hf-meas".to_vec(),
            pq_pubkey: pk,
            fork_spec_hash: Some([0xEF; 32]),
            new_header_version: Some(3),
        };
        let sign_frame = encode_message(
            MessageType::SignAuthorizationTicket,
            &encode_sign_authorization_ticket_request(&SignAuthorizationTicketRequest { ticket })
                .unwrap(),
        )
        .unwrap();
        let resp = process_framed_with_shared_state(&sign_frame, &mut state, trust).unwrap();
        let decoded = decode_message(&resp).unwrap();
        assert!(!is_wire_error_payload(&decoded.payload));
        let sign = decode_sign_authorization_ticket_response(&decoded.payload).unwrap();
        assert_eq!(sign.signature.len(), ML_DSA65_SIGNATURE_LEN);
    }

    /// Two logical connections share one `EnclaveState`: wire ARM on the first, then sign on
    /// separate lock scopes (production vsock / UDS shared-state path).
    #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
    #[test]
    fn shared_enclave_state_wire_arm_rejects_second_hardfork_mldsa() {
        use crate::host_test_fixtures::sample_arm_for_production_frame_with_pubkey;
        use crate::{
            decode_arm_for_production_response, decode_get_status_response,
            decode_sign_authorization_ticket_response, decode_wire_error,
            encode_get_status_request, encode_message, encode_sign_authorization_ticket_request,
            is_wire_error_payload, peek_msg_type_from_frame, AuthorizationTicketPayload,
            MessageType, SignAuthorizationTicketRequest,
        };
        use std::sync::{Arc, Mutex};

        let _guard = install_reference_sealed_signer_for_tests();
        let pk = pq_signer::sealed_signer_public_key_bytes().expect("sealed pk");
        let trust = reference_test_attestation_trust();
        let state = Arc::new(Mutex::new(EnclaveState::Unarmed));

        let arm_frame = sample_arm_for_production_frame_with_pubkey(pk.clone());
        {
            let mut guard = state.lock().unwrap();
            let arm_resp = process_framed_with_shared_state(&arm_frame, &mut guard, trust).unwrap();
            let arm_decoded = decode_message(&arm_resp).unwrap();
            let arm_body = decode_arm_for_production_response(&arm_decoded.payload).unwrap();
            assert_eq!(arm_body.status, "armed");
        }

        {
            let mut guard = state.lock().unwrap();
            let status_frame = encode_message(
                MessageType::GetStatus,
                &encode_get_status_request(&GetStatusRequest { version: 1 }).unwrap(),
            )
            .unwrap();
            let status_resp =
                process_framed_with_shared_state(&status_frame, &mut guard, trust).unwrap();
            let status =
                decode_get_status_response(&decode_message(&status_resp).unwrap().payload).unwrap();
            assert!(status.armed);
            assert_eq!(status.proof_finalized_height, Some(10_000_050));
        }

        let first_ticket = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0x01; 32],
            activation_height: 10_000_100,
            new_measurement: b"hf-a".to_vec(),
            pq_pubkey: pk.clone(),
            fork_spec_hash: Some([0xEF; 32]),
            new_header_version: Some(3),
        };
        let first_frame = encode_message(
            MessageType::SignAuthorizationTicket,
            &encode_sign_authorization_ticket_request(&SignAuthorizationTicketRequest {
                ticket: first_ticket,
            })
            .unwrap(),
        )
        .unwrap();

        {
            let mut guard = state.lock().unwrap();
            let resp = process_framed_with_shared_state(&first_frame, &mut guard, trust).unwrap();
            let decoded = decode_message(&resp).unwrap();
            assert!(!is_wire_error_payload(&decoded.payload));
            let sign = decode_sign_authorization_ticket_response(&decoded.payload).unwrap();
            assert_eq!(sign.signature.len(), ML_DSA65_SIGNATURE_LEN);
        }

        let second_ticket = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 2,
            context_hash: [0x02; 32],
            activation_height: 10_000_200,
            new_measurement: b"hf-b".to_vec(),
            pq_pubkey: pk,
            fork_spec_hash: Some([0xEF; 32]),
            new_header_version: Some(3),
        };
        let second_frame = encode_message(
            MessageType::SignAuthorizationTicket,
            &encode_sign_authorization_ticket_request(&SignAuthorizationTicketRequest {
                ticket: second_ticket,
            })
            .unwrap(),
        )
        .unwrap();

        {
            let mut guard = state.lock().unwrap();
            let resp = process_framed_with_shared_state(&second_frame, &mut guard, trust).unwrap();
            let decoded = decode_message(&resp).unwrap();
            assert!(is_wire_error_payload(&decoded.payload));
            let (code, reason) = decode_wire_error(&decoded.payload).unwrap();
            assert_eq!(code, 1);
            assert!(reason.contains("only one HARD_FORK_ACTIVATION"));
            assert_eq!(
                peek_msg_type_from_frame(&resp),
                Some(MessageType::SignAuthorizationTicket)
            );
        }
    }

    #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
    #[test]
    fn staging_sign_hardfork_fails_without_sealed_signer() {
        let _guard = pq_signer::SealedSignerTestGuard::acquire();
        pq_signer::reset_installed_pq_signer_for_tests();
        assert!(!pq_signing_ready());

        let mut state = EnclaveState::Unarmed;
        dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(vec![0xDE; 48], 10_000_000, 10_000_050)),
            &mut state,
            test_attestation_trust(),
        );
        let ticket = sample_hardfork_ticket(vec![0xDE; 48], 10_000_100);
        let resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket }),
            &mut state,
            test_attestation_trust(),
        );
        match resp {
            Response::Error(msg) => {
                assert!(
                    msg.contains("ML-DSA-65 signer not provisioned")
                        || msg.contains("sign_authorization_ticket failed")
                );
            }
            _ => panic!("expected SIGN failure without sealed signer"),
        }
    }

    /// Simulates two UDS connections sharing one `EnclaveState` (variant A for compact 6765).
    #[cfg(all(feature = "test-support", feature = "demo-mock-sign"))]
    #[test]
    fn shared_enclave_state_across_connections_rejects_second_hardfork() {
        use crate::{
            decode_sign_authorization_ticket_response, decode_wire_error, encode_message,
            encode_sign_authorization_ticket_request, is_wire_error_payload,
            peek_msg_type_from_frame, AuthorizationTicketPayload, MessageType,
            SignAuthorizationTicketRequest,
        };
        use std::sync::{Arc, Mutex};

        let trust = HostSession::reference_test().attestation_trust;
        let pq = vec![0xDE; 48];
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq.clone(),
            measurement: b"m".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };
        let proof =
            signed_recent_chain_proof(10_000_050, [0xFE; 32], vec![[0xAA; 32]], &authorized);
        // demo-mock-sign cannot ARM over the wire (pq_signing_ready is false); seed armed state
        // directly to exercise second hard-fork rejection while "armed".
        let state = Arc::new(Mutex::new(EnclaveState::Armed(EnclaveArmedState {
            proof,
            attestation_trust: trust,
            authorized_activated_at_height: authorized.activated_at_height,
            authorized_measurement: authorized.measurement,
            authorized_pq_pubkey: authorized.pq_pubkey,
            source_ticket_hash: authorized.source_ticket_hash,
            pending_hard_fork_height: None,
        })));
        let first_ticket = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0x01; 32],
            activation_height: 10_000_100,
            new_measurement: b"hf-a".to_vec(),
            pq_pubkey: pq.clone(),
            fork_spec_hash: Some([0xEF; 32]),
            new_header_version: Some(3),
        };
        let first_frame = encode_message(
            MessageType::SignAuthorizationTicket,
            &encode_sign_authorization_ticket_request(&SignAuthorizationTicketRequest {
                ticket: first_ticket,
            })
            .unwrap(),
        )
        .unwrap();

        {
            let mut guard = state.lock().unwrap();
            let resp = process_framed_with_shared_state(&first_frame, &mut guard, trust).unwrap();
            let decoded = decode_message(&resp).unwrap();
            assert!(!is_wire_error_payload(&decoded.payload));
            let sign = decode_sign_authorization_ticket_response(&decoded.payload).unwrap();
            assert_eq!(sign.signature.len(), 64);
        }

        let second_ticket = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 2,
            context_hash: [0x02; 32],
            activation_height: 10_000_200,
            new_measurement: b"hf-b".to_vec(),
            pq_pubkey: pq,
            fork_spec_hash: Some([0xEF; 32]),
            new_header_version: Some(3),
        };
        let second_frame = encode_message(
            MessageType::SignAuthorizationTicket,
            &encode_sign_authorization_ticket_request(&SignAuthorizationTicketRequest {
                ticket: second_ticket,
            })
            .unwrap(),
        )
        .unwrap();

        {
            let mut guard = state.lock().unwrap();
            let resp = process_framed_with_shared_state(&second_frame, &mut guard, trust).unwrap();
            let decoded = decode_message(&resp).unwrap();
            assert!(is_wire_error_payload(&decoded.payload));
            let (code, reason) = decode_wire_error(&decoded.payload).unwrap();
            assert_eq!(code, 1);
            assert!(reason.contains("only one HARD_FORK_ACTIVATION"));
            assert_eq!(
                peek_msg_type_from_frame(&resp),
                Some(MessageType::SignAuthorizationTicket)
            );
        }
    }

    // ---------------------------------------------------------------------
    // TRACK B — RecentChainProof validation tests
    // ---------------------------------------------------------------------

    #[test]
    fn roundtrip_recent_chain_proof_cbor() {
        let proof = RecentChainProof {
            finalized_height: 1_234_567,
            finalized_header_hash: [0xAB; 32],
            recovery_history_tail: vec![[0x11; 32], [0x22; 32]],
            proof_data: vec![1, 2, 3, 4],
            signature_from_recent_producer: Some(vec![9; 64]),
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&proof, &mut buf).unwrap();

        let decoded: RecentChainProof = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.finalized_height, 1_234_567);
        assert_eq!(decoded.recovery_history_tail.len(), 2);
    }

    #[test]
    fn validate_recent_chain_proof_accepts_valid_signed_proof() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCA; 32],
        };

        let proof = signed_recent_chain_proof(150, [0xFE; 32], vec![[0xCA; 32]], &state);
        assert!(validate_recent_chain_proof(&proof, &state, &test_attestation_trust()).is_ok());
    }

    #[test]
    fn validate_recent_chain_proof_rejects_empty_proof_data() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCA; 32],
        };

        let proof = RecentChainProof {
            finalized_height: 150,
            finalized_header_hash: [0xFE; 32],
            recovery_history_tail: vec![[0xCA; 32]],
            proof_data: vec![],
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        assert!(validate_recent_chain_proof(&proof, &state, &test_attestation_trust()).is_err());
    }

    #[test]
    fn validate_recent_chain_proof_rejects_missing_signature() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCA; 32],
        };

        let proof = RecentChainProof {
            finalized_height: 150,
            finalized_header_hash: [0xFE; 32],
            recovery_history_tail: vec![[0xCA; 32]],
            proof_data: build_proof_data_v1(&[[0xCA; 32]]),
            signature_from_recent_producer: None,
        };

        assert!(validate_recent_chain_proof(&proof, &state, &test_attestation_trust()).is_err());
    }

    #[test]
    fn validate_recent_chain_proof_rejects_forged_height_with_valid_signature() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCA; 32],
        };

        let mut proof = signed_recent_chain_proof(150, [0xFE; 32], vec![[0xCA; 32]], &state);
        proof.finalized_height = 9999;
        assert!(validate_recent_chain_proof(&proof, &state, &test_attestation_trust()).is_err());
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn arm_and_hardfork_reject_unsigned_proof() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq.clone(),
            measurement: b"m".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCC; 32],
        };

        let unsigned = RecentChainProof {
            finalized_height: 200,
            finalized_header_hash: [0xDD; 32],
            recovery_history_tail: vec![[0xCC; 32]],
            proof_data: vec![],
            signature_from_recent_producer: None,
        };

        let arm_err = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: unsigned.clone(),
            },
            test_attestation_trust(),
        )
        .unwrap_err();
        assert!(matches!(
            arm_err,
            ProtocolError::RecentChainProofValidation(_)
        ));

        let mut state = EnclaveState::Unarmed;
        dispatch_command_with_state(
            Command::ArmForProduction(ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: signed_recent_chain_proof(
                    200,
                    [0xDD; 32],
                    vec![[0xCC; 32]],
                    &authorized,
                ),
            }),
            &mut state,
            test_attestation_trust(),
        );

        let ticket = sample_hardfork_ticket(pq.clone(), 300);
        let sign_resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket }),
            &mut state,
            test_attestation_trust(),
        );
        assert!(matches!(sign_resp, Response::SignAuthorizationTicket(_)));

        if let EnclaveState::Armed(ref armed) = state {
            let mut tampered = armed.proof.clone();
            tampered.proof_data.clear();
            tampered.signature_from_recent_producer = None;
            let mut bad_state = EnclaveState::Armed(EnclaveArmedState {
                proof: tampered,
                pending_hard_fork_height: None,
                ..armed.clone()
            });
            let ticket2 = sample_hardfork_ticket(pq.clone(), 400);
            let err = handle_sign_authorization_ticket_with_state(
                SignAuthorizationTicketRequest { ticket: ticket2 },
                &mut bad_state,
            )
            .unwrap_err();
            assert!(
                matches!(err, ProtocolError::RecentChainProofValidation(_)),
                "expected proof re-validation at sign time, got {:?}",
                err
            );
        }
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn arm_rejects_measurement_mismatch_after_signing() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq,
            measurement: b"legit-meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCC; 32],
        };
        let proof = signed_recent_chain_proof(200, [0xDD; 32], vec![[0xCC; 32]], &authorized);
        let mut forged = authorized.clone();
        forged.measurement = b"evil-meas".to_vec();
        let err = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: forged,
                recent_chain_proof: proof,
            },
            test_attestation_trust(),
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn re_arm_requires_strictly_fresher_finalized_height() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq,
            measurement: b"m".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };

        let first = signed_recent_chain_proof(200, [0x11; 32], vec![[0xAA; 32]], &authorized);
        let armed = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: first,
            },
            test_attestation_trust(),
        )
        .unwrap();

        let stale_rearm = signed_recent_chain_proof(200, [0x22; 32], vec![[0xAA; 32]], &authorized);
        let err = arm_for_production(
            &armed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: stale_rearm,
            },
            test_attestation_trust(),
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));

        let fresher = signed_recent_chain_proof(250, [0x33; 32], vec![[0xAA; 32]], &authorized);
        assert!(arm_for_production(
            &armed,
            ArmForProductionRequest {
                authorized_state: authorized,
                recent_chain_proof: fresher,
            },
            test_attestation_trust(),
        )
        .is_ok());
    }

    #[test]
    fn validate_recent_chain_proof_rejects_non_empty_tail_without_source_ticket() {
        // This is the central anti-replay case that was made a hard error in 5369c3a
        let state = AuthorizedProducerState {
            pq_pubkey: vec![],
            measurement: vec![],
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };

        let bad = RecentChainProof {
            finalized_height: 150,
            finalized_header_hash: [0xFE; 32],
            recovery_history_tail: vec![[0x11; 32]], // non-empty but does not contain source
            proof_data: build_proof_data_v1(&[[0x11; 32]]),
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        let err = validate_recent_chain_proof(&bad, &state, &test_attestation_trust()).unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));
    }

    #[test]
    #[cfg(not(feature = "ml-dsa-65"))]
    fn arm_for_production_rejects_when_pq_signing_not_ready_on_default_profile() {
        assert!(!pq_signing_ready());
        let authorized = AuthorizedProducerState {
            pq_pubkey: vec![0xAB; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };
        let err = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: signed_recent_chain_proof(
                    150,
                    [0xFE; 32],
                    vec![[0xAA; 32]],
                    &authorized,
                ),
            },
            test_attestation_trust(),
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::PqSigningUnavailable(_)));
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn arm_for_production_transitions_state_on_valid_proof() {
        // Basic test for the new arm_for_production function (AC #7)
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let initial = EnclaveState::Unarmed;

        let authorized = AuthorizedProducerState {
            pq_pubkey: pq,
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };
        let req = ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(
                150,
                [0xFE; 32],
                vec![[0xAA; 32]],
                &authorized,
            ),
        };

        let new_state = arm_for_production(&initial, req, test_attestation_trust())
            .expect("arming should succeed");

        match new_state {
            EnclaveState::Armed(s) => {
                assert_eq!(s.authorized_activated_at_height, 100);
            }
            EnclaveState::Unarmed => panic!("expected Armed state"),
        }
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn dispatch_arm_for_production_updates_state() {
        // Demonstrates using the stateful dispatcher (the new recommended path)
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let mut state = EnclaveState::Unarmed;

        let authorized = AuthorizedProducerState {
            pq_pubkey: pq,
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };
        let req = ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(
                150,
                [0xFE; 32],
                vec![[0xAA; 32]],
                &authorized,
            ),
        };

        let cmd = Command::ArmForProduction(req);
        let resp = dispatch_command_with_state(cmd, &mut state, test_attestation_trust());

        match resp {
            Response::ArmForProduction(r) => {
                assert_eq!(r.status, "armed");
            }
            _ => panic!("expected ArmForProduction response"),
        }

        // State should now be armed
        assert!(matches!(state, EnclaveState::Armed(_)));

        // Also verify via GetStatus
        let status = match dispatch_command_with_state(
            Command::GetStatus(GetStatusRequest { version: 1 }),
            &mut state,
            test_attestation_trust(),
        ) {
            Response::GetStatus(r) => r,
            _ => panic!("expected GetStatus"),
        };
        assert!(status.armed);
        assert_eq!(status.authorized_activated_at_height, Some(100));
        assert_eq!(status.proof_finalized_height, Some(150));
        assert_eq!(status.source_ticket_hash, Some([0xAA; 32]));
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn get_status_reflects_armed_state() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let mut state = EnclaveState::Unarmed;

        let authorized = AuthorizedProducerState {
            pq_pubkey: pq.clone(),
            measurement: b"armed-measurement-v1".to_vec(),
            activated_at_height: 200,
            source_ticket_hash: [0xBB; 32],
        };
        let req = ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(
                250,
                [0xCC; 32],
                vec![[0xBB; 32]],
                &authorized,
            ),
        };

        let _ = dispatch_command_with_state(
            Command::ArmForProduction(req),
            &mut state,
            test_attestation_trust(),
        );

        let status_resp = match dispatch_command_with_state(
            Command::GetStatus(GetStatusRequest { version: 1 }),
            &mut state,
            test_attestation_trust(),
        ) {
            Response::GetStatus(r) => r,
            _ => panic!("expected GetStatus"),
        };

        assert!(status_resp.armed);
        assert_eq!(status_resp.authorized_measurement, b"armed-measurement-v1");
        assert_eq!(status_resp.authorized_pq_pubkey, pq);
        assert_eq!(status_resp.authorized_activated_at_height, Some(200));
        assert_eq!(status_resp.proof_finalized_height, Some(250));
        assert_eq!(status_resp.source_ticket_hash, Some([0xBB; 32]));
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn arm_for_production_fails_with_invalid_proof() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let mut state = EnclaveState::Unarmed;

        let bad_req = ArmForProductionRequest {
            authorized_state: AuthorizedProducerState {
                pq_pubkey: pq.clone(),
                measurement: b"meas".to_vec(),
                activated_at_height: 100,
                source_ticket_hash: [0xAA; 32],
            },
            recent_chain_proof: {
                let authorized = AuthorizedProducerState {
                    pq_pubkey: pq,
                    measurement: b"meas".to_vec(),
                    activated_at_height: 100,
                    source_ticket_hash: [0xAA; 32],
                };
                // Height 50 is stale; signing still uses a structurally valid proof blob.
                signed_recent_chain_proof(50, [0x11; 32], vec![[0xAA; 32]], &authorized)
            },
        };

        let resp = dispatch_command_with_state(
            Command::ArmForProduction(bad_req),
            &mut state,
            test_attestation_trust(),
        );

        match resp {
            Response::ArmForProduction(r) => {
                assert_eq!(r.status, "refused");
                let reason = r.reason.expect("expected refusal reason");
                assert!(
                    reason.contains("finalized_height is older"),
                    "expected stale-height refusal, got: {}",
                    reason
                );
            }
            _ => panic!("expected ArmForProduction response"),
        }

        assert!(matches!(state, EnclaveState::Unarmed));
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn stateful_sign_second_hardfork_while_armed_fails() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let mut state = EnclaveState::Unarmed;

        dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq.clone(), 10_000_000, 10_000_050)),
            &mut state,
            test_attestation_trust(),
        );

        let first = sample_hardfork_ticket(pq.clone(), 10_000_100);
        let ok = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: first }),
            &mut state,
            test_attestation_trust(),
        );
        assert!(matches!(ok, Response::SignAuthorizationTicket(_)));

        let second = sample_hardfork_ticket(pq, 10_000_200);
        let resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: second }),
            &mut state,
            test_attestation_trust(),
        );
        match resp {
            Response::Error(msg) => assert!(msg.contains("only one HARD_FORK_ACTIVATION")),
            _ => panic!("expected refusal of second hard-fork sign"),
        }
    }

    #[test]
    fn validate_recent_chain_proof_rejects_zero_header_hash() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![],
            measurement: vec![],
            activated_at_height: 10,
            source_ticket_hash: [0; 32],
        };

        let bad = RecentChainProof {
            finalized_height: 20,
            finalized_header_hash: [0; 32],
            recovery_history_tail: vec![],
            proof_data: build_proof_data_v1(&[]),
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        let err = validate_recent_chain_proof(&bad, &state, &test_attestation_trust()).unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));
    }

    #[test]
    fn validate_recent_chain_proof_rejects_stale_height() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![],
            measurement: vec![],
            activated_at_height: 1000,
            source_ticket_hash: [0; 32],
        };

        let stale = RecentChainProof {
            finalized_height: 500, // older than activation
            finalized_header_hash: [0x11; 32],
            recovery_history_tail: vec![],
            proof_data: build_proof_data_v1(&[]),
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        let err =
            validate_recent_chain_proof(&stale, &state, &test_attestation_trust()).unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));
    }

    #[test]
    fn validate_recent_chain_proof_rejects_zero_in_recovery_tail() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![],
            measurement: vec![],
            activated_at_height: 10,
            source_ticket_hash: [0xAA; 32],
        };

        let bad = RecentChainProof {
            finalized_height: 50,
            finalized_header_hash: [0xBB; 32],
            recovery_history_tail: vec![[0; 32]], // zero hash in tail
            proof_data: build_proof_data_v1(&[[0; 32]]),
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        let err = validate_recent_chain_proof(&bad, &state, &test_attestation_trust()).unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));
    }

    #[test]
    fn arm_request_now_carries_typed_proof() {
        // Compile-time + basic runtime check that the type change took effect
        let req = ArmForProductionRequest {
            authorized_state: AuthorizedProducerState {
                pq_pubkey: vec![1; 48],
                measurement: b"m".to_vec(),
                activated_at_height: 1,
                source_ticket_hash: [0x01; 32],
            },
            recent_chain_proof: signed_recent_chain_proof(
                10,
                [0x02; 32],
                vec![],
                &AuthorizedProducerState {
                    pq_pubkey: vec![1; 48],
                    measurement: b"m".to_vec(),
                    activated_at_height: 1,
                    source_ticket_hash: [0x01; 32],
                },
            ),
        };

        assert_eq!(req.recent_chain_proof.finalized_height, 10);
    }

    // ---------------------------------------------------------------------
    // TRACK A — Sign via dispatch + framing roundtrips
    // ---------------------------------------------------------------------

    #[test]
    fn roundtrip_sign_via_framing_and_dispatch_recovery() {
        #[cfg(all(feature = "ml-dsa-65", not(feature = "reference-test-key")))]
        let _signer_lock = clear_sealed_signer_for_mock_pubkey_tests();
        #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
        let _guard = install_reference_sealed_signer_for_tests();
        #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
        let pq_pubkey = pq_signer::sealed_signer_public_key_bytes().expect("sealed pk");
        #[cfg(not(all(feature = "ml-dsa-65", feature = "reference-test-key")))]
        let pq_pubkey = vec![0x11; 48];
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0x1111,
            context_hash: [0xAA; 32],
            activation_height: 1_000_000,
            new_measurement: b"recovery-dispatch".to_vec(),
            pq_pubkey,
            fork_spec_hash: None,
            new_header_version: None,
        };

        let cmd = Command::SignAuthorizationTicket(SignAuthorizationTicketRequest {
            ticket: payload.clone(),
        });

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cmd, &mut bytes).unwrap();

        let framed = encode_message(MessageType::SignAuthorizationTicket, &bytes).unwrap();
        let received = decode_message(&framed).unwrap();

        let received_cmd: Command = ciborium::de::from_reader(&received.payload[..]).unwrap();
        let resp = dispatch_command(received_cmd);

        match resp {
            Response::SignAuthorizationTicket(r) => {
                assert_eq!(r.ticket_hash, compute_canonical_ticket_hash(&payload));
                assert!(!r.signature.is_empty());
            }
            _ => panic!("expected SignAuthorizationTicket response"),
        }
    }

    fn sample_arm_request(
        pq_pubkey: Vec<u8>,
        activated_at_height: u64,
        finalized_height: u64,
    ) -> ArmForProductionRequest {
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq_pubkey.clone(),
            measurement: b"prod-enclave-v1".to_vec(),
            activated_at_height,
            source_ticket_hash: [0xAA; 32],
        };
        ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(
                finalized_height,
                [0x11; 32],
                vec![[0xAA; 32]],
                &authorized,
            ),
        }
    }

    fn sample_hardfork_ticket(
        pq_pubkey: Vec<u8>,
        activation_height: u64,
    ) -> AuthorizationTicketPayload {
        AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 42,
            context_hash: [0xAB; 32],
            activation_height,
            new_measurement: b"hardfork-v5".to_vec(),
            pq_pubkey,
            fork_spec_hash: Some([0xEF; 32]),
            new_header_version: Some(3),
        }
    }

    #[test]
    fn roundtrip_sign_via_framing_and_dispatch_hardfork() {
        // Stateless dispatch still rejects hard-fork (requires armed state).
        let payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 0x2222,
            context_hash: [0xBB; 32],
            activation_height: 2_000_000,
            new_measurement: b"hardfork-dispatch".to_vec(),
            pq_pubkey: vec![0x22; 48],
            fork_spec_hash: Some([0xCC; 32]),
            new_header_version: Some(3),
        };

        let cmd =
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: payload });

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cmd, &mut bytes).unwrap();

        let framed = encode_message(MessageType::SignAuthorizationTicket, &bytes).unwrap();
        let received = decode_message(&framed).unwrap();

        let received_cmd: Command = ciborium::de::from_reader(&received.payload[..]).unwrap();
        let resp = dispatch_command(received_cmd);

        match resp {
            Response::Error(msg) => {
                assert!(msg.contains("requires armed enclave state"));
            }
            _ => panic!("expected Error response for hard-fork without state"),
        }
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn stateful_arm_then_sign_hardfork_succeeds() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let mut state = EnclaveState::Unarmed;

        let arm_resp = dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq.clone(), 10_000_000, 10_000_050)),
            &mut state,
            test_attestation_trust(),
        );
        match arm_resp {
            Response::ArmForProduction(r) => assert_eq!(r.status, "armed"),
            _ => panic!("expected arm success"),
        }

        let ticket = sample_hardfork_ticket(pq, 10_000_100);
        let sign_resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest {
                ticket: ticket.clone(),
            }),
            &mut state,
            test_attestation_trust(),
        );

        match sign_resp {
            Response::SignAuthorizationTicket(r) => {
                assert_eq!(r.ticket_hash, compute_canonical_ticket_hash(&ticket));
                #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
                {
                    assert_eq!(r.signature.len(), ML_DSA65_SIGNATURE_LEN);
                    mldsa65::ReferenceMlDsa65Signer::global()
                        .verify_ticket_hash(&r.ticket_hash, &r.signature)
                        .unwrap();
                }
                #[cfg(feature = "test-support")]
                assert_eq!(r.signature.len(), 64);
            }
            other => panic!("expected sign success, got {:?}", other),
        }

        let status = match dispatch_command_with_state(
            Command::GetStatus(GetStatusRequest { version: 1 }),
            &mut state,
            test_attestation_trust(),
        ) {
            Response::GetStatus(s) => s,
            _ => panic!("expected GetStatus"),
        };
        assert_eq!(status.pending_hard_fork_height, Some(10_000_100));
        assert_eq!(status.last_known_block, Some(10_000_050));
    }

    #[test]
    fn stateful_sign_hardfork_without_arming_fails() {
        let mut state = EnclaveState::Unarmed;
        let ticket = sample_hardfork_ticket(vec![0xCD; 48], 10_000_100);

        let resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket }),
            &mut state,
            test_attestation_trust(),
        );

        match resp {
            Response::Error(msg) => assert!(msg.contains("requires the enclave to be armed")),
            _ => panic!("expected error when signing hard-fork while unarmed"),
        }
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn stateful_sign_hardfork_wrong_pubkey_fails() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let mut state = EnclaveState::Unarmed;

        dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq.clone(), 10_000_000, 10_000_050)),
            &mut state,
            test_attestation_trust(),
        );
        let mut wrong_pk = pq;
        wrong_pk[0] ^= 0xFF;
        let ticket = sample_hardfork_ticket(wrong_pk, 10_000_100);
        let resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket }),
            &mut state,
            test_attestation_trust(),
        );
        match resp {
            Response::Error(msg) => assert!(msg.contains("pq_pubkey")),
            _ => panic!("expected pubkey mismatch error"),
        }
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn stateful_sign_hardfork_stale_activation_height_fails() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let mut state = EnclaveState::Unarmed;

        dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq.clone(), 10_000_000, 10_000_050)),
            &mut state,
            test_attestation_trust(),
        );

        // activation_height not strictly above proof.finalized_height
        let ticket = sample_hardfork_ticket(pq, 10_000_050);
        let resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket }),
            &mut state,
            test_attestation_trust(),
        );

        match resp {
            Response::Error(msg) => {
                assert!(msg.contains("activation_height must be strictly greater"))
            }
            _ => panic!("expected stale activation_height error"),
        }
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn stateful_framing_roundtrip_hardfork_after_arm() {
        let Some((_pq_guard, pq)) = arm_test_pq_setup() else {
            return;
        };
        let mut state = EnclaveState::Unarmed;

        dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq.clone(), 100, 500)),
            &mut state,
            test_attestation_trust(),
        );

        let payload = sample_hardfork_ticket(pq, 600);
        let cmd = Command::SignAuthorizationTicket(SignAuthorizationTicketRequest {
            ticket: payload.clone(),
        });

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cmd, &mut bytes).unwrap();
        let framed = encode_message(MessageType::SignAuthorizationTicket, &bytes).unwrap();
        let received = decode_message(&framed).unwrap();
        let received_cmd: Command = ciborium::de::from_reader(&received.payload[..]).unwrap();

        let resp = dispatch_command_with_state(received_cmd, &mut state, test_attestation_trust());
        match resp {
            Response::SignAuthorizationTicket(r) => {
                assert_eq!(r.ticket_hash, compute_canonical_ticket_hash(&payload));
            }
            _ => panic!("expected successful hard-fork sign after arm"),
        }
    }

    #[test]
    fn stateful_get_measurement_lists_hardfork_type() {
        let mut state = EnclaveState::Unarmed;
        let resp = dispatch_command_with_state(
            Command::GetMeasurement(GetMeasurementRequest { version: 1 }),
            &mut state,
            test_attestation_trust(),
        );
        match resp {
            Response::GetMeasurement(r) => {
                assert!(r.supported_ticket_types.contains(&0));
                assert!(r.supported_ticket_types.contains(&1));
            }
            _ => panic!("expected GetMeasurement"),
        }
    }

    #[test]
    fn dispatch_invalid_hardfork_ticket_yields_error_response() {
        let bad = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0; 32],
            activation_height: 100,
            new_measurement: vec![],
            pq_pubkey: vec![],
            fork_spec_hash: None, // missing required fields
            new_header_version: None,
        };

        let cmd = Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: bad });
        let resp = dispatch_command(cmd);

        match resp {
            Response::Error(msg) => assert!(msg.contains("sign_authorization_ticket failed")),
            _ => panic!("expected Error response"),
        }
    }

    #[test]
    fn dispatch_recovery_ticket_with_hardfork_fields_yields_error() {
        let polluted = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 1,
            context_hash: [0; 32],
            activation_height: 10,
            new_measurement: vec![1],
            pq_pubkey: vec![2],
            fork_spec_hash: Some([3; 32]),
            new_header_version: Some(1),
        };

        let cmd =
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: polluted });
        let resp = dispatch_command(cmd);

        match resp {
            Response::Error(msg) => assert!(msg.contains("sign_authorization_ticket failed")),
            _ => panic!("expected Error response"),
        }
    }

    #[test]
    #[cfg(feature = "ml-dsa-65")]
    fn arm_rejects_when_pq_signing_not_ready() {
        let _cleared = clear_sealed_signer_for_mock_pubkey_tests();
        assert!(!pq_signing_ready());
        let pq = vec![0xAB; 48];
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq,
            measurement: b"m".to_vec(),
            activated_at_height: 1,
            source_ticket_hash: [0xCC; 32],
        };
        let err = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: signed_recent_chain_proof(10, [0xDD; 32], vec![], &authorized),
            },
            test_attestation_trust(),
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::PqSigningUnavailable(_)));
    }

    #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
    fn install_reference_sealed_signer_for_tests() -> pq_signer::SealedSignerTestGuard {
        let guard = pq_signer::SealedSignerTestGuard::acquire();
        pq_signer::reset_installed_pq_signer_for_tests();
        install_reference_sealed_signer_from_embedded().expect("reference signer install");
        guard
    }

    #[test]
    #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
    fn sealed_signer_sets_pq_signing_ready_and_measurement_pubkey() {
        let _guard = install_reference_sealed_signer_for_tests();
        assert!(pq_signing_ready());
        let resp = dispatch_command(Command::GetMeasurement(GetMeasurementRequest {
            version: 1,
        }));
        match resp {
            Response::GetMeasurement(r) => {
                assert!(r.pq_signing_ready);
                assert_eq!(r.pq_pubkey.len(), ML_DSA65_PUBKEY_LEN);
            }
            _ => panic!("expected GetMeasurement"),
        }
    }

    #[test]
    #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
    fn recovery_sign_rejects_pq_pubkey_mismatch_when_sealed() {
        let _guard = install_reference_sealed_signer_for_tests();
        let ticket = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 1,
            context_hash: [0x01; 32],
            activation_height: 100,
            new_measurement: b"m".to_vec(),
            pq_pubkey: vec![0xFF; ML_DSA65_PUBKEY_LEN],
            fork_spec_hash: None,
            new_header_version: None,
        };
        let err = handle_sign_authorization_ticket(SignAuthorizationTicketRequest { ticket })
            .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidTicket(_)));
    }

    #[test]
    #[cfg(all(feature = "ml-dsa-65", feature = "reference-test-key"))]
    fn recovery_sign_accepts_matching_pq_pubkey_when_sealed() {
        let _guard = install_reference_sealed_signer_for_tests();
        let pk = pq_signer::sealed_signer_public_key_bytes().unwrap();
        let ticket = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 7,
            context_hash: [0x02; 32],
            activation_height: 200,
            new_measurement: b"recovery".to_vec(),
            pq_pubkey: pk,
            fork_spec_hash: None,
            new_header_version: None,
        };
        let resp =
            handle_sign_authorization_ticket(SignAuthorizationTicketRequest { ticket }).unwrap();
        assert_eq!(resp.signature.len(), ML_DSA65_SIGNATURE_LEN);
    }

    #[test]
    fn dispatch_get_measurement_works() {
        #[cfg(feature = "ml-dsa-65")]
        let _guard = pq_signer::SealedSignerTestGuard::acquire();
        #[cfg(feature = "ml-dsa-65")]
        pq_signer::reset_installed_pq_signer_for_tests();

        let cmd = Command::GetMeasurement(GetMeasurementRequest { version: 1 });
        let resp = dispatch_command(cmd);

        match resp {
            Response::GetMeasurement(r) => {
                assert_eq!(r.supported_ticket_types, vec![0, 1]); // static capability; type=1 needs armed state
                assert!(!r.pq_signing_ready);
                assert!(!r.measurement.is_empty());
            }
            _ => panic!("expected GetMeasurement response"),
        }
    }

    #[test]
    fn canonical_ticket_hash_is_deterministic_and_distinct() {
        let mut payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 42,
            context_hash: [0u8; 32],
            activation_height: 1_500_000,
            new_measurement: vec![1, 2, 3],
            pq_pubkey: vec![4, 5, 6],
            fork_spec_hash: Some([7u8; 32]),
            new_header_version: Some(2),
        };

        let h1 = compute_canonical_ticket_hash(&payload);

        // Changing any field must change the hash
        payload.nonce = 43;
        let h2 = compute_canonical_ticket_hash(&payload);
        assert_ne!(h1, h2);

        // Different hard-fork intent must produce different hash
        payload.fork_spec_hash = Some([8u8; 32]);
        let h3 = compute_canonical_ticket_hash(&payload);
        assert_ne!(h2, h3);
    }

    #[test]
    fn hard_fork_validation_rejects_missing_fields() {
        let bad_payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0u8; 32],
            activation_height: 100,
            new_measurement: vec![],
            pq_pubkey: vec![],
            fork_spec_hash: None, // missing!
            new_header_version: None,
        };

        assert!(validate_ticket_payload(&bad_payload).is_err());
    }

    #[test]
    fn hard_fork_validation_rejects_zero_fork_fields() {
        let zero_fork = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0u8; 32],
            activation_height: 100,
            new_measurement: vec![],
            pq_pubkey: vec![1],
            fork_spec_hash: Some([0u8; 32]),
            new_header_version: Some(1),
        };
        assert!(validate_ticket_payload(&zero_fork).is_err());

        let zero_version = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0u8; 32],
            activation_height: 100,
            new_measurement: vec![],
            pq_pubkey: vec![1],
            fork_spec_hash: Some([0xAB; 32]),
            new_header_version: Some(0),
        };
        assert!(validate_ticket_payload(&zero_version).is_err());
    }

    #[test]
    fn unknown_ticket_type_is_rejected() {
        let unknown = AuthorizationTicketPayload {
            ticket_type: 42, // undefined type
            nonce: 1,
            context_hash: [0u8; 32],
            activation_height: 100,
            new_measurement: vec![1],
            pq_pubkey: vec![2],
            fork_spec_hash: None,
            new_header_version: None,
        };

        assert!(validate_ticket_payload(&unknown).is_err());
        assert!(prepare_ticket_for_signing(&unknown).is_err());
    }

    #[test]
    fn different_tickets_produce_different_hashes_even_with_similar_data() {
        let base = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 1,
            context_hash: [0x42; 32],
            activation_height: 10,
            new_measurement: vec![1, 2, 3],
            pq_pubkey: vec![4, 5, 6],
            fork_spec_hash: None,
            new_header_version: None,
        };

        let h1 = compute_canonical_ticket_hash(&base);

        let mut modified = base.clone();
        modified.pq_pubkey = vec![4, 5, 7]; // меняем один байт

        let h2 = compute_canonical_ticket_hash(&modified);

        assert_ne!(
            h1, h2,
            "Changing even one byte in the payload must change the canonical hash"
        );
    }

    #[test]
    fn hard_fork_ticket_without_required_fields_is_rejected() {
        let incomplete = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 99,
            context_hash: [0xAA; 32],
            activation_height: 5_000_000,
            new_measurement: vec![9, 9, 9],
            pq_pubkey: vec![8; 48],
            fork_spec_hash: None, // deliberately missing
            new_header_version: None,
        };

        assert!(validate_ticket_payload(&incomplete).is_err());
        assert!(prepare_ticket_for_signing(&incomplete).is_err());
    }

    #[test]
    fn recovery_ticket_with_hard_fork_fields_is_rejected() {
        let polluted = AuthorizationTicketPayload {
            ticket_type: 0, // Recovery
            nonce: 100,
            context_hash: [0xBB; 32],
            activation_height: 5_000_001,
            new_measurement: vec![1],
            pq_pubkey: vec![2],
            fork_spec_hash: Some([3; 32]), // should not be present
            new_header_version: Some(2),
        };

        assert!(validate_ticket_payload(&polluted).is_err());
    }

    #[test]
    fn hard_fork_and_recovery_with_same_base_data_produce_different_hashes() {
        let base = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 777,
            context_hash: [0x01; 32],
            activation_height: 3_000_000,
            new_measurement: vec![10, 20, 30],
            pq_pubkey: vec![40, 50, 60],
            fork_spec_hash: None,
            new_header_version: None,
        };

        let recovery_hash = compute_canonical_ticket_hash(&base);

        let mut hardfork = base.clone();
        hardfork.ticket_type = 1;
        hardfork.fork_spec_hash = Some([0xAA; 32]);
        hardfork.new_header_version = Some(2);

        let hardfork_hash = compute_canonical_ticket_hash(&hardfork);

        assert_ne!(recovery_hash, hardfork_hash);
    }

    // =====================================================================
    // AUTOMATED CROSS-VERIFICATION WITH SOLIDITY (via Forge) — Track C
    //
    // These tests compare `compute_canonical_ticket_hash` against the *exact*
    // value produced by the on-chain `abi.encode(...) + keccak256` using the
    // normative Solidity script (`CanonicalTicketHash.s.sol`).
    //
    // This is the living contract between the TEE implementation and the
    // on-chain AuthorizationTickets precompile.
    //
    // The mechanism is intentionally graceful by default (so `cargo test`
    // works on machines without Foundry). In CI you can make it mandatory:
    //
    //     cargo test --features enforce-forge-crosscheck
    //
    // See Cargo.toml for the feature description.
    // =====================================================================

    /// Centralized helper for the automated Forge cross-check vectors.
    ///
    /// - If we got a Solidity hash → assert bit-for-bit equality with Rust.
    /// - If we could not run Forge (missing script or forge-std) → print a
    ///   very loud, actionable banner and either skip (default) or panic
    ///   (when `enforce-forge-crosscheck` feature is enabled).
    fn handle_forge_result(
        solidity_hash: Option<[u8; 32]>,
        rust_hash: [u8; 32],
        vector_label: &str,
    ) {
        if let Some(s) = solidity_hash {
            assert_eq!(
                rust_hash, s,
                "Rust canonical hash diverges from Solidity abi.encode + keccak256 for {}",
                vector_label
            );
            return;
        }

        // Skip / enforcement path
        let banner = format!(
            "\n\
            ============================================================\n\
            [LIVE CONTRACT] Automated canonical hash cross-check SKIPPED\n\
            Vector: {}\n\
            ============================================================\n\
            The Rust implementation of `compute_canonical_ticket_hash` must\n\
            stay bit-for-bit identical to the on-chain `abi.encode` used by\n\
            the AuthorizationTickets precompile.\n\n\
            One-time setup (run once):\n\
                cd impl/solidity && forge install foundry-rs/forge-std\n\n\
            To make this check mandatory in CI (fail on skip):\n\
                cargo test --features enforce-forge-crosscheck\n\
            ============================================================\n",
            vector_label
        );

        eprintln!("{}", banner);

        #[cfg(feature = "enforce-forge-crosscheck")]
        panic!(
            "Forge cross-check vector '{}' was skipped, but the feature 'enforce-forge-crosscheck' is enabled. \
             This is a hard failure in CI.",
            vector_label
        );
    }

    #[test]
    fn automated_cross_check_recovery_vector() {
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0x1234,
            context_hash: [0xAB; 32],
            activation_height: 10_000_000,
            new_measurement: b"recovery-v1".to_vec(),
            pq_pubkey: hex::decode("deadbeefcafebabe").unwrap(),
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(
            solidity_hash,
            rust_hash,
            "recovery ticket (original reference vector)",
        );
    }

    #[test]
    fn automated_cross_check_hardfork_vector() {
        let payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 0x5678,
            context_hash: [0xCD; 32],
            activation_height: 12_000_000,
            new_measurement: b"hardfork-v2".to_vec(),
            pq_pubkey: hex::decode("feedface").unwrap(),
            fork_spec_hash: Some([0x11; 32]),
            new_header_version: Some(4),
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(
            solidity_hash,
            rust_hash,
            "hard-fork ticket (original reference vector)",
        );
    }

    // ---------------------------------------------------------------------
    // NEW EDGE-CASE VECTORS (Track C)
    // ---------------------------------------------------------------------

    #[test]
    fn automated_cross_check_recovery_empty_measurement() {
        // 0-byte dynamic field — exercises length=0 + padding only.
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0xDEAD_BEEF,
            context_hash: [0x11; 32],
            activation_height: 42,
            new_measurement: vec![],
            pq_pubkey: b"pq-empty-meas".to_vec(),
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(
            solidity_hash,
            rust_hash,
            "recovery ticket — empty new_measurement (0 bytes)",
        );
    }

    #[test]
    fn automated_cross_check_recovery_32byte_measurement() {
        // Exactly 32 bytes of data → clean single-word case.
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0x1234_5678,
            context_hash: [0x22; 32],
            activation_height: 7_000_000,
            new_measurement: [0xEE; 32].to_vec(),
            pq_pubkey: b"pq-32-byte".to_vec(),
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(
            solidity_hash,
            rust_hash,
            "recovery ticket — exactly 32-byte new_measurement",
        );
    }

    #[test]
    fn automated_cross_check_hardfork_33byte_measurement() {
        // 33 bytes → crosses into next word, requires 31 bytes of padding.
        let payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 0xCAFE,
            context_hash: [0x33; 32],
            activation_height: 1_000,
            new_measurement: vec![0xDE; 33],
            pq_pubkey: b"33-byte-boundary".to_vec(),
            fork_spec_hash: Some([0x22; 32]),
            new_header_version: Some(7),
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(
            solidity_hash,
            rust_hash,
            "hard-fork ticket — 33-byte new_measurement (padding boundary)",
        );
    }

    #[test]
    fn automated_cross_check_recovery_large_measurement() {
        // 200 bytes → multi-word + non-trivial padding.
        let large_meas: Vec<u8> = (0u8..200).collect();
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0xFEED_FACE_CAFE_BABE,
            context_hash: [0x44; 32],
            activation_height: 99_999_999,
            new_measurement: large_meas,
            pq_pubkey: vec![0xAB; 48],
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(
            solidity_hash,
            rust_hash,
            "recovery ticket — large (200-byte) new_measurement",
        );
    }

    #[test]
    fn automated_cross_check_recovery_zero_height_max_nonce() {
        // Extreme scalar values in the static head (activationHeight = 0, nonce = u64::MAX).
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: u64::MAX,
            context_hash: [0x99; 32],
            activation_height: 0,
            new_measurement: b"zero-height-max-nonce".to_vec(),
            pq_pubkey: vec![0xAB; 64],
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(
            solidity_hash,
            rust_hash,
            "recovery ticket — activation_height=0 and nonce=u64::MAX",
        );
    }

    /// Calls the Foundry script via JSON exchange to get the ground-truth hash
    /// from the *normative* Solidity implementation.
    ///
    /// This is the mechanism that makes the automated cross-checks actually
    /// compare against the on-chain encoding (the live contract).
    ///
    /// The script (`CanonicalTicketHash.s.sol`) reads `INPUT_JSON`, computes
    /// `keccak256(abi.encode(...))` using the real EVM rules (including the
    /// special casing for ticketType==0 vs 1), and writes the result to
    /// `OUTPUT_JSON`.
    ///
    /// If forge or the required files are missing, returns None (the caller
    /// then decides skip vs panic according to the policy in
    /// `handle_forge_result`).
    fn compute_hash_via_forge(payload: &AuthorizationTicketPayload) -> Option<[u8; 32]> {
        use std::fs;
        use std::path::PathBuf;
        use std::process::Command;
        use std::sync::atomic::{AtomicU64, Ordering};

        static FORGE_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

        // Locate repo root
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir.ancestors().nth(3).unwrap_or(&manifest_dir);

        let solidity_dir = repo_root.join("impl/solidity");
        let script_path = solidity_dir.join("CanonicalTicketHash.s.sol");
        if !script_path.exists() {
            return None;
        }

        // Keep I/O inside impl/solidity so Forge fs_permissions (foundry.toml) allow read/write.
        let temp_dir = solidity_dir.join(".forge-crosscheck");
        fs::create_dir_all(&temp_dir).ok()?;
        let seq = FORGE_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let input_path = temp_dir.join(format!("input-{seq}.json"));
        let output_path = temp_dir.join(format!("output-{seq}.json"));

        // Build input JSON in the exact format the script expects
        let input_json = serde_json::json!({
            "ticketType": payload.ticket_type,
            "nonce": payload.nonce,
            "contextHash": format!("0x{}", hex::encode(payload.context_hash)),
            "activationHeight": payload.activation_height,
            "newMeasurement": format!("0x{}", hex::encode(&payload.new_measurement)),
            "pqPubkey": format!("0x{}", hex::encode(&payload.pq_pubkey)),
            "forkSpecHash": format!("0x{}", hex::encode(payload.fork_spec_hash.unwrap_or([0u8; 32]))),
            "newHeaderVersion": payload.new_header_version.unwrap_or(0),
        });

        fs::write(&input_path, serde_json::to_string_pretty(&input_json).ok()?).ok()?;

        // Run the script with environment variables (from the solidity dir so foundry.toml is found)
        let output = Command::new("forge")
            .current_dir(&solidity_dir)
            .env("INPUT_JSON", &input_path)
            .env("OUTPUT_JSON", &output_path)
            .args(["script", "CanonicalTicketHash.s.sol", "--silent"])
            .output()
            .ok()?;

        if !output.status.success() {
            eprintln!("Forge script failed while computing canonical hash for test vector.");
            eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
            eprintln!("\nOne-time setup (run once):");
            eprintln!("    cd impl/solidity && forge install foundry-rs/forge-std --no-commit\n");
            return None;
        }

        let output_content = fs::read_to_string(&output_path).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&output_content).ok()?;
        let hash_hex = parsed["hash"].as_str()?;

        hex::decode(hash_hex.trim_start_matches("0x"))
            .ok()
            .and_then(|b| {
                if b.len() == 32 {
                    Some(b.try_into().unwrap())
                } else {
                    None
                }
            })
    }
}

#[cfg(test)]
mod agent_gateway_framing_tests {
    use super::*;

    // AC#21: existing producer frames still decode after adding 0x40 AgentGateway.
    #[test]
    fn producer_frames_still_decode_after_agentgateway_added() {
        for t in [
            MessageType::GetMeasurement,
            MessageType::SignAuthorizationTicket,
            MessageType::ArmForProduction,
            MessageType::GetStatus,
        ] {
            let frame = encode_message(t, &[]).unwrap();
            assert_eq!(decode_message(&frame).unwrap().msg_type, t);
        }
    }

    // AC#20: peek classifies 0x40 and fails closed (None) on unknown bytes —
    // it must NOT fall back to a producer type (the old fail-open bug).
    #[test]
    fn peek_classifies_agent_gateway_and_fails_closed_on_unknown() {
        let mk = |type_byte: u8| [0u8, 0, 0, 2, PROTOCOL_VERSION, type_byte];
        assert_eq!(
            peek_msg_type_from_frame(&mk(0x01)),
            Some(MessageType::GetMeasurement)
        );
        assert_eq!(
            peek_msg_type_from_frame(&mk(0x40)),
            Some(MessageType::AgentGateway)
        );
        // 0x41 = AGENT_BOOT_RELAY (TASK-7.7 5b-2, enclave-initiated boot handshake frame).
        assert_eq!(
            peek_msg_type_from_frame(&mk(0x41)),
            Some(MessageType::AgentBootRelay)
        );
        // 0x44 = AGENT_ANCHOR_MARKS_RELAY (TASK-7.7 5b-2e, enclave-initiated AdoptForward marks fetch).
        assert_eq!(
            peek_msg_type_from_frame(&mk(0x44)),
            Some(MessageType::AgentAnchorMarksRelay)
        );
        // 0x45 = AGENT_ANCHOR_COMMIT_RELAY (TASK-7.7 slice 6, enclave-initiated per-op commit).
        assert_eq!(
            peek_msg_type_from_frame(&mk(0x45)),
            Some(MessageType::AgentAnchorCommitRelay)
        );
        // Unknown bytes still fail closed (None) — must NOT fall back to a producer type (the old bug).
        // 0x42/0x43 are inner AgentError CODES, NOT outer MessageType bytes → still None.
        assert_eq!(peek_msg_type_from_frame(&mk(0x42)), None);
        assert_eq!(peek_msg_type_from_frame(&mk(0x43)), None);
        assert_eq!(peek_msg_type_from_frame(&mk(0xFF)), None);
        assert_eq!(peek_msg_type_from_frame(&[]), None);
    }

    // 5b-2e: the 0x44 marks-relay frame round-trips at the framing layer but is NEVER serve-dispatched
    // (enclave-initiated). A hostile inbound 0x44 to the serve dispatcher fails closed.
    #[test]
    fn agent_anchor_marks_relay_decodes_but_is_not_serve_dispatchable() {
        let frame = encode_message(MessageType::AgentAnchorMarksRelay, &[0xA0]).unwrap();
        let decoded = decode_message(&frame).unwrap();
        assert_eq!(decoded.msg_type, MessageType::AgentAnchorMarksRelay);
        assert!(
            matches!(
                decode_wire_command(decoded.msg_type, &decoded.payload),
                Err(ProtocolError::WireProtocol(m)) if m.contains("enclave-initiated")
            ),
            "a hostile inbound 0x44 must fail closed in the serve dispatcher"
        );
    }

    // slice 6: the 0x45 commit-relay frame round-trips at the framing layer but is NEVER serve-dispatched
    // (enclave-initiated, MUTATING). A hostile inbound 0x45 to the serve dispatcher fails closed.
    #[test]
    fn agent_anchor_commit_relay_decodes_but_is_not_serve_dispatchable() {
        let frame = encode_message(MessageType::AgentAnchorCommitRelay, &[0xA0]).unwrap();
        let decoded = decode_message(&frame).unwrap();
        assert_eq!(decoded.msg_type, MessageType::AgentAnchorCommitRelay);
        assert!(
            matches!(
                decode_wire_command(decoded.msg_type, &decoded.payload),
                Err(ProtocolError::WireProtocol(m)) if m.contains("enclave-initiated")
            ),
            "a hostile inbound 0x45 must fail closed in the serve dispatcher"
        );
    }

    // A 0x40 frame is recognized at the framing layer. WITHOUT the agent-gateway feature the
    // reserved namespace fails closed at decode; WITH it, 0x40 decodes to a raw-payload
    // AgentGateway command (agent_dispatch routes/encodes the response, incl. §10.9 errors — the
    // end-to-end frame path is exercised in agent_dispatch::tests::frame_handler_*).
    #[test]
    fn agent_gateway_frame_decode_per_feature() {
        let frame = encode_message(MessageType::AgentGateway, &[0xA0]).unwrap(); // 0xA0 = empty CBOR map
        let decoded = decode_message(&frame).unwrap();
        assert_eq!(decoded.msg_type, MessageType::AgentGateway);
        let cmd = decode_wire_command(decoded.msg_type, &decoded.payload);
        #[cfg(feature = "agent-gateway")]
        assert!(
            matches!(cmd, Ok(Command::AgentGateway(_))),
            "0x40 decodes under agent-gateway"
        );
        #[cfg(not(feature = "agent-gateway"))]
        assert!(
            matches!(cmd, Err(ProtocolError::WireProtocol(_))),
            "0x40 reserved/fail-closed without the agent-gateway feature"
        );
    }

    // AC#20: an unknown-type or reserved-agent request yields an error frame that
    // echoes its OWN type byte, never a producer type (no fail-open misrouting).
    #[test]
    fn error_frames_echo_their_own_type_byte_not_a_producer_type() {
        let unknown = encode_message_raw(0x77, &[0xA0]).unwrap();
        let resp = process_framed_bytes(&unknown).unwrap();
        assert_eq!(
            resp[5], 0x77,
            "unknown type must be echoed, not defaulted to 0x01"
        );

        let agent = encode_message(MessageType::AgentGateway, &[0xA0]).unwrap();
        let resp = process_framed_bytes(&agent).unwrap();
        assert_eq!(
            resp[5], 0x40,
            "agent gateway error must echo 0x40, not 0x01"
        );
    }
}
