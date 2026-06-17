//! TASK-7.7 5b-2c-iii **lab SNP live-smoke** surface — **TEST KEYS ONLY, release-banned**.
//!
//! Everything the aya live smoke needs that is not the real agent-gateway bin lives HERE, in one
//! in-crate module, so every smoke artifact (the minted smoke keystore, the lab anchor stub, the
//! host-side 0x40 client cores) reuses the crate's own canonical encoders/verifiers and is
//! cross-validated against the real serve/verify paths by deviceless tests — protocol drift between
//! the smoke tooling and the enclave is made unrepresentable before anything runs on SNP hardware.
//!
//! ## TEST KEYS ONLY
//! [`LAB_ANCHOR_TEST_SEED`] is a public, in-repo Ed25519 seed and [`SMOKE_SECRET_SCALAR`] is a
//! public secp256k1 scalar. They carry **no secrecy claim whatsoever**: they exist so the smoke
//! keystore fixture, the anchor stub and the client expectations are reproducible from one source.
//! The whole module is gated behind `lab-agent-smoke`, which is hard-banned from release builds by
//! a `compile_error!` in `lib.rs` (mirrors `lab-quote-smoke`); under plain `cfg(test)` it compiles
//! only for the freeze/cross-validation tests.
//!
//! The guest image does NOT enable this feature: the guest runs the real `twod-hsm-agent-gateway`
//! bin with `lab-agent-keystore-from-file` pointing at the fixture minted here.

// The mint constants/helpers land first (this commit); the anchor stub + client cores that consume
// them outside cfg(test) land in the follow-on commits of this slice. Mirror the agent_anchor
// staging discipline: allow dead-code in the non-test lib build only, remove when fully consumed.
#![cfg_attr(not(test), allow(dead_code))]

use crate::agent_keystore::{
    seal_keystore_with_nonce, AuditRing, CreationMetadata, FaucetState, KeyAlgorithm, KeyEntry,
    KeyPurpose, KeystoreBody, KeystoreConfig,
};
use crate::AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT;
use zeroize::Zeroizing;

/// **TEST KEYS ONLY** — public in-repo Ed25519 seed for the lab anchor stub. The smoke keystore's
/// `anchor_root` is the verifying key derived from this seed, so the stub (and only a holder of
/// this public constant) can sign freshness responses the smoke guest accepts. No secrecy claim;
/// the enclosing feature is release-banned.
pub(crate) const LAB_ANCHOR_TEST_SEED: [u8; 32] = [0x42; 32];

/// **TEST KEYS ONLY** — public secp256k1 secret scalar of the smoke keystore's single key entry
/// (a valid non-zero scalar `< n`). Public on purpose: the host-side client derives the expected
/// PUBLIC_IDENTITY reply (pubkey/eth/tron) from it via the crate's own `secp256k1` path.
pub(crate) const SMOKE_SECRET_SCALAR: [u8; 32] = [0x77; 32];

/// The smoke entry's opaque key handle (request key 6 of the PUBLIC_IDENTITY round-trip).
/// Distinct from every genesis literal so a mixed-up fixture fails loudly.
pub(crate) const SMOKE_KEY_REF: [u8; 32] = [0x11; 32];

/// **TEST KEYS ONLY** — public in-repo Ed25519 seed for the smoke keystore's ADMIN authority
/// (slice 6-7b write path). The sealed `admin_authority_pk` below is this seed's verifying key, so
/// the write-path smoke client (and only a holder of this public constant) can sign GENERATE_KEYS
/// capabilities the smoke guest's `verify_capability` accepts. Distinct from `LAB_ANCHOR_TEST_SEED`
/// (`[0x42; 32]`, the anchor signer) — the two authorities are independent. No secrecy claim; the
/// enclosing feature is release-banned.
pub(crate) const SMOKE_ADMIN_SEED: [u8; 32] = [0x0a; 32];

/// Fixed seal nonce → byte-stable smoke golden blob (the only randomness in the seal).
/// Distinct from the genesis nonce (`[0x5d; 24]`).
pub(crate) const SMOKE_SEAL_NONCE: [u8; 24] = [0x5e; 24];

/// The committed reference provisioning root the smoke fixture is sealed under — the SAME root file
/// the producer lab fixtures use (`TWOD_HSM_PQ_SEAL_V1_ROOT_FILE` points here in the lab guest);
/// the agent/producer KDF domains are separated inside `agent_keystore`, not by distinct roots.
pub(crate) const SMOKE_SEAL_ROOT: &[u8; 32] =
    include_bytes!("../testvectors/seal_v1_provisioning_root.bin");

/// `environment_identifier` of the smoke scope (charset-valid per TASK-7.1 §10.6).
pub(crate) const SMOKE_ENVIRONMENT: &str = "lab-snp-smoke";

/// `twod_chain_id` of the smoke scope (matches the vector convention used across the crate).
pub(crate) const SMOKE_CHAIN_ID: u64 = 11565;

/// The minted 5b-2c-iii smoke keystore body — the single source feeding the committed fixture
/// (regen test), the lab anchor stub's scope/marks derivation AND the host-side client's expected
/// PUBLIC_IDENTITY reply. Differences from the genesis body, all load-bearing for the smoke:
/// `anchor_root` is derived from [`LAB_ANCHOR_TEST_SEED`] (the stub can actually sign for it, so
/// boot reaches `Ready`), and there is ONE key entry (so PUBLIC_IDENTITY returns a SUCCESS body,
/// not `0x42` — the zero-entry genesis stays the negative control).
pub(crate) fn smoke_body() -> KeystoreBody {
    let anchor_root = ed25519_dalek::SigningKey::from_bytes(&LAB_ANCHOR_TEST_SEED)
        .verifying_key()
        .to_bytes();
    // 6-7b write path: the admin authority is a KNOWN test seed so the smoke client can sign a valid
    // GENERATE_KEYS capability. Derived through ed25519-dalek (never a pasted literal) so the fixture
    // and the client's signer can never split.
    let admin_authority_pk = ed25519_dalek::SigningKey::from_bytes(&SMOKE_ADMIN_SEED)
        .verifying_key()
        .to_bytes();
    // On-curve by construction: derive the public identity through the crate's own secp256k1 path,
    // never pasted hex (a stale literal here would split the fixture from the client expectations).
    let keypair = crate::secp256k1::Keypair::from_secret_bytes(&SMOKE_SECRET_SCALAR)
        .expect("SMOKE_SECRET_SCALAR is a valid non-zero scalar < n");
    KeystoreBody {
        config: KeystoreConfig {
            twod_chain_id: SMOKE_CHAIN_ID,
            environment_identifier: SMOKE_ENVIRONMENT.to_string(),
            // 6-7b: a REAL verifying key (was placeholder `[0xa1; 32]`) so the write-path client can
            // forge a valid GENERATE_KEYS cap; recovery stays a placeholder (RESTORE is NotConfigured).
            admin_authority_pk,
            recovery_authority_pk: [0xa2; 32],
            backup_recovery_wrapping_pubkey: vec![0x33; 1568],
            monotonic_treasury_config_version: 0,
            authority_epoch: 0,
            anchor_root,
        },
        entries: vec![KeyEntry {
            key_ref: SMOKE_KEY_REF,
            purpose: KeyPurpose::AgentTransferK1,
            algorithm: KeyAlgorithm::Secp256k1,
            public_identity: keypair.public_key_uncompressed().to_vec(),
            secret_scalar: Zeroizing::new(SMOKE_SECRET_SCALAR.to_vec()),
            creation_metadata: CreationMetadata {
                config_version: 0,
                counter_snapshot: 0,
                batch_id: 0,
            },
            backup_export_metadata: Default::default(),
        }],
        counters: vec![],
        faucet: FaucetState {
            per_dispense_max_amount: [0; 32],
            max_gas_limit: 0,
            max_effective_gas_fee_rate: 0,
            cumulative_native_spend: [0; 32],
            lifetime_spend: [0; 32],
            circuit_breaker_threshold: None,
            cumulative_signing_budget: [0; 32],
        },
        audit: AuditRing { records: vec![], capacity: 256, last_exported_seq: 0, next_seq: 1 },
        freshness_epoch: 1,
        structural_version: 1,
        strict_recovery_counter: 0,
    }
}

/// Deterministic CBOR of `body` — exactly what `seal_body` encodes internally, so `unseal_body`
/// round-trips a blob sealed from this (mirrors the genesis helper in `boot_agent_keystore`).
fn cbor_of(body: &KeystoreBody) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(body, &mut buf).expect("smoke body encodes");
    buf
}

/// The byte-stable smoke golden blob: committed reference root + placeholder measurement + fixed
/// nonce. The placeholder measurement matches the genesis precedent — the real attested 48-byte
/// SNP launch measurement is the deferred production keystore-source slice, recorded as explicit
/// non-coverage in SMOKE-PASS-CRITERIA.
pub(crate) fn smoke_sealed_blob() -> Vec<u8> {
    seal_keystore_with_nonce(
        &cbor_of(&smoke_body()),
        SMOKE_SEAL_ROOT,
        AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
        &SMOKE_SEAL_NONCE,
    )
    .expect("smoke body seals")
}

/// Build a stub-conformant 0x41 request frame for the SMOKE scope and `nonce`: correct cleartext
/// `report_data` binding + a minimal synthetic quote whose EMBEDDED report_data (offset 0x50)
/// matches it. Shared by the deviceless stub-conformance tests AND the aya `#[ignore]`
/// relay+anchor vsock-loopback composition test in `host_anchor_relay` (the TASK-21 seed).
pub(crate) fn smoke_request_frame(nonce: [u8; 32]) -> Vec<u8> {
    let body = smoke_body();
    smoke_request_frame_for_scope(
        body.config.twod_chain_id,
        &body.config.environment_identifier,
        nonce,
        None,
    )
}

/// [`smoke_request_frame`] for an ARBITRARY `(chain, env)` scope; `quote_override` lets a test
/// supply a quote whose embedded report_data deliberately mismatches the (always-correct)
/// cleartext binding at key 5.
pub(crate) fn smoke_request_frame_for_scope(
    chain_id: u64,
    env: &str,
    nonce: [u8; 32],
    quote_override: Option<Vec<u8>>,
) -> Vec<u8> {
    let report_data = crate::agent_anchor::anchor_handshake_report_data(chain_id, env, &nonce);
    let quote = quote_override.unwrap_or_else(|| {
        let mut q = vec![0u8; 0x50];
        q.extend_from_slice(&report_data);
        q
    });
    let req = crate::agent_boot_driver::AnchorBootRequest {
        chain_id,
        environment_identifier: env,
        nonce,
        report_data,
    };
    crate::agent_boot_relay::encode_anchor_boot_request(&quote, &[], &req)
        .expect("smoke request encodes")
}

// ---------------------------------------------------------------------------------------------
// Lab anchor stub — the TCP endpoint `twod-hsm-host-anchor-relay` dials during the smoke's boot
// handshake. Serial accept, one pump per connection, never dies (mirrors the relay's loop
// discipline). It composes the crate's OWN codec ends — `decode_anchor_boot_request`,
// `test_signed_response_bytes` (the single reference response builder), `frame_anchor_response` —
// so the stub structurally cannot drift from what the guest's `verify_anchor_response_bytes`
// accepts; the conformance tests below pin exactly that, deviceless.
// ---------------------------------------------------------------------------------------------

/// Stub listen address env (host loopback TCP; the relay's `TWOD_HSM_ANCHOR_ENDPOINT` points here).
pub(crate) const TWOD_HSM_LAB_ANCHOR_LISTEN: &str = "TWOD_HSM_LAB_ANCHOR_LISTEN";
/// Default stub listen address (relay=5001 vsock, agent serve=5002 vsock, stub=5003 TCP loopback).
pub(crate) const LAB_ANCHOR_DEFAULT_LISTEN: &str = "127.0.0.1:5003";
/// Sealed smoke-keystore blob path env (REQUIRED, no default, fail-closed).
pub(crate) const TWOD_HSM_LAB_ANCHOR_KEYSTORE_FILE: &str = "TWOD_HSM_LAB_ANCHOR_KEYSTORE_FILE";
/// 32-byte provisioning-root path env (REQUIRED, no default, fail-closed).
pub(crate) const TWOD_HSM_LAB_ANCHOR_SEAL_ROOT_FILE: &str = "TWOD_HSM_LAB_ANCHOR_SEAL_ROOT_FILE";

/// Whole-pump I/O budget per accepted connection (read request + sign + write response). Generous
/// against the guest's per-leg default (5 s) while still bounding a black-holing peer.
const STUB_PUMP_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// `let _ = writeln!` NEVER `eprintln!` (a broken-stderr panic must not kill the stub) — the (b)
/// relay house rule.
fn stub_log(args: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "twod-hsm-lab-anchor: {args}");
}

/// The startup fixture↔seed pairing assert: the verifying key derived from [`LAB_ANCHOR_TEST_SEED`]
/// must BE the unsealed body's `anchor_root`. A stale/mismatched fixture fails loudly HERE at stub
/// start — never as a mystery `SignatureInvalid` inside the guest on aya.
pub(crate) fn lab_anchor_root_matches(body: &KeystoreBody) -> Result<(), crate::ProtocolError> {
    let derived = ed25519_dalek::SigningKey::from_bytes(&LAB_ANCHOR_TEST_SEED)
        .verifying_key()
        .to_bytes();
    if body.config.anchor_root != derived {
        return Err(crate::ProtocolError::PqSigningUnavailable(
            "lab anchor: keystore anchor_root does not match LAB_ANCHOR_TEST_SEED \
             (stale or mismatched smoke fixture) — refusing to start",
        ));
    }
    Ok(())
}

/// One stub pump: read the full frame (the relay forwards it VERBATIM, 6-byte header included), PEEK
/// the type, and answer the matching enclave-initiated leg — `0x41` freshness (quote + cert) or
/// `0x44` raw-marks (5b-2e, no quote). Each leg validates with the crate's OWN request decoder, guards
/// the scope against the provisioned keystore, and answers with the reference-built signed response
/// framed by the shared writer. Every `Err` is a fault-close with ZERO bytes written back (every write
/// happens after all checks). Returns the echoed nonce prefix for the log line.
///
/// MATCH-ONLY quote policy (recorded non-goal, 0x41 only): the stub checks `report[0x50..0x90] == key 5`
/// and performs NO AMD cert-chain verification — guest-side security never depends on anchor-side policy
/// (the guest verifies the RESPONSE signature against its sealed root); this check exists only to catch
/// a producer wiring bug live instead of silently signing over garbage.
pub(crate) fn lab_anchor_pump_one<S: std::io::Read + std::io::Write>(
    conn: &mut S,
    body: &KeystoreBody,
    signing_key: &ed25519_dalek::SigningKey,
    deadline: std::time::Instant,
    ledger: &mut LabCommitLedger,
) -> Result<[u8; 8], crate::ProtocolError> {
    let frame = crate::read_framed_message_with_idle_deadline(conn, Some(deadline))?;
    match crate::peek_msg_type_from_frame(&frame) {
        Some(crate::MessageType::AgentBootRelay) => lab_anchor_freshness_reply(conn, &frame, body, signing_key, deadline),
        Some(crate::MessageType::AgentAnchorMarksRelay) => lab_anchor_marks_reply(conn, &frame, body, signing_key, deadline),
        Some(crate::MessageType::AgentAnchorCommitRelay) => lab_anchor_commit_reply(conn, &frame, body, signing_key, deadline, ledger),
        _ => Err(crate::ProtocolError::WireProtocol(
            "lab anchor: only AGENT_BOOT_RELAY (0x41) / AGENT_ANCHOR_MARKS_RELAY (0x44) / AGENT_ANCHOR_COMMIT_RELAY (0x45) are answerable",
        )),
    }
}

/// The 0x41 freshness leg: validate + scope-guard + match-only quote check, then the signed freshness
/// response committing the provisioned body's `(epoch, structural_version, marks_digest)`.
fn lab_anchor_freshness_reply<S: std::io::Read + std::io::Write>(
    conn: &mut S,
    frame: &[u8],
    body: &KeystoreBody,
    signing_key: &ed25519_dalek::SigningKey,
    deadline: std::time::Instant,
) -> Result<[u8; 8], crate::ProtocolError> {
    let req = crate::agent_boot_relay::decode_anchor_boot_request(frame)?;
    if req.chain_id != body.config.twod_chain_id
        || req.environment_identifier != body.config.environment_identifier
    {
        return Err(crate::ProtocolError::WireProtocol(
            "lab anchor: request scope does not match the provisioned smoke keystore",
        ));
    }
    let embedded = crate::snp_report::report_data_from_report(&req.quote_report)?;
    if embedded != req.report_data {
        return Err(crate::ProtocolError::WireProtocol(
            "lab anchor: embedded quote report_data does not match the request binding",
        ));
    }
    let response = crate::agent_anchor::test_signed_response_bytes(
        signing_key,
        req.chain_id,
        &req.environment_identifier,
        body.freshness_epoch,
        body.structural_version,
        body.compute_local_marks_digest(),
        req.nonce,
    );
    let wire = crate::agent_boot_relay::frame_anchor_response(&response)?;
    crate::agent_boot_relay::deadline_guarded_write(conn, &wire, deadline, "lab anchor: deadline before response write")?;
    let mut nonce8 = [0u8; 8];
    nonce8.copy_from_slice(&req.nonce[..8]);
    Ok(nonce8)
}

/// The 5b-2e 0x44 raw-marks leg: validate + scope-guard, then the signed marks response carrying the
/// provisioned body's OWN marks payload (so it self-consistently hashes to the `marks_digest` the
/// freshness leg commits). Echoes the request epoch + nonce (the guest binds to both). NO quote.
fn lab_anchor_marks_reply<S: std::io::Read + std::io::Write>(
    conn: &mut S,
    frame: &[u8],
    body: &KeystoreBody,
    signing_key: &ed25519_dalek::SigningKey,
    deadline: std::time::Instant,
) -> Result<[u8; 8], crate::ProtocolError> {
    let req = crate::agent_boot_relay::decode_anchor_marks_request(frame)?;
    if req.chain_id != body.config.twod_chain_id
        || req.environment_identifier != body.config.environment_identifier
    {
        return Err(crate::ProtocolError::WireProtocol(
            "lab anchor: marks request scope does not match the provisioned smoke keystore",
        ));
    }
    // The raw marks ARE the provisioned body's marks payload — so SHA3(MARKS_DOMAIN ‖ payload) equals
    // the digest the freshness leg signs, and the guest's hash-equality gate accepts.
    let payload = body.encode_marks_payload();
    let response = crate::agent_anchor::test_signed_marks_response_bytes(
        signing_key,
        req.chain_id,
        &req.environment_identifier,
        req.epoch,
        req.nonce,
        payload,
    );
    let wire = crate::agent_boot_relay::frame_response_cap(
        &response,
        crate::agent_boot_relay::MAX_MARKS_RESPONSE_LEN,
    )?;
    crate::agent_boot_relay::deadline_guarded_write(conn, &wire, deadline, "lab anchor: deadline before marks response write")?;
    let mut nonce8 = [0u8; 8];
    nonce8.copy_from_slice(&req.nonce[..8]);
    Ok(nonce8)
}

/// The lab anchor's durable commit record (slice 6-5): `request_id → (epoch, structural_version,
/// marks_digest)`. Models the real anchor's idempotency/conflict contract so the deviceless tests can
/// exercise the enclave's retry behaviour. The KEY is the `request_id` ALONE — it identifies a LOGICAL
/// op, which must commit AT MOST ONCE; the nonce is deliberately NOT part of the record (per-attempt,
/// fresh — the ack is re-signed for it).
pub(crate) type LabCommitLedger = std::collections::HashMap<Vec<u8>, (u64, u64, [u8; 32])>;

/// The slice-6 0x45 per-op commit leg: validate + scope-guard, then a signed commit ACK ECHOING the
/// proposed `(epoch, structural_version, marks_digest, nonce, request_id)`. slice 6-5 makes the lab
/// anchor STATEFUL so it models the idempotency contract: it durably records the post-op
/// `(epoch, structural_version, marks_digest)` keyed by the `request_id` and
/// - a retry under the SAME request_id with the SAME `{epoch, structural, marks}` is **idempotent** — it
///   re-signs an ACK for the CURRENT (fresh per-op) nonce so the enclave's anti-replay echo passes, but
///   does NOT advance the durable record again (no double-advance);
/// - a re-commit under the SAME request_id proposing ANY DIFFERENT `{epoch, structural, marks}` is a
///   **conflict** ⇒ reject (the enclave then fails closed). A DIFFERENT epoch is included deliberately:
///   that is the double-advance a post-`AdoptForward` re-issue of the same logical op would attempt, and
///   keying by `(request_id, epoch)` would WRONGLY admit it as a fresh entry.
///
/// NO quote; the ACK is small → 4096 cap.
fn lab_anchor_commit_reply<S: std::io::Read + std::io::Write>(
    conn: &mut S,
    frame: &[u8],
    body: &KeystoreBody,
    signing_key: &ed25519_dalek::SigningKey,
    deadline: std::time::Instant,
    ledger: &mut LabCommitLedger,
) -> Result<[u8; 8], crate::ProtocolError> {
    // The decode + scope-guard + ledger + sign logic is the ONE pure `lab_commit_ack_for_request`
    // (shared with the deviceless write-path `LabCommitChannel`); this stub wrapper only adds the
    // stream framing + bounded write.
    let (response, nonce8) = lab_commit_ack_for_request(frame, body, signing_key, ledger)?;
    let wire = crate::agent_boot_relay::frame_response_cap(
        &response,
        crate::agent_boot_relay::MAX_ANCHOR_RESPONSE_LEN,
    )?;
    crate::agent_boot_relay::deadline_guarded_write(conn, &wire, deadline, "lab anchor: deadline before commit ack write")?;
    Ok(nonce8)
}

/// The PURE 0x45 commit-ack computation: decode the request, scope-guard it against `body`, apply the
/// slice-6-5 `request_id`-keyed idempotency/conflict ledger, then return the UNFRAMED signed commit ACK
/// (what `BootRelayChannel::round_trip` hands back to the enclave) plus the `nonce8` log breadcrumb.
/// The SINGLE source shared by the stream stub ([`lab_anchor_commit_reply`], which frames + writes it)
/// and the deviceless write-path commit channel ([`LabCommitChannel`], which returns it verbatim) — so
/// the aya stub and the in-process cross-validation can never drift on the anchor's commit semantics.
pub(crate) fn lab_commit_ack_for_request(
    frame: &[u8],
    body: &KeystoreBody,
    signing_key: &ed25519_dalek::SigningKey,
    ledger: &mut LabCommitLedger,
) -> Result<(Vec<u8>, [u8; 8]), crate::ProtocolError> {
    let req = crate::agent_boot_relay::decode_anchor_commit_request(frame)?;
    if req.chain_id != body.config.twod_chain_id
        || req.environment_identifier != body.config.environment_identifier
    {
        return Err(crate::ProtocolError::WireProtocol(
            "lab anchor: commit request scope does not match the provisioned smoke keystore",
        ));
    }
    // slice 6-5 idempotency/conflict on the `request_id` durability key (the logical-op identity,
    // commit-at-most-once). `.copied()` ends the immutable borrow so the None arm can insert;
    // (u64, u64, [u8;32]) is Copy.
    let key = req.request_id.clone();
    let proposed = (req.new_epoch, req.new_structural_version, req.marks_digest);
    match ledger.get(&key).copied() {
        Some(recorded) if recorded != proposed => {
            return Err(crate::ProtocolError::WireProtocol(
                "lab anchor: commit conflict — request_id already durably recorded with a different \
                 (epoch, structural_version, marks_digest)",
            ));
        }
        Some(_) => { /* idempotent retry: durable record UNCHANGED; re-sign with the current nonce below */ }
        None => {
            ledger.insert(key, proposed);
        }
    }
    let mut nonce8 = [0u8; 8];
    nonce8.copy_from_slice(&req.nonce[..8]);
    let response = crate::agent_anchor::test_signed_commit_ack_bytes(
        signing_key,
        req.chain_id,
        &req.environment_identifier,
        req.new_epoch,
        req.new_structural_version,
        req.marks_digest,
        req.nonce,
        req.request_id, // moved (not cloned) — req.request_id is unused after this; req.nonce is Copy
    );
    Ok((response, nonce8))
}

/// Env-driven lab anchor stub entrypoint (the `twod-hsm-lab-anchor` bin's sole call). Fail-closed
/// startup: required file envs (capped reads, exact root length), unseal under the placeholder
/// measurement, the seed↔`anchor_root` pairing assert — THEN bind + the never-dying serial loop
/// (per-connection faults are logged + closed; accept errors back off [`ACCEPT_ERROR_BACKOFF`]).
/// `Ok` is unconstructible.
pub fn run_lab_anchor_stub() -> Result<std::convert::Infallible, crate::ProtocolError> {
    use crate::enclave_serve::ACCEPT_ERROR_BACKOFF;
    // NotPresent → default; NotUnicode → fail closed naming the var (the env_config contract).
    let listen = match std::env::var(TWOD_HSM_LAB_ANCHOR_LISTEN) {
        Ok(s) => s,
        Err(std::env::VarError::NotPresent) => LAB_ANCHOR_DEFAULT_LISTEN.to_string(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(crate::ProtocolError::PqSigningUnavailable(
                "lab anchor: TWOD_HSM_LAB_ANCHOR_LISTEN is not valid UTF-8",
            ))
        }
    };
    let require_path = |var: &str, missing: &'static str| -> Result<std::path::PathBuf, crate::ProtocolError> {
        match std::env::var_os(var) {
            Some(v) => Ok(std::path::PathBuf::from(v)),
            None => Err(crate::ProtocolError::PqSigningUnavailable(missing)),
        }
    };
    let root_path = require_path(
        TWOD_HSM_LAB_ANCHOR_SEAL_ROOT_FILE,
        "lab anchor: TWOD_HSM_LAB_ANCHOR_SEAL_ROOT_FILE is required (no default)",
    )?;
    let blob_path = require_path(
        TWOD_HSM_LAB_ANCHOR_KEYSTORE_FILE,
        "lab anchor: TWOD_HSM_LAB_ANCHOR_KEYSTORE_FILE is required (no default)",
    )?;
    let root_bytes = crate::boot_input::read_boot_file_capped(
        &root_path,
        32,
        "lab anchor: cannot read the seal-root file",
    )?;
    let root: [u8; 32] = root_bytes.as_slice().try_into().map_err(|_| {
        crate::ProtocolError::PqSigningUnavailable("lab anchor: seal root must be exactly 32 bytes")
    })?;
    let blob = crate::boot_input::read_boot_file_capped(
        &blob_path,
        crate::agent_keystore::MAX_KEYSTORE_BLOB_SIZE,
        "lab anchor: cannot read the sealed keystore file",
    )?;
    let body = crate::agent_keystore::unseal_body(
        &blob,
        &root,
        AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
    )
    .map_err(|e| {
        stub_log(format_args!("keystore unseal failed: {e:?}"));
        crate::ProtocolError::PqSigningUnavailable(
            "lab anchor: sealed keystore unseal failed (see prior log line)",
        )
    })?;
    lab_anchor_root_matches(&body)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&LAB_ANCHOR_TEST_SEED);
    let listener = std::net::TcpListener::bind(&listen).map_err(|e| {
        stub_log(format_args!("bind {listen} failed: {e}"));
        crate::ProtocolError::PqSigningUnavailable("lab anchor: TCP bind failed (see prior log line)")
    })?;
    stub_log(format_args!("listening on {listen}"));
    // slice 6-5: ONE durable commit ledger across all connections — the anchor's idempotency/conflict
    // state must survive per-connection lifetimes (a retry arrives on a fresh connection).
    let mut commit_ledger = LabCommitLedger::new();
    for accepted in listener.incoming() {
        let mut conn = match accepted {
            Ok(conn) => conn,
            Err(e) => {
                stub_log(format_args!("fault (accept: {})", e.kind()));
                std::thread::sleep(ACCEPT_ERROR_BACKOFF);
                continue;
            }
        };
        // SO_*TIMEO arming so the pump deadline is actually enforceable against a stalled peer
        // (the read_framed/deadline_guarded helpers re-check between syscalls, not inside one).
        if conn.set_read_timeout(Some(STUB_PUMP_BUDGET)).is_err()
            || conn.set_write_timeout(Some(STUB_PUMP_BUDGET)).is_err()
        {
            stub_log(format_args!("fault (stream setup failed)"));
            continue;
        }
        let deadline = std::time::Instant::now() + STUB_PUMP_BUDGET;
        match lab_anchor_pump_one(&mut conn, &body, &signing_key, deadline, &mut commit_ledger) {
            Ok(nonce8) => {
                let mut hex8 = String::with_capacity(16);
                for b in nonce8 {
                    hex8.push_str(&format!("{b:02x}"));
                }
                stub_log(format_args!("signed response (nonce8={hex8})"));
            }
            Err(e) => stub_log(format_args!("fault ({e})")),
        }
    }
    unreachable!("TcpListener::incoming() never terminates")
}

// ---------------------------------------------------------------------------------------------
// Host-side 0x40 smoke client core — generic over the stream (the bin supplies a vsock connector;
// the deviceless cross-validation drives it over UnixStream pairs against the REAL shipped serve
// glue). Expectations derive from `smoke_body()` IN-CRATE: zero env plumbing, zero sidecar parsing,
// no drift surface between the fixture and what the client asserts.
// ---------------------------------------------------------------------------------------------

/// Idle-expiry acceptance floor: `SESSION_IDLE_TIMEOUT` − 2 s slop. NEVER an exact floor — the
/// (d-ii) run-1 lesson (a poll(2) whole-millisecond truncation produced a legitimate 399 ms lapse
/// against an exact 400 ms floor).
pub(crate) const IDLE_EXPIRY_FLOOR_MS: u128 = 298_000;
/// Idle-expiry acceptance ceiling: `SESSION_IDLE_TIMEOUT` + the per-stream 30 s `SO_RCVTIMEO` read
/// arm + 10 s load slop. The +30 s term is STRUCTURAL, not generosity: the serve pump re-checks the
/// idle deadline only when the blocking read wakes, so the close lands at the first 30 s tick ≥ the
/// deadline. CRITICAL: `SESSION_IDLE_TIMEOUT` (300 s) is an EXACT multiple of the 30 s read arm, so
/// the deadline falls on a read BOUNDARY — the close is bimodal between ~300 s (the 10th read's
/// post-check sees ≥ deadline) and ~330 s (a sub-second-early `SO_RCVTIMEO` return makes the 10th
/// post-check see < deadline, forcing an 11th full tick). Recorded aya runs hit the ~300 s mode
/// (≈301.8 s), but the ~330 s mode is one early read-return away, so the ceiling MUST clear 330 s
/// with real headroom for the final tick's jitter under load — 10 s, not the original 2 s (which
/// left a load-jitter false-RED at the 330 s mode). Pinned by `idle_expiry_window_bounds_are_sane`.
pub(crate) const IDLE_EXPIRY_CEILING_MS: u128 = 340_000;
/// The read timeout the CONNECTOR must arm on idle-phase streams: strictly above the window
/// ceiling, so the EOF measurement can never be cut short by a socket timeout misread as a close.
pub const SMOKE_CLIENT_IDLE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(360);

/// Per-round-trip reply deadline for the non-idle phases (server replies immediately; generous).
const SMOKE_REPLY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Build the strict-canonical 0x40 inner envelope `{1: version, 2: opcode, 3: domain,
/// 4: request_id, 6?: key_ref}` with the SAME canonical encoders the dispatch decoder requires
/// (shortest-form ints, ascending keys) — `strict_decode_map` rejects anything else.
fn smoke_envelope(opcode: u8, request_id: &[u8], key_ref: Option<&[u8; 32]>) -> Vec<u8> {
    use crate::agent_capability::{put_bytes, put_text, put_uint};
    let mut p = Vec::with_capacity(96);
    put_uint(&mut p, 5, if key_ref.is_some() { 5 } else { 4 });
    put_uint(&mut p, 0, 1);
    put_uint(&mut p, 0, u64::from(crate::agent_identity::AGENT_GATEWAY_VERSION));
    put_uint(&mut p, 0, 2);
    put_uint(&mut p, 0, u64::from(opcode));
    put_uint(&mut p, 0, 3);
    put_text(&mut p, crate::agent_dispatch::COMMAND_DOMAIN);
    put_uint(&mut p, 0, 4);
    put_bytes(&mut p, request_id);
    if let Some(kr) = key_ref {
        put_uint(&mut p, 0, 6);
        put_bytes(&mut p, kr);
    }
    p
}

/// One framed 0x40 round-trip: write the request frame, read + decode the reply frame, require the
/// 0x40 type, return the decoded CBOR body map.
fn smoke_round_trip<S: std::io::Read + std::io::Write>(
    conn: &mut S,
    envelope: &[u8],
) -> Result<Vec<(ciborium::value::Value, ciborium::value::Value)>, String> {
    let frame = crate::encode_message(crate::MessageType::AgentGateway, envelope)
        .map_err(|e| format!("encode: {e}"))?;
    conn.write_all(&frame).and_then(|()| conn.flush()).map_err(|e| format!("write: {e}"))?;
    let deadline = std::time::Instant::now() + SMOKE_REPLY_DEADLINE;
    let reply = crate::read_framed_message_with_idle_deadline(conn, Some(deadline))
        .map_err(|e| format!("read reply: {e}"))?;
    let decoded = crate::decode_message(&reply).map_err(|e| format!("decode reply: {e}"))?;
    if decoded.msg_type != crate::MessageType::AgentGateway {
        return Err(format!("reply type {:?} is not AgentGateway", decoded.msg_type));
    }
    let mut cursor = std::io::Cursor::new(decoded.payload.as_slice());
    let value: ciborium::value::Value =
        ciborium::de::from_reader(&mut cursor).map_err(|e| format!("reply body CBOR: {e}"))?;
    match value {
        ciborium::value::Value::Map(m) => Ok(m),
        _ => Err("reply body is not a CBOR map".to_string()),
    }
}

fn map_bytes(m: &[(ciborium::value::Value, ciborium::value::Value)], key: u64) -> Option<&[u8]> {
    use crate::agent_cbor::{as_bytes, map_get};
    map_get(m, key).and_then(as_bytes)
}

fn map_u64(m: &[(ciborium::value::Value, ciborium::value::Value)], key: u64) -> Option<u64> {
    use crate::agent_cbor::{as_u64, map_get};
    map_get(m, key).and_then(as_u64)
}

/// The expected PUBLIC_IDENTITY success body, asserted byte-exact against `smoke_body()`'s minted
/// entry (request key 6 = [`SMOKE_KEY_REF`]; reply keys per §10.4).
fn assert_public_identity_success(
    m: &[(ciborium::value::Value, ciborium::value::Value)],
) -> Result<(), String> {
    use crate::agent_cbor::map_get;
    use ciborium::value::Value;
    let keypair = crate::secp256k1::Keypair::from_secret_bytes(&SMOKE_SECRET_SCALAR)
        .expect("SMOKE_SECRET_SCALAR is valid");
    if map_bytes(m, 1) != Some(keypair.public_key_uncompressed().as_slice()) {
        return Err("key 1 (pubkey) mismatch".into());
    }
    if map_bytes(m, 2) != Some(keypair.eth_address().as_slice()) {
        return Err("key 2 (eth address) mismatch".into());
    }
    match map_get(m, 3) {
        Some(Value::Text(t)) if *t == keypair.tron_address() => {}
        _ => return Err("key 3 (tron address) mismatch".into()),
    }
    if map_bytes(m, 4) != Some(SMOKE_KEY_REF.as_slice()) {
        return Err("key 4 (key_ref echo) mismatch".into());
    }
    // AgentTransferK1 purpose code = 1; backend_version = the agent protocol version (1).
    if map_u64(m, 5) != Some(1) {
        return Err("key 5 (purpose code) mismatch".into());
    }
    if map_u64(m, 6) != Some(u64::from(crate::agent_identity::AGENT_GATEWAY_VERSION)) {
        return Err("key 6 (backend_version) mismatch".into());
    }
    Ok(())
}

/// PUBLIC_IDENTITY opcode (2) — the dispatch enum is the authority; transcribed as a local const so
/// the client core never imports the whole opcode surface.
const OPCODE_PUBLIC_IDENTITY: u8 = 2;
/// The deterministic error for an unknown 32-byte key_ref: `AGENT_KEY_PURPOSE_MISMATCH` (0x42).
const EXPECTED_UNKNOWN_KEYREF_CODE: u64 = 0x42;

/// Drain a connection expecting an EOF close with ZERO bytes received. Returns elapsed-to-EOF.
/// Any received byte, any socket-timeout (`TimedOut`/`WouldBlock` — the connector's read timeout
/// fired before the server closed) or any other IO error is a failure with the cause named.
fn read_expect_silent_eof<S: std::io::Read>(conn: &mut S) -> Result<std::time::Duration, String> {
    let start = std::time::Instant::now();
    let mut buf = [0u8; 256];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => return Ok(start.elapsed()),
            Ok(n) => return Err(format!("expected silent close, received {n} unexpected bytes")),
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Err(format!(
                    "connector read timeout fired before the server closed (after {} ms) — \
                     arm a read timeout above the expected close",
                    start.elapsed().as_millis()
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // A peer RST surfaces as ConnectionReset on some stacks — the connection IS closed and
            // no bytes were delivered; treat as the close observation, not a failure.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return Ok(start.elapsed()),
            Err(e) => return Err(format!("read during close-wait failed: {e}")),
        }
    }
}

/// The 5b-2c-iii host-side smoke client core. `connect` opens a FRESH stream per phase (the serial
/// server closes per-connection; stale-reply isolation); `skip_idle` drops the 300 s wall-clock
/// phase for fast iteration runs and emits the structurally-unmatchable `RESULT PASS-DEV phases=4`
/// token (the official grep accepts ONLY `RESULT PASS phases=5`). Marker grammar mirrors the (d-ii)
/// quote smoke: `twod-hsm-agent-smoke: PHASE <name> PASS|FAIL <detail>` then one terminal RESULT
/// line; first failure stops the run. Returns `true` iff every executed phase passed.
pub fn run_agent_smoke_client<S, C, W>(mut connect: C, skip_idle: bool, sink: &mut W) -> bool
where
    S: std::io::Read + std::io::Write,
    C: FnMut() -> std::io::Result<S>,
    W: std::io::Write,
{
    let mut mark = |args: std::fmt::Arguments<'_>| {
        let _ = writeln!(sink, "twod-hsm-agent-smoke: {args}");
    };
    let mut phases_passed: u32 = 0;
    // Each closure returns Ok(detail) / Err(detail); phase names are the runner's grep anchors.
    macro_rules! phase {
        ($name:expr, $body:expr) => {{
            let outcome: Result<String, String> = (|| $body)();
            match outcome {
                Ok(detail) => {
                    mark(format_args!("PHASE {} PASS {detail}", $name));
                    phases_passed += 1;
                }
                Err(detail) => {
                    mark(format_args!("PHASE {} FAIL {detail}", $name));
                    mark(format_args!("RESULT FAIL phase={}", $name));
                    return false;
                }
            }
        }};
    }

    // C1: the core acceptance — a real 0x40 PUBLIC_IDENTITY success round-trip.
    phase!("public-identity", {
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let m = smoke_round_trip(
            &mut conn,
            &smoke_envelope(OPCODE_PUBLIC_IDENTITY, b"smoke-c1", Some(&SMOKE_KEY_REF)),
        )?;
        assert_public_identity_success(&m)?;
        Ok("pubkey/eth/tron/key_ref/purpose/backend all byte-exact".to_string())
    });

    // C2: the expected-error shape stays live-pinned (deterministic 0x42 for an unknown key_ref).
    phase!("identity-unknown-keyref", {
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let unknown = [0xee_u8; 32];
        let m = smoke_round_trip(
            &mut conn,
            &smoke_envelope(OPCODE_PUBLIC_IDENTITY, b"smoke-c2", Some(&unknown)),
        )?;
        match (map_u64(&m, 1), map_get_text(&m, 2)) {
            (Some(code), Some(reason)) if code == EXPECTED_UNKNOWN_KEYREF_CODE && reason.starts_with("agent: ") => {
                Ok(format!("code=0x{code:02x}"))
            }
            (code, reason) => Err(format!(
                "expected {{1: 0x42, 2: \"agent: …\"}}, got code={code:?} reason={reason:?}"
            )),
        }
    });

    // C3: the 0x40-only listener closes a non-0x40 frame SILENTLY (zero reply bytes).
    phase!("non-agent-close", {
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let probe = crate::encode_message(crate::MessageType::GetMeasurement, &[])
            .map_err(|e| format!("encode probe: {e}"))?;
        conn.write_all(&probe).and_then(|()| conn.flush()).map_err(|e| format!("write: {e}"))?;
        let elapsed = read_expect_silent_eof(&mut conn)?;
        Ok(format!("silent close after {} ms, zero bytes", elapsed.as_millis()))
    });

    // C4: the real 300 s wall-clock idle expiry (the checklisted acceptance item deviceless tests
    // cannot drive). One SUCCESS frame arms the idle budget; then silence until the server closes.
    if skip_idle {
        mark(format_args!(
            "PHASE idle-expiry SKIPPED dev-iteration run (TWOD_HSM_AGENT_SMOKE_SKIP_IDLE)"
        ));
    } else {
        phase!("idle-expiry", {
            let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
            let m = smoke_round_trip(
                &mut conn,
                &smoke_envelope(OPCODE_PUBLIC_IDENTITY, b"smoke-c4", Some(&SMOKE_KEY_REF)),
            )?;
            assert_public_identity_success(&m)?;
            // Clock starts AFTER the success reply is fully read (that reply reset the idle budget).
            let elapsed = read_expect_silent_eof(&mut conn)?;
            let ms = elapsed.as_millis();
            if (IDLE_EXPIRY_FLOOR_MS..IDLE_EXPIRY_CEILING_MS).contains(&ms) {
                Ok(format!("elapsed_ms={ms}"))
            } else {
                Err(format!(
                    "elapsed_ms={ms} outside [{IDLE_EXPIRY_FLOOR_MS},{IDLE_EXPIRY_CEILING_MS})"
                ))
            }
        });
    }

    // C5: the SERIAL loop serves the next client after the idle close (post-expiry liveness).
    phase!("post-expiry-liveness", {
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let m = smoke_round_trip(
            &mut conn,
            &smoke_envelope(OPCODE_PUBLIC_IDENTITY, b"smoke-c5", Some(&SMOKE_KEY_REF)),
        )?;
        assert_public_identity_success(&m)?;
        Ok("second success round-trip on a fresh connection".to_string())
    });

    if skip_idle {
        // Structurally unmatchable by the official `RESULT PASS phases=5([^0-9]|$)` grep: a dev
        // iteration run can never masquerade as the checklisted full-window PASS.
        mark(format_args!("RESULT PASS-DEV phases={phases_passed}"));
    } else {
        mark(format_args!("RESULT PASS phases={phases_passed}"));
    }
    true
}

fn map_get_text(
    m: &[(ciborium::value::Value, ciborium::value::Value)],
    key: u64,
) -> Option<&str> {
    match crate::agent_cbor::map_get(m, key) {
        Some(ciborium::value::Value::Text(t)) => Some(t.as_str()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// slice 6-7b WRITE-PATH smoke (GENERATE_KEYS). Gated on `agent-keygen-exec-preview` — the ONLY build
// where the enclave actually executes GENERATE_KEYS (`seal → 0x45 commit → ack-verify → swap → emit`);
// without it the dispatch routes GENERATE_KEYS to NotConfigured. The client mints a VALID admin
// capability against the smoke keystore's KNOWN admin seed ([`SMOKE_ADMIN_SEED`]) and asserts the
// success reply carries the minted key list AND a resealed keystore blob that UNSEALS to a body whose
// entries + structural_version + freshness_epoch all advanced — which can only hold if the full
// seal-before-emit sequence completed end-to-end against the (anchor_root-signed) commit ACK.
// ---------------------------------------------------------------------------------------------

/// GENERATE_KEYS opcode (1) — the dispatch enum is the authority; transcribed locally.
#[cfg(feature = "agent-keygen-exec-preview")]
const OPCODE_GENERATE_KEYS: u8 = 1;
/// AgentTransferK1 purpose code (1) — the smoke mints transfer keys (the seeded entry's purpose).
#[cfg(feature = "agent-keygen-exec-preview")]
const SMOKE_KEYGEN_PURPOSE: u64 = 1;
/// `AGENT_CAPABILITY_REJECTED` (0x43) — the deterministic code for a cap that fails verification.
#[cfg(feature = "agent-keygen-exec-preview")]
const EXPECTED_CAP_REJECTED_CODE: u64 = 0x43;
/// The scope_target the write-path smoke commits its GENERATE_KEYS batch under (the per-authority
/// contiguous-counter key); a single in-repo constant for the cap's scope binding.
#[cfg(feature = "agent-keygen-exec-preview")]
const SMOKE_KEYGEN_SCOPE_TARGET: &[u8] = b"smoke-generate-transfer";

/// Build a strict-canonical 0x40 GENERATE_KEYS request envelope for the smoke scope, signing the
/// capability with `signer` (the W1 success path passes the [`SMOKE_ADMIN_SEED`] key whose verifying
/// key IS the sealed `admin_authority_pk`; the negative phase passes a WRONG key so the Ed25519 verify
/// fails → 0x43 with no commit). The cap binds `{opcode, scope, counter, request_id, payload}` and the
/// payload `{1: purpose, 2: count}` is built from the SAME `generate_keys_canonical_params` the handler
/// re-derives, so a binding mismatch is unrepresentable. Mirrors the dispatch test envelope shape
/// (keys 1,2,3,4,5,7 ascending) — already proven decoder-accepted by the wired GenerateKeys tests.
#[cfg(feature = "agent-keygen-exec-preview")]
fn smoke_generate_keys_envelope(
    request_id: &[u8],
    counter: u64,
    count: u64,
    signer: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    use ciborium::value::Value;
    let pb = crate::agent_capability::payload_binding(
        OPCODE_GENERATE_KEYS,
        None,
        request_id,
        &crate::agent_dispatch::generate_keys_canonical_params(SMOKE_KEYGEN_PURPOSE, count),
    );
    let cap = crate::agent_capability::test_signed_capability(
        signer,
        OPCODE_GENERATE_KEYS,
        request_id,
        counter,
        false, // not a recovery cap
        SMOKE_CHAIN_ID,
        SMOKE_ENVIRONMENT,
        0, // scope_class
        SMOKE_KEYGEN_SCOPE_TARGET,
        SMOKE_KEYGEN_PURPOSE as u8,
        pb,
    );
    let payload = vec![
        (Value::Integer(1.into()), Value::Integer(SMOKE_KEYGEN_PURPOSE.into())),
        (Value::Integer(2.into()), Value::Integer(count.into())),
    ];
    let m = vec![
        (
            Value::Integer(1.into()),
            Value::Integer(u64::from(crate::agent_identity::AGENT_GATEWAY_VERSION).into()),
        ),
        (Value::Integer(2.into()), Value::Integer(u64::from(OPCODE_GENERATE_KEYS).into())),
        (Value::Integer(3.into()), Value::Text(crate::agent_dispatch::COMMAND_DOMAIN.to_string())),
        (Value::Integer(4.into()), Value::Bytes(request_id.to_vec())),
        (Value::Integer(5.into()), Value::Map(cap)),
        (Value::Integer(7.into()), Value::Map(payload)),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(m), &mut buf).expect("keygen envelope encodes");
    buf
}

/// Assert a GENERATE_KEYS SUCCESS reply `{1: [key…], 2: sealed_blob}` (§10.4): `count` minted transfer
/// keys, AND the resealed blob UNSEALS (under the smoke root + placeholder measurement) to a body whose
/// `entries` grew by `count` and whose `structural_version`/`freshness_epoch` each advanced +1 — the
/// observable end-to-end witness that seal→commit→ack-verify→swap→emit completed (a fail-closed op would
/// have returned a `{1: code, 2: reason}` error map, never this).
#[cfg(feature = "agent-keygen-exec-preview")]
fn assert_generate_keys_success(
    m: &[(ciborium::value::Value, ciborium::value::Value)],
    count: usize,
) -> Result<(), String> {
    use crate::agent_cbor::map_get;
    use ciborium::value::Value;
    let list = match map_get(m, 1) {
        Some(Value::Array(a)) => a,
        other => return Err(format!("key 1 (key list) is not an array: {other:?}")),
    };
    if list.len() != count {
        return Err(format!("expected {count} minted keys, got {}", list.len()));
    }
    let mut minted_refs: Vec<Vec<u8>> = Vec::with_capacity(count);
    for (i, entry) in list.iter().enumerate() {
        let em = match entry {
            Value::Map(em) => em.as_slice(),
            _ => return Err(format!("minted key {i} is not a CBOR map")),
        };
        match map_get(em, 1) {
            Some(Value::Bytes(b)) if b.len() == 32 => minted_refs.push(b.clone()),
            _ => return Err(format!("minted key {i}: key_ref (entry key 1) is not 32 bytes")),
        }
        match map_get(em, 2) {
            Some(Value::Bytes(b)) if b.len() == 65 && b.first() == Some(&0x04) => {}
            _ => return Err(format!("minted key {i}: pubkey (entry key 2) is not 65B uncompressed")),
        }
        let purpose = map_get(em, 5).and_then(crate::agent_cbor::as_u64);
        if purpose != Some(SMOKE_KEYGEN_PURPOSE) {
            return Err(format!("minted key {i}: purpose (entry key 5) != transfer (got {purpose:?})"));
        }
    }
    // The minted key_refs must be mutually DISTINCT and distinct from the seeded SMOKE_KEY_REF — else a
    // regression that minted colliding refs (or re-emitted the seeded one) would slip past the count check.
    let mut uniq = minted_refs.clone();
    uniq.sort();
    uniq.dedup();
    if uniq.len() != minted_refs.len() {
        return Err("minted key_refs are not mutually distinct".to_string());
    }
    if minted_refs.iter().any(|r| r.as_slice() == SMOKE_KEY_REF.as_slice()) {
        return Err("a minted key_ref collides with the seeded SMOKE_KEY_REF".to_string());
    }
    let blob = match map_get(m, 2) {
        Some(Value::Bytes(b)) => b.as_slice(),
        _ => return Err("key 2 (resealed keystore blob) missing or not bytes".into()),
    };
    let resealed = crate::agent_keystore::unseal_body(
        blob,
        SMOKE_SEAL_ROOT,
        AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
    )
    .map_err(|e| format!("returned blob does NOT unseal under the smoke root/measurement: {e:?}"))?;
    let base = smoke_body();
    if resealed.entries.len() != base.entries.len() + count {
        return Err(format!(
            "resealed entries {} != base {} + minted {count}",
            resealed.entries.len(),
            base.entries.len()
        ));
    }
    // The pre-existing seeded entry MUST survive the swap (the op APPENDS; a regression that clobbered or
    // dropped it while minting an extra key would still hit the count above — pin it explicitly).
    if !resealed.entries.iter().any(|e| e.key_ref == SMOKE_KEY_REF) {
        return Err("the seeded SMOKE_KEY_REF entry did not survive the GENERATE_KEYS swap".to_string());
    }
    // 6-4: GENERATE_KEYS is a Structural op ⇒ the ATOMIC per-op bump advances structural_version AND
    // freshness_epoch together by exactly +1, regardless of `count`.
    if resealed.structural_version != base.structural_version + 1 {
        return Err(format!(
            "structural_version {} != base {} + 1",
            resealed.structural_version, base.structural_version
        ));
    }
    if resealed.freshness_epoch != base.freshness_epoch + 1 {
        return Err(format!(
            "freshness_epoch {} != base {} + 1",
            resealed.freshness_epoch, base.freshness_epoch
        ));
    }
    Ok(())
}

/// The slice-6-7b WRITE-PATH smoke client core (mirrors [`run_agent_smoke_client`]'s marker grammar,
/// but for the GENERATE_KEYS seal→commit→swap→emit path; targets the `agent-keygen-exec-preview`
/// image). `connect` opens a FRESH stream per phase. Emits
/// `twod-hsm-agent-keygen-smoke: PHASE <name> PASS|FAIL <detail>` then a terminal
/// `RESULT PASS phases=N`; first failure stops the run. Returns `true` iff every phase passed.
#[cfg(feature = "agent-keygen-exec-preview")]
pub fn run_agent_keygen_smoke_client<S, C, W>(mut connect: C, sink: &mut W) -> bool
where
    S: std::io::Read + std::io::Write,
    C: FnMut() -> std::io::Result<S>,
    W: std::io::Write,
{
    let mut mark = |args: std::fmt::Arguments<'_>| {
        let _ = writeln!(sink, "twod-hsm-agent-keygen-smoke: {args}");
    };
    let mut phases_passed: u32 = 0;
    macro_rules! phase {
        ($name:expr, $body:expr) => {{
            let outcome: Result<String, String> = (|| $body)();
            match outcome {
                Ok(detail) => {
                    mark(format_args!("PHASE {} PASS {detail}", $name));
                    phases_passed += 1;
                }
                Err(detail) => {
                    mark(format_args!("PHASE {} FAIL {detail}", $name));
                    mark(format_args!("RESULT FAIL phase={}", $name));
                    return false;
                }
            }
        }};
    }

    // Each phase uses a DISTINCT envelope request_id (`keygen-smoke-w1` / `-w2`): per-op uniqueness is
    // the 6-5 anchor-idempotency contract (a REUSED id would conflate the op — the anchor would idempotently
    // re-sign for the recorded state instead of recording a fresh advance), and only W1 commits.

    // W1: the core acceptance — a REAL signed GENERATE_KEYS (count=2) executes the full
    // seal→commit→ack-verify→swap→emit path and returns the minted keys + the resealed blob.
    phase!("generate-keys", {
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let admin = ed25519_dalek::SigningKey::from_bytes(&SMOKE_ADMIN_SEED);
        let env = smoke_generate_keys_envelope(b"keygen-smoke-w1", 1, 2, &admin);
        let m = smoke_round_trip(&mut conn, &env)?;
        assert_generate_keys_success(&m, 2)?;
        Ok("2 transfer keys minted; resealed blob unseals with entries+2, structural+1, epoch+1 \
            (one Structural op; seal→commit→ack→swap→emit held)"
            .to_string())
    });

    // W2: the auth gate stays live-pinned — a cap signed by the WRONG key is rejected 0x43 BEFORE any
    // seal/commit (fail-closed), so a forged authority can never reach the anchor. counter=2 is
    // LOAD-BEARING for non-vacuity: W1 consumed counter 1 on this scope, so 2 is the NEXT-CONTIGUOUS the
    // counter check would ACCEPT. Thus the ONLY thing that can reject this cap is the signature check —
    // a regression that bypassed or reordered verify_capability's Ed25519 verify ahead of the counter
    // check would let this cap EXECUTE (return a success body), failing this phase. (A stale counter=1
    // would have rejected 0x43 via the contiguity check even with the signature gate broken, hiding it.)
    phase!("generate-keys-bad-cap", {
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let wrong = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32]);
        let env = smoke_generate_keys_envelope(b"keygen-smoke-w2", 2, 1, &wrong);
        let m = smoke_round_trip(&mut conn, &env)?;
        match (map_u64(&m, 1), map_get_text(&m, 2)) {
            (Some(code), Some(reason))
                if code == EXPECTED_CAP_REJECTED_CODE && reason.starts_with("agent: ") =>
            {
                Ok(format!("code=0x{code:02x}"))
            }
            (code, reason) => Err(format!(
                "expected {{1: 0x43, 2: \"agent: …\"}}, got code={code:?} reason={reason:?}"
            )),
        }
    });

    mark(format_args!("RESULT PASS phases={phases_passed}"));
    true
}

// ---------------------------------------------------------------------------------------------
// TASK-15 combined FAUCET write-path smoke (15-3c / 15-6): the end-to-end fund-custody flow that only
// became reachable once SIGN_FAUCET_DISPENSE (15-3b) AND CONFIGURE_TREASURY (15-4) both landed. Needs
// ALL THREE preview gates: keygen-exec (mint the treasury key), configure-treasury (set caps + a
// budget), sign-faucet (the dispense). The runtime mint+configure means NO throwaway fixture — the
// production flow exactly. Recipient = the SEEDED transfer key (SMOKE_KEY_REF, derived from
// SMOKE_SECRET_SCALAR), already in `smoke_body()`; only the treasury key is minted at runtime.
// ---------------------------------------------------------------------------------------------

/// CONFIGURE_TREASURY(6) / SIGN_FAUCET_DISPENSE(5) opcodes — the dispatch enum is the authority.
#[cfg(all(
    feature = "agent-keygen-exec-preview",
    feature = "agent-configure-treasury-preview",
    feature = "agent-sign-faucet-preview"
))]
mod faucet {
    use super::*;
    use ciborium::value::Value;
    use ed25519_dalek::SigningKey;

    pub(super) const OPCODE_CONFIGURE_TREASURY: u8 = 6;
    pub(super) const OPCODE_SIGN_FAUCET_DISPENSE: u8 = 5;
    pub(super) const FAUCET_TREASURY_PURPOSE: u64 = 2; // AgentFaucetTreasuryK1
    /// Per-`command_class` counter lanes (each `scope_target` is its own contiguous counter; see the
    /// host-integration contract §AC#18). The treasury keygen, the transfer recipient already seeded,
    /// and the two CONFIGURE sub-ops each sit in their own lane — so every cap below uses counter 1
    /// EXCEPT refill_budget (counter 2, same lane as set_limits).
    pub(super) const GENFAUCET_SCOPE_TARGET: &[u8] = b"smoke-generate-faucet";
    pub(super) const CONFIGURE_SCOPE_TARGET: &[u8] = b"smoke-configure-treasury";
    // Caps set by set_limits (≥ the dispense values) + the refilled budget (≫ one worst-case).
    pub(super) const PER_DISPENSE_MAX: u64 = 1_000_000;
    pub(super) const MAX_GAS_LIMIT: u64 = 21_000;
    pub(super) const MAX_FEE_RATE: u64 = 1_000_000_000;
    pub(super) const BUDGET: u64 = 10_000_000;
    // The dispense (within the caps): worst_case = amount + gas_limit*gas_price = 1000 + 21000*100.
    pub(super) const DISPENSE_AMOUNT: u64 = 1_000;
    pub(super) const DISPENSE_GAS_LIMIT: u64 = 21_000;
    pub(super) const DISPENSE_GAS_PRICE: u64 = 100;
    pub(super) fn worst_case() -> u64 {
        DISPENSE_AMOUNT + DISPENSE_GAS_LIMIT * DISPENSE_GAS_PRICE
    }
    /// Minimal big-endian bytes of a u64 (the canonical u256 wire form for u64-fitting values).
    pub(super) fn min_be(x: u64) -> Vec<u8> {
        let b = x.to_be_bytes();
        let i = b.iter().position(|&y| y != 0).unwrap_or(b.len());
        b[i..].to_vec()
    }
    fn u256_be(x: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&x.to_be_bytes());
        out
    }

    /// Inner-envelope map with version/opcode/domain/request_id + optional key_ref(6) + cap(5) + payload(7).
    fn envelope(
        opcode: u8,
        request_id: &[u8],
        key_ref: Option<&[u8; 32]>,
        cap: Option<Vec<(Value, Value)>>,
        payload: Vec<(Value, Value)>,
    ) -> Vec<u8> {
        let mut m = vec![
            (
                Value::Integer(1.into()),
                Value::Integer(u64::from(crate::agent_identity::AGENT_GATEWAY_VERSION).into()),
            ),
            (Value::Integer(2.into()), Value::Integer(u64::from(opcode).into())),
            (Value::Integer(3.into()), Value::Text(crate::agent_dispatch::COMMAND_DOMAIN.to_string())),
            (Value::Integer(4.into()), Value::Bytes(request_id.to_vec())),
        ];
        if let Some(c) = cap {
            m.push((Value::Integer(5.into()), Value::Map(c)));
        }
        if let Some(kr) = key_ref {
            m.push((Value::Integer(6.into()), Value::Bytes(kr.to_vec())));
        }
        m.push((Value::Integer(7.into()), Value::Map(payload)));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(m), &mut buf).expect("faucet smoke envelope encodes");
        buf
    }

    /// GENERATE_KEYS(purpose=2 treasury, count=1) for the faucet smoke (its own counter lane).
    pub(super) fn treasury_keygen_envelope(request_id: &[u8], counter: u64, signer: &SigningKey) -> Vec<u8> {
        let pb = crate::agent_capability::payload_binding(
            OPCODE_GENERATE_KEYS,
            None,
            request_id,
            &crate::agent_dispatch::generate_keys_canonical_params(FAUCET_TREASURY_PURPOSE, 1),
        );
        let cap = crate::agent_capability::test_signed_capability(
            signer, OPCODE_GENERATE_KEYS, request_id, counter, false, SMOKE_CHAIN_ID, SMOKE_ENVIRONMENT,
            0, GENFAUCET_SCOPE_TARGET, FAUCET_TREASURY_PURPOSE as u8, pb,
        );
        envelope(
            OPCODE_GENERATE_KEYS,
            request_id,
            None,
            Some(cap),
            vec![
                (Value::Integer(1.into()), Value::Integer(FAUCET_TREASURY_PURPOSE.into())),
                (Value::Integer(2.into()), Value::Integer(1.into())),
            ],
        )
    }

    /// CONFIGURE_TREASURY(sub_op) — admin cap on the configure lane. set_limits carries keys 3,4.
    pub(super) fn configure_envelope(
        request_id: &[u8],
        counter: u64,
        sub_op: u8,
        field2_min: &[u8],
        set_limits_gas: Option<(u64, u64)>,
        signer: &SigningKey,
    ) -> Vec<u8> {
        let cp = crate::agent_dispatch::configure_treasury_canonical_params(sub_op, field2_min, set_limits_gas);
        let pb = crate::agent_capability::payload_binding(OPCODE_CONFIGURE_TREASURY, Some(sub_op), request_id, &cp);
        let cap = crate::agent_capability::test_signed_capability_with_sub_op(
            signer, OPCODE_CONFIGURE_TREASURY, Some(sub_op), request_id, counter, false, SMOKE_CHAIN_ID,
            SMOKE_ENVIRONMENT, 0, CONFIGURE_SCOPE_TARGET, 2, pb,
        );
        let mut payload = vec![
            (Value::Integer(1.into()), Value::Integer(u64::from(sub_op).into())),
            (Value::Integer(2.into()), Value::Bytes(field2_min.to_vec())),
        ];
        if let Some((gl, fr)) = set_limits_gas {
            payload.push((Value::Integer(3.into()), Value::Integer(gl.into())));
            payload.push((Value::Integer(4.into()), Value::Integer(fr.into())));
        }
        envelope(OPCODE_CONFIGURE_TREASURY, request_id, None, Some(cap), payload)
    }

    /// SIGN_FAUCET_DISPENSE — NO cap (runtime op); the strict 8-field EIP-155 payload + key_ref(6).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn dispense_envelope(
        request_id: &[u8],
        treasury_key_ref: &[u8; 32],
        from: &[u8; 20],
        to: &[u8; 20],
        amount_min: &[u8],
        gas_price_min: &[u8],
    ) -> Vec<u8> {
        envelope(
            OPCODE_SIGN_FAUCET_DISPENSE,
            request_id,
            Some(treasury_key_ref),
            None,
            vec![
                (Value::Integer(1.into()), Value::Integer(SMOKE_CHAIN_ID.into())),
                (Value::Integer(2.into()), Value::Bytes(from.to_vec())),
                (Value::Integer(3.into()), Value::Bytes(to.to_vec())),
                (Value::Integer(4.into()), Value::Bytes(amount_min.to_vec())),
                (Value::Integer(5.into()), Value::Integer(0.into())), // nonce
                (Value::Integer(6.into()), Value::Integer(DISPENSE_GAS_LIMIT.into())),
                (Value::Integer(7.into()), Value::Bytes(gas_price_min.to_vec())),
                (Value::Integer(8.into()), Value::Bytes(vec![])), // data MUST be empty
            ],
        )
    }

    /// Extract the single minted treasury key's `(key_ref, eth_address)` from a GENERATE_KEYS success
    /// reply `{1: [{1: key_ref, 2: pubkey, 3: eth_address, …}], 2: blob}`, asserting purpose==2.
    pub(super) fn extract_minted_treasury(
        m: &[(Value, Value)],
    ) -> Result<([u8; 32], [u8; 20]), String> {
        use crate::agent_cbor::map_get;
        let list = match map_get(m, 1) {
            Some(Value::Array(a)) if a.len() == 1 => a,
            other => return Err(format!("treasury keygen: key 1 is not a 1-element array: {other:?}")),
        };
        let km = match &list[0] {
            Value::Map(km) => km.as_slice(),
            _ => return Err("treasury keygen: minted key is not a map".into()),
        };
        if map_get(km, 5).and_then(crate::agent_cbor::as_u64) != Some(FAUCET_TREASURY_PURPOSE) {
            return Err("treasury keygen: minted purpose != faucet treasury".into());
        }
        let key_ref: [u8; 32] = match map_get(km, 1) {
            Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| "key_ref not 32B".to_string())?,
            _ => return Err("treasury keygen: key_ref (entry key 1) missing".into()),
        };
        let eth: [u8; 20] = match map_get(km, 3) {
            Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| "eth not 20B".to_string())?,
            _ => return Err("treasury keygen: eth_address (entry key 3) missing".into()),
        };
        Ok((key_ref, eth))
    }

    /// Assert a SIGN_FAUCET_DISPENSE success reply: `{1: signed_rlp, …, 7: from, 8: sealed_blob}` — the
    /// signed tx is present + recovers `from`==treasury, and the resealed blob UNSEALS to a body whose
    /// faucet `cumulative_native_spend` AND `lifetime_spend` BOTH advanced by exactly `worst_case` (the
    /// dual-counter debit) from zero (refill reset the cumulative window in F3) — the observable witness
    /// the EpochOnly seal→commit→swap→emit completed with the §2 gate's debit.
    pub(super) fn assert_dispense_success(
        m: &[(Value, Value)],
        treasury_from: &[u8; 20],
    ) -> Result<(), String> {
        use crate::agent_cbor::map_get;
        match map_get(m, 1) {
            Some(Value::Bytes(b)) if !b.is_empty() => {}
            other => return Err(format!("dispense: key 1 (signed_rlp) missing/empty: {other:?}")),
        }
        match map_get(m, 7) {
            Some(Value::Bytes(b)) if b.as_slice() == treasury_from.as_slice() => {}
            other => return Err(format!("dispense: key 7 (from) != treasury address: {other:?}")),
        }
        let blob = match map_get(m, 8) {
            Some(Value::Bytes(b)) => b.as_slice(),
            _ => return Err("dispense: key 8 (resealed blob) missing".into()),
        };
        let resealed = crate::agent_keystore::unseal_body(
            blob, SMOKE_SEAL_ROOT, AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
        )
        .map_err(|e| format!("dispense: resealed blob does NOT unseal: {e:?}"))?;
        let wc = u256_be(worst_case());
        if resealed.faucet.cumulative_native_spend != wc {
            return Err(format!(
                "dispense: cumulative_native_spend {:?} != worst_case {:?}",
                resealed.faucet.cumulative_native_spend, wc
            ));
        }
        if resealed.faucet.lifetime_spend != wc {
            return Err(format!(
                "dispense: lifetime_spend {:?} != worst_case {:?} (dual-counter debit)",
                resealed.faucet.lifetime_spend, wc
            ));
        }
        Ok(())
    }

    /// Unseal a CONFIGURE_TREASURY success reply's `{1: sealed_keystore_blob}` so the smoke can
    /// CONTENT-VALIDATE that the sub-op's mutation actually landed in the resealed body — not merely that
    /// "a blob came back" (a blob that failed to apply the config would still be returned on success).
    pub(super) fn unseal_configure_reply(
        m: &[(Value, Value)],
    ) -> Result<crate::agent_keystore::KeystoreBody, String> {
        use crate::agent_cbor::map_get;
        let blob = match map_get(m, 1) {
            Some(Value::Bytes(b)) if !b.is_empty() => b.as_slice(),
            other => return Err(format!("configure: key 1 (sealed blob) missing/empty: {other:?}")),
        };
        crate::agent_keystore::unseal_body(blob, SMOKE_SEAL_ROOT, AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT)
            .map_err(|e| format!("configure: resealed blob does NOT unseal: {e:?}"))
    }

    /// The expected u256 (big-endian `[u8; 32]`) of a u64 — for content-validating sealed faucet caps.
    pub(super) fn u256_of(x: u64) -> [u8; 32] {
        u256_be(x)
    }
}

/// The combined FAUCET write-path smoke client (mirrors [`run_agent_keygen_smoke_client`]). Drives the
/// full mint→set_limits→refill→dispense fund-custody flow + a fail-closed gate phase, each through the
/// real seal→commit→swap→emit seam. Marker prefix `twod-hsm-agent-faucet-smoke:`; terminal
/// `RESULT PASS phases=5`. `connect` opens a FRESH stream per phase. Returns `true` iff all phases pass.
#[cfg(all(
    feature = "agent-keygen-exec-preview",
    feature = "agent-configure-treasury-preview",
    feature = "agent-sign-faucet-preview"
))]
pub fn run_agent_faucet_smoke_client<S, C, W>(mut connect: C, sink: &mut W) -> bool
where
    S: std::io::Read + std::io::Write,
    C: FnMut() -> std::io::Result<S>,
    W: std::io::Write,
{
    use faucet::*;
    let mut mark = |args: std::fmt::Arguments<'_>| {
        let _ = writeln!(sink, "twod-hsm-agent-faucet-smoke: {args}");
    };
    let mut phases_passed: u32 = 0;
    macro_rules! phase {
        ($name:expr, $body:expr) => {{
            let outcome: Result<String, String> = (|| $body)();
            match outcome {
                Ok(detail) => {
                    mark(format_args!("PHASE {} PASS {detail}", $name));
                    phases_passed += 1;
                }
                Err(detail) => {
                    mark(format_args!("PHASE {} FAIL {detail}", $name));
                    mark(format_args!("RESULT FAIL phase={}", $name));
                    return false;
                }
            }
        }};
    }
    let admin = ed25519_dalek::SigningKey::from_bytes(&SMOKE_ADMIN_SEED);
    // The recipient `to` = the SEEDED transfer key's derived eth address (already in smoke_body()).
    let recipient = crate::secp256k1::Keypair::from_secret_bytes(&SMOKE_SECRET_SCALAR)
        .expect("SMOKE_SECRET_SCALAR valid")
        .eth_address();
    // F1 returns the minted treasury key_ref + its derived `from` address; carried into F4.
    let mut treasury: Option<([u8; 32], [u8; 20])> = None;

    // F1: mint the singleton treasury key (Structural commit). Reply carries its key_ref + eth address.
    phase!("mint-treasury", {
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let env = treasury_keygen_envelope(b"faucet-smoke-f1", 1, &admin);
        let m = smoke_round_trip(&mut conn, &env)?;
        let (kr, from) = extract_minted_treasury(&m)?;
        treasury = Some((kr, from));
        Ok("1 faucet treasury key minted (Structural seal→commit→swap)".to_string())
    });

    // F2: set the per-field caps so a real dispense fits (per_dispense_max raised from genesis 0).
    // CONTENT-VALIDATE: unseal the returned blob and assert the limit triple actually landed.
    phase!("configure-set-limits", {
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let env = configure_envelope(
            b"faucet-smoke-f2", 1, 0, &min_be(PER_DISPENSE_MAX), Some((MAX_GAS_LIMIT, MAX_FEE_RATE)), &admin,
        );
        let m = smoke_round_trip(&mut conn, &env)?;
        let b = unseal_configure_reply(&m)?;
        if b.faucet.per_dispense_max_amount != u256_of(PER_DISPENSE_MAX) {
            return Err(format!("set_limits: per_dispense_max not applied ({:?})", b.faucet.per_dispense_max_amount));
        }
        if b.faucet.max_gas_limit != MAX_GAS_LIMIT || b.faucet.max_effective_gas_fee_rate != MAX_FEE_RATE {
            return Err(format!(
                "set_limits: gas caps not applied (gas_limit={}, fee_rate={})",
                b.faucet.max_gas_limit, b.faucet.max_effective_gas_fee_rate
            ));
        }
        Ok("caps applied (resealed blob unseals to the limit triple)".to_string())
    });

    // F3: refill the cumulative signing budget (resets the refillable spend window to 0).
    // CONTENT-VALIDATE: unseal and assert the budget landed AND cumulative_native_spend was reset to 0.
    phase!("configure-refill-budget", {
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let env = configure_envelope(b"faucet-smoke-f3", 2, 1, &min_be(BUDGET), None, &admin);
        let m = smoke_round_trip(&mut conn, &env)?;
        let b = unseal_configure_reply(&m)?;
        if b.faucet.cumulative_signing_budget != u256_of(BUDGET) {
            return Err(format!("refill_budget: budget not applied ({:?})", b.faucet.cumulative_signing_budget));
        }
        if b.faucet.cumulative_native_spend != [0u8; 32] {
            return Err("refill_budget: cumulative_native_spend not reset to 0 (the fresh refill window)".to_string());
        }
        Ok(format!("budget applied (resealed blob unseals to budget={BUDGET}, spend window reset)"))
    });

    // F4: the dispense — treasury → the seeded transfer key, within caps. Asserts the dual-counter debit.
    phase!("dispense", {
        let (kr, from) = treasury.ok_or("dispense: F1 did not record the treasury key")?;
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let env = dispense_envelope(
            b"faucet-smoke-f4", &kr, &from, &recipient, &min_be(DISPENSE_AMOUNT), &min_be(DISPENSE_GAS_PRICE),
        );
        let m = smoke_round_trip(&mut conn, &env)?;
        assert_dispense_success(&m, &from)?;
        Ok(format!("dispensed; both spend counters debited by worst_case={}", worst_case()))
    });

    // F5 (fail-closed gate): a dispense to a STRANGER (not a stored transfer key) → 0x42, proving the
    // recipient allowlist is live (non-vacuity, like the keygen W2 bad-cap phase).
    phase!("dispense-stranger-rejected", {
        let (kr, from) = treasury.ok_or("F1 did not record the treasury key")?;
        let mut conn = connect().map_err(|e| format!("connect: {e}"))?;
        let env = dispense_envelope(
            b"faucet-smoke-f5", &kr, &from, &[0xab; 20], &min_be(DISPENSE_AMOUNT), &min_be(DISPENSE_GAS_PRICE),
        );
        let m = smoke_round_trip(&mut conn, &env)?;
        match (map_u64(&m, 1), map_get_text(&m, 2)) {
            (Some(0x42), Some(reason)) if reason.starts_with("agent: ") => Ok("stranger recipient → 0x42".to_string()),
            (code, reason) => Err(format!("expected {{1:0x42, 2:\"agent: …\"}}, got code={code:?} reason={reason:?}")),
        }
    });

    mark(format_args!("RESULT PASS phases={phases_passed}"));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_keystore::{unseal_body, MAX_KEYSTORE_BLOB_SIZE};
    use sha3::Digest;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn smoke_body_validates_and_round_trips() {
        let body = smoke_body();
        body.validate().expect("smoke body passes structural validation");
        let blob = smoke_sealed_blob();
        assert_eq!(&blob[8..10], &[0x00, 0x03], "format_version 3 in the header");
        assert!(blob.len() <= MAX_KEYSTORE_BLOB_SIZE, "smoke blob is re-installable");
        let unsealed =
            unseal_body(&blob, SMOKE_SEAL_ROOT, AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT)
                .expect("smoke blob unseals");
        assert_eq!(unsealed, body);
    }

    #[test]
    fn smoke_anchor_root_is_derived_from_the_test_seed() {
        // The whole point of the minted fixture: the stub's seed-derived verifying key IS the
        // sealed anchor_root (the genesis fixture fails this by construction — [0xa3; 32]).
        let derived = ed25519_dalek::SigningKey::from_bytes(&LAB_ANCHOR_TEST_SEED)
            .verifying_key()
            .to_bytes();
        assert_eq!(smoke_body().config.anchor_root, derived);
    }

    #[test]
    fn smoke_marks_payload_digest_is_the_documented_75_bytes() {
        // Couples `compute_local_marks_digest`'s input for the EXACT provisioned smoke state
        // (empty counters, zero spend, strict_recovery_counter 0) to the frozen v1 marks grammar:
        // `a4 01 80 02 58 20 [32x00] 03 58 20 [32x00] 04 00` (75 bytes). The lab anchor stub
        // derives its response key-6 from this same digest, so a marks-grammar drift fails HERE,
        // deviceless, never as a mystery FailClosed(Inconsistent) on aya.
        let mut expected_payload = Vec::with_capacity(75);
        expected_payload.extend_from_slice(&[0xa4, 0x01, 0x80, 0x02, 0x58, 0x20]);
        expected_payload.extend_from_slice(&[0u8; 32]);
        expected_payload.extend_from_slice(&[0x03, 0x58, 0x20]);
        expected_payload.extend_from_slice(&[0u8; 32]);
        expected_payload.extend_from_slice(&[0x04, 0x00]);
        assert_eq!(expected_payload.len(), 75);
        let mut h = sha3::Sha3_256::new();
        h.update(crate::agent_keystore::MARKS_DOMAIN);
        h.update(&expected_payload);
        let expected_digest: [u8; 32] = h.finalize().into();
        assert_eq!(smoke_body().compute_local_marks_digest(), expected_digest);
    }

    #[test]
    fn agent_smoke_golden_blob_is_byte_exact() {
        // The in-source mint and the committed bytes must agree byte-for-byte — any deterministic-
        // CBOR / header / KeystoreBody-field drift flips this AND the guest's from-disk unseal.
        let committed: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_keystore_smoke_v1.sealed.bin");
        assert_eq!(
            smoke_sealed_blob().as_slice(),
            committed,
            "smoke golden drifted; if the body layout/format_version changed intentionally, regen \
             via `regen_agent_smoke_golden_vector` (it re-mints the .json sidecar too) in the same \
             commit"
        );
        let body =
            unseal_body(committed, SMOKE_SEAL_ROOT, AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT)
                .expect("committed smoke golden unseals");
        assert_eq!(body, smoke_body());
    }

    #[test]
    fn agent_smoke_golden_sidecar_matches_blob() {
        // Field-coupled (not substring) sidecar check, mirroring the genesis discipline: a regen
        // that updates the blob but forgets the sidecar — or vice versa — fails CI. The regen test
        // mints BOTH files from the same constants, so passing this means they agree.
        use sha2::{Digest as _, Sha256};
        let blob: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_keystore_smoke_v1.sealed.bin");
        let sidecar = include_str!("../testvectors/agent-gateway/agent_keystore_smoke_v1.json");
        let v: serde_json::Value =
            serde_json::from_str(sidecar).expect("smoke sidecar must be valid JSON");
        let body = smoke_body();
        let keypair = crate::secp256k1::Keypair::from_secret_bytes(&SMOKE_SECRET_SCALAR).unwrap();
        assert_eq!(v["warning"].as_str(), Some("TEST KEYS ONLY"), "sidecar warning banner");
        assert_eq!(
            v["blob_sha256"].as_str(),
            Some(hex(&Sha256::digest(blob)).as_str()),
            "sidecar blob_sha256 drift — re-run the regen test (it re-mints both files)"
        );
        assert_eq!(v["blob_len_bytes"].as_u64(), Some(blob.len() as u64), "blob_len_bytes drift");
        assert_eq!(
            v["envelope"]["nonce_hex"].as_str(),
            Some(hex(&SMOKE_SEAL_NONCE).as_str()),
            "nonce_hex drift"
        );
        assert_eq!(
            v["seal_inputs"]["provisioning_root_hex"].as_str(),
            Some(hex(SMOKE_SEAL_ROOT).as_str()),
            "provisioning_root_hex drift"
        );
        assert_eq!(
            v["seal_inputs"]["enclave_measurement_hex"].as_str(),
            Some(hex(AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT).as_str()),
            "enclave_measurement_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["anchor_root_hex"].as_str(),
            Some(hex(&body.config.anchor_root).as_str()),
            "anchor_root_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["admin_seed_hex"].as_str(),
            Some(hex(&SMOKE_ADMIN_SEED).as_str()),
            "admin_seed_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["admin_authority_pk_hex"].as_str(),
            Some(hex(&body.config.admin_authority_pk).as_str()),
            "admin_authority_pk_hex drift — the write-path client signs caps against this key"
        );
        assert_eq!(
            v["smoke_identity"]["key_ref_hex"].as_str(),
            Some(hex(&SMOKE_KEY_REF).as_str()),
            "key_ref_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["public_identity_hex"].as_str(),
            Some(hex(&keypair.public_key_uncompressed()).as_str()),
            "public_identity_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["eth_address_hex"].as_str(),
            Some(hex(&keypair.eth_address()).as_str()),
            "eth_address_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["tron_address"].as_str(),
            Some(keypair.tron_address().as_str()),
            "tron_address drift"
        );
    }

    // ---- lab anchor stub conformance (deviceless; the drift-unrepresentable pins) ----

    /// Drive ONE real stub pump over an in-memory stream pair: write `request_frame` into the
    /// peer end, run [`lab_anchor_pump_one`], return (pump result, every byte the stub wrote back).
    /// Each call gets a FRESH commit ledger (a single commit is always first-seen), so existing
    /// single-pump callers are unchanged; the idempotency test drives multiple pumps through a SHARED
    /// ledger via [`drive_stub_pump_with_ledger`].
    fn drive_stub_pump(
        body: &KeystoreBody,
        request_frame: &[u8],
    ) -> (Result<[u8; 8], crate::ProtocolError>, Vec<u8>) {
        drive_stub_pump_with_ledger(body, request_frame, &mut LabCommitLedger::new())
    }

    /// Like [`drive_stub_pump`] but threads a caller-owned commit ledger, so a SEQUENCE of pumps shares
    /// the anchor's durable per-`request_id` commit state (slice 6-5 idempotency/conflict tests).
    fn drive_stub_pump_with_ledger(
        body: &KeystoreBody,
        request_frame: &[u8],
        ledger: &mut LabCommitLedger,
    ) -> (Result<[u8; 8], crate::ProtocolError>, Vec<u8>) {
        use std::io::{Read as _, Write as _};
        let (mut stub_end, mut peer_end) =
            std::os::unix::net::UnixStream::pair().expect("socketpair");
        for s in [&stub_end, &peer_end] {
            s.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            s.set_write_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        }
        peer_end.write_all(request_frame).and_then(|()| peer_end.flush()).expect("write request");
        let key = ed25519_dalek::SigningKey::from_bytes(&LAB_ANCHOR_TEST_SEED);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let outcome = lab_anchor_pump_one(&mut stub_end, body, &key, deadline, ledger);
        drop(stub_end); // close-on-fault / close-after-response either way → peer sees EOF
        let mut written_back = Vec::new();
        let _ = peer_end.read_to_end(&mut written_back);
        (outcome, written_back)
    }

    #[test]
    fn stub_response_passes_guest_verify_path() {
        // THE conformance pin: the stub's exact wire bytes, read back through the relay-side
        // bounded reader, must verify through the REAL guest path (strict-canonical decode +
        // Ed25519 against the smoke fixture's sealed anchor_root + scope + nonce echo) and land
        // reconcile == Fresh. Makes "the anchor stub can't reach Ready" unrepresentable pre-aya.
        let body = smoke_body();
        let nonce = [0xab_u8; 32];
        let (outcome, written_back) = drive_stub_pump(&body, &smoke_request_frame(nonce));
        outcome.expect("stub pump succeeds on a conformant request");
        let raw = crate::agent_boot_relay::read_bounded_anchor_response(
            &mut std::io::Cursor::new(written_back),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .expect("stub framed the response with the shared 4-byte BE prefix writer");
        assert!(raw.len() <= crate::agent_boot_relay::MAX_ANCHOR_RESPONSE_LEN);
        let state =
            crate::agent_anchor::verify_anchor_response_bytes(&raw, &nonce, &body.config)
                .expect("stub response passes the REAL guest verify path");
        assert_eq!(
            crate::agent_anchor::reconcile(
                body.freshness_epoch,
                body.structural_version,
                &body.compute_local_marks_digest(),
                &state,
            ),
            crate::agent_anchor::ReconcileDecision::Fresh,
            "anchor state derived from the provisioned body must reconcile Fresh"
        );
    }

    #[test]
    fn stub_marks_reply_passes_guest_marks_verify_and_executes_adopt() {
        // 5b-2e D11 conformance: the lab stub's 0x44 marks reply, read back through the marks-cap
        // reader, must pass the REAL guest verify_marks_response_bytes AND drive execute_adopt_forward
        // to a candidate whose digest matches — the whole AdoptForward channel, deviceless, against a
        // real second signer. The provisioned body's marks self-consistently hash to the digest, so a
        // freshness AnchorState carrying that digest at a HIGHER epoch reconciles Fresh after the seed.
        let body = smoke_body();
        let nonce = [0x6e_u8; 32];
        let epoch = body.freshness_epoch + 1; // the anchor is AHEAD by a counter/spend-only gap
        let req = crate::agent_boot_relay::encode_anchor_marks_request(
            &crate::agent_boot_relay::AnchorMarksRequest {
                chain_id: body.config.twod_chain_id,
                environment_identifier: &body.config.environment_identifier,
                nonce,
                epoch,
            },
        )
        .unwrap();
        let (outcome, written_back) = drive_stub_pump(&body, &req);
        outcome.expect("stub answers the 0x44 marks request");
        let raw = crate::agent_boot_relay::read_bounded_response_cap(
            &mut std::io::Cursor::new(written_back),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            crate::agent_boot_relay::MAX_MARKS_RESPONSE_LEN,
        )
        .expect("stub framed the marks response with the shared writer");
        // The guest verifies the marks message (sig/scope/nonce/epoch) and returns the payload.
        let payload = crate::agent_anchor::verify_marks_response_bytes(&raw, &nonce, epoch, &body.config)
            .expect("stub marks reply passes the REAL guest marks-verify path");
        // And the whole execute_adopt_forward gate accepts it (the marks hash the freshness-committed
        // digest at this epoch), producing a candidate that reconciles Fresh.
        let state = crate::agent_anchor::AnchorState {
            epoch,
            structural_version: body.structural_version,
            marks_digest: body.compute_local_marks_digest(),
            chain_height: None,
            chain_block_hash: None,
        };
        // sanity: the returned payload is exactly the body's marks payload (self-consistent stub).
        assert_eq!(payload, body.encode_marks_payload());
        let candidate = crate::agent_boot::execute_adopt_forward(&raw, &body, &state, &nonce)
            .expect("the marks reply drives execute_adopt_forward to a candidate");
        assert_eq!(candidate.freshness_epoch, epoch);
        // `seed_marks_forward` must NOT bump structural_version — assert it directly so a regression that
        // bumped it (leaving the re-run stuck in AdoptForward instead of Fresh) fails HERE, not silently.
        assert_eq!(
            candidate.structural_version, state.structural_version,
            "seed advances epoch + marks only; structural_version is unchanged"
        );
        assert_eq!(candidate.compute_local_marks_digest(), state.marks_digest);
        // The candidate now reconciles Fresh against the same anchor state (epoch + structural + marks
        // all match) — the post-seed re-run would reach Ready. Asserts the seed truly clears AdoptForward.
        assert_eq!(
            crate::agent_anchor::reconcile(
                candidate.freshness_epoch,
                candidate.structural_version,
                &candidate.compute_local_marks_digest(),
                &state,
            ),
            crate::agent_anchor::ReconcileDecision::Fresh,
            "the adopted candidate reconciles Fresh — the next handshake reaches Ready"
        );
    }

    #[test]
    fn stub_commit_reply_passes_guest_commit_verify() {
        // slice 6 conformance: the lab stub's 0x45 commit reply, read back through the bounded reader,
        // must pass the REAL guest verify_commit_ack_bytes against the smoke fixture's sealed anchor_root
        // — the whole per-op commit channel, deviceless. Makes "the stub can't ACK a commit" unrepresentable.
        let body = smoke_body();
        let nonce = [0x77_u8; 32];
        let proposed_epoch = body.freshness_epoch + 1;
        let proposed_structural = body.structural_version + 1;
        let marks_digest = body.compute_local_marks_digest();
        let request_id: &[u8] = b"op-7";
        let req = crate::agent_boot_relay::encode_anchor_commit_request(
            &crate::agent_boot_relay::AnchorCommitRequest {
                chain_id: body.config.twod_chain_id,
                environment_identifier: &body.config.environment_identifier,
                new_epoch: proposed_epoch,
                new_structural_version: proposed_structural,
                marks_digest,
                nonce,
                request_id,
            },
        )
        .unwrap();
        let (outcome, written_back) = drive_stub_pump(&body, &req);
        outcome.expect("stub answers the 0x45 commit request");
        let ack = crate::agent_boot_relay::read_bounded_anchor_response(
            &mut std::io::Cursor::new(written_back),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .expect("stub framed the commit ack with the shared 4-byte BE writer");
        assert!(ack.len() <= crate::agent_boot_relay::MAX_ANCHOR_RESPONSE_LEN);
        // The guest verifier accepts it against EXACTLY the proposed values.
        crate::agent_anchor::verify_commit_ack_bytes(
            &ack,
            &crate::agent_anchor::ExpectedCommitAck {
                nonce: &nonce,
                epoch: proposed_epoch,
                structural_version: proposed_structural,
                marks_digest: &marks_digest,
                request_id,
            },
            &body.config,
        )
        .expect("stub commit ack passes the REAL guest verify path");
    }

    /// slice 6-5 idempotency + conflict: the lab anchor durably records `request_id → (epoch, structural,
    /// marks)` — `request_id` is the LOGICAL-op identity, commit-at-most-once. A RETRY of the same op
    /// (same request_id + same `{epoch,structural,marks}`) with a FRESH nonce re-signs an ack the guest
    /// verifies for THAT nonce — no double-advance. A re-commit under the same request_id proposing ANY
    /// different `{epoch, structural, marks}` (different marks, OR a different epoch — the cross-crash
    /// double-advance a post-AdoptForward re-issue would attempt) is a CONFLICT the anchor rejects (no
    /// ack), which `run_anchor_commit` surfaces as a commit failure ⇒ fail closed. The nonce is
    /// per-attempt, never part of the record.
    #[test]
    fn stub_commit_idempotent_per_request_id_and_rejects_conflict() {
        let body = smoke_body();
        let chain_id = body.config.twod_chain_id;
        let env = body.config.environment_identifier.clone();
        let epoch = body.freshness_epoch + 1;
        let structural = body.structural_version + 1;
        let marks = body.compute_local_marks_digest();
        let request_id: &[u8] = b"op-idem";
        let commit_frame = |epoch: u64, marks: [u8; 32], nonce: [u8; 32]| {
            crate::agent_boot_relay::encode_anchor_commit_request(
                &crate::agent_boot_relay::AnchorCommitRequest {
                    chain_id,
                    environment_identifier: &env,
                    new_epoch: epoch,
                    new_structural_version: structural,
                    marks_digest: marks,
                    nonce,
                    request_id,
                },
            )
            .unwrap()
        };
        let verify = |written: Vec<u8>, nonce: &[u8; 32], marks: &[u8; 32]| {
            let ack = crate::agent_boot_relay::read_bounded_anchor_response(
                &mut std::io::Cursor::new(written),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .expect("stub framed an ack");
            crate::agent_anchor::verify_commit_ack_bytes(
                &ack,
                &crate::agent_anchor::ExpectedCommitAck {
                    nonce,
                    epoch,
                    structural_version: structural,
                    marks_digest: marks,
                    request_id,
                },
                &body.config,
            )
        };
        let expect_rejected = |o: Result<[u8; 8], crate::ProtocolError>, w: Vec<u8>, ledger: &LabCommitLedger, why: &str| {
            assert!(o.is_err(), "{why}: conflict must be rejected");
            assert!(w.is_empty(), "{why}: a rejected conflict writes NO ack (the enclave then fails closed)");
            assert_eq!(ledger.len(), 1, "{why}: a rejected conflict does NOT alter the durable record");
        };

        let mut ledger = LabCommitLedger::new();
        let (n_a, n_b) = ([0xa1_u8; 32], [0xb2_u8; 32]);
        // (1) First commit (nonce A) → first-seen: recorded + signed; verifies for A.
        let (o1, w1) = drive_stub_pump_with_ledger(&body, &commit_frame(epoch, marks, n_a), &mut ledger);
        o1.expect("first commit ok");
        verify(w1, &n_a, &marks).expect("first ack verifies for nonce A");
        // (2) RETRY same op (same request_id + same {epoch,structural,marks}) with FRESH nonce B →
        //     idempotent: re-signed for B, durable record UNCHANGED.
        let (o2, w2) = drive_stub_pump_with_ledger(&body, &commit_frame(epoch, marks, n_b), &mut ledger);
        o2.expect("idempotent retry ok");
        verify(w2, &n_b, &marks).expect("retry ack is re-signed for the CURRENT nonce B");
        assert_eq!(ledger.len(), 1, "an idempotent retry does NOT add a second durable record");
        // (3) CONFLICT — same request_id, same epoch, DIFFERENT marks ⇒ reject.
        let (o3, w3) = drive_stub_pump_with_ledger(&body, &commit_frame(epoch, [0xcc; 32], n_a), &mut ledger);
        expect_rejected(o3, w3, &ledger, "different marks under the same request_id");
        // (4) CONFLICT — same request_id, DIFFERENT epoch ⇒ reject. THIS is the cross-crash double-advance
        //     a post-AdoptForward re-issue of the SAME logical op would attempt; keying by request_id
        //     ALONE (not (request_id, epoch)) catches it, so the same op cannot commit twice.
        let (o4, w4) = drive_stub_pump_with_ledger(&body, &commit_frame(epoch + 1, marks, n_a), &mut ledger);
        expect_rejected(o4, w4, &ledger, "different epoch under the same request_id");
    }

    #[test]
    fn stub_signs_per_request_nonce_distinct() {
        // Pins the canned-response impossibility as a deviceless fact: two requests with distinct
        // nonces yield DISTINCT signed bodies, each verifying ONLY against its own nonce.
        let body = smoke_body();
        let (n1, n2) = ([0x01_u8; 32], [0x02_u8; 32]);
        let mut raws = Vec::new();
        for nonce in [n1, n2] {
            let (outcome, written) = drive_stub_pump(&body, &smoke_request_frame(nonce));
            outcome.expect("pump ok");
            let raw = crate::agent_boot_relay::read_bounded_anchor_response(
                &mut std::io::Cursor::new(written),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap();
            raws.push(raw);
        }
        assert_ne!(raws[0], raws[1], "distinct nonces must produce distinct signed responses");
        assert!(crate::agent_anchor::verify_anchor_response_bytes(&raws[0], &n1, &body.config).is_ok());
        assert!(matches!(
            crate::agent_anchor::verify_anchor_response_bytes(&raws[0], &n2, &body.config),
            Err(crate::agent_anchor::AnchorError::NonceMismatch)
        ));
    }

    #[test]
    fn stub_rejects_non_0x41_and_garbage_with_zero_bytes() {
        // Fail-closed close-silently: every reject path returns Err BEFORE any write.
        let body = smoke_body();
        // A well-formed frame of the WRONG type (0x40).
        let wrong_type =
            crate::encode_message(crate::MessageType::AgentGateway, &[0x01]).unwrap();
        // A short/garbage byte string (sub-header).
        let garbage = vec![0x00, 0x01, 0x02];
        for bad in [wrong_type, garbage] {
            let (outcome, written_back) = drive_stub_pump(&body, &bad);
            assert!(outcome.is_err(), "stub must reject the malformed/misrouted frame");
            assert!(
                written_back.is_empty(),
                "reject must write ZERO bytes back (close-silently)"
            );
        }
    }

    #[test]
    fn stub_rejects_scope_mismatch_with_zero_bytes() {
        // A request whose cleartext binding is self-consistent but for a DIFFERENT scope than the
        // provisioned keystore: decode passes, the stub's scope guard must fault-close.
        let body = smoke_body();
        let frame = smoke_request_frame_for_scope(9999, "some-other-env", [0xcd_u8; 32], None);
        let (outcome, written_back) = drive_stub_pump(&body, &frame);
        assert!(matches!(outcome, Err(crate::ProtocolError::WireProtocol(m)) if m.contains("scope")));
        assert!(written_back.is_empty());
    }

    #[test]
    fn stub_rejects_embedded_quote_mismatch_with_zero_bytes() {
        // Key 5 carries the CORRECT binding but the quote's embedded report_data (offset 0x50)
        // does not match it — the match-only quote policy must fault-close, zero bytes back.
        let body = smoke_body();
        let frame = smoke_request_frame_for_scope(
            body.config.twod_chain_id,
            &body.config.environment_identifier,
            [0xef_u8; 32],
            Some(vec![0u8; 0x90]), // embedded report_data = zeros ≠ the key-5 binding
        );
        let (outcome, written_back) = drive_stub_pump(&body, &frame);
        assert!(matches!(outcome, Err(crate::ProtocolError::WireProtocol(m)) if m.contains("report_data")));
        assert!(written_back.is_empty());
    }

    #[test]
    fn stub_misconfig_fails_closed() {
        // A keystore whose anchor_root does NOT pair with LAB_ANCHOR_TEST_SEED (the genesis-style
        // [0xa3;32] literal) must be refused at startup — never a mystery SignatureInvalid on aya.
        let mut body = smoke_body();
        body.config.anchor_root = [0xa3; 32];
        assert!(lab_anchor_root_matches(&body).is_err());
        assert!(lab_anchor_root_matches(&smoke_body()).is_ok());
    }

    // ---- idle-expiry window (C4) bounds ----

    #[test]
    fn idle_expiry_window_bounds_are_sane() {
        // Mirrors quote_smoke's lapse_probe_deadline_is_inside_binding_window discipline: the C4
        // acceptance window must bracket the REAL consts — floor strictly below SESSION_IDLE_TIMEOUT
        // (never an exact floor; the 399 ms run-1 lesson) and ceiling strictly above
        // SESSION_IDLE_TIMEOUT + the per-stream 30 s SO_RCVTIMEO read arm (the close lands at the
        // first read-wake tick ≥ the idle deadline). The connector's idle read-timeout must clear
        // the whole window so a socket timeout can never masquerade as the close.
        let idle_ms = crate::enclave_serve::SESSION_IDLE_TIMEOUT.as_millis();
        let read_arm_ms = crate::enclave_serve::READ_TIMEOUT.as_millis();
        assert!(IDLE_EXPIRY_FLOOR_MS < idle_ms, "floor must be strictly below the idle timeout");
        assert!(
            idle_ms - IDLE_EXPIRY_FLOOR_MS >= 1_000,
            "floor slop must be a real margin, not an exact floor"
        );
        // The ceiling must clear the STRUCTURAL worst case (idle + one full read-arm tick) with real
        // load-jitter headroom — NOT a hair over it. Because idle_ms is an exact multiple of the read
        // arm, the close is bimodal at ~idle and ~idle+tick (see the IDLE_EXPIRY_CEILING_MS doc); a
        // ceiling that only just exceeds idle+tick (the original +2 s) leaves a load-jitter false-RED
        // at the upper mode. Require ≥ 8 s of headroom above idle+tick.
        assert!(
            IDLE_EXPIRY_CEILING_MS >= idle_ms + read_arm_ms + 8_000,
            "ceiling must clear idle + the 30s read-arm tick by a real load-jitter margin"
        );
        // The idle timeout being an EXACT multiple of the read arm is what makes the close bimodal —
        // pin that precondition so a future READ_TIMEOUT/SESSION_IDLE_TIMEOUT change that breaks the
        // alignment re-reviews this window rather than silently shifting the modes.
        assert_eq!(
            idle_ms % read_arm_ms,
            0,
            "the bimodal-close reasoning assumes idle is an exact multiple of the read arm"
        );
        assert!(
            SMOKE_CLIENT_IDLE_READ_TIMEOUT.as_millis() >= IDLE_EXPIRY_CEILING_MS,
            "connector idle read-timeout must be at or above the window ceiling"
        );
    }

    // ---- client ↔ serve cross-validation (fresh pair per phase; skip_idle — no wall clocks) ----

    /// Run the client core's deviceless phases (C1/C2/C3/C5; skip_idle) against `router` served by
    /// the REAL `serve_framed_pump` kernel over UnixStream pairs — a fresh pair per phase, exactly
    /// the serial server's per-connection shape. Returns (client verdict, captured marker log).
    fn run_client_against_router(
        router: fn(&[u8]) -> Result<Vec<u8>, crate::ProtocolError>,
    ) -> (bool, String) {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        assert!(crate::agent_dispatch::install_agent_keystore(
            smoke_body(),
            AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT
        ));
        let connect = move || -> std::io::Result<std::os::unix::net::UnixStream> {
            let (client, mut server) = std::os::unix::net::UnixStream::pair()?;
            client.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            client.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            // Short per-syscall read timeout: the pump's idle re-check wakes on it (prod arms 30 s).
            server.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
            server.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            std::thread::spawn(move || {
                let _ = crate::enclave_serve::serve_framed_pump(
                    &mut server,
                    router,
                    std::time::Duration::from_secs(2),
                );
            });
            Ok(client)
        };
        let mut sink = Vec::new();
        let ok = run_agent_smoke_client(connect, true, &mut sink);
        (ok, String::from_utf8_lossy(&sink).into_owned())
    }

    /// REPLICA of `agent_gateway_boot::agent_serve_one_frame` for the darwin-runnable copy of the
    /// cross-validation (that module is linux+vsock gated). CLEARLY LABELED: the LINUX test below,
    /// which drives the SHIPPED `pub(crate)` glue, is the BINDING one; this copy exists so local
    /// darwin iteration still exercises the full client path.
    fn replica_agent_serve_one_frame(frame: &[u8]) -> Result<Vec<u8>, crate::ProtocolError> {
        let decoded = crate::decode_message(frame)?;
        if decoded.msg_type != crate::MessageType::AgentGateway {
            return Err(crate::ProtocolError::WireProtocol(
                "replica: non-0x40 frame on the agent listener",
            ));
        }
        let body = crate::agent_dispatch::handle_agent_gateway_frame(&decoded.payload);
        crate::encode_message(crate::MessageType::AgentGateway, &body)
    }

    #[test]
    fn client_phases_pass_against_replica_router() {
        let (ok, log) = run_client_against_router(replica_agent_serve_one_frame);
        assert!(ok, "client phases failed:\n{log}");
        assert!(log.contains("twod-hsm-agent-smoke: RESULT PASS-DEV phases=4"), "log:\n{log}");
        assert!(log.contains("PHASE public-identity PASS"), "log:\n{log}");
        assert!(log.contains("PHASE identity-unknown-keyref PASS"), "log:\n{log}");
        assert!(log.contains("PHASE non-agent-close PASS"), "log:\n{log}");
        assert!(log.contains("PHASE post-expiry-liveness PASS"), "log:\n{log}");
        assert!(!log.contains("RESULT PASS phases="), "PASS-DEV must not match the official token");
    }

    /// The BINDING cross-validation: the client core against the SHIPPED 0x40 type-guard + reframe
    /// glue (`agent_gateway_boot::agent_serve_one_frame`, now `pub(crate)`) through the real serve
    /// kernel. Runs in the CI ubuntu vsock-transport lane and on aya; compiled out on darwin (the
    /// module is linux+vsock gated).
    #[cfg(all(target_os = "linux", feature = "vsock-transport"))]
    #[test]
    fn client_phases_pass_against_shipped_serve_glue() {
        let (ok, log) =
            run_client_against_router(crate::agent_gateway_boot::agent_serve_one_frame);
        assert!(ok, "client phases failed against the SHIPPED glue:\n{log}");
        assert!(log.contains("twod-hsm-agent-smoke: RESULT PASS-DEV phases=4"), "log:\n{log}");
    }

    // ---- slice 6-7b WRITE-PATH cross-validation (deviceless; proves seal→commit→swap→emit in-process
    //      before any SNP run, exactly as the read-path cross-val proves the read path) ----

    /// The deviceless per-op commit channel: signs commit ACKs with the smoke `anchor_root`
    /// ([`LAB_ANCHOR_TEST_SEED`]) via the SAME pure [`lab_commit_ack_for_request`] the aya
    /// `twod-hsm-lab-anchor` stub runs — so the in-process write-path proof and the live anchor can
    /// never drift on the commit semantics. `body` is the STATIC `smoke_body()` (epoch/structural at
    /// boot): correct across MULTIPLE committing phases (the keygen smoke commits once at W1; the TASK-15
    /// faucet smoke reuses this channel for FOUR committing phases F1-F4) because the commit leg only
    /// scope-guards + signs the enclave's PROPOSED state — it scope-guards ONLY the CONSTANT config
    /// (`twod_chain_id` / `environment_identifier` / `anchor_root`, which no committing op mutates) and
    /// never re-derives or compares against `body`'s advancing `freshness_epoch`/`structural_version`/marks.
    /// So a static `smoke_body()` is sufficient regardless of phase count; the ledger keys by request_id.
    #[cfg(feature = "agent-keygen-exec-preview")]
    struct LabCommitChannel {
        body: KeystoreBody,
        signing_key: ed25519_dalek::SigningKey,
        ledger: LabCommitLedger,
    }
    #[cfg(feature = "agent-keygen-exec-preview")]
    impl LabCommitChannel {
        fn new() -> Self {
            Self {
                body: smoke_body(),
                signing_key: ed25519_dalek::SigningKey::from_bytes(&LAB_ANCHOR_TEST_SEED),
                ledger: LabCommitLedger::new(),
            }
        }
    }
    #[cfg(feature = "agent-keygen-exec-preview")]
    impl crate::agent_boot_relay::BootRelayChannel for LabCommitChannel {
        fn round_trip(
            &mut self,
            frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            // Return the UNFRAMED signed ACK (what the enclave's `run_anchor_commit` expects back); any
            // local failure maps to the coarse always-retryable transport error ⇒ the enclave fails the
            // op CLOSED (it never reaches swap/emit), matching the production channel contract.
            match lab_commit_ack_for_request(frame, &self.body, &self.signing_key, &mut self.ledger) {
                Ok((ack, _nonce8)) => Ok(ack),
                Err(_) => Err(crate::agent_boot_driver::AnchorTransportError(
                    "lab commit channel: ack computation failed",
                )),
            }
        }
        fn marks_round_trip(
            &mut self,
            _frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            // Unreachable by construction (the GENERATE_KEYS commit path calls ONLY round_trip). A
            // propagated Err — not unreachable!() — because this channel runs inside the SPAWNED
            // serve_framed_pump thread: a panic here would kill that thread and surface as a cryptic
            // client-side connection reset, whereas an Err fails the op closed and is reported cleanly.
            Err(crate::agent_boot_driver::AnchorTransportError(
                "lab commit channel: marks_round_trip must not be called on the per-op commit channel",
            ))
        }
    }

    /// Drive the WRITE-path client core against `router` served by the REAL `serve_framed_pump`, with
    /// the process globals a booted preview guest would hold: the installed smoke keystore, the
    /// anti-rollback binding (boot installs it on a Fresh reconcile — here installed directly, exactly
    /// as `boot_reconcile_anti_rollback` does), and the per-op [`LabCommitChannel`]. The seal root is
    /// reset to the cfg(test) reference root (= [`SMOKE_SEAL_ROOT`]) so the client can unseal the
    /// returned blob. Returns (client verdict, captured marker log).
    #[cfg(feature = "agent-keygen-exec-preview")]
    fn run_keygen_client_against_router(
        router: fn(&[u8]) -> Result<Vec<u8>, crate::ProtocolError>,
    ) -> (bool, String) {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        // commit_before_emit seals via resolve_provisioning_root(); force the None→reference-root
        // fallthrough so the seal uses SMOKE_SEAL_ROOT and the client's unseal matches (guarded against
        // a stale platform root a serialized agent-global test may have left set). NB the seal root is a
        // `seal_root`-module global (NOT one of the agent globals `lock_and_reset_agent_process_globals`
        // manages), so it is reset HERE; resetting to None leaves it in the process-start PRISTINE state
        // (const-init None), so this is symmetric-by-default — no teardown restore is owed.
        crate::seal_root::reset_pq_seal_v1_provisioning_root_for_tests();
        assert!(crate::agent_dispatch::install_agent_keystore(
            smoke_body(),
            AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT
        ));
        assert!(crate::agent_dispatch::install_anti_rollback_binding(
            crate::agent_dispatch::AntiRollbackBinding { epoch: 1, active: true }
        ));
        assert!(crate::agent_dispatch::install_commit_channel(Box::new(LabCommitChannel::new())));
        let connect = move || -> std::io::Result<std::os::unix::net::UnixStream> {
            let (client, mut server) = std::os::unix::net::UnixStream::pair()?;
            client.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            client.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            server.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
            server.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            std::thread::spawn(move || {
                let _ = crate::enclave_serve::serve_framed_pump(
                    &mut server,
                    router,
                    std::time::Duration::from_secs(5),
                );
            });
            Ok(client)
        };
        let mut sink = Vec::new();
        let ok = run_agent_keygen_smoke_client(connect, &mut sink);
        (ok, String::from_utf8_lossy(&sink).into_owned())
    }

    /// Darwin-runnable write-path cross-val (the replica router, mirroring
    /// `client_phases_pass_against_replica_router`): a real GENERATE_KEYS executes the full
    /// seal→commit→swap→emit path and the negative phase stays fail-closed.
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn keygen_client_drives_real_generate_keys_against_replica_router() {
        let (ok, log) = run_keygen_client_against_router(replica_agent_serve_one_frame);
        assert!(ok, "keygen client phases failed:\n{log}");
        assert!(
            log.contains("twod-hsm-agent-keygen-smoke: PHASE generate-keys PASS"),
            "log:\n{log}"
        );
        assert!(
            log.contains("twod-hsm-agent-keygen-smoke: PHASE generate-keys-bad-cap PASS"),
            "log:\n{log}"
        );
        assert!(
            log.contains("twod-hsm-agent-keygen-smoke: RESULT PASS phases=2"),
            "log:\n{log}"
        );
    }

    /// The BINDING write-path cross-val: the same against the SHIPPED `agent_serve_one_frame` glue +
    /// real serve kernel (linux+vsock lane + aya). This is the deviceless proof the 6-7b SNP smoke
    /// rests on — protocol drift between the write-path client and the enclave is caught HERE.
    #[cfg(all(
        target_os = "linux",
        feature = "vsock-transport",
        feature = "agent-keygen-exec-preview"
    ))]
    #[test]
    fn keygen_client_drives_real_generate_keys_against_shipped_serve_glue() {
        let (ok, log) =
            run_keygen_client_against_router(crate::agent_gateway_boot::agent_serve_one_frame);
        assert!(ok, "keygen client failed against the SHIPPED glue:\n{log}");
        assert!(
            log.contains("twod-hsm-agent-keygen-smoke: RESULT PASS phases=2"),
            "log:\n{log}"
        );
    }

    /// TASK-15 combined FAUCET write-path deviceless cross-val (mirrors `run_keygen_client_against_router`,
    /// all 3 preview gates): the SAME process-global setup a booted preview guest holds (installed smoke
    /// keystore + Fresh-reconcile anti-rollback binding + the per-op `LabCommitChannel` — static body is
    /// fine across the FOUR committing phases (F1-F4; F5 is rejected at the recipient-allowlist gate BEFORE
    /// any commit) because the commit leg only scope-guards the constant config + signs the proposed state,
    /// and the ledger keys by per-phase-distinct request_id). Drives the full
    /// mint→set_limits→refill→dispense fund-custody flow through the real serve kernel.
    #[cfg(all(
        feature = "agent-keygen-exec-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-sign-faucet-preview"
    ))]
    fn run_faucet_client_against_router(
        router: fn(&[u8]) -> Result<Vec<u8>, crate::ProtocolError>,
    ) -> (bool, String) {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        crate::seal_root::reset_pq_seal_v1_provisioning_root_for_tests();
        assert!(crate::agent_dispatch::install_agent_keystore(
            smoke_body(),
            AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT
        ));
        assert!(crate::agent_dispatch::install_anti_rollback_binding(
            crate::agent_dispatch::AntiRollbackBinding { epoch: 1, active: true }
        ));
        assert!(crate::agent_dispatch::install_commit_channel(Box::new(LabCommitChannel::new())));
        let connect = move || -> std::io::Result<std::os::unix::net::UnixStream> {
            let (client, mut server) = std::os::unix::net::UnixStream::pair()?;
            client.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            client.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            server.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
            server.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            std::thread::spawn(move || {
                let _ = crate::enclave_serve::serve_framed_pump(
                    &mut server,
                    router,
                    std::time::Duration::from_secs(5),
                );
            });
            Ok(client)
        };
        let mut sink = Vec::new();
        let ok = run_agent_faucet_smoke_client(connect, &mut sink);
        (ok, String::from_utf8_lossy(&sink).into_owned())
    }

    /// Darwin-runnable combined-faucet cross-val (replica router): mint treasury → set_limits → refill →
    /// dispense (dual-counter debit) → fail-closed stranger-recipient gate, all end-to-end through the
    /// real seal→commit→swap→emit seam.
    #[cfg(all(
        feature = "agent-keygen-exec-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-sign-faucet-preview"
    ))]
    #[test]
    fn faucet_client_drives_combined_flow_against_replica_router() {
        let (ok, log) = run_faucet_client_against_router(replica_agent_serve_one_frame);
        assert!(ok, "faucet client phases failed:\n{log}");
        for ph in ["mint-treasury", "configure-set-limits", "configure-refill-budget", "dispense", "dispense-stranger-rejected"] {
            assert!(
                log.contains(&format!("twod-hsm-agent-faucet-smoke: PHASE {ph} PASS")),
                "phase {ph} did not pass:\n{log}"
            );
        }
        assert!(
            log.contains("twod-hsm-agent-faucet-smoke: RESULT PASS phases=5"),
            "log:\n{log}"
        );
    }

    /// The BINDING faucet write-path cross-val against the SHIPPED `agent_serve_one_frame` glue + real
    /// serve kernel (linux+vsock lane + aya) — the deviceless proof the faucet SNP smoke rests on.
    #[cfg(all(
        target_os = "linux",
        feature = "vsock-transport",
        feature = "agent-keygen-exec-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-sign-faucet-preview"
    ))]
    #[test]
    fn faucet_client_drives_combined_flow_against_shipped_serve_glue() {
        let (ok, log) =
            run_faucet_client_against_router(crate::agent_gateway_boot::agent_serve_one_frame);
        assert!(ok, "faucet client failed against the SHIPPED glue:\n{log}");
        assert!(
            log.contains("twod-hsm-agent-faucet-smoke: RESULT PASS phases=5"),
            "log:\n{log}"
        );
    }

    /// REGEN (manual): `cargo test --features agent-gateway,lab-agent-smoke \
    /// regen_agent_smoke_golden_vector -- --ignored --nocapture`, then commit BOTH files and re-run
    /// the suite (`git diff --exit-code` over `testvectors/` must be clean on a second regen —
    /// regen-idempotence). Unlike the genesis regen this mints the `.json` sidecar too, so the
    /// blob/sidecar pair can never be regenerated apart.
    #[test]
    #[ignore]
    fn regen_agent_smoke_golden_vector() {
        use sha2::{Digest as _, Sha256};
        let blob = smoke_sealed_blob();
        let body = smoke_body();
        let keypair = crate::secp256k1::Keypair::from_secret_bytes(&SMOKE_SECRET_SCALAR).unwrap();
        let bin_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testvectors/agent-gateway/agent_keystore_smoke_v1.sealed.bin"
        );
        std::fs::write(bin_path, &blob).expect("write smoke keystore blob");
        let sidecar = serde_json::json!({
            "_comment": "TASK-7.7 5b-2c-iii minted SMOKE keystore for the aya SNP live smoke. \
                 TEST KEYS ONLY — the anchor seed and the secp256k1 scalar are public in-repo \
                 constants (lab_agent_smoke.rs); never a production keystore. Re-mint BOTH files \
                 via `cargo test --features agent-gateway,lab-agent-smoke \
                 regen_agent_smoke_golden_vector -- --ignored --nocapture`; the \
                 agent_smoke_golden_* tests fail CI if either file drifts.",
            "warning": "TEST KEYS ONLY",
            "blob_file": "agent_keystore_smoke_v1.sealed.bin",
            "blob_len_bytes": blob.len(),
            "blob_sha256": hex(&Sha256::digest(&blob)),
            "envelope": {
                "keystore_magic_ascii": "2DAGTKS<NUL>",
                "keystore_format_version": 3,
                "aead": "XChaCha20Poly1305",
                "nonce_hex": hex(&SMOKE_SEAL_NONCE),
            },
            "seal_inputs": {
                "provisioning_root_file": "../seal_v1_provisioning_root.bin",
                "provisioning_root_hex": hex(SMOKE_SEAL_ROOT),
                "enclave_measurement_str": "agent-keystore-measurement-placeholder",
                "enclave_measurement_hex": hex(AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT),
                "enclave_measurement_note": "AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT — the \
                     real attested 48-byte SNP launch measurement is the deferred production \
                     keystore-source slice (explicit smoke non-coverage).",
            },
            "smoke_identity": {
                "anchor_test_seed_hex": hex(&LAB_ANCHOR_TEST_SEED),
                "anchor_root_hex": hex(&body.config.anchor_root),
                "admin_seed_hex": hex(&SMOKE_ADMIN_SEED),
                "admin_authority_pk_hex": hex(&body.config.admin_authority_pk),
                "key_ref_hex": hex(&SMOKE_KEY_REF),
                "secret_scalar_hex": hex(&SMOKE_SECRET_SCALAR),
                "public_identity_hex": hex(&keypair.public_key_uncompressed()),
                "eth_address_hex": hex(&keypair.eth_address()),
                "tron_address": keypair.tron_address(),
            },
            "scope": {
                "twod_chain_id": SMOKE_CHAIN_ID,
                "environment_identifier": SMOKE_ENVIRONMENT,
                "freshness_epoch": 1,
                "structural_version": 1,
                "strict_recovery_counter": 0,
            },
        });
        let json_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testvectors/agent-gateway/agent_keystore_smoke_v1.json"
        );
        let pretty = serde_json::to_string_pretty(&sidecar).expect("sidecar serializes");
        std::fs::write(json_path, pretty + "\n").expect("write smoke keystore sidecar");
        eprintln!("wrote {} bytes -> {bin_path}\nwrote sidecar -> {json_path}", blob.len());
    }
}
