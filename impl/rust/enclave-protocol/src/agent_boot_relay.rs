//! Agent Gateway anti-rollback **boot-relay wire protocol + transport seam** (TASK-7.7, slice 5b-2a).
//!
//! The boot anti-rollback handshake is enclave-initiated: the enclave produces an SNP quote committing
//! to its fresh challenge `report_data`, relays it (with the public challenge) to the anchor *through an
//! untrusted host relay*, and receives the anchor's Ed25519-signed freshness response. This module is
//! the **pure, CI-testable** half of that: the request CBOR codec, a bounded response reader, the two
//! platform seams ([`BootRelayChannel`] = the raw round-trip, [`BootQuoteProducer`] = the SNP quote),
//! and [`RelayAnchorTransport`] — the concrete [`crate::agent_boot_driver::AnchorBootTransport`] that
//! composes quote-fetch → request-encode → channel-relay and returns the anchor's response **bytes
//! verbatim** to the 5b-1 driver.
//!
//! ## Untrusted-relay threat model (load-bearing)
//! The host relay is a dumb, UNTRUSTED pipe. This module NEVER trusts or parses the response: it returns
//! the raw bytes straight to [`crate::agent_boot::boot_reconcile_anti_rollback`], whose
//! `verify_anchor_response_bytes` strict-decodes them and Ed25519-verifies against the sealed
//! `anchor_root` + the issued nonce. Re-encoding the response in the enclave would break
//! `agent_anchor`'s "signature binds the exact wire bytes" property, so the response side here is only a
//! **bounded read** (cap-before-alloc) — no decode of anchor internals. A garbage / wrong-nonce /
//! substituted reply is safe: the driver turns it into a terminal `VerifyNonceMismatch` /
//! `SignatureInvalid` / `Malformed` (fail-closed, never a serve). Every value the request carries
//! (`chain_id`, `environment_identifier`, `nonce`, `report_data`, the quote, the cert chain) is PUBLIC —
//! it transits the host to the anchor by design; nothing sealed/secret crosses the seam.
//!
//! ## Stale-reply safety (structural)
//! `BootRelayChannel` implementations MUST open a **fresh connection per `round_trip`** and drop it on
//! return: a late reply to a timed-out prior attempt then lands on a closed socket and can never be
//! returned for the current attempt. There is deliberately **no nonce-precheck** in the transport — a
//! precheck-to-retryable would be harmful (it could downgrade a genuine terminal `VerifyNonceMismatch`
//! into a retry, a grind lever). The downstream verify against the issued nonce is the sole, sufficient
//! freshness gate.
//!
//! ## UNWIRED — slice 5b-2b adds the platform leaves
//! Like 5a/5b-1, the module is dead-code in the non-test lib build; the test build drives the FULL
//! composition (this transport + the 5b-1 driver + 5a verify) end-to-end with a mock channel + fake
//! quote producer. The aya/SNP work is split into ordered slices (see §8): **5b-2b-ii** — the real
//! `VsockBootRelayChannel` (fresh per call, hard-cancellable `connect_bounded` to host CID 2 — LANDED, (a)
//! PR #54 + (a') PR #56) and the still-open host-side relay daemon (b) (which uses
//! [`decode_anchor_boot_request`]) — the `vsock-transport`-gated
//! leaf. (The cooperative `SnpQuoteProducer` landed HERE in 5b-2b-i and was DELETED in (d-ii)(4a)
//! together with `snp_report::fetch_report_deadline` — wiring a cooperative producer is
//! unrepresentable; the wired producer is `HardBoundedQuoteProducer` ((d-ii)/2, `quote_subprocess`,
//! triple-gated; plain-text reference); live wiring is (4b)/5b-2c.) Then
//! **5b-2c** the agent-gateway
//! bin + boot sequencing; **5b-2d** the sealed-blob source + unseal; **5b-2e** `AdoptForward` raw-marks.
#![cfg_attr(not(test), allow(dead_code))]

use crate::agent_boot_driver::{AnchorBootRequest, AnchorBootTransport, AnchorTransportError};
use crate::ProtocolError;
use ciborium::value::Value;

/// Body-level version of the boot-relay request map (key 1), distinct from the frame `PROTOCOL_VERSION`
/// byte — mirrors every wire/agent CBOR map carrying its own key-1 version.
const RELAY_REQUEST_VERSION: u64 = 1;

/// Upper bound on the anchor's signed response, checked against the length prefix BEFORE allocation so a
/// hostile relay cannot force a large alloc / OOM in the memory-constrained TEE. The real signed response
/// (`agent_anchor` schema: keys `1..=7`, optional `8/9` chain-binding, `13` = 64-byte signature) is
/// ~250–512 B; 4 KiB is generous headroom (matches `agent_cbor::MAX_STR_LEN`'s "tiny agent map" sizing)
/// and far below `MAX_MESSAGE_SIZE`. FORWARD-COMPAT: a silent hard cap — a future response schema that
/// grows past it would be rejected; keep it in lockstep with the `agent_anchor` response size.
pub(crate) const MAX_ANCHOR_RESPONSE_LEN: usize = 4096;

/// Generous upper bound on the SNP quote (`ATTESTATION_REPORT`) the request carries — checked before the
/// payload allocation so even a buggy/oversized quote producer can't force a large alloc ahead of the
/// frame-level `MAX_MESSAGE_SIZE` check, and enforced on BOTH encode and decode so the two size envelopes
/// match (the cert-chain lesson). The real report is ~1184 B; 8 KiB is ample headroom for future report
/// versions while staying tiny.
pub(crate) const MAX_QUOTE_REPORT_LEN: usize = 8192;

/// 5b-2e: envelope reserve over the marks payload for the marks RESPONSE (keys 1–5 scope/nonce/epoch
/// ~80 B + the key-6 bstr length prefix ~5 B + the key-13 64-byte signature + map overhead). 256 B is
/// comfortable headroom.
pub(crate) const MARKS_RESP_ENVELOPE_RESERVE: usize = 256;

/// 5b-2e: upper bound on the `anchor_root`-signed RAW-MARKS response — DISTINCT from
/// [`MAX_ANCHOR_RESPONSE_LEN`] (4096): a marks payload describing a non-trivial counter table is
/// multi-KiB (a body sealing under [`crate::agent_keystore::MAX_KEYSTORE_BLOB_SIZE`] is the genuine
/// ceiling), so the marks leg gets its OWN cap. The 4 KiB freshness-leg cap is UNCHANGED (raising a
/// single shared cap would loosen the freshness DoS bound). Checked before alloc, like
/// [`read_bounded_anchor_response`]; the marks fetch is only paid on the `AdoptForward` path.
pub(crate) const MAX_MARKS_RESPONSE_LEN: usize =
    crate::agent_anchor::MAX_MARKS_PAYLOAD_LEN + MARKS_RESP_ENVELOPE_RESERVE;

/// Body-level version of the 5b-2e marks-relay request map (key 1).
const MARKS_REQUEST_VERSION: u64 = 1;

/// Owned, decoded boot-relay request — for the untrusted **host relay** (5b-2b) and round-trip tests.
/// NOT an enclave trust boundary: the enclave only *encodes* the request and *verifies the response*; it
/// never decodes a request. (Kept hardened anyway — see [`decode_anchor_boot_request`].)
pub(crate) struct DecodedBootRequest {
    pub chain_id: u64,
    pub environment_identifier: String,
    pub nonce: [u8; 32],
    pub report_data: [u8; 64],
    pub quote_report: Vec<u8>,
    pub cert_chain: Vec<u8>,
}

/// Encode a boot-relay request frame: a canonical integer-keyed CBOR map (keys 1..=7) carried as the
/// payload of a [`crate::MessageType::AgentBootRelay`] (`0x41`) frame. Returns the FULL frame ready for
/// the channel to write. The cert chain is bounded by [`crate::snp_report::MAX_CERT_CHAIN_LEN`] (and the
/// frame by `MAX_MESSAGE_SIZE`); an over-large chain is a `WireProtocol` error rather than an unbounded
/// outbound. Built with the same canonical encoders the capability/anchor signers use, so a conformant
/// host relay/anchor recomputes identical bytes.
pub(crate) fn encode_anchor_boot_request(
    quote_report: &[u8],
    cert_chain: &[u8],
    request: &AnchorBootRequest,
) -> Result<Vec<u8>, ProtocolError> {
    use crate::agent_capability::{put_bytes, put_text, put_uint};
    // Bound BOTH large fields before reserving/copying, so no producer (however buggy) can force a large
    // alloc ahead of the frame-level MAX_MESSAGE_SIZE check.
    if quote_report.len() > MAX_QUOTE_REPORT_LEN {
        return Err(ProtocolError::WireProtocol("anchor boot request: quote_report too large"));
    }
    if cert_chain.len() > crate::snp_report::MAX_CERT_CHAIN_LEN {
        return Err(ProtocolError::WireProtocol("anchor boot request: cert_chain too large"));
    }
    let mut payload = Vec::with_capacity(quote_report.len() + cert_chain.len() + 128);
    put_uint(&mut payload, 5, 7); // map header: 7 pairs
    put_uint(&mut payload, 0, 1);
    put_uint(&mut payload, 0, RELAY_REQUEST_VERSION);
    put_uint(&mut payload, 0, 2);
    put_uint(&mut payload, 0, request.chain_id);
    put_uint(&mut payload, 0, 3);
    put_text(&mut payload, request.environment_identifier);
    put_uint(&mut payload, 0, 4);
    put_bytes(&mut payload, &request.nonce);
    put_uint(&mut payload, 0, 5);
    put_bytes(&mut payload, &request.report_data);
    put_uint(&mut payload, 0, 6);
    put_bytes(&mut payload, quote_report);
    put_uint(&mut payload, 0, 7);
    put_bytes(&mut payload, cert_chain);
    crate::encode_message(crate::MessageType::AgentBootRelay, &payload)
}

/// Decode + validate a boot-relay request frame (for the untrusted host relay + tests). Uses a
/// **lenient** CBOR decode (NOT the 4 KiB-per-string strict decoder — the request legitimately carries a
/// multi-KiB cert chain, and it is not signature-bound so byte-level canonicality is not load-bearing;
/// see the body). What IS enforced: no trailing bytes after the map; integer keys exactly `{1..=7}` with
/// **no duplicates** (`check_strict_keys`; key *ordering* is NOT enforced); version `== 1`; exact-length
/// `nonce` (32) / `report_data` (64); `cert_chain ≤ MAX_CERT_CHAIN_LEN`; AND the `report_data ==
/// anchor_handshake_report_data(chain_id, env, nonce)` binding (binds the cleartext scope+nonce to the
/// quote commitment — defense-in-depth at the relay boundary; the anchor re-checks). Every failure is
/// [`ProtocolError::WireProtocol`].
pub(crate) fn decode_anchor_boot_request(frame: &[u8]) -> Result<DecodedBootRequest, ProtocolError> {
    use crate::agent_cbor::{as_bytes, as_bytes_n, as_u64, check_strict_keys, map_get};

    let framed = crate::decode_message(frame)?;
    if framed.msg_type != crate::MessageType::AgentBootRelay {
        return Err(ProtocolError::WireProtocol("not an AGENT_BOOT_RELAY frame"));
    }
    // Lenient ciborium decode — NOT `strict_decode_map`, whose per-byte-string cap (`MAX_STR_LEN`,
    // 4 KiB) is sized for tiny agent maps and would reject a legitimate request carrying the ~1184 B SNP
    // quote + a cert_chain up to `MAX_CERT_CHAIN_LEN` (64 KiB). The request is enclave-produced and NOT
    // signature-bound (the anchor re-derives `report_data` from the public fields; the enclave verifies
    // only the RESPONSE), so byte-level canonical strictness is not load-bearing here. What IS enforced:
    // no trailing bytes, integer-key rigor (`check_strict_keys`: range + no-dup), exact field
    // types/lengths, the cert_chain bound, and the `report_data` binding. The whole frame is bounded by
    // `MAX_MESSAGE_SIZE` upstream in `decode_message`.
    let mut cursor = std::io::Cursor::new(framed.payload.as_slice());
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|_| ProtocolError::WireProtocol("boot request: bad CBOR"))?;
    if cursor.position() as usize != framed.payload.len() {
        return Err(ProtocolError::WireProtocol("boot request: trailing bytes after CBOR"));
    }
    let Value::Map(map) = value else {
        return Err(ProtocolError::WireProtocol("boot request: payload is not a CBOR map"));
    };
    if !check_strict_keys(&map, |n| (1..=7).contains(&n)) {
        return Err(ProtocolError::WireProtocol("boot request: unexpected/missing/duplicate key"));
    }
    let req_u64 = |k: u64| map_get(&map, k).and_then(as_u64).ok_or(ProtocolError::WireProtocol("boot request: bad uint"));
    if req_u64(1)? != RELAY_REQUEST_VERSION {
        return Err(ProtocolError::WireProtocol("boot request: unsupported version"));
    }
    let chain_id = req_u64(2)?;
    let environment_identifier = match map_get(&map, 3) {
        Some(Value::Text(s)) => s.clone(),
        _ => return Err(ProtocolError::WireProtocol("boot request: env must be text")),
    };
    let nonce = map_get(&map, 4).and_then(as_bytes_n::<32>).ok_or(ProtocolError::WireProtocol("boot request: nonce must be 32 bytes"))?;
    let report_data = map_get(&map, 5).and_then(as_bytes_n::<64>).ok_or(ProtocolError::WireProtocol("boot request: report_data must be 64 bytes"))?;
    // Check each large field's length on the borrowed slice BEFORE cloning, so an over-large field is
    // rejected without a second owned allocation.
    let quote_slice = map_get(&map, 6).and_then(as_bytes).ok_or(ProtocolError::WireProtocol("boot request: quote_report must be bytes"))?;
    if quote_slice.len() > MAX_QUOTE_REPORT_LEN {
        return Err(ProtocolError::WireProtocol("boot request: quote_report too large"));
    }
    let cert_slice = map_get(&map, 7).and_then(as_bytes).ok_or(ProtocolError::WireProtocol("boot request: cert_chain must be bytes"))?;
    if cert_slice.len() > crate::snp_report::MAX_CERT_CHAIN_LEN {
        return Err(ProtocolError::WireProtocol("boot request: cert_chain too large"));
    }
    let quote_report = quote_slice.to_vec();
    let cert_chain = cert_slice.to_vec();
    // Bind the cleartext (chain, env, nonce) to the quote commitment.
    let expected = crate::agent_anchor::anchor_handshake_report_data(chain_id, &environment_identifier, &nonce);
    if report_data != expected {
        return Err(ProtocolError::WireProtocol("boot request: report_data inconsistent with (chain,env,nonce)"));
    }
    Ok(DecodedBootRequest {
        chain_id,
        environment_identifier,
        nonce,
        report_data,
        quote_report,
        cert_chain,
    })
}

/// 5b-2e raw-marks request the enclave writes on the `AdoptForward` path. Borrows the scope so it
/// shares the `&body.config` lifetime; carries the SAME fresh nonce + the adopted epoch, **NO quote**.
pub(crate) struct AnchorMarksRequest<'a> {
    pub chain_id: u64,
    pub environment_identifier: &'a str,
    pub nonce: [u8; 32],
    pub epoch: u64,
}

/// Owned, decoded marks request — for the untrusted **host relay** (it peeks the type, validates, and
/// forwards). NOT an enclave trust boundary (the enclave only encodes the request + verifies the
/// signed response); hardened anyway, mirroring [`DecodedBootRequest`].
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 5b/8 (consumed by the relay + tests)
#[derive(Debug)]
pub(crate) struct DecodedMarksRequest {
    pub chain_id: u64,
    pub environment_identifier: String,
    pub nonce: [u8; 32],
    pub epoch: u64,
}

/// Encode a 5b-2e raw-marks request frame: a canonical int-keyed CBOR map (keys 1..=5) under a
/// [`crate::MessageType::AgentAnchorMarksRelay`] (`0x44`) frame. NO quote/cert (the attestation was
/// bound on the `0x41` leg this attempt). Built with the same canonical encoders so a conformant
/// anchor recomputes identical bytes.
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 5b/8 (consumed by the transport seam, commit 6)
pub(crate) fn encode_anchor_marks_request(
    request: &AnchorMarksRequest,
) -> Result<Vec<u8>, ProtocolError> {
    use crate::agent_capability::{put_bytes, put_text, put_uint};
    let mut payload = Vec::with_capacity(96 + request.environment_identifier.len());
    put_uint(&mut payload, 5, 5); // map header: 5 pairs
    put_uint(&mut payload, 0, 1);
    put_uint(&mut payload, 0, MARKS_REQUEST_VERSION);
    put_uint(&mut payload, 0, 2);
    put_uint(&mut payload, 0, request.chain_id);
    put_uint(&mut payload, 0, 3);
    put_text(&mut payload, request.environment_identifier);
    put_uint(&mut payload, 0, 4);
    put_bytes(&mut payload, &request.nonce);
    put_uint(&mut payload, 0, 5);
    put_uint(&mut payload, 0, request.epoch);
    crate::encode_message(crate::MessageType::AgentAnchorMarksRelay, &payload)
}

/// Decode + validate a 5b-2e marks request frame (for the untrusted host relay + tests). Lenient
/// ciborium decode is fine (no quote/cert; not signature-bound — the enclave verifies only the
/// RESPONSE), but the shape is strictly enforced: `0x44` type, integer keys exactly `{1..=5}` no dup,
/// version `== 1`, exact-length nonce (32). Every failure is [`ProtocolError::WireProtocol`].
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 5b/8 (consumed by the relay branch, host_anchor_relay)
pub(crate) fn decode_anchor_marks_request(frame: &[u8]) -> Result<DecodedMarksRequest, ProtocolError> {
    use crate::agent_cbor::{as_bytes_n, as_u64, check_strict_keys, map_get};
    use ciborium::value::Value;

    let framed = crate::decode_message(frame)?;
    if framed.msg_type != crate::MessageType::AgentAnchorMarksRelay {
        return Err(ProtocolError::WireProtocol("not an AGENT_ANCHOR_MARKS_RELAY frame"));
    }
    let mut cursor = std::io::Cursor::new(framed.payload.as_slice());
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|_| ProtocolError::WireProtocol("marks request: bad CBOR"))?;
    if cursor.position() as usize != framed.payload.len() {
        return Err(ProtocolError::WireProtocol("marks request: trailing bytes after CBOR"));
    }
    let Value::Map(map) = value else {
        return Err(ProtocolError::WireProtocol("marks request: payload is not a CBOR map"));
    };
    if !check_strict_keys(&map, |n| (1..=5).contains(&n)) {
        return Err(ProtocolError::WireProtocol("marks request: unexpected/missing/duplicate key"));
    }
    let req_u64 = |k: u64| map_get(&map, k).and_then(as_u64).ok_or(ProtocolError::WireProtocol("marks request: bad uint"));
    if req_u64(1)? != MARKS_REQUEST_VERSION {
        return Err(ProtocolError::WireProtocol("marks request: unsupported version"));
    }
    let chain_id = req_u64(2)?;
    let environment_identifier = match map_get(&map, 3) {
        Some(Value::Text(s)) => s.clone(),
        _ => return Err(ProtocolError::WireProtocol("marks request: env must be text")),
    };
    let nonce = map_get(&map, 4).and_then(as_bytes_n::<32>).ok_or(ProtocolError::WireProtocol("marks request: nonce must be 32 bytes"))?;
    let epoch = req_u64(5)?;
    Ok(DecodedMarksRequest { chain_id, environment_identifier, nonce, epoch })
}

/// Only commit-request-format version this build understands.
const COMMIT_REQUEST_VERSION: u64 = 1;

/// The per-op COMMIT request the enclave writes on a rollback-sensitive op (TASK-7.7 slice 6). Borrows
/// the scope so it shares the `&body.config` lifetime; carries the PROPOSED post-op state (new
/// `epoch`/`structural_version` + the post-op `marks_digest`), the fresh per-op `nonce`, and the op's
/// `request_id` — **NO quote** (the attestation was bound on the `0x41` boot leg; serve-time ops run
/// after a verified boot). The anchor durably records this and returns a signed ACK.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1; consumed by the 6-3 transport seam
pub(crate) struct AnchorCommitRequest<'a> {
    pub chain_id: u64,
    pub environment_identifier: &'a str,
    pub new_epoch: u64,
    pub new_structural_version: u64,
    pub marks_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub request_id: &'a [u8],
}

/// Owned, decoded commit request — for the untrusted **host relay** (it peeks the type, validates, and
/// forwards). NOT an enclave trust boundary (the enclave only encodes the request + verifies the signed
/// ACK); hardened anyway, mirroring [`DecodedMarksRequest`].
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1 (consumed by the relay branch + tests)
#[derive(Debug)]
pub(crate) struct DecodedCommitRequest {
    pub chain_id: u64,
    pub environment_identifier: String,
    pub new_epoch: u64,
    pub new_structural_version: u64,
    pub marks_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub request_id: Vec<u8>,
}

/// Encode a slice-6 commit-request frame: a canonical int-keyed CBOR map (keys 1..=8) under a
/// [`crate::MessageType::AgentAnchorCommitRelay`] (`0x45`) frame. NO quote/cert. Built with the same
/// canonical encoders so a conformant anchor recomputes identical preimage bytes for its ACK signature.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1; consumed by the 6-3 transport seam
pub(crate) fn encode_anchor_commit_request(
    request: &AnchorCommitRequest,
) -> Result<Vec<u8>, ProtocolError> {
    use crate::agent_capability::{put_bytes, put_text, put_uint};
    // Defense-in-depth: reject an over-cap request_id at ENCODE — the decoder + ack verifier enforce the
    // same MAX_REQUEST_ID_LEN, so an over-cap internal caller would otherwise mint a frame this crate
    // later rejects. Fail-closed before allocating.
    if request.request_id.len() > crate::agent_dispatch::MAX_REQUEST_ID_LEN {
        return Err(ProtocolError::WireProtocol("commit request: request_id exceeds MAX_REQUEST_ID_LEN"));
    }
    let mut payload = Vec::with_capacity(160 + request.environment_identifier.len() + request.request_id.len());
    put_uint(&mut payload, 5, 8); // map header: 8 pairs
    put_uint(&mut payload, 0, 1);
    put_uint(&mut payload, 0, COMMIT_REQUEST_VERSION);
    put_uint(&mut payload, 0, 2);
    put_uint(&mut payload, 0, request.chain_id);
    put_uint(&mut payload, 0, 3);
    put_text(&mut payload, request.environment_identifier);
    put_uint(&mut payload, 0, 4);
    put_uint(&mut payload, 0, request.new_epoch);
    put_uint(&mut payload, 0, 5);
    put_uint(&mut payload, 0, request.new_structural_version);
    put_uint(&mut payload, 0, 6);
    put_bytes(&mut payload, &request.marks_digest);
    put_uint(&mut payload, 0, 7);
    put_bytes(&mut payload, &request.nonce);
    put_uint(&mut payload, 0, 8);
    put_bytes(&mut payload, request.request_id);
    crate::encode_message(crate::MessageType::AgentAnchorCommitRelay, &payload)
}

/// Decode + validate a slice-6 commit request frame (for the untrusted host relay + tests). Lenient
/// ciborium decode is fine (not signature-bound — the enclave verifies only the ACK), but the shape is
/// strictly enforced: `0x45` type, integer keys exactly `{1..=8}` no dup, version `== 1`, exact-length
/// marks_digest+nonce (32), `request_id` ≤ [`crate::agent_dispatch::MAX_REQUEST_ID_LEN`]. Every failure
/// is [`ProtocolError::WireProtocol`].
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1 (consumed by the relay branch, host_anchor_relay)
pub(crate) fn decode_anchor_commit_request(frame: &[u8]) -> Result<DecodedCommitRequest, ProtocolError> {
    use crate::agent_cbor::{as_bytes, as_bytes_n, as_u64, check_strict_keys, map_get};
    use ciborium::value::Value;

    let framed = crate::decode_message(frame)?;
    if framed.msg_type != crate::MessageType::AgentAnchorCommitRelay {
        return Err(ProtocolError::WireProtocol("not an AGENT_ANCHOR_COMMIT_RELAY frame"));
    }
    let mut cursor = std::io::Cursor::new(framed.payload.as_slice());
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|_| ProtocolError::WireProtocol("commit request: bad CBOR"))?;
    if cursor.position() as usize != framed.payload.len() {
        return Err(ProtocolError::WireProtocol("commit request: trailing bytes after CBOR"));
    }
    let Value::Map(map) = value else {
        return Err(ProtocolError::WireProtocol("commit request: payload is not a CBOR map"));
    };
    if !check_strict_keys(&map, |n| (1..=8).contains(&n)) {
        return Err(ProtocolError::WireProtocol("commit request: unexpected/missing/duplicate key"));
    }
    let req_u64 = |k: u64| map_get(&map, k).and_then(as_u64).ok_or(ProtocolError::WireProtocol("commit request: bad uint"));
    if req_u64(1)? != COMMIT_REQUEST_VERSION {
        return Err(ProtocolError::WireProtocol("commit request: unsupported version"));
    }
    let chain_id = req_u64(2)?;
    let environment_identifier = match map_get(&map, 3) {
        Some(Value::Text(s)) => s.clone(),
        _ => return Err(ProtocolError::WireProtocol("commit request: env must be text")),
    };
    let new_epoch = req_u64(4)?;
    let new_structural_version = req_u64(5)?;
    let marks_digest = map_get(&map, 6).and_then(as_bytes_n::<32>).ok_or(ProtocolError::WireProtocol("commit request: marks_digest must be 32 bytes"))?;
    let nonce = map_get(&map, 7).and_then(as_bytes_n::<32>).ok_or(ProtocolError::WireProtocol("commit request: nonce must be 32 bytes"))?;
    let request_id = match map_get(&map, 8).and_then(as_bytes) {
        Some(b) if b.len() <= crate::agent_dispatch::MAX_REQUEST_ID_LEN => b.to_vec(),
        _ => return Err(ProtocolError::WireProtocol("commit request: request_id missing or over cap")),
    };
    Ok(DecodedCommitRequest {
        chain_id,
        environment_identifier,
        new_epoch,
        new_structural_version,
        marks_digest,
        nonce,
        request_id,
    })
}

/// Why a per-op anchor COMMIT failed — coarse, always-FAIL-CLOSED band (slice 6). On ANY variant the
/// caller MUST fail the op closed: no seal, no signature/refs emitted (seal-before-emit; there is no
/// offline window for fund custody). No "retryable vs terminal" split at this layer — a failed commit
/// means the op did NOT durably commit, full stop.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-3; consumed by the 6-4 dispatch wiring
#[derive(Debug)]
pub(crate) enum CommitFailure {
    /// The 0x45 request frame could not be encoded (e.g. over-cap request_id).
    Encode,
    /// The channel round-trip failed — anchor unreachable / relay dropped the leg / timeout.
    Transport(AnchorTransportError),
    /// The signed ACK did not verify against the proposed values (forged / replayed / scope / nonce /
    /// epoch / structural / marks / request_id mismatch — the anchor did not durably record what was
    /// proposed).
    Ack(crate::agent_anchor::CommitAckError),
}

/// The enclave-PROPOSED post-op state for ONE per-op anchor commit (slice 6). The 0x45 request the
/// enclave SENDS and the values the ACK must ECHO are BOTH built from this one struct (in
/// [`run_anchor_commit`]), so they cannot diverge.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-3; consumed by the 6-4 dispatch wiring
pub(crate) struct AnchorCommit<'a> {
    pub chain_id: u64,
    pub environment_identifier: &'a str,
    pub new_epoch: u64,
    pub new_structural_version: u64,
    pub marks_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub request_id: &'a [u8],
}

/// slice 6-3: run ONE per-op anchor commit round-trip over a [`BootRelayChannel`] — encode the 0x45
/// request, send it (fresh-conn, deadline-bounded, 4096-cap read — the ACK is small), and verify the
/// signed ACK against the proposed values via [`crate::agent_anchor::verify_commit_ack_bytes`]. Returns
/// `Ok(())` ONLY when the anchor durably recorded EXACTLY the proposed `(epoch, structural, marks)` under
/// the op's `nonce` + `request_id` — that `Ok(())` is the seal-before-emit GO signal. ANY failure
/// ([`CommitFailure`]) ⇒ the caller fails the op CLOSED (no seal, no emit). Pure over the channel seam:
/// the request and the expected-ack are built from the ONE [`AnchorCommit`], so a drift is unrepresentable.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-3; consumed by the 6-4 dispatch wiring
pub(crate) fn run_anchor_commit<C: BootRelayChannel>(
    channel: &mut C,
    commit: &AnchorCommit,
    config: &crate::agent_keystore::KeystoreConfig,
    deadline: std::time::Instant,
) -> Result<(), CommitFailure> {
    let frame = encode_anchor_commit_request(&AnchorCommitRequest {
        chain_id: commit.chain_id,
        environment_identifier: commit.environment_identifier,
        new_epoch: commit.new_epoch,
        new_structural_version: commit.new_structural_version,
        marks_digest: commit.marks_digest,
        nonce: commit.nonce,
        request_id: commit.request_id,
    })
    .map_err(|_| CommitFailure::Encode)?;
    // The ACK is a fixed-shape signed record; the channel's 4096-cap `round_trip` suffices (NOT the
    // multi-KiB marks cap). Fresh-connection-per-call + deadline-bounded are the channel's obligations.
    let ack = channel.round_trip(&frame, deadline).map_err(CommitFailure::Transport)?;
    crate::agent_anchor::verify_commit_ack_bytes(
        &ack,
        &crate::agent_anchor::ExpectedCommitAck {
            nonce: &commit.nonce,
            epoch: commit.new_epoch,
            structural_version: commit.new_structural_version,
            marks_digest: &commit.marks_digest,
            request_id: commit.request_id,
        },
        config,
    )
    .map_err(CommitFailure::Ack)?;
    Ok(())
}

/// Read the anchor response off a stream: a single 4-byte BE length prefix then exactly that many raw
/// anchor-signed bytes (no version/type framing — the relay forwards exactly what the anchor signed).
/// The length is checked against [`MAX_ANCHOR_RESPONSE_LEN`] **before** allocating, so a hostile relay
/// cannot force a large alloc. Returns the raw bytes verbatim for the driver to verify — this helper
/// never parses anchor internals.
///
/// **Deadline precondition (5b-2b):** the `deadline` is only enforceable if `reader`'s underlying socket
/// is configured with a read timeout (`SO_RCVTIMEO`) or non-blocking mode — the deadline is re-checked
/// between/around `read` syscalls, but a fully-blocking `read` that never returns is not interruptible
/// here. `VsockBootRelayChannel` satisfies this via `DeadlineSocket` (both Linux/vsock-gated), which
/// reapplies `SO_RCVTIMEO`/`SO_SNDTIMEO` = the remaining budget before every read/write (connect is a
/// separate hard, cancellable bound — obligation (a'), DONE: non-blocking connect + `poll(POLLOUT)` to the
/// deadline, see `connect_bounded` — not intra-doc-linked: that item is vsock-gated narrower than this one).
/// Its `#[ignore]` aya tests verify the bound **behaviorally** — `SO_RCVTIMEO` via a stalled-peer read that
/// times out within budget, the connect bound via a prompt connect-failure — and **directly**: the
/// blocking-mode + readback aya test asserts `O_NONBLOCK` is cleared after connect and reads the armed
/// `SO_RCVTIMEO`/`SO_SNDTIMEO` values back via SAFE `nix` getsockopt (`sockopt::ReceiveTimeout`/
/// `SendTimeout`, enabled by the same `socket` feature the connect bound uses — the old "readback would
/// need `unsafe`/`libc`" limitation is gone).
pub(crate) fn read_bounded_anchor_response<R: std::io::Read>(
    reader: &mut R,
    deadline: std::time::Instant,
) -> Result<Vec<u8>, ProtocolError> {
    read_bounded_response_cap(reader, deadline, MAX_ANCHOR_RESPONSE_LEN)
}

/// 5b-2e: read a length-prefixed raw response bounded by an EXPLICIT `cap` (cap-before-alloc). The
/// freshness leg passes [`MAX_ANCHOR_RESPONSE_LEN`] (4096, unchanged); the marks leg passes
/// [`MAX_MARKS_RESPONSE_LEN`]. The cap is a parameter — NOT a single shared constant raised for both —
/// so the freshness-path DoS bound stays tight.
pub(crate) fn read_bounded_response_cap<R: std::io::Read>(
    reader: &mut R,
    deadline: std::time::Instant,
    cap: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    crate::read_exact_with_idle_deadline(reader, &mut len_buf, Some(deadline))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > cap {
        return Err(ProtocolError::WireProtocol("anchor response too large"));
    }
    let mut body = vec![0u8; len];
    crate::read_exact_with_idle_deadline(reader, &mut body, Some(deadline))?;
    Ok(body)
}

/// Frame an anchor response for the wire: a single 4-byte BE length prefix + the raw signed bytes. The
/// canonical writer — shared by the host-relay daemon (5b-2b) and the tests so the response framing is a
/// FUNCTION, not prose, preventing a BE/LE or prefix-inclusion drift between the writer and
/// [`read_bounded_anchor_response`]. Rejects a response over [`MAX_ANCHOR_RESPONSE_LEN`] (the reader
/// would reject it anyway — fail at the source).
pub(crate) fn frame_anchor_response(response_bytes: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    frame_response_cap(response_bytes, MAX_ANCHOR_RESPONSE_LEN)
}

/// 5b-2e: frame a length-prefixed raw response bounded by an EXPLICIT `cap` (the marks leg passes
/// [`MAX_MARKS_RESPONSE_LEN`]; the freshness leg keeps 4096). Sibling of [`read_bounded_response_cap`].
pub(crate) fn frame_response_cap(response_bytes: &[u8], cap: usize) -> Result<Vec<u8>, ProtocolError> {
    if response_bytes.len() > cap {
        return Err(ProtocolError::WireProtocol("anchor response too large to frame"));
    }
    let mut out = Vec::with_capacity(4 + response_bytes.len());
    out.extend_from_slice(&(response_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(response_bytes);
    Ok(out)
}

/// The raw enclave-initiated round-trip seam. ONE method; the real (5b-2b) impl over vsock. Obligations
/// (load-bearing): (a) **fresh connection per call**, dropped on return (stale-reply isolation); (b)
/// bound connect+write+read by `deadline` (one budget); (c) read the response via
/// [`read_bounded_anchor_response`] (cap-before-alloc). Every failure maps to the coarse,
/// always-retryable [`AnchorTransportError`] — the channel cannot smuggle a terminal/serve signal.
pub(crate) trait BootRelayChannel {
    fn round_trip(
        &mut self,
        request_frame: &[u8],
        deadline: std::time::Instant,
    ) -> Result<Vec<u8>, AnchorTransportError>;

    /// 5b-2e: the raw-marks round-trip — identical obligations to [`round_trip`], but the response is
    /// bounded by [`MAX_MARKS_RESPONSE_LEN`] (a marks payload is multi-KiB) instead of the 4096
    /// freshness cap. Used ONLY on the `AdoptForward` path.
    fn marks_round_trip(
        &mut self,
        request_frame: &[u8],
        deadline: std::time::Instant,
    ) -> Result<Vec<u8>, AnchorTransportError>;
}

/// The SNP-quote seam: fetch a quote committing to `report_data`, returning `(report, cert_chain)`. The
/// PRODUCTION impl is `HardBoundedQuoteProducer` ((d-ii)/2, `quote_subprocess` — see the hard-bound
/// paragraph below; the cooperative `SnpQuoteProducer` was deleted in (4a)); the test fake records the
/// `report_data` it was handed (proving the quote↔nonce binding).
///
/// **`deadline` bounds the quote fetch's own wall-clock** (`RelayAnchorTransport` gives this leg its own
/// `timeout` budget, separate from the channel's, so a wedged sev-guest/configfs provider can't starve
/// the channel's budget). `fetch` MUST honor it and return [`ProtocolError`] (→ retryable
/// `AnchorTransportError`) rather than block past it.
///
/// **The hard bound EXISTS ((d-ii)/2):** `HardBoundedQuoteProducer` in `quote_subprocess` (triple-gated
/// `linux + vsock-transport + agent-gateway`; plain-text reference — the type does not exist in every
/// build that has this trait). Its `fetch` IS the killable-subprocess orchestration: spawn → pipe-poll
/// to the seam-minted absolute deadline → SIGKILL at the lapse → bounded reap → abandoned-child ledger.
///
/// **`&mut self` (load-bearing):** the production impl owns process-level mutable state — THE one
/// abandoned-child ledger, whose budget binds only under strictly-serial fetches (§8 pin). The
/// exclusive borrow makes the single-mutator rule a borrow-checker fact and is uniform with the
/// sibling seams ([`BootRelayChannel::round_trip`], `AnchorBootTransport::anchor_round_trip`). NOT
/// interior mutability by design: a `Mutex` held across a multi-second blocking pipe poll would make
/// a second caller block UNBOUNDED on `lock()` — violating this very deadline contract — and a panic
/// mid-sweep poisons the ledger into unprovable budget accounting; `RefCell` trades the compile-time
/// proof for a latent runtime borrow panic.
///
/// **Best-effort caveat — RETIRED in (4a):** the cooperative impl (`SnpQuoteProducer`, honoring the
/// deadline only *between* configfs steps) is DELETED. A single wedged in-kernel `read(outblob)` is not
/// interruptible under `#![forbid(unsafe_code)]`, so NO in-process impl can satisfy this trait's
/// deadline contract — any new impl must deliver a cancellable hard bound (the killable subprocess).
pub(crate) trait BootQuoteProducer {
    fn fetch(
        &mut self,
        report_data: &[u8; 64],
        deadline: std::time::Instant,
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError>;
}

/// The concrete [`AnchorBootTransport`] for the 5b-1 driver: compose quote-fetch → request-encode →
/// channel round-trip, returning the anchor's response bytes verbatim. Monomorphized over the two seams
/// (no `dyn`); (4b)/5b-2c instantiates it with `Q = HardBoundedQuoteProducer` (plain-text reference —
/// triple-gated type) and `C = VsockBootRelayChannel`.
///
/// `timeout` is a **per-leg** budget: the quote fetch AND the channel round-trip each get their own
/// `Instant::now() + timeout` deadline, so one freshness attempt is bounded by ≤ `2·timeout + ε`
/// wall-clock (ε = the quote-subprocess dispose overhead, `QUOTE_ATTEMPT_OVERHEAD`). An attempt that
/// adopts (5b-2e) runs a THIRD bounded leg — the `marks_round_trip` — so its worst case is
/// `3·timeout + ε`; the driver's `max_attempts` count bound caps total boot at
/// `max_attempts · (3·timeout + ε)` — the ε term is load-bearing, §8: the ε-less product is NOT a valid
/// ceiling. The single-budget model is final for 5b-2b; splitting
/// into distinct `quote_timeout` / `relay_timeout` is deferred to 5b-2c (see §8). The bound is HARD
/// once (4b) wires `HardBoundedQuoteProducer` ((d-ii)/2 — landed); (4a) deleted the only cooperative
/// impl (`SnpQuoteProducer`) — SCOPE HONESTLY: that deletes the TYPE, not the CLASS (the trait stays
/// open and `new` reachable, so an in-crate unbounded shim would still compile); the production door
/// that names the concrete producer is `ValidatedBootBudget::transport_with_spawn` (the shared mint;
/// `production_transport` is its production-spawn instantiation), consumed by the (4b) wired entry
/// `run_boot_handshake_wired` (`agent_gateway_boot`, plain-text reference — triple-gated module),
/// guarded by the §8 never-generic-Q rule.
pub(crate) struct RelayAnchorTransport<Q: BootQuoteProducer, C: BootRelayChannel> {
    quote: Q,
    channel: C,
    timeout: std::time::Duration,
}

impl<Q: BootQuoteProducer, C: BootRelayChannel> RelayAnchorTransport<Q, C> {
    /// `new` stays Duration-typed and reachable for in-crate fakes/tests (it also compiles in
    /// agent-gateway-without-vsock builds where `ValidatedBootBudget` does not exist — the
    /// cfg-lattice fact); the PRODUCTION path's exclusivity through the validated budget is
    /// `ValidatedBootBudget::production_transport` (quote_subprocess, plain-text reference) + the
    /// (4b) discharge — same residual class as `ExecChildSpawn`'s pub(crate) fields, now also
    /// carried by the shared mint `transport_with_spawn` (any new caller is a review flag).
    pub(crate) fn new(quote: Q, channel: C, timeout: std::time::Duration) -> Self {
        Self { quote, channel, timeout }
    }

    /// Test-only pin accessor for the (d-ii)/3 composition test (deadline origination). Gated to
    /// exactly the combos where `ValidatedBootBudget` exists: the inner cfg below contributes
    /// `test + linux + vsock-transport`, and the ENCLOSING MODULE is `agent-gateway`-gated
    /// (lib.rs), completing the triple — the same outer/inner split as the `agent_dispatch` reset
    /// hook. So `cargo test --features agent-gateway` (CI) sees no dead code, and a
    /// `linux+vsock-transport`-without-`agent-gateway` build never compiles this file at all.
    #[cfg(all(test, target_os = "linux", feature = "vsock-transport"))]
    pub(crate) fn per_leg_timeout_for_tests(&self) -> std::time::Duration {
        self.timeout
    }
}

impl<Q: BootQuoteProducer, C: BootRelayChannel> AnchorBootTransport for RelayAnchorTransport<Q, C> {
    fn anchor_round_trip(
        &mut self,
        request: &AnchorBootRequest,
    ) -> Result<Vec<u8>, AnchorTransportError> {
        // Each leg gets its OWN `timeout` budget (a fresh deadline computed just before it runs), so quote
        // latency does NOT eat into the channel's budget (no false channel timeout). The quote leg's hard
        // bound EXISTS ((d-ii)/2): `HardBoundedQuoteProducer` kills a wedged child at this deadline, so
        // with it the `2×timeout(+ε)` per-attempt bound holds — and the boot-budget validation artifact
        // EXISTS too ((d-ii)/3, `ValidatedBootBudget`; its `transport_with_spawn` mint — of which
        // `production_transport` is the production-spawn instantiation — is the production
        // construction path for THIS type, threading the validated per-leg value into `timeout`, which
        // also keeps the `Instant::now() + self.timeout` mints below panic-free via the
        // MAX_PER_LEG_TIMEOUT sanity arm — an in-crate test caller bypassing the budget owns that
        // hazard itself). Wired at (4b) by `run_boot_handshake_wired` (agent_gateway_boot); live serve
        // still gated on (4c) + 5b-2c (witness from operator config); the cooperative
        // producer is GONE ((4a)) — nothing best-effort remains wireable.
        // The channel leg IS hard-bounded by its deadline + the socket `SO_*TIMEO`. The driver bounds
        // the attempt COUNT on top.
        let (report, cert_chain) = self
            .quote
            .fetch(&request.report_data, std::time::Instant::now() + self.timeout)
            .map_err(|_| AnchorTransportError("anchor relay: SNP quote fetch failed"))?;
        let frame = encode_anchor_boot_request(&report, &cert_chain, request)
            .map_err(|_| AnchorTransportError("anchor relay: request encode failed"))?;
        // The returned bytes are UNTRUSTED and returned verbatim — verified downstream by the driver.
        self.channel.round_trip(&frame, std::time::Instant::now() + self.timeout)
    }

    fn marks_round_trip(
        &mut self,
        request: &AnchorMarksRequest,
    ) -> Result<Vec<u8>, AnchorTransportError> {
        // The marks leg carries NO quote (the attestation was bound on the freshness leg this attempt),
        // so it is a pure channel round-trip under its OWN `timeout` budget — no quote-fetch sub-leg.
        let frame = encode_anchor_marks_request(request)
            .map_err(|_| AnchorTransportError("anchor relay: marks request encode failed"))?;
        self.channel.marks_round_trip(&frame, std::time::Instant::now() + self.timeout)
    }
}

/// Write `bytes` then flush `stream`, checking `deadline` before **both** the `write_all` AND the `flush`
/// — each is potentially-blocking I/O, so a budget that lapsed during the write must not even initiate the
/// flush. `what` localizes which leg tripped. The single shared writer used by both relay cores, so the
/// "guard before every potentially-blocking write op" contract can't drift between them. (A blocking op
/// already in flight is still bounded only by the socket `SO_SNDTIMEO` — a 5b-2b-ii obligation; this just
/// avoids *initiating* a doomed write/flush.)
///
/// **Variant caveat (5b-2b-ii):** a deadline lapse returns `ProtocolError::WireProtocol(..)` — whose name
/// reads as "malformed", but here it is a *timeout*. Per the [`BootRelayChannel`] contract every failure
/// maps to the always-retryable `AnchorTransportError`, so `VsockBootRelayChannel` MUST map ALL
/// `ProtocolError` from these cores to a retryable transport close — do NOT key terminal-vs-retryable off
/// the `ProtocolError` variant (else a timeout becomes a terminal `VerifyMalformed`, burning the budget).
pub(crate) fn deadline_guarded_write<W: std::io::Write>(
    stream: &mut W,
    bytes: &[u8],
    deadline: std::time::Instant,
    what: &'static str,
) -> Result<(), ProtocolError> {
    if std::time::Instant::now() >= deadline {
        return Err(ProtocolError::WireProtocol(what));
    }
    stream.write_all(bytes).map_err(ProtocolError::from)?;
    if std::time::Instant::now() >= deadline {
        return Err(ProtocolError::WireProtocol(what));
    }
    stream.flush().map_err(ProtocolError::from)
}

/// The channel **framing core** (TASK-7.7 5b-2b): write the already-framed `request_frame` to a duplex
/// `stream`, then bounded-read the anchor response. Generic over `Read + Write` so it is CI-tested over an
/// in-memory duplex — the real `VsockBootRelayChannel` (5b-2b-ii, `vsock-transport`) is a thin wrapper
/// that connects a `VsockStream`, sets the socket timeouts, and calls this.
///
/// **Deadline coverage:** via [`deadline_guarded_write`] this fn checks the deadline before the write AND
/// before the flush, and the bounded read enforces it across reads. The blocking `write_all`/`flush`
/// op *already in flight* is bounded ONLY by the socket's `SO_SNDTIMEO` (and the read by `SO_RCVTIMEO`) —
/// so 5b-2b-ii's wrapper MUST set BOTH (+ a connect timeout) for the per-attempt wall-clock to actually
/// hold against a black-holing relay; the in-fn checks bound only *initiating* a write/flush, not a stalled
/// in-kernel one. `request_frame` is ALREADY a complete `0x41` frame — written verbatim, never re-framed.
/// Returns the raw response bytes for the driver to verify (never parsed here).
pub(crate) fn relay_round_trip_over_stream<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    request_frame: &[u8],
    deadline: std::time::Instant,
) -> Result<Vec<u8>, ProtocolError> {
    relay_round_trip_over_stream_cap(stream, request_frame, deadline, MAX_ANCHOR_RESPONSE_LEN)
}

/// 5b-2e: [`relay_round_trip_over_stream`] with an EXPLICIT response cap — the marks (`0x44`) leg passes
/// [`MAX_MARKS_RESPONSE_LEN`]; the freshness (`0x41`) leg keeps the 4096 default. Same deadline-guarded
/// write + cap-before-alloc read; only the cap differs, so the freshness DoS bound stays tight.
pub(crate) fn relay_round_trip_over_stream_cap<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    request_frame: &[u8],
    deadline: std::time::Instant,
    cap: usize,
) -> Result<Vec<u8>, ProtocolError> {
    deadline_guarded_write(stream, request_frame, deadline, "anchor relay: deadline before write")?;
    read_bounded_response_cap(stream, deadline, cap)
}

/// The host-relay **forward core** (TASK-7.7 5b-2b): the one enclave↔anchor pump the host relay daemon
/// loops on. Generic over both stream sides so it is CI-tested over in-memory duplexes; the daemon bin
/// (5b-2b-ii) supplies the real vsock (enclave) + upstream-anchor (TCP/UDS) streams. Reads the `0x41`
/// request frame from the enclave, **rejects a malformed request before spending an anchor round-trip**
/// (defense-in-depth — the relay is untrusted but a malformed forward would just burn the enclave's
/// attempt budget on a terminal verify failure), forwards the frame verbatim to the anchor, reads the
/// raw signed response (bounded), and writes it back to the enclave via the shared
/// [`frame_anchor_response`] writer (so the two sides can't drift on the response framing). The relay
/// never parses/trusts the anchor response — verification is entirely in the enclave.
///
/// This is **HOST-side, untrusted** code — NOT an enclave trust boundary; the enclave's own per-leg
/// channel deadline + downstream verification are what protect custody. The single `deadline` here spans
/// the WHOLE pump (enclave read + anchor write + anchor read). The deadline is checked at every read AND
/// **before each `write_all`/`flush` leg** (so a lapsed budget never even initiates a write — symmetric
/// with `relay_round_trip_over_stream`); the daemon (5b-2b-ii) must still set `SO_RCVTIMEO`/`SO_SNDTIMEO`
/// on BOTH the enclave- and anchor-facing sockets, since the in-fn check bounds only *initiating* a write
/// — a black-holing peer that stalls a write already in flight is bounded only by `SO_SNDTIMEO`.
pub(crate) fn relay_forward_once<E, A>(
    enclave: &mut E,
    anchor: &mut A,
    deadline: std::time::Instant,
) -> Result<(), ProtocolError>
where
    E: std::io::Read + std::io::Write,
    A: std::io::Read + std::io::Write,
{
    let frame = crate::read_framed_message_with_idle_deadline(enclave, Some(deadline))?;
    let _ = decode_anchor_boot_request(&frame)?; // reject malformed BEFORE an anchor round-trip
    // Both write legs go through `deadline_guarded_write` (checks the budget before the write AND the
    // flush) — same contract as `relay_round_trip_over_stream`: a budget that lapsed during the enclave
    // read / anchor read never initiates another write, so the daemon turns it into a retryable close.
    deadline_guarded_write(anchor, &frame, deadline, "anchor relay: deadline before anchor write")?;
    let response = read_bounded_anchor_response(anchor, deadline)?;
    let wire = frame_anchor_response(&response)?;
    deadline_guarded_write(enclave, &wire, deadline, "anchor relay: deadline before enclave write")
}

/// The production [`BootRelayChannel`] over AF_VSOCK (TASK-7.7 5b-2b-ii(a)). Gated
/// `all(target_os = "linux", feature = "vsock-transport")` because it pulls the Linux-only `vsock` crate;
/// dead-code until the 5b-2c bin constructs it. It is the thin platform leaf over the CI-proven
/// [`relay_round_trip_over_stream`]: open a **fresh** `VsockStream` to the host relay endpoint
/// `(VMADDR_CID_HOST, port)`, set deadline-derived socket timeouts, run the round-trip, and drop the
/// connection on return. Every failure folds to the always-retryable [`AnchorTransportError`].
///
/// ## Budget model
/// The single per-leg `deadline` covers connect AND the round-trip I/O **sequentially** (connect first,
/// then the framed exchange share the remaining budget). So a slow-but-successful connect shrinks the I/O
/// budget; for a local host↔guest vsock connect (fast) the I/O leg gets ~the whole budget, but 5b-2c MUST
/// size the per-leg timeout to comfortably cover BOTH a connect and a round-trip. (A connect can consume
/// "nearly the whole budget" — yielding a retryable lapse before I/O, safe but a wasted attempt — only when
/// the per-leg budget is ≲ the kernel's ~2s connect timer below; for longer budgets a wedged connect is
/// kernel-capped at ~2s, so the I/O leg keeps the rest.)
///
/// ## Connect-timeout (hard, cancellable — 5b-2b-ii(a') DONE)
/// The connect leg is bounded by [`connect_bounded`] (the single source for the mechanism — non-blocking
/// connect + `poll_with_deadline(POLLOUT)` to the deadline, no watchdog thread, no leaked fd; see its doc).
/// **Timing note for budget sizing:** the kernel ALSO arms its own per-socket connect timer for
/// non-blocking AF_VSOCK connects (`VSOCK_DEFAULT_CONNECT_TIMEOUT` ≈ 2s; `connect_bounded` does not raise
/// `SO_VM_SOCKETS_CONNECT_TIMEOUT`), which fails a black-holed in-flight connect with `ETIMEDOUT` at ~2s —
/// so a wedged connect leg costs ~`min(per-leg budget, ~2s)`, and the caller's `deadline` is the binding
/// connect bound only when its remaining budget is shorter than the kernel timer. The quote-fetch hard
/// bound (§8 5b-2b-ii(d)) remains the separate open item.
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
pub(crate) struct VsockBootRelayChannel {
    host_cid: u32,
    port: u32,
}

// `remaining_or_lapsed` (the deadline→remaining-budget helper, with the MIN_BOUNDARY_BUDGET floor) now lives
// in `crate::cancellable_boundary` so it is shared with the `poll_with_deadline` cancellable primitive.
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
use crate::cancellable_boundary::remaining_or_lapsed;

/// The connect-leg deadline-LAPSE triage string (single source, 73ddd5d house pattern): emitted by
/// `connect_bounded`'s entry-lapse arm and its poll-lapse relabel arm, asserted by the deviceless
/// relabel test and the (4c) `quote_smoke` vsock-lapse phase. Value frozen by its pin test.
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
pub(crate) const VSOCK_CONNECT_LAPSE_MSG: &str = "anchor relay: vsock connect deadline lapsed";
/// The connect-leg poll-VETO triage string (error-readiness/kernel-`ETIMEDOUT` refusal — the
/// `connect_poll_succeeded` veto arm). Distinct from the lapse string so the (4c) smoke can
/// discriminate "our deadline bound fired" from "the kernel timer/RST preempted us". Value frozen
/// by its pin test.
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
pub(crate) const VSOCK_CONNECT_VETO_MSG: &str = "anchor relay: vsock connect failed (poll)";

/// Open a fresh `VsockStream` to `(host_cid, port)`, with a TRUE cancellable connect bound (5b-2b-ii(a')):
/// a non-blocking `connect` + [`crate::cancellable_boundary::poll_with_deadline`] on `POLLOUT`. On a
/// deadline lapse the `poll` returns and the `OwnedFd` drops in-scope (closing the fd, aborting the
/// connect) — **no watchdog thread, no leaked fd**. Returns a retryable `ProtocolError` on lapse/failure.
/// (The no-leak guarantee relies on the kernel tearing down the in-flight connect when the fd is closed —
/// verified against af_vsock.c: `__vsock_release` forces immediate teardown for a non-established socket
/// and sets `sk_shutdown = SHUTDOWN_MASK`, which neutralizes the pending connect timer; a kernel-internal
/// sock ref may linger ≤ ~2s, but no fd/thread leaks to userspace.)
///
/// **Kernel connect-timer interplay:** for a non-blocking AF_VSOCK connect the kernel arms its own
/// per-socket timer (`vsk->connect_timeout`, default `VSOCK_DEFAULT_CONNECT_TIMEOUT` ≈ 2s; we do not set
/// `SO_VM_SOCKETS_CONNECT_TIMEOUT`). A black-holed in-flight connect therefore fails at ~2s with
/// `sk_err = ETIMEDOUT` → the poll wakes `POLLERR|POLLOUT` → the
/// [`crate::cancellable_boundary::connect_poll_succeeded`] veto fires — BEFORE our `deadline` whenever
/// `deadline > ~2s`. The `poll_with_deadline` lapse arm is the binding bound only for deadlines shorter
/// than the kernel timer. The real-vsock lapse test now lives in `quote_smoke` phase `vsock-lapse`
/// ((4c), in-guest, 400ms deadline via `connect_bounded_for_smoke` — plain-backtick: that shim is
/// QUADRUPLE-gated and this doc compiles in lab-quote-smoke-less builds where a link would dangle) —
/// in-guest is the ONLY place it can live: a HOST-side lapse staging is impossible (host→nonexistent
/// CID fails synchronously `ENODEV` in `vhost_transport_send_pkt` — no `EINPROGRESS`, no black hole).
///
/// The fd is created `SOCK_NONBLOCK` so the connect can be polled; **after** the connect completes it is
/// returned to BLOCKING mode (`set_nonblocking(false)`) so the caller's [`DeadlineSocket`]
/// `SO_RCVTIMEO`/`SO_SNDTIMEO` actually take effect (a non-blocking socket ignores `SO_*TIMEO`) — asserted
/// directly by the blocking-mode/readback aya test. All nix calls (`socket`/`connect`/`getsockopt`) and
/// vsock's `set_nonblocking` are SAFE wrappers — no `unsafe`.
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
fn connect_bounded(
    host_cid: u32,
    port: u32,
    deadline: std::time::Instant,
) -> Result<vsock::VsockStream, ProtocolError> {
    use nix::poll::PollFlags;
    use nix::sys::socket::{
        connect, getsockopt, socket, sockopt::SocketError, AddressFamily, SockFlag, SockType, VsockAddr,
    };
    use std::os::fd::AsRawFd;

    // Upfront deadline check: an already-lapsed deadline at entry is a clean retryable error BEFORE we
    // allocate an fd. Without this, a synchronous `connect` success (`Ok(())`, e.g. vsock loopback) would
    // hand back a live stream whose lapse is only caught later in `DeadlineSocket::arm_*` — restoring the
    // contract that a lapsed deadline at entry fails fast (and avoiding a wasted socket). The connect-leg
    // relabel keeps lapse triage attributable (the shared helper's string is deliberately subsystem-neutral).
    remaining_or_lapsed(deadline).map_err(|_| ProtocolError::WireProtocol(VSOCK_CONNECT_LAPSE_MSG))?;

    // Fresh non-blocking vsock SOCK_STREAM fd. NOT vsock 0.5's `VsockSocket` (that is SOCK_DGRAM).
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|_| ProtocolError::WireProtocol("anchor relay: vsock socket() failed"))?;

    let addr = VsockAddr::new(host_cid, port);
    match connect(fd.as_raw_fd(), &addr) {
        Ok(()) => {} // connected synchronously (uncommon for a non-blocking connect)
        // EINPROGRESS = connect in flight → poll POLLOUT for completion.
        Err(nix::errno::Errno::EINPROGRESS) => {
            // Wait (cancellably) for completion. `poll_with_deadline` returns `Ok(revents)` even for
            // error-readiness (POLLERR/HUP/NVAL), so a bare `Ok(_)` is NOT success —
            // `connect_poll_succeeded` requires POLLOUT AND no error flag. On a deadline lapse it returns
            // Err (relabelled below to keep the connect leg attributable) and `fd` drops below. NB the
            // kernel's own ~2s connect timer usually preempts the lapse for longer deadlines (see fn doc).
            let revents =
                crate::cancellable_boundary::poll_with_deadline(&fd, PollFlags::POLLOUT, deadline)
                    .map_err(|e| match e {
                        // Keep non-lapse poll failures distinct ("poll: syscall error" etc.). The lapse
                        // string is matched via the shared const so a reword in the helper can't silently
                        // turn this arm into dead code (also pinned by the deviceless entry-lapse test).
                        ProtocolError::WireProtocol(crate::cancellable_boundary::DEADLINE_LAPSED_MSG) => {
                            ProtocolError::WireProtocol(VSOCK_CONNECT_LAPSE_MSG)
                        }
                        other => other,
                    })?;
            if !crate::cancellable_boundary::connect_poll_succeeded(revents) {
                return Err(ProtocolError::WireProtocol(VSOCK_CONNECT_VETO_MSG));
            }
        }
        // Any other errno — INCLUDING EINTR — fails immediately (intentional). For a non-blocking AF_VSOCK
        // SOCK_STREAM connect the only "in flight" return is EINPROGRESS. EINTR must NOT be routed to the
        // poll path: af_vsock's signal path CANCELS the attempt (sk_state → TCP_CLOSE, transport cancel_pkt,
        // sk_err left 0), and vsock_poll's "simulate INET" branch reports a cancelled socket as bare clean
        // POLLOUT — so polling after EINTR would pass connect_poll_succeeded AND SO_ERROR==0 and hand back a
        // NEVER-CONNECTED stream as success. (Unreachable today anyway: the O_NONBLOCK path returns before
        // any interruptible wait.) Errors like ECONNRESET/ENODEV are genuine connect failures, not a
        // not-yet-complete state — fail fast and let the driver retry.
        Err(_) => return Err(ProtocolError::WireProtocol("anchor relay: vsock connect failed")),
    }

    // SO_ERROR carries the real non-blocking-connect result and must be 0 even once POLLOUT fired
    // (nix 0.31 `SocketError` is a `GetOnly` i32 sockopt → `Result<i32, Errno>`; 0 = no pending error).
    // Distinguish the two failure modes so diagnostics aren't misleading: a non-zero SO_ERROR (a real
    // socket-level connect failure, e.g. ECONNREFUSED) vs. the `getsockopt` syscall itself failing (e.g.
    // EBADF — a bad fd state, not a connect error).
    match getsockopt(&fd, SocketError) {
        Ok(0) => {}
        Ok(_) => return Err(ProtocolError::WireProtocol("anchor relay: vsock connect SO_ERROR set")),
        Err(_) => {
            return Err(ProtocolError::WireProtocol(
                "anchor relay: vsock connect getsockopt(SO_ERROR) failed",
            ))
        }
    }

    // Promote to VsockStream, then restore BLOCKING mode so DeadlineSocket's SO_*TIMEO take effect.
    let stream = vsock::VsockStream::from(fd);
    stream
        .set_nonblocking(false)
        .map_err(|_| ProtocolError::WireProtocol("anchor relay: clear O_NONBLOCK failed"))?;
    Ok(stream)
}

/// Smoke-only door for the (4c) in-guest vsock-lapse arm (`quote_smoke` phase `vsock-lapse`):
/// a 1-line forwarder so [`connect_bounded`] itself STAYS module-private. Quadruple-gated — it
/// cannot exist outside a `lab-quote-smoke` build.
///
/// - The (b) host-relay daemon MUST NOT reuse this (nor `connect_bounded`'s sequence): its anchor
///   leg is TCP→`std::net::TcpStream::connect_timeout` / UDS→`EAGAIN`-not-`EINPROGRESS` — different
///   connect semantics (§8 "(b) host relay daemon" bullet).
/// - A HOST-side lapse test is IMPOSSIBLE: host→nonexistent CID fails synchronously `ENODEV` in
///   `vhost_transport_send_pkt` — no `EINPROGRESS`, no black hole. Only the in-guest
///   guest→nonexistent-CID probe reaches the genuine in-flight-connect lapse (the guest's virtio
///   transport queues the REQUEST unconditionally; host vhost_vsock silently FREES packets whose
///   `dst_cid != 2` — no RST, no RESPONSE). If a future kernel RSTs unknown-CID instead, the probe
///   FAILS loudly with [`VSOCK_CONNECT_VETO_MSG`]; pre-designed fallbacks: SIGSTOP a second booted
///   guest and connect to ITS CID (frozen virtqueue = true black hole), or raise
///   `SO_VM_SOCKETS_CONNECT_TIMEOUT` and keep the deadline under the timer.
#[cfg(all(target_os = "linux", feature = "vsock-transport",
          feature = "agent-gateway", feature = "lab-quote-smoke"))]
pub(crate) fn connect_bounded_for_smoke(
    cid: u32,
    port: u32,
    deadline: std::time::Instant,
) -> Result<vsock::VsockStream, ProtocolError> {
    connect_bounded(cid, port, deadline)
}

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
impl VsockBootRelayChannel {
    /// Dial `(host_cid, port)`. 5b-2c wires `host_cid = vsock_addr::VMADDR_CID_HOST` and
    /// `port = vsock_addr::anchor_relay_port_from_env()?`.
    pub(crate) fn new(host_cid: u32, port: u32) -> Self {
        Self { host_cid, port }
    }

    /// Fresh connect → wrap in a [`DeadlineSocket`] (per-syscall `SO_*TIMEO`) → [`relay_round_trip_over_stream`]
    /// → drop the stream on return (RAII; the stream is a function-local, never stored in `self` —
    /// stale-reply isolation). Returns the raw `ProtocolError`; [`BootRelayChannel::round_trip`] folds it to
    /// retryable.
    fn round_trip_inner(
        &self,
        request_frame: &[u8],
        deadline: std::time::Instant,
        cap: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut stream = connect_bounded(self.host_cid, self.port, deadline)?;
        // TIGHT per-syscall deadline: DeadlineSocket reapplies SO_RCVTIMEO/SO_SNDTIMEO = the budget
        // REMAINING to `deadline` before EVERY read/write — so a syscall that begins late in the framed
        // exchange cannot block past the absolute deadline (a once-set timeout could overrun by up to one
        // socket-timeout; see §8 "Exact-bound caveat"). The in-fn deadline re-checks in
        // relay_round_trip_over_stream_cap still bound the loop; together the leg is bounded by ~`deadline`.
        let mut socket = DeadlineSocket { inner: &mut stream, deadline };
        relay_round_trip_over_stream_cap(&mut socket, request_frame, deadline, cap)
    }
}

/// Wraps a connected [`vsock::VsockStream`] so EACH `read`/`write`/`flush` first reapplies the socket
/// timeout to the budget remaining until `deadline` (not a value computed once before the exchange). This
/// makes the per-leg deadline a tight bound: a syscall starting late in the round-trip gets a
/// correspondingly-shrunk `SO_*TIMEO`, so it can't block past the absolute deadline. A lapsed budget yields
/// a `TimedOut` io error (which `relay_round_trip_over_stream`/`read_exact_with_idle_deadline` fold to a
/// clean error → retryable upstream). vsock's `flush` is a no-op, but the arm is kept for symmetry.
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
struct DeadlineSocket<'a> {
    inner: &'a mut vsock::VsockStream,
    deadline: std::time::Instant,
}

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
impl DeadlineSocket<'_> {
    fn arm_read(&self) -> std::io::Result<()> {
        let rem = remaining_or_lapsed(self.deadline)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "anchor relay: deadline lapsed"))?;
        self.inner.set_read_timeout(Some(rem))
    }
    fn arm_write(&self) -> std::io::Result<()> {
        let rem = remaining_or_lapsed(self.deadline)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "anchor relay: deadline lapsed"))?;
        self.inner.set_write_timeout(Some(rem))
    }
}

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
impl std::io::Read for DeadlineSocket<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm_read()?;
        self.inner.read(buf)
    }
}

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
impl std::io::Write for DeadlineSocket<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm_write()?;
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.arm_write()?;
        self.inner.flush()
    }
}

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
impl BootRelayChannel for VsockBootRelayChannel {
    fn round_trip(
        &mut self,
        request_frame: &[u8],
        deadline: std::time::Instant,
    ) -> Result<Vec<u8>, AnchorTransportError> {
        // Blanket map: EVERY ProtocolError (incl. a deadline-lapse WireProtocol, which reads as
        // "malformed" but is a timeout) folds to the always-retryable AnchorTransportError. Do NOT key
        // terminal-vs-retryable off the variant (see deadline_guarded_write's variant caveat).
        self.round_trip_inner(request_frame, deadline, MAX_ANCHOR_RESPONSE_LEN)
            .map_err(|_| AnchorTransportError("anchor relay: vsock channel round-trip failed"))
    }

    fn marks_round_trip(
        &mut self,
        request_frame: &[u8],
        deadline: std::time::Instant,
    ) -> Result<Vec<u8>, AnchorTransportError> {
        // Same channel mechanics; only the response cap differs (marks payloads are multi-KiB).
        self.round_trip_inner(request_frame, deadline, MAX_MARKS_RESPONSE_LEN)
            .map_err(|_| AnchorTransportError("anchor relay: vsock marks round-trip failed"))
    }
}

// Canonical test chain/env, shared by BOTH the agent-gateway `tests` module and the Linux/vsock
// `vsock_aya_tests` module (siblings — a const in one is not reachable from the other, so they live at
// module root under `#[cfg(test)]` and both pull them via `use super::*`). Keeps the aya acceptance tests
// on the same canonical inputs as the rest of the suite.
#[cfg(test)]
const ENV: &str = "testnet";
#[cfg(test)]
const CHAIN: u64 = 11565;

// Canonical golden INPUTS (TASK-7.7 5b-2b-ii(0)) — the SINGLE SOURCE, `#[cfg(test)] pub(crate)` at module
// root so BOTH this module's `tests` submodule AND the `host_anchor_relay` sibling test module share ONE
// definition (a sibling `mod tests`-private const is not reachable cross-module, hence module root). Fixed,
// fully-documented inputs (see boot_relay_anchor_handshake_v1.json): report_data is DERIVED
// (anchor_handshake_report_data), so the only free inputs are these. quote_report/cert_chain are opaque
// frame-format filler (NOT a valid attestation — the quote does not embed this report_data). Editing ANY of
// them requires regenerating the .bin via `regen_boot_relay_golden_vector`.
#[cfg(test)]
pub(crate) const GOLDEN_NONCE: [u8; 32] = [0x33; 32];
#[cfg(test)]
pub(crate) fn golden_quote() -> Vec<u8> {
    vec![0xa5; 100]
}
#[cfg(test)]
pub(crate) fn golden_cert() -> Vec<u8> {
    vec![0xc7; 8]
}

/// Test-only cross-module helper (TASK-7.7 5b-2b-ii(b)): the canonical, decoder-valid boot-relay
/// request frame the host-relay daemon forwards. `pub(crate)` so the `host_anchor_relay` sibling test
/// module drives the SAME canonical request this module's golden-vector tests freeze (no re-encode, no
/// drift) — built from the single-source [`GOLDEN_NONCE`]/[`golden_quote`]/[`golden_cert`] above.
#[cfg(test)]
pub(crate) fn test_golden_request_frame() -> Vec<u8> {
    use crate::agent_anchor::anchor_handshake_report_data;
    let rd = anchor_handshake_report_data(CHAIN, ENV, &GOLDEN_NONCE);
    let req = AnchorBootRequest {
        chain_id: CHAIN,
        environment_identifier: ENV,
        nonce: GOLDEN_NONCE,
        report_data: rd,
    };
    encode_anchor_boot_request(&golden_quote(), &golden_cert(), &req).unwrap()
}

/// Test-only cross-module helper (TASK-7.7 5b-2b-ii(b)): the FROZEN canonical request golden vector
/// (`boot_relay_anchor_handshake_v1.frame.bin`, the 5b-2b-ii(0) artifact). `pub(crate)` so the
/// `host_anchor_relay` sibling test proves the daemon forwards the canonical PRODUCTION request
/// verbatim (golden_vector_reuse). Byte-identical to [`test_golden_request_frame`] (pinned by this
/// module's `boot_relay_golden_vector_is_byte_exact_and_round_trips`).
#[cfg(test)]
pub(crate) fn test_boot_relay_golden_frame() -> &'static [u8] {
    include_bytes!("../testvectors/agent-gateway/boot_relay_anchor_handshake_v1.frame.bin")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_anchor::{anchor_handshake_report_data, test_signed_response_bytes};
    use crate::agent_boot::BootFailReason;
    use crate::agent_boot_driver::{
        run_boot_anti_rollback_handshake, BootDriverFail, BootDriverOutcome,
    };
    use crate::agent_keystore::{AuditRing, FaucetState, KeystoreBody, KeystoreConfig};
    use ed25519_dalek::SigningKey;
    use std::collections::VecDeque;
    use std::time::Duration;

    fn anchor_key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::agent_dispatch::lock_and_reset_agent_process_globals()
    }

    // ---- 5b-2e marks request codec (commit 5b/8) ----

    #[test]
    fn marks_request_encodes_and_decodes_round_trip() {
        let req = AnchorMarksRequest {
            chain_id: 11565,
            environment_identifier: "testnet",
            nonce: [0x9a; 32],
            epoch: 7,
        };
        let frame = encode_anchor_marks_request(&req).unwrap();
        // It is a 0x44 frame (not 0x41), and never serve-dispatchable (enclave-initiated).
        assert_eq!(crate::peek_msg_type_from_frame(&frame), Some(crate::MessageType::AgentAnchorMarksRelay));
        let d = decode_anchor_marks_request(&frame).unwrap();
        assert_eq!(d.chain_id, 11565);
        assert_eq!(d.environment_identifier, "testnet");
        assert_eq!(d.nonce, [0x9a; 32]);
        assert_eq!(d.epoch, 7);
    }

    #[test]
    fn commit_request_encodes_and_decodes_round_trip() {
        let req = AnchorCommitRequest {
            chain_id: 11565,
            environment_identifier: "testnet",
            new_epoch: 8,
            new_structural_version: 3,
            marks_digest: [0x5c; 32],
            nonce: [0x9a; 32],
            request_id: b"op-req-1",
        };
        let frame = encode_anchor_commit_request(&req).unwrap();
        // It is a 0x45 frame (not 0x41/0x44), and never serve-dispatchable (enclave-initiated).
        assert_eq!(crate::peek_msg_type_from_frame(&frame), Some(crate::MessageType::AgentAnchorCommitRelay));
        let d = decode_anchor_commit_request(&frame).unwrap();
        assert_eq!(d.chain_id, 11565);
        assert_eq!(d.environment_identifier, "testnet");
        assert_eq!(d.new_epoch, 8);
        assert_eq!(d.new_structural_version, 3);
        assert_eq!(d.marks_digest, [0x5c; 32]);
        assert_eq!(d.nonce, [0x9a; 32]);
        assert_eq!(d.request_id, b"op-req-1");
    }

    #[test]
    fn commit_request_decode_rejects_wrong_type_over_cap_and_trailing() {
        // A 0x44 marks-relay frame is NOT a commit request.
        let marks = encode_anchor_marks_request(&AnchorMarksRequest {
            chain_id: 1,
            environment_identifier: "e",
            nonce: [0; 32],
            epoch: 0,
        })
        .unwrap();
        assert!(decode_anchor_commit_request(&marks).is_err());
        // request_id over the 64-byte cap → the ENCODER rejects it (defense-in-depth, never mints a frame
        // the decoder would reject).
        let big = vec![0x41u8; crate::agent_dispatch::MAX_REQUEST_ID_LEN + 1];
        let enc_err = encode_anchor_commit_request(&AnchorCommitRequest {
            chain_id: 1,
            environment_identifier: "e",
            new_epoch: 1,
            new_structural_version: 1,
            marks_digest: [0; 32],
            nonce: [0; 32],
            request_id: &big,
        })
        .unwrap_err();
        assert!(matches!(enc_err, ProtocolError::WireProtocol(m) if m.contains("request_id")), "got {enc_err:?}");
        // ... and the DECODER (the trust boundary for untrusted host frames) rejects a HOSTILE over-cap
        // frame the encoder would never produce — hand-built via ciborium to bypass the encoder cap.
        use ciborium::value::Value;
        let hostile = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), Value::Integer(1.into())),
            (Value::Integer(3.into()), Value::Text("e".into())),
            (Value::Integer(4.into()), Value::Integer(1.into())),
            (Value::Integer(5.into()), Value::Integer(1.into())),
            (Value::Integer(6.into()), Value::Bytes(vec![0u8; 32])),
            (Value::Integer(7.into()), Value::Bytes(vec![0u8; 32])),
            (Value::Integer(8.into()), Value::Bytes(big)),
        ];
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&Value::Map(hostile), &mut payload).unwrap();
        let frame = crate::encode_message(crate::MessageType::AgentAnchorCommitRelay, &payload).unwrap();
        let dec_err = decode_anchor_commit_request(&frame).unwrap_err();
        assert!(matches!(dec_err, ProtocolError::WireProtocol(m) if m.contains("request_id")), "got {dec_err:?}");
        // Trailing bytes INSIDE the framed payload → reject the inner trailing-CBOR guard (re-frame, as
        // the marks test does, so the frame-length check doesn't reject it first).
        let frame = encode_anchor_commit_request(&AnchorCommitRequest {
            chain_id: 1,
            environment_identifier: "e",
            new_epoch: 1,
            new_structural_version: 1,
            marks_digest: [0; 32],
            nonce: [0; 32],
            request_id: b"r",
        })
        .unwrap();
        let mut payload = crate::decode_message(&frame).unwrap().payload;
        payload.push(0x00);
        let frame =
            crate::encode_message(crate::MessageType::AgentAnchorCommitRelay, &payload).unwrap();
        let err = decode_anchor_commit_request(&frame).unwrap_err();
        assert!(matches!(err, ProtocolError::WireProtocol(m) if m.contains("trailing bytes")), "got {err:?}");
    }

    #[test]
    fn commit_request_and_ack_preimage_are_field_compatible() {
        // Anti-drift (review wf_16383b1d): the commit-request encoder (here) and the ack preimage
        // (agent_anchor::commit_ack_signed_preimage) are two independent hand-rolled map(8) emitters that
        // MUST stay field-compatible — a conformant anchor parses the 0x45 request (keys 1..=8) and
        // re-emits those exact fields under COMMIT_ACK_DOMAIN to produce the ACK the enclave verifies. A
        // drift in either (add/reorder/type-slip a signed field) silently breaks every conformant ACK
        // (fail-closed). This test pins the WHOLE loop — request encode → decode → anchor-signed ACK →
        // verify Ok — so any such drift fails HERE rather than at runtime against a real anchor.
        let req = AnchorCommitRequest {
            chain_id: CHAIN,
            environment_identifier: ENV,
            new_epoch: 8,
            new_structural_version: 3,
            marks_digest: [0x5c; 32],
            nonce: [0x9a; 32],
            request_id: b"op-req-1",
        };
        let frame = encode_anchor_commit_request(&req).unwrap();
        let d = decode_anchor_commit_request(&frame).unwrap();
        // The conformant anchor echoes the DECODED request fields into a signed ACK ...
        let ack = crate::agent_anchor::test_signed_commit_ack_bytes(
            &anchor_key(),
            d.chain_id,
            &d.environment_identifier,
            d.new_epoch,
            d.new_structural_version,
            d.marks_digest,
            d.nonce,
            d.request_id.clone(),
        );
        // ... and the enclave's verifier accepts it against the SAME proposed values.
        let expected = crate::agent_anchor::ExpectedCommitAck {
            nonce: &d.nonce,
            epoch: d.new_epoch,
            structural_version: d.new_structural_version,
            marks_digest: &d.marks_digest,
            request_id: &d.request_id,
        };
        assert_eq!(
            crate::agent_anchor::verify_commit_ack_bytes(&ack, &expected, &test_config()),
            Ok(())
        );
    }

    // ---- slice 6-3: run_anchor_commit composition ----

    /// A scripted commit channel: decodes the 0x45 request (recovering the proposed fields) and answers
    /// per the action — a conformant anchor echoing the proposal, a transport failure, a forged signer,
    /// or an anchor that recorded a DIFFERENT epoch than proposed.
    enum CommitAct {
        Ok,
        Transport,
        Forged,
        WrongEpoch,
    }
    struct CommitMock(CommitAct);
    impl BootRelayChannel for CommitMock {
        fn round_trip(
            &mut self,
            request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, AnchorTransportError> {
            let d = decode_anchor_commit_request(request_frame).expect("commit frame decodes");
            let sign = |key: &SigningKey, epoch: u64| {
                crate::agent_anchor::test_signed_commit_ack_bytes(
                    key, d.chain_id, &d.environment_identifier, epoch, d.new_structural_version,
                    d.marks_digest, d.nonce, d.request_id.clone(),
                )
            };
            match self.0 {
                CommitAct::Ok => Ok(sign(&anchor_key(), d.new_epoch)),
                CommitAct::Transport => Err(AnchorTransportError("commit transport down")),
                CommitAct::Forged => Ok(sign(&SigningKey::from_bytes(&[9u8; 32]), d.new_epoch)),
                CommitAct::WrongEpoch => Ok(sign(&anchor_key(), d.new_epoch + 1)),
            }
        }
        fn marks_round_trip(
            &mut self,
            _request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, AnchorTransportError> {
            unreachable!("commit tests never call marks_round_trip")
        }
    }

    #[test]
    fn run_anchor_commit_ok_and_fail_closed_paths() {
        let commit = AnchorCommit {
            chain_id: CHAIN,
            environment_identifier: ENV,
            new_epoch: 8,
            new_structural_version: 3,
            marks_digest: [0x5c; 32],
            nonce: [0x9a; 32],
            request_id: b"op-req-1",
        };
        let cfg = test_config();
        // A conformant ACK echoing the proposal → Ok(()) (the seal-before-emit GO signal).
        assert!(matches!(
            run_anchor_commit(&mut CommitMock(CommitAct::Ok), &commit, &cfg, far_deadline()),
            Ok(())
        ));
        // Transport failure → fail-closed Transport (anchor unavailable ⇒ no offline window).
        assert!(matches!(
            run_anchor_commit(&mut CommitMock(CommitAct::Transport), &commit, &cfg, far_deadline()),
            Err(CommitFailure::Transport(_))
        ));
        // Forged ACK (signed by a NON-anchor_root key) → fail-closed Ack(SignatureInvalid).
        assert!(matches!(
            run_anchor_commit(&mut CommitMock(CommitAct::Forged), &commit, &cfg, far_deadline()),
            Err(CommitFailure::Ack(crate::agent_anchor::CommitAckError::SignatureInvalid))
        ));
        // The anchor recorded a DIFFERENT epoch than proposed → fail-closed Ack(EpochMismatch): the
        // enclave must NOT seal/emit when the durable record diverges from what it's about to seal.
        assert!(matches!(
            run_anchor_commit(&mut CommitMock(CommitAct::WrongEpoch), &commit, &cfg, far_deadline()),
            Err(CommitFailure::Ack(crate::agent_anchor::CommitAckError::EpochMismatch))
        ));
    }

    #[test]
    fn marks_request_decode_rejects_wrong_type_and_shape() {
        // A 0x41 boot-relay frame is NOT a marks request.
        let boot = encode_anchor_boot_request(
            &[0u8; 0x50],
            &[],
            &AnchorBootRequest {
                chain_id: 11565,
                environment_identifier: "testnet",
                nonce: [0; 32],
                report_data: anchor_handshake_report_data(11565, "testnet", &[0; 32]),
            },
        )
        .unwrap();
        assert!(decode_anchor_marks_request(&boot).is_err());
        // Trailing bytes after the CBOR map → reject. The extra byte must live INSIDE the framed
        // payload (re-frame with the correct length), NOT appended after the outer frame — otherwise the
        // frame-length check rejects it first and the inner `cursor.position() != payload.len()`
        // trailing-CBOR guard is never exercised (the branch this test exists to pin).
        let frame = encode_anchor_marks_request(&AnchorMarksRequest {
            chain_id: 1,
            environment_identifier: "e",
            nonce: [0; 32],
            epoch: 0,
        })
        .unwrap();
        let mut payload = crate::decode_message(&frame).unwrap().payload;
        payload.push(0x00);
        let frame =
            crate::encode_message(crate::MessageType::AgentAnchorMarksRelay, &payload).unwrap();
        let err = decode_anchor_marks_request(&frame).unwrap_err();
        assert!(
            matches!(err, ProtocolError::WireProtocol(m) if m.contains("trailing bytes")),
            "must hit the inner trailing-CBOR guard, got {err:?}"
        );
    }

    #[test]
    fn marks_response_cap_is_above_payload_and_distinct_from_freshness() {
        // The marks response cap is the payload ceiling + a small reserve, and is FAR above the 4096
        // freshness cap (which is unchanged) — so a non-trivial marks table is deliverable.
        assert_eq!(MAX_MARKS_RESPONSE_LEN, crate::agent_anchor::MAX_MARKS_PAYLOAD_LEN + MARKS_RESP_ENVELOPE_RESERVE);
        const _: () = assert!(MAX_MARKS_RESPONSE_LEN > MAX_ANCHOR_RESPONSE_LEN);
        assert_eq!(MAX_ANCHOR_RESPONSE_LEN, 4096, "freshness cap unchanged");
    }

    #[test]
    fn marks_response_reserve_covers_max_env_id_and_max_payload() {
        // coderabbit review: the outer signed marks response ALSO carries `environment_identifier`, so
        // MARKS_RESP_ENVELOPE_RESERVE (256) must cover it on top of the fixed envelope (version/chain/
        // nonce/epoch/signature + CBOR framing). It always does — env_id is structurally bounded to 64
        // bytes by `validate_environment_identifier` (the sealed config the request scope comes from AND
        // the verify both enforce 1..=64), so the WORST CASE is a 64-char env_id over a MAX payload.
        // Build exactly that and assert it still fits the read cap — so `read_bounded_response_cap` never
        // rejects a legitimately-signed reply before verification.
        let env64 = "a".repeat(64); // valid per the keystore env rules, the reachable maximum
        let max_payload = vec![0u8; crate::agent_anchor::MAX_MARKS_PAYLOAD_LEN];
        let signed = crate::agent_anchor::test_signed_marks_response_bytes(
            &anchor_key(),
            CHAIN,
            &env64,
            0,
            [0u8; 32],
            max_payload,
        );
        assert!(
            signed.len() <= MAX_MARKS_RESPONSE_LEN,
            "worst-case signed marks response ({}) must fit the read cap ({MAX_MARKS_RESPONSE_LEN})",
            signed.len(),
        );
    }

    fn test_config() -> KeystoreConfig {
        KeystoreConfig {
            twod_chain_id: CHAIN,
            environment_identifier: ENV.to_string(),
            admin_authority_pk: [0xa1; 32],
            recovery_authority_pk: [0xa2; 32],
            backup_recovery_wrapping_pubkey: vec![0xb0; 1568],
            monotonic_treasury_config_version: 1,
            authority_epoch: 0,
            anchor_root: anchor_key().verifying_key().to_bytes(),
        }
    }

    fn test_body(freshness_epoch: u64, structural_version: u64) -> KeystoreBody {
        KeystoreBody {
            config: test_config(),
            entries: vec![],
            counters: vec![],
            faucet: FaucetState {
                per_dispense_max_amount: [0; 32],
                max_gas_limit: 21000,
                max_effective_gas_fee_rate: 100,
                cumulative_native_spend: [0; 32],
                lifetime_spend: [0; 32],
                circuit_breaker_threshold: None,
            },
            audit: AuditRing { records: vec![], capacity: 64, last_exported_seq: 0, next_seq: 1 },
            freshness_epoch,
            structural_version,
            strict_recovery_counter: 0,
        }
    }

    /// Build an `AnchorBootRequest` with a chosen nonce; `report_data` is the real binding hash.
    fn request_for(nonce: [u8; 32]) -> ([u8; 32], [u8; 64]) {
        let rd = anchor_handshake_report_data(CHAIN, ENV, &nonce);
        (nonce, rd)
    }

    /// Extract the `WireProtocol` message (pins WHICH rejection branch fired, not just "an error").
    fn wire_msg(r: Result<DecodedBootRequest, ProtocolError>) -> &'static str {
        match r {
            Err(ProtocolError::WireProtocol(m)) => m,
            Err(e) => panic!("expected WireProtocol, got {e:?}"),
            Ok(_) => panic!("expected WireProtocol error, got Ok"),
        }
    }

    /// Hand-build a boot-relay request frame with arbitrary field values (to craft malformed cases the
    /// encoder would refuse). `cert` may be any size (bypasses the encoder's cert_chain bound).
    fn craft_frame(version: u64, chain: u64, env: &str, nonce: &[u8], rd: &[u8], quote: &[u8], cert: &[u8]) -> Vec<u8> {
        use crate::agent_capability::{put_bytes, put_text, put_uint};
        let mut p = Vec::new();
        put_uint(&mut p, 5, 7);
        put_uint(&mut p, 0, 1); put_uint(&mut p, 0, version);
        put_uint(&mut p, 0, 2); put_uint(&mut p, 0, chain);
        put_uint(&mut p, 0, 3); put_text(&mut p, env);
        put_uint(&mut p, 0, 4); put_bytes(&mut p, nonce);
        put_uint(&mut p, 0, 5); put_bytes(&mut p, rd);
        put_uint(&mut p, 0, 6); put_bytes(&mut p, quote);
        put_uint(&mut p, 0, 7); put_bytes(&mut p, cert);
        crate::encode_message(crate::MessageType::AgentBootRelay, &p).unwrap()
    }

    /// Fake SNP quote producer: returns canned (report, cert_chain) and records each `report_data`.
    struct FakeQuote {
        report: Vec<u8>,
        cert_chain: Vec<u8>,
        fail: bool,
        /// If true, honor the deadline: error when `now >= deadline` (models a real bounded fetch).
        honor_deadline: bool,
        /// Plain `Vec` — `fetch(&mut self)` made the old `RefCell` ceremony unnecessary.
        seen: Vec<[u8; 64]>,
    }
    impl FakeQuote {
        fn ok() -> Self {
            Self { report: vec![0xa5; 64], cert_chain: vec![0xc7; 8], fail: false, honor_deadline: false, seen: Default::default() }
        }
        fn failing() -> Self {
            Self { report: vec![], cert_chain: vec![], fail: true, honor_deadline: false, seen: Default::default() }
        }
        /// A producer that respects the deadline — used to prove a slow quote cannot hang an attempt.
        fn deadline_honoring() -> Self {
            Self { report: vec![0xa5; 64], cert_chain: vec![0xc7; 8], fail: false, honor_deadline: true, seen: Default::default() }
        }
    }
    impl BootQuoteProducer for FakeQuote {
        fn fetch(
            &mut self,
            report_data: &[u8; 64],
            deadline: std::time::Instant,
        ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
            self.seen.push(*report_data);
            if self.fail {
                return Err(ProtocolError::PqSigningUnavailable("fake quote fetch failed"));
            }
            if self.honor_deadline && std::time::Instant::now() >= deadline {
                return Err(ProtocolError::PqSigningUnavailable("quote fetch deadline exceeded"));
            }
            Ok((self.report.clone(), self.cert_chain.clone()))
        }
    }

    /// Scripted mock channel. Each `round_trip` decodes the request frame (exercising
    /// `decode_anchor_boot_request`) so a `SignFresh`/`SignWrongNonce` action can sign against the live
    /// per-attempt nonce.
    enum ChAct {
        Err,
        Raw(Vec<u8>),
        SignFresh { epoch: u64, sv: u64, marks: [u8; 32] },
        /// Like SignFresh, but round-trips the signed bytes through the REAL wire framing
        /// (frame_anchor_response → read_bounded_anchor_response) so the response-frame path itself is
        /// exercised in the composition (a real vsock channel mishandling the 4-byte prefix would fail).
        SignFreshFramed { epoch: u64, sv: u64, marks: [u8; 32] },
        SignWrongNonce { epoch: u64, sv: u64, marks: [u8; 32] },
    }
    struct MockChannel {
        actions: VecDeque<ChAct>,
        connects: u32,
        seen_nonces: Vec<[u8; 32]>,
    }
    impl MockChannel {
        fn new(actions: Vec<ChAct>) -> Self {
            Self { actions: actions.into(), connects: 0, seen_nonces: Vec::new() }
        }
    }
    impl BootRelayChannel for MockChannel {
        fn round_trip(
            &mut self,
            request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, AnchorTransportError> {
            self.connects += 1;
            // Fresh connection per call: decode THIS attempt's request to recover its nonce.
            let decoded = decode_anchor_boot_request(request_frame)
                .expect("driver-encoded request must decode");
            self.seen_nonces.push(decoded.nonce);
            let act = self.actions.pop_front().unwrap_or(ChAct::Err);
            let bytes = match act {
                ChAct::Err => return Err(AnchorTransportError("mock channel error")),
                ChAct::Raw(b) => b,
                ChAct::SignFresh { epoch, sv, marks } => test_signed_response_bytes(
                    &anchor_key(), CHAIN, ENV, epoch, sv, marks, decoded.nonce,
                ),
                ChAct::SignFreshFramed { epoch, sv, marks } => {
                    let signed = test_signed_response_bytes(&anchor_key(), CHAIN, ENV, epoch, sv, marks, decoded.nonce);
                    // Exercise the actual response wire framing the 5b-2b vsock channel will use.
                    let wire = frame_anchor_response(&signed).expect("framable");
                    let mut cur = std::io::Cursor::new(wire);
                    read_bounded_anchor_response(&mut cur, far_deadline()).expect("read back")
                }
                ChAct::SignWrongNonce { epoch, sv, marks } => {
                    let mut wrong = decoded.nonce;
                    wrong[0] ^= 0xff;
                    test_signed_response_bytes(&anchor_key(), CHAIN, ENV, epoch, sv, marks, wrong)
                }
            };
            Ok(bytes)
        }

        fn marks_round_trip(
            &mut self,
            _request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, AnchorTransportError> {
            // These RelayAnchorTransport composition tests exercise only the FRESHNESS leg; the marks
            // leg is driven by the driver-level execute-arm tests (agent_boot_driver TestTransport).
            Err(AnchorTransportError("mock channel: marks_round_trip not scripted"))
        }
    }

    // ---- request codec ----

    #[test]
    fn request_encode_decode_round_trip() {
        let (nonce, rd) = request_for([0x33; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let frame = encode_anchor_boot_request(&[0xa5; 100], &[0xc7; 8], &req).unwrap();
        // valid AgentBootRelay frame
        assert_eq!(crate::peek_msg_type_from_frame(&frame), Some(crate::MessageType::AgentBootRelay));
        let d = decode_anchor_boot_request(&frame).unwrap();
        assert_eq!(d.chain_id, CHAIN);
        assert_eq!(d.environment_identifier, ENV);
        assert_eq!(d.nonce, nonce);
        assert_eq!(d.report_data, rd);
        assert_eq!(d.quote_report, vec![0xa5; 100]);
        assert_eq!(d.cert_chain, vec![0xc7; 8]);
    }

    // ---- 5b-2b-ii(0): canonical AgentBootRelay request golden vector ----
    // The inputs (GOLDEN_NONCE / golden_quote / golden_cert), the canonical frame
    // (test_golden_request_frame), and the frozen .bin (test_boot_relay_golden_frame) are the module-root
    // SINGLE SOURCE, pulled here via `use super::*` and shared with the host_anchor_relay sibling tests —
    // no per-module duplication, so the freeze below can't silently drift from the sibling forwarder.

    /// REGEN (manual): `cargo test --features agent-gateway regen_boot_relay_golden_vector -- --ignored
    /// --nocapture`, then commit the .bin. This is the documented regeneration mechanism: the Elixir
    /// `gen_agent_vectors.exs` cannot emit CBOR/SHA3-512 frames, so `encode_anchor_boot_request` is the
    /// canonical source. The byte-exact + canonical-layout assertions in
    /// `boot_relay_golden_vector_is_byte_exact_and_round_trips` independently pin the wire format.
    #[test]
    #[ignore]
    fn regen_boot_relay_golden_vector() {
        let frame = test_golden_request_frame();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testvectors/agent-gateway/boot_relay_anchor_handshake_v1.frame.bin"
        );
        std::fs::write(path, &frame).expect("write golden frame");
        eprintln!("wrote {} bytes -> {path}", frame.len());
    }

    #[test]
    fn boot_relay_golden_vector_is_byte_exact_and_round_trips() {
        let frame = test_golden_request_frame();
        // (1) BYTE-EXACT freeze vs the committed golden — catches ANY encoder drift (key order, non-shortest
        // integers, length-prefix changes) that the lenient decoder would silently round-trip through.
        assert_eq!(
            frame.as_slice(),
            test_boot_relay_golden_frame(),
            "AgentBootRelay frame must be byte-exact vs the golden vector; if the wire format changed \
             intentionally, regen via `regen_boot_relay_golden_vector` and bump the doc/json"
        );
        // (2) decode(golden) yields exactly the inputs.
        let d = decode_anchor_boot_request(test_boot_relay_golden_frame()).unwrap();
        assert_eq!(d.chain_id, CHAIN);
        assert_eq!(d.environment_identifier, ENV);
        assert_eq!(d.nonce, GOLDEN_NONCE);
        assert_eq!(d.report_data, anchor_handshake_report_data(CHAIN, ENV, &GOLDEN_NONCE));
        assert_eq!(d.quote_report, golden_quote());
        assert_eq!(d.cert_chain, golden_cert());
        // (3) canonical-layout assertions on the GOLDEN bytes directly (the lenient decoder enforces NONE
        // of these — key order, shortest-form ints, bstr length prefixes). This pins the format by
        // hand-audit, not just "encode matches a possibly-buggy-encoder-emitted golden". Payload (after the
        // 4-byte BE len + version + type frame header) is the integer-keyed CBOR map:
        let framed = crate::decode_message(test_boot_relay_golden_frame()).unwrap();
        assert_eq!(framed.msg_type, crate::MessageType::AgentBootRelay);
        let p = framed.payload.as_slice();
        // map(7), key1=ver shortest uint 1, key2, chain_id 11565 canonical 2-byte (0x19 0x2D 0x2D), key3:
        assert_eq!(&p[0..8], &[0xA7, 0x01, 0x01, 0x02, 0x19, 0x2D, 0x2D, 0x03], "map header + canonical ver/chain_id + key order");
        // key3 text(7) "testnet":
        assert_eq!(p[8], 0x67, "env = CBOR text(7)");
        assert_eq!(&p[9..16], b"testnet");
        // key4 + nonce bstr(32) prefix:
        assert_eq!(&p[16..19], &[0x04, 0x58, 0x20], "key4 + 32-byte nonce bstr prefix");
        // key5 (offset 16 + 1 + 2 + 32 = 51) + report_data bstr(64) prefix:
        assert_eq!(&p[51..54], &[0x05, 0x58, 0x40], "key5 + 64-byte report_data bstr prefix");
    }

    #[test]
    fn request_round_trip_empty_cert_chain() {
        let (nonce, rd) = request_for([0x11; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let frame = encode_anchor_boot_request(&[0xa5; 32], &[], &req).unwrap();
        assert!(decode_anchor_boot_request(&frame).unwrap().cert_chain.is_empty());
    }

    #[test]
    fn decode_rejects_wrong_frame_type() {
        // A GET_STATUS-typed frame is not AGENT_BOOT_RELAY.
        let frame = crate::encode_message(crate::MessageType::GetStatus, &[0xa0]).unwrap();
        assert!(decode_anchor_boot_request(&frame).is_err());
    }

    #[test]
    fn decode_rejects_bad_version() {
        let (nonce, rd) = request_for([0x22; 32]);
        // version 2 -> must fail at the version branch specifically.
        let frame = craft_frame(2, CHAIN, ENV, &nonce, &rd, &[0xa5; 8], &[]);
        assert!(wire_msg(decode_anchor_boot_request(&frame)).contains("version"));
    }

    #[test]
    fn decode_rejects_inconsistent_report_data() {
        let (nonce, _) = request_for([0x22; 32]);
        // valid-length but non-matching report_data -> the binding branch fires.
        let frame = craft_frame(1, CHAIN, ENV, &nonce, &[0x00; 64], &[0xa5; 8], &[]);
        assert!(wire_msg(decode_anchor_boot_request(&frame)).contains("report_data"));
    }

    #[test]
    fn decode_rejects_wrong_nonce_length() {
        let (_, rd) = request_for([0x22; 32]);
        // 31-byte nonce -> must fail at the nonce-length branch (before the binding check).
        let frame = craft_frame(1, CHAIN, ENV, &[0x11; 31], &rd, &[0xa5; 8], &[]);
        assert!(wire_msg(decode_anchor_boot_request(&frame)).contains("nonce"));
    }

    #[test]
    fn decode_rejects_wrong_scope() {
        // report_data binds (CHAIN, ENV, nonce) but the frame claims chain CHAIN+1 -> the binding check
        // (report_data == hash(chain,env,nonce)) fails: the realistic relay-substitution attack.
        let (nonce, rd) = request_for([0x55; 32]);
        let frame = craft_frame(1, CHAIN + 1, ENV, &nonce, &rd, &[0xa5; 8], &[]);
        assert!(wire_msg(decode_anchor_boot_request(&frame)).contains("report_data"));
        // ...and a wrong env likewise breaks the binding.
        let frame2 = craft_frame(1, CHAIN, "other-env", &nonce, &rd, &[0xa5; 8], &[]);
        assert!(wire_msg(decode_anchor_boot_request(&frame2)).contains("report_data"));
    }

    #[test]
    fn decode_rejects_oversize_cert_chain() {
        // The host-relay decode path is the real untrusted boundary; an oversize cert_chain must be
        // rejected there too (not just at the enclave's encode). report_data must match so the bound
        // check is what fires.
        let nonce = [0x66; 32];
        let rd = anchor_handshake_report_data(CHAIN, ENV, &nonce);
        let too_big = vec![0u8; crate::snp_report::MAX_CERT_CHAIN_LEN + 1];
        let frame = craft_frame(1, CHAIN, ENV, &nonce, &rd, &[0xa5; 8], &too_big);
        assert!(wire_msg(decode_anchor_boot_request(&frame)).contains("cert_chain"));
    }

    #[test]
    fn decode_accepts_large_cert_chain() {
        // Regression for the strict_decode_map 4 KiB cap bug: a realistic >4 KiB (here 16 KiB) cert
        // chain — well within MAX_CERT_CHAIN_LEN — must round-trip through encode + decode.
        let (nonce, rd) = request_for([0x67; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let big_cert = vec![0x5a; 16 * 1024];
        let frame = encode_anchor_boot_request(&[0xa5; 1184], &big_cert, &req).unwrap();
        let d = decode_anchor_boot_request(&frame).unwrap();
        assert_eq!(d.cert_chain.len(), 16 * 1024);
        assert_eq!(d.quote_report.len(), 1184);
    }

    #[test]
    fn encode_rejects_oversize_cert_chain() {
        let (nonce, rd) = request_for([0x44; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let too_big = vec![0u8; crate::snp_report::MAX_CERT_CHAIN_LEN + 1];
        assert!(encode_anchor_boot_request(&[0xa5; 8], &too_big, &req).is_err());
        // exactly MAX is accepted (still under MAX_MESSAGE_SIZE with the report).
        let at_max = vec![0u8; crate::snp_report::MAX_CERT_CHAIN_LEN];
        assert!(encode_anchor_boot_request(&[0xa5; 1184], &at_max, &req).is_ok());
    }

    #[test]
    fn encode_and_decode_reject_oversize_quote() {
        let (nonce, rd) = request_for([0x4a; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        // encode rejects an oversized quote before allocating; a real ~1184 B report is accepted.
        assert!(encode_anchor_boot_request(&vec![0u8; MAX_QUOTE_REPORT_LEN + 1], &[], &req).is_err());
        assert!(encode_anchor_boot_request(&vec![0u8; 1184], &[], &req).is_ok());
        // decode (host-relay path) rejects an oversized quote too — matched envelopes.
        let frame = craft_frame(1, CHAIN, ENV, &nonce, &rd, &vec![0u8; MAX_QUOTE_REPORT_LEN + 1], &[]);
        assert!(wire_msg(decode_anchor_boot_request(&frame)).contains("quote_report"));
    }

    // ---- bounded response read ----

    #[test]
    fn read_bounded_accepts_small_response_verbatim() {
        let body = vec![0xab; 300];
        // The shared writer (`frame_anchor_response`) and the reader round-trip — one codec, no drift.
        let wire = frame_anchor_response(&body).unwrap();
        let mut cur = std::io::Cursor::new(wire);
        let got = read_bounded_anchor_response(&mut cur, far_deadline()).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_bounded_max_boundary() {
        // Exactly MAX is accepted; MAX+1 is rejected (pins the `>` cap, not `>=`).
        let at_max = vec![0xcd; MAX_ANCHOR_RESPONSE_LEN];
        let wire = frame_anchor_response(&at_max).unwrap();
        let mut cur = std::io::Cursor::new(wire);
        assert_eq!(read_bounded_anchor_response(&mut cur, far_deadline()).unwrap().len(), MAX_ANCHOR_RESPONSE_LEN);
        // frame_anchor_response itself refuses MAX+1; and a hand-built MAX+1 prefix is rejected by the reader.
        assert!(frame_anchor_response(&vec![0u8; MAX_ANCHOR_RESPONSE_LEN + 1]).is_err());
        let mut over = ((MAX_ANCHOR_RESPONSE_LEN + 1) as u32).to_be_bytes().to_vec();
        over.extend_from_slice(&vec![0u8; MAX_ANCHOR_RESPONSE_LEN + 1]);
        let mut cur2 = std::io::Cursor::new(over);
        assert!(read_bounded_anchor_response(&mut cur2, far_deadline()).is_err());
    }

    #[test]
    fn read_bounded_rejects_oversize_before_alloc() {
        // 0xFFFFFFFF length prefix, no body — must reject on the length check, not try to read 4 GiB.
        let mut wire = u32::MAX.to_be_bytes().to_vec();
        wire.extend_from_slice(&[]);
        let mut cur = std::io::Cursor::new(wire);
        assert!(read_bounded_anchor_response(&mut cur, far_deadline()).is_err());
    }

    #[test]
    fn read_bounded_rejects_truncated_stream() {
        // length says 300 but only 10 body bytes available -> EOF error.
        let mut wire = (300u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&[0u8; 10]);
        let mut cur = std::io::Cursor::new(wire);
        assert!(read_bounded_anchor_response(&mut cur, far_deadline()).is_err());
    }

    fn far_deadline() -> std::time::Instant {
        std::time::Instant::now() + Duration::from_secs(60)
    }
    fn near_past() -> std::time::Instant {
        // Direct subtraction so it can never silently yield a non-past instant (see snp_report's `past`,
        // greptile P2); real monotonic clocks are always far past the epoch, so this can't overflow.
        std::time::Instant::now() - Duration::from_secs(1)
    }

    // ---- transport composition (direct) ----

    fn transport(quote: FakeQuote, ch: MockChannel) -> RelayAnchorTransport<FakeQuote, MockChannel> {
        RelayAnchorTransport::new(quote, ch, Duration::from_secs(5))
    }

    #[test]
    fn transport_success_returns_verifiable_bytes() {
        let (nonce, rd) = request_for([0x77; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let mut t = transport(
            FakeQuote::ok(),
            MockChannel::new(vec![ChAct::SignFresh { epoch: 7, sv: 2, marks: [0xab; 32] }]),
        );
        let bytes = t.anchor_round_trip(&req).expect("ok round trip");
        // the returned (untrusted) bytes verify against the issued nonce + sealed anchor_root.
        let st = crate::agent_anchor::verify_anchor_response_bytes(&bytes, &nonce, &test_config())
            .expect("a conformant signed response verifies");
        assert_eq!(st.epoch, 7);
        // the fake quote was handed exactly request.report_data (quote<->nonce binding).
        assert_eq!(t.quote.seen.as_slice(), &[rd]);
    }

    #[test]
    fn transport_quote_failure_is_retryable_error_no_channel_call() {
        let (nonce, rd) = request_for([0x88; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let mut t = transport(FakeQuote::failing(), MockChannel::new(vec![]));
        assert_eq!(t.anchor_round_trip(&req), Err(AnchorTransportError("anchor relay: SNP quote fetch failed")));
        assert_eq!(t.channel.connects, 0, "channel never called when the quote fetch fails");
    }

    #[test]
    fn transport_quote_over_deadline_is_retryable_no_channel_call() {
        // A quote producer that honors the deadline, with a ZERO timeout, sees now >= deadline and
        // errors — proving a slow/hung quote fetch cannot block the attempt (it folds to a retryable
        // AnchorTransportError) and the channel is never reached.
        let (nonce, rd) = request_for([0xbb; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let mut t = RelayAnchorTransport::new(
            FakeQuote::deadline_honoring(),
            MockChannel::new(vec![]),
            Duration::ZERO, // deadline = now() + 0 ⇒ already past by the time fetch runs
        );
        assert_eq!(t.anchor_round_trip(&req), Err(AnchorTransportError("anchor relay: SNP quote fetch failed")));
        assert_eq!(t.channel.connects, 0, "channel never reached when the quote fetch times out");
    }

    #[test]
    fn transport_channel_error_is_retryable() {
        let (nonce, rd) = request_for([0x99; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let mut t = transport(FakeQuote::ok(), MockChannel::new(vec![ChAct::Err]));
        assert_eq!(t.anchor_round_trip(&req), Err(AnchorTransportError("mock channel error")));
    }

    #[test]
    fn transport_returns_untrusted_bytes_verbatim() {
        // The transport does NOT pre-reject a garbage reply — it returns it; verification is downstream.
        let (nonce, rd) = request_for([0xaa; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let garbage = vec![0xff, 0xff, 0xff];
        let mut t = transport(FakeQuote::ok(), MockChannel::new(vec![ChAct::Raw(garbage.clone())]));
        assert_eq!(t.anchor_round_trip(&req), Ok(garbage));
    }

    // ---- end-to-end through the real 5b-1 driver ----

    #[test]
    fn driver_ready_through_relay_transport() {
        let _g = test_lock();
        let mut body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        let mut t = transport(
            FakeQuote::ok(),
            MockChannel::new(vec![ChAct::SignFresh { epoch: 7, sv: 2, marks }]),
        );
        match run_boot_anti_rollback_handshake(&mut t, &mut body, 5) {
            BootDriverOutcome::Ready(st) => assert_eq!(st.epoch, 7),
            other => panic!("expected Ready, got {other:?}"),
        }
        assert_eq!(t.channel.connects, 1);
    }

    #[test]
    fn driver_ready_through_real_response_framing() {
        // Same as driver_ready_through_relay_transport, but the channel round-trips the response through
        // frame_anchor_response → read_bounded_anchor_response — so the 4-byte-prefix response framing is
        // exercised in the full composition, not bypassed by returning raw bytes.
        let _g = test_lock();
        let mut body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        let mut t = transport(
            FakeQuote::ok(),
            MockChannel::new(vec![ChAct::SignFreshFramed { epoch: 7, sv: 2, marks }]),
        );
        match run_boot_anti_rollback_handshake(&mut t, &mut body, 5) {
            BootDriverOutcome::Ready(st) => assert_eq!(st.epoch, 7),
            other => panic!("expected Ready, got {other:?}"),
        }
        assert_eq!(t.channel.connects, 1);
    }

    #[test]
    fn driver_retry_then_ready_uses_fresh_nonce_each_attempt() {
        let _g = test_lock();
        let mut body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        let mut t = transport(
            FakeQuote::ok(),
            MockChannel::new(vec![ChAct::Err, ChAct::SignFresh { epoch: 7, sv: 2, marks }]),
        );
        assert!(matches!(run_boot_anti_rollback_handshake(&mut t, &mut body, 5), BootDriverOutcome::Ready(_)));
        assert_eq!(t.channel.connects, 2, "one channel error then success = 2 connects");
        assert_ne!(t.channel.seen_nonces[0], t.channel.seen_nonces[1], "a fresh nonce per attempt");
    }

    #[test]
    fn driver_wrong_nonce_reply_is_terminal() {
        let _g = test_lock();
        let mut body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        let mut t = transport(
            FakeQuote::ok(),
            MockChannel::new(vec![ChAct::SignWrongNonce { epoch: 7, sv: 2, marks }]),
        );
        match run_boot_anti_rollback_handshake(&mut t, &mut body, 5) {
            BootDriverOutcome::FailClosed(BootDriverFail::Reconcile(BootFailReason::VerifyNonceMismatch)) => {}
            other => panic!("expected VerifyNonceMismatch, got {other:?}"),
        }
        assert_eq!(t.channel.connects, 1, "a wrong-nonce reply is terminal, not a grind lever");
    }

    // ---- framing core / forward core / quote producer (5b-2b-i, all CI) ----

    /// In-memory duplex: writes append to `written`; reads pull from `to_read`.
    struct TestStream {
        written: Vec<u8>,
        to_read: std::io::Cursor<Vec<u8>>,
    }
    impl TestStream {
        fn new(to_read: Vec<u8>) -> Self {
            Self { written: Vec::new(), to_read: std::io::Cursor::new(to_read) }
        }
    }
    impl std::io::Read for TestStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.to_read, buf)
        }
    }
    impl std::io::Write for TestStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn relay_round_trip_over_stream_writes_request_reads_response() {
        let signed = vec![0xab; 200];
        let mut stream = TestStream::new(frame_anchor_response(&signed).unwrap());
        let req = vec![0x01, 0x02, 0x03];
        let got = relay_round_trip_over_stream(&mut stream, &req, far_deadline()).unwrap();
        assert_eq!(got, signed, "response returned verbatim");
        assert_eq!(stream.written, req, "request frame written verbatim, not re-framed");
    }

    #[test]
    fn relay_round_trip_past_deadline_errors_before_write() {
        let mut stream = TestStream::new(vec![]);
        let r = relay_round_trip_over_stream(&mut stream, &[0xaa], near_past());
        assert!(r.is_err());
        assert!(stream.written.is_empty(), "nothing written when the deadline is already past");
    }

    /// A stream whose `write` SLEEPS past `cross_at` (so the deadline lapses *during* the write), and whose
    /// `flush` records whether it was called — to prove the pre-flush deadline guard skips a doomed flush.
    struct FlushGuardStream {
        cross_at: std::time::Instant,
        wrote: usize,
        flush_called: bool,
    }
    impl std::io::Read for FlushGuardStream {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            // Unreachable in this test: the pre-flush guard returns Err before any response read.
            Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unreached"))
        }
    }
    impl std::io::Write for FlushGuardStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let now = std::time::Instant::now();
            if now < self.cross_at {
                std::thread::sleep(self.cross_at - now); // cross the deadline DURING the write
            }
            self.wrote += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_called = true;
            Ok(())
        }
    }

    #[test]
    fn relay_round_trip_flush_skipped_when_deadline_lapses_during_write() {
        // pre-write guard passes (deadline still future); the write crosses the deadline; the pre-flush
        // guard then fires — the flush must NOT be initiated after the budget is gone.
        let dl = std::time::Instant::now() + Duration::from_millis(50);
        let mut s = FlushGuardStream { cross_at: dl, wrote: 0, flush_called: false };
        let r = relay_round_trip_over_stream(&mut s, &[0xaa; 8], dl);
        assert!(r.is_err(), "lapsed-during-write must error");
        assert!(s.wrote > 0, "the write itself ran");
        assert!(!s.flush_called, "flush must be skipped once the deadline lapsed during the write");
    }

    #[test]
    fn relay_round_trip_truncated_response_errors() {
        // length prefix says 300 but only 4 body bytes -> bounded reader errors.
        let mut wire = (300u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&[0u8; 4]);
        let mut stream = TestStream::new(wire);
        assert!(relay_round_trip_over_stream(&mut stream, &[0xaa], far_deadline()).is_err());
    }

    #[test]
    fn relay_forward_once_pipes_request_and_frames_response() {
        let (nonce, rd) = request_for([0x33; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let req_frame = encode_anchor_boot_request(&[0xa5; 100], &[0xc7; 8], &req).unwrap();
        let anchor_resp = vec![0xab; 200];
        let mut enclave = TestStream::new(req_frame.clone());
        let mut anchor = TestStream::new(frame_anchor_response(&anchor_resp).unwrap());
        relay_forward_once(&mut enclave, &mut anchor, far_deadline()).unwrap();
        assert_eq!(anchor.written, req_frame, "request forwarded byte-identical");
        assert_eq!(enclave.written, frame_anchor_response(&anchor_resp).unwrap(), "enclave gets the framed response");
    }

    #[test]
    fn relay_forward_once_rejects_malformed_request_before_anchor() {
        // A 0x41 frame whose payload isn't a valid boot request (garbage CBOR).
        let bad = crate::encode_message(crate::MessageType::AgentBootRelay, &[0xff, 0xff]).unwrap();
        let mut enclave = TestStream::new(bad);
        let mut anchor = TestStream::new(vec![]);
        // Pin that the rejection is the decode gate (a "boot request: ..." WireProtocol), not some other
        // early error — proving the malformed request is rejected BEFORE any anchor write.
        match relay_forward_once(&mut enclave, &mut anchor, far_deadline()) {
            Err(crate::ProtocolError::WireProtocol(m)) => {
                assert!(m.contains("boot request"), "expected a decode rejection, got: {m}")
            }
            other => panic!("expected WireProtocol decode rejection, got {other:?}"),
        }
        assert!(anchor.written.is_empty(), "anchor never written on a malformed request");
    }

    #[test]
    fn relay_forward_once_past_deadline_forwards_nothing() {
        // An already-past deadline: the pump must forward nothing to the anchor (the enclave-read guard
        // trips first here, but the safety property — no forward once the budget is gone — is what matters).
        let (nonce, rd) = request_for([0x51; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let req_frame = encode_anchor_boot_request(&[0xa5; 8], &[], &req).unwrap();
        let mut enclave = TestStream::new(req_frame);
        let mut anchor = TestStream::new(vec![]);
        assert!(relay_forward_once(&mut enclave, &mut anchor, near_past()).is_err());
        assert!(anchor.written.is_empty(), "nothing forwarded to the anchor past the deadline");
        assert!(enclave.written.is_empty(), "nothing written back to the enclave past the deadline");
    }

    /// Stream that delivers all of `to_read` but BUSY-WAITS across `spin_until` on the read that returns the
    /// frame body — so the caller crosses the deadline *after* the read completes Ok, exercising the
    /// pre-write guard (not the read's entry-check). First read (4-byte length prefix) returns instantly.
    struct DeadlineCrossingStream {
        to_read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
        spin_until: std::time::Instant,
        reads: u32,
    }
    impl std::io::Read for DeadlineCrossingStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            if self.reads >= 2 {
                // Sleep (don't spin a core) until the deadline is crossed; the caller's generous margin
                // makes the post-read pre-write guard fire deterministically even under CI scheduler jitter.
                let now = std::time::Instant::now();
                if now < self.spin_until {
                    std::thread::sleep(self.spin_until - now);
                }
            }
            std::io::Read::read(&mut self.to_read, buf)
        }
    }
    impl std::io::Write for DeadlineCrossingStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn relay_forward_once_deadline_lapse_after_read_blocks_anchor_write() {
        // The enclave frame reads OK, but the deadline lapses during the body read; the pre-anchor-write
        // guard then fires BEFORE any anchor write — proving the guard, not the read's entry-check.
        let (nonce, rd) = request_for([0x52; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let req_frame = encode_anchor_boot_request(&[0xa5; 8], &[], &req).unwrap();
        let dl = std::time::Instant::now() + Duration::from_millis(50);
        let mut enclave = DeadlineCrossingStream {
            to_read: std::io::Cursor::new(req_frame),
            written: Vec::new(),
            spin_until: dl,
            reads: 0,
        };
        let mut anchor = TestStream::new(vec![]);
        match relay_forward_once(&mut enclave, &mut anchor, dl) {
            Err(crate::ProtocolError::WireProtocol(m)) => {
                assert!(m.contains("deadline before anchor write"), "expected pre-anchor-write guard, got: {m}")
            }
            other => panic!("expected pre-write WireProtocol, got {other:?}"),
        }
        assert!(anchor.written.is_empty(), "no anchor write once the deadline lapsed mid-pump");
    }

    #[test]
    fn relay_forward_once_oversize_anchor_response_rejected() {
        let (nonce, rd) = request_for([0x44; 32]);
        let req = AnchorBootRequest { chain_id: CHAIN, environment_identifier: ENV, nonce, report_data: rd };
        let req_frame = encode_anchor_boot_request(&[0xa5; 8], &[], &req).unwrap();
        let mut enclave = TestStream::new(req_frame);
        // anchor returns an oversize length prefix.
        let mut over = ((MAX_ANCHOR_RESPONSE_LEN + 1) as u32).to_be_bytes().to_vec();
        over.extend_from_slice(&vec![0u8; MAX_ANCHOR_RESPONSE_LEN + 1]);
        let mut anchor = TestStream::new(over);
        assert!(relay_forward_once(&mut enclave, &mut anchor, far_deadline()).is_err());
        assert!(enclave.written.is_empty(), "no response framed back when the anchor reply is oversize");
    }

    #[test]
    fn driver_oversize_quote_response_garbage_is_terminal_malformed() {
        let _g = test_lock();
        let mut body = test_body(7, 2);
        // A garbage (non-CBOR) reply -> driver -> verify -> Malformed (terminal). Confirms untrusted
        // bytes are safely rejected downstream, not by the transport.
        let mut t = transport(FakeQuote::ok(), MockChannel::new(vec![ChAct::Raw(vec![0xff, 0xff])]));
        match run_boot_anti_rollback_handshake(&mut t, &mut body, 5) {
            BootDriverOutcome::FailClosed(BootDriverFail::Reconcile(BootFailReason::VerifyMalformed)) => {}
            other => panic!("expected VerifyMalformed, got {other:?}"),
        }
        assert_eq!(t.channel.connects, 1);
    }
}

/// 5b-2b-ii(a) acceptance tests for [`VsockBootRelayChannel`] over a REAL `VsockStream`. Gated
/// `all(test, target_os = "linux", feature = "vsock-transport")` (so they compile only where the channel
/// does) and `#[ignore]` (they need a live vsock environment, so THESE tests are skipped by ordinary CI —
/// but CI does compile AND RUN the deviceless suite under the same features, `cargo test --features
/// vsock-transport,agent-gateway` in nix-hsm.yml, which executes the `cancellable_boundary` unit tests this
/// module's coverage notes lean on). RUN on aya:
///   cargo test --features vsock-transport,agent-gateway -- --ignored --nocapture
/// The loopback test needs the `vsock_loopback` kernel module (or run inside the SNP guest).
#[cfg(all(test, target_os = "linux", feature = "vsock-transport"))]
mod vsock_aya_tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, Instant};

    /// `VMADDR_CID_LOCAL` — vsock loopback CID (requires the `vsock_loopback` module).
    const LOOPBACK_CID: u32 = 1;

    fn build_request_frame() -> Vec<u8> {
        // Use the shared canonical CHAIN/ENV (module-root #[cfg(test)] consts) so the aya tests stay on the
        // same inputs as the rest of the suite. (Distinct nonce/filler from the golden vector — these are a
        // separate live-transport fixture, NOT a regression of the frozen golden frame.)
        let nonce = [0x44u8; 32];
        let rd = crate::agent_anchor::anchor_handshake_report_data(CHAIN, ENV, &nonce);
        let req = AnchorBootRequest {
            chain_id: CHAIN,
            environment_identifier: ENV,
            nonce,
            report_data: rd,
        };
        encode_anchor_boot_request(&[0xa5; 64], &[0xc7; 8], &req).unwrap()
    }

    /// Full round-trip over a real loopback `VsockStream`: a listener echoes a framed anchor response;
    /// the channel connects fresh, sets deadline-derived timeouts, forwards the request, and returns the
    /// response verbatim. Exercises connect + `set_read/write_timeout` + `relay_round_trip_over_stream`.
    #[test]
    #[ignore]
    fn vsock_channel_loopback_round_trip() {
        let port = 5999;
        let listener =
            crate::vsock_listen::bind_vsock_listener(LOOPBACK_CID, port).expect("bind loopback");
        let signed = vec![0xab; 200];
        let wire = frame_anchor_response(&signed).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _addr) = listener.accept().expect("accept");
            let req = crate::read_framed_message_with_idle_deadline(
                &mut s,
                Some(Instant::now() + Duration::from_secs(5)),
            )
            .expect("server reads the request frame");
            assert!(decode_anchor_boot_request(&req).is_ok(), "server got a valid boot-relay request");
            s.write_all(&wire).expect("server writes response");
            s.flush().expect("server flush");
        });
        let mut ch = VsockBootRelayChannel::new(LOOPBACK_CID, port);
        let got = ch
            .round_trip(&build_request_frame(), Instant::now() + Duration::from_secs(5))
            .expect("channel round trip");
        assert_eq!(got, signed, "anchor response returned verbatim over real vsock");
        server.join().unwrap();
    }

    /// Connect to a no-listener endpoint under a short deadline: must fail (retryable) PROMPTLY, never hang.
    /// What this PROVES: **prompt socket-level connect refusal + retryable folding**. Kernel reality
    /// (af_vsock): the non-blocking connect returns `EINPROGRESS` (the synchronous-`Ok`/`Err` arms are
    /// structurally unreachable for a refusal — `vsock_connect` holds the sock lock and the REQUEST tx is
    /// workqueued), the transport's RST then lands as `sk_err = ECONNRESET`, and the poll wakes *immediately*
    /// with `POLLERR|POLLOUT` → the `connect_poll_succeeded` veto arm ([`VSOCK_CONNECT_VETO_MSG`]).
    /// The elapsed bound is BELOW the deadline, so this assert genuinely discriminates prompt refusal
    /// from a deadline-lapse (a lapse would run the full deadline out and fail the bound). It does NOT exercise
    /// the deadline-LAPSE path (a black-holed in-flight connect): that is covered structurally by
    /// `cancellable_boundary::poll_times_out_when_not_ready` + RAII fd drop; the real-vsock lapse test
    /// now lives in `quote_smoke` phase `vsock-lapse` ((4c), IN-GUEST — guest→nonexistent CID; a
    /// host-side staging is impossible: host→nonexistent CID fails synchronously `ENODEV` in
    /// `vhost_transport_send_pkt`, no black hole), with a deadline **shorter than the kernel's ~2s
    /// `VSOCK_DEFAULT_CONNECT_TIMEOUT`** (400ms), else the kernel's `ETIMEDOUT` timer preempts the
    /// lapse via the veto arm (see the design doc §8).
    #[test]
    #[ignore]
    fn vsock_channel_connect_failure_is_prompt_and_retryable() {
        // 1s deadline / 800ms bound: a real refusal is microsecond-scale, a lapse takes the full 1s, so
        // the 800ms bound discriminates with ~200ms of scheduler-jitter margin (both well under the
        // kernel's ~2s connect timer, which never engages for a refusal). Triage note: a deterministic
        // FAILURE here can also mean a stray process is LISTENING on vsock port 5998 (connect then
        // succeeds and the read runs the deadline out) — check `ss --vsock` before chasing the connect path.
        //
        // Stage 1 — ARM ATTRIBUTION (matrix finding: round_trip blanket-folds every ProtocolError, so it
        // cannot pin WHICH arm rejected): call connect_bounded directly and assert the exact veto-arm
        // string. Kernel reality (af_vsock): the refusal lands as sk_err=ECONNRESET -> error-ready poll
        // (POLLERR|POLLOUT) -> the connect_poll_succeeded veto; the synchronous and SO_ERROR arms are
        // structurally unreachable for a refusal (vsock_connect holds the sock lock; REQUEST tx is
        // workqueued).
        match connect_bounded(
            crate::vsock_addr::VMADDR_CID_HOST,
            5998,
            Instant::now() + Duration::from_millis(1000),
        ) {
            Err(ProtocolError::WireProtocol(msg)) => assert_eq!(
                msg, VSOCK_CONNECT_VETO_MSG,
                "a no-listener refusal must be rejected by the poll-veto arm specifically"
            ),
            Err(other) => panic!("expected the poll-veto arm error, got {other:?}"),
            Ok(_) => panic!("connect to a dead endpoint must not succeed (stray listener on 5998?)"),
        }
        // Stage 2 — PROMPT + RETRYABLE FOLDING through the public channel API.
        let mut ch = VsockBootRelayChannel::new(crate::vsock_addr::VMADDR_CID_HOST, 5998);
        let start = Instant::now();
        let r = ch.round_trip(&build_request_frame(), start + Duration::from_millis(1000));
        assert!(r.is_err(), "connect to a dead endpoint must error, not hang");
        assert!(
            start.elapsed() < Duration::from_millis(800),
            "refusal must arrive promptly (error-ready poll), NOT by running the 1s deadline out — \
             a lapse here means the prompt-refusal property regressed (or port 5998 has a stray listener)"
        );
    }

    /// Deviceless (NOT `#[ignore]` — runs in ordinary Linux CI): pins the connect-leg lapse RELABEL and,
    /// through the shared `DEADLINE_LAPSED_MSG` const, the cross-module string coupling — if the helper's
    /// lapse message and the relabel match-arm ever drift apart, this fails before any triage degrades.
    /// Uses the entry-check path (a past deadline fails BEFORE any socket is created), so no vsock device
    /// is needed.
    #[test]
    fn connect_bounded_entry_lapse_is_relabelled_deviceless() {
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        match connect_bounded(LOOPBACK_CID, 5995, past) {
            Err(ProtocolError::WireProtocol(msg)) => assert_eq!(
                msg, VSOCK_CONNECT_LAPSE_MSG,
                "entry lapse must carry the connect-leg triage label"
            ),
            Err(other) => panic!("expected relabelled entry-lapse error, got {other:?}"),
            Ok(_) => panic!("a past deadline must fail at entry, not connect"),
        }
    }

    /// Deviceless literal pin: freezes [`VSOCK_CONNECT_LAPSE_MSG`]'s VALUE. Regression: a reword of
    /// the const would silently re-key every downstream exact-match consumer (the (4c) smoke's
    /// lapse-arm discrimination, host-side log greps) without any compile error — the single-source
    /// refactor moves the drift hazard from "three literals disagree" to "the one literal changes",
    /// and this pin makes that change loud.
    #[test]
    fn vsock_connect_lapse_msg_literal_is_pinned() {
        assert_eq!(VSOCK_CONNECT_LAPSE_MSG, "anchor relay: vsock connect deadline lapsed");
    }

    /// Deviceless literal pin: freezes [`VSOCK_CONNECT_VETO_MSG`]'s VALUE (same regression class as
    /// the lapse pin — the (4c) smoke prints/discriminates this exact string when the kernel
    /// timer/RST preempts the lapse arm).
    #[test]
    fn vsock_connect_veto_msg_literal_is_pinned() {
        assert_eq!(VSOCK_CONNECT_VETO_MSG, "anchor relay: vsock connect failed (poll)");
    }

    /// Direct assertions for the two properties the behavioral tests cannot discriminate: (1) after
    /// `connect_bounded` the fd is back in BLOCKING mode (`F_GETFL` has `O_NONBLOCK` cleared) — if a
    /// regression left it non-blocking, `SO_*TIMEO` would be silently ignored and every channel read would
    /// busy-spin WouldBlock until the deadline, passing the stalled-peer test on wall-clock alone; (2)
    /// `DeadlineSocket::arm_read`/`arm_write` really arm `SO_RCVTIMEO`/`SO_SNDTIMEO` to ~the remaining
    /// budget, read back via SAFE `nix` getsockopt (`sockopt::ReceiveTimeout`/`SendTimeout`) — the readback
    /// the docs previously (wrongly, since the nix `socket` feature landed) claimed needed `unsafe`/`libc`.
    #[test]
    #[ignore]
    fn vsock_connect_restores_blocking_and_arms_so_timeo() {
        use nix::fcntl::{fcntl, FcntlArg, OFlag};
        use nix::sys::socket::{getsockopt, sockopt::ReceiveTimeout, sockopt::SendTimeout};
        let port = 5996;
        let listener =
            crate::vsock_listen::bind_vsock_listener(LOOPBACK_CID, port).expect("bind loopback");
        let server = std::thread::spawn(move || {
            let (_s, _addr) = listener.accept().expect("accept");
            std::thread::sleep(Duration::from_millis(300)); // keep the peer alive while we probe
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = connect_bounded(LOOPBACK_CID, port, deadline).expect("connect_bounded");
        // (1) Blocking-mode restored: O_NONBLOCK must be CLEARED (SOCK_NONBLOCK was set at creation).
        let flags = OFlag::from_bits_retain(fcntl(&stream, FcntlArg::F_GETFL).expect("F_GETFL"));
        assert!(
            !flags.contains(OFlag::O_NONBLOCK),
            "connect_bounded must hand back a BLOCKING fd (O_NONBLOCK cleared), got flags {flags:?}"
        );
        // (2) Arm via DeadlineSocket, then read the armed values back (safe nix getsockopt).
        let sock = DeadlineSocket { inner: &mut stream, deadline };
        sock.arm_read().expect("arm_read");
        sock.arm_write().expect("arm_write");
        let rcv = getsockopt(&*sock.inner, ReceiveTimeout).expect("getsockopt(SO_RCVTIMEO)");
        let snd = getsockopt(&*sock.inner, SendTimeout).expect("getsockopt(SO_SNDTIMEO)");
        for (name, tv) in [("SO_RCVTIMEO", rcv), ("SO_SNDTIMEO", snd)] {
            let armed_ms = tv.tv_sec() * 1000 + i64::from(tv.tv_usec()) / 1000;
            // Tight LOWER bound: the remaining budget at arm time is ~2990ms (connect + F_GETFL take
            // milliseconds), so anything below 2000ms means arm_* did NOT derive the timeout from the
            // remaining budget (e.g. a regression arming a hardcoded 1s would otherwise pass both this
            // and the stalled-peer behavioral test). Upper bound: armed value is strictly < 3000ms and
            // kernel jiffy round-UP can reach exactly 3000ms, never exceed it.
            assert!(
                (2000..=3000).contains(&armed_ms),
                "{name} must be armed to ~the remaining budget (2000 <= t <= 3000ms), got {armed_ms}ms"
            );
        }
        server.join().unwrap();
    }

    /// A peer that CONNECTS then STALLS (never sends a response): the channel's read must time out within
    /// ~the deadline (DeadlineSocket SO_RCVTIMEO + the in-fn deadline re-check), NOT block for the peer's
    /// full stall. This is the headline SO_RCVTIMEO-enforcement case the matrix flagged as untested.
    #[test]
    #[ignore]
    fn vsock_channel_stalled_peer_read_times_out_within_budget() {
        let port = 5997;
        let listener =
            crate::vsock_listen::bind_vsock_listener(LOOPBACK_CID, port).expect("bind loopback");
        let server = std::thread::spawn(move || {
            let (_s, _addr) = listener.accept().expect("accept");
            // Accept, then STALL well past the client's deadline without sending a response.
            std::thread::sleep(Duration::from_millis(1500));
            // _s dropped here.
        });
        let mut ch = VsockBootRelayChannel::new(LOOPBACK_CID, port);
        let start = Instant::now();
        let r = ch.round_trip(&build_request_frame(), start + Duration::from_millis(500));
        assert!(r.is_err(), "a stalled peer must make the read time out, not hang");
        assert!(
            start.elapsed() < Duration::from_millis(1300),
            "must return on the client's own ~500ms read deadline, NOT wait out the peer's 1500ms stall"
        );
        server.join().unwrap();
    }
}
