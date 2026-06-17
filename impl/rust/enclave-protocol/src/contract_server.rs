//! Deviceless, cross-platform (Linux + macOS) 0x40 serve loop for the contract-test server (TASK-23).
//!
//! Composes existing pub seams — `bind_unix_listener` → [`install_reference_agent_keystore`] →
//! `serve_framed_pump` — over AF_UNIX, with NO SNP boot handshake and NO vsock, so downstream 2d
//! (Elixir/macOS) can live-contract-test the 0x40 protocol. The serve glue is a CROSS-PLATFORM replica
//! of `agent_gateway_boot::agent_serve_one_frame` (which is `pub(crate)` inside the Linux-only,
//! triple-gated `agent_gateway_boot` module and so unreachable here); it uses only pub cross-platform
//! fns (`decode_message`, `handle_agent_gateway_frame`, `encode_message`).
//!
//! **NEVER a production endpoint** (TASK-23 AC#4): no attestation, no anti-rollback durability, PUBLIC
//! reference keys, trust boundary = local file permissions only (socket 0600 / parent 0700). The bin is
//! release-banned (`agent-contract-server`); the production path is the AF_VSOCK + SNP
//! `twod-hsm-agent-gateway` bin.

use crate::enclave_serve::{configure_unix_session_timeouts, serve_framed_pump, SESSION_IDLE_TIMEOUT};
use crate::reference_keystore::install_reference_agent_keystore;
use crate::ProtocolError;
use std::path::Path;

/// Serve ONE framed message as the agent listener: decode the wire frame, require msg_type `0x40`
/// (any other type is a fail-closed wire reject — the accept loop logs + drops the connection, never
/// synthesizing an agent body for a misrouted type), dispatch the inner envelope through the pub
/// [`crate::agent_dispatch::handle_agent_gateway_frame`] (which folds all errors into the
/// `0x40..=0x46` agent band and never panics), and reframe the body as a `0x40` reply. A verbatim
/// cross-platform replica of `agent_gateway_boot::agent_serve_one_frame`.
pub fn serve_one_agent_frame(frame: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let decoded = crate::decode_message(frame)?;
    if decoded.msg_type != crate::MessageType::AgentGateway {
        return Err(ProtocolError::WireProtocol("contract server: non-0x40 frame on the agent listener"));
    }
    let body = crate::agent_dispatch::handle_agent_gateway_frame(&decoded.payload);
    crate::encode_message(crate::MessageType::AgentGateway, &body)
}

/// A DEVICELESS mock anchor commit channel: signs the per-op commit ACK the enclave's `commit_before_emit`
/// expects, so the mutating ops complete instead of failing closed (`0x46`). It signs with the reference
/// `anchor_root` seed, so `verify_commit_ack_bytes` (Ed25519 vs the sealed `anchor_root`) accepts it. A
/// standalone replica of `lab_agent_smoke::lab_commit_ack_for_request` (lab-gated) that single-sources the
/// ack wire shape through `agent_anchor::test_signed_commit_ack_bytes`. **No durability** — acks are
/// in-memory; the host anchor is mocked. Test/contract-server only.
#[cfg(all(
    any(feature = "agent-keygen-exec-preview", feature = "agent-configure-treasury-preview", feature = "agent-sign-faucet-preview"),
    any(test, feature = "agent-contract-server")
))]
struct ReferenceCommitChannel {
    chain_id: u64,
    environment_identifier: String,
    signing_key: ed25519_dalek::SigningKey,
    /// slice-6-5 idempotency: request_id → (epoch, structural, marks). Commit-at-most-once per logical op.
    ledger: std::collections::HashMap<Vec<u8>, (u64, u64, [u8; 32])>,
}

#[cfg(all(
    any(feature = "agent-keygen-exec-preview", feature = "agent-configure-treasury-preview", feature = "agent-sign-faucet-preview"),
    any(test, feature = "agent-contract-server")
))]
impl ReferenceCommitChannel {
    fn new() -> Self {
        let body = crate::reference_keystore::reference_keystore_body();
        Self {
            chain_id: body.config.twod_chain_id,
            environment_identifier: body.config.environment_identifier.clone(),
            signing_key: ed25519_dalek::SigningKey::from_bytes(&crate::reference_keystore::REFERENCE_ANCHOR_SEED),
            ledger: std::collections::HashMap::new(),
        }
    }

    /// Decode the 0x45 commit request, scope-guard the CONSTANT config (chain/env — no committing op
    /// mutates them), idempotency-ledger by request_id, and sign the ack with the anchor key.
    fn ack(&mut self, frame: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let req = crate::agent_boot_relay::decode_anchor_commit_request(frame)?;
        if req.chain_id != self.chain_id || req.environment_identifier != self.environment_identifier {
            return Err(ProtocolError::WireProtocol(
                "reference commit channel: commit scope != reference keystore",
            ));
        }
        let proposed = (req.new_epoch, req.new_structural_version, req.marks_digest);
        match self.ledger.get(&req.request_id).copied() {
            Some(rec) if rec != proposed => {
                return Err(ProtocolError::WireProtocol(
                    "reference commit channel: request_id already recorded with a different state",
                ));
            }
            Some(_) => { /* idempotent retry: re-sign for the fresh nonce below */ }
            None => {
                self.ledger.insert(req.request_id.clone(), proposed);
            }
        }
        Ok(crate::agent_anchor::test_signed_commit_ack_bytes(
            &self.signing_key,
            req.chain_id,
            &req.environment_identifier,
            req.new_epoch,
            req.new_structural_version,
            req.marks_digest,
            req.nonce,
            req.request_id,
        ))
    }
}

#[cfg(all(
    any(feature = "agent-keygen-exec-preview", feature = "agent-configure-treasury-preview", feature = "agent-sign-faucet-preview"),
    any(test, feature = "agent-contract-server")
))]
impl crate::agent_boot_relay::BootRelayChannel for ReferenceCommitChannel {
    fn round_trip(&mut self, frame: &[u8], _deadline: std::time::Instant) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
        // Return the UNFRAMED signed ack; any local failure → coarse always-retryable transport error ⇒
        // the enclave fails the op CLOSED (never reaches swap/emit), matching the production contract.
        self.ack(frame).map_err(|_| crate::agent_boot_driver::AnchorTransportError("reference commit channel: ack computation failed"))
    }
    fn marks_round_trip(&mut self, _frame: &[u8], _deadline: std::time::Instant) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
        // The per-op commit path calls ONLY round_trip; an Err (not panic) keeps a misuse fail-closed.
        Err(crate::agent_boot_driver::AnchorTransportError("reference commit channel: marks_round_trip not used on the per-op commit channel"))
    }
}

/// Install the anti-rollback binding + the mock commit channel for the MUTATING preview lanes. A no-op
/// when no mutating preview is enabled (PUBLIC_IDENTITY / PROVE_IDENTITY / SIGN_TRANSFER need neither).
fn install_mutating_op_support() {
    #[cfg(all(
    any(feature = "agent-keygen-exec-preview", feature = "agent-configure-treasury-preview", feature = "agent-sign-faucet-preview"),
    any(test, feature = "agent-contract-server")
))]
    {
        // Best-effort: the reference body makes both succeed; if either failed, the mutating ops simply
        // stay fail-closed (0x45/0x46), which is the safe outcome for a contract harness.
        let _ = crate::agent_dispatch::install_anti_rollback_binding(crate::agent_dispatch::AntiRollbackBinding {
            epoch: 1,
            active: true,
        });
        let _ = crate::agent_dispatch::install_commit_channel(Box::new(ReferenceCommitChannel::new()));
    }
}

/// Bind the UDS socket at `socket_path` (parent `private_dir` chmod 0700, socket 0600), install the
/// reference agent keystore (so `PUBLIC_IDENTITY` returns a real identity instead of the empty-store
/// `0x41`), then serve 0x40 connections SERIALLY forever. Cross-platform: `std::os::unix` `UnixListener`,
/// no vsock, no SNP boot. Returns `Err` only on a fatal setup failure (keystore install / bind); a
/// per-connection fault is logged and the loop continues (never die on one client).
#[cfg(unix)]
pub fn run_contract_server(
    socket_path: &Path,
    private_dir: &Path,
) -> Result<std::convert::Infallible, ProtocolError> {
    use std::io::Write as _;
    // Defense-in-depth: this is a pub fn whose `private_dir` is handed to bind_unix_listener, which may
    // chmod it 0700 — and `set_permissions` FOLLOWS symlinks, so a symlinked private_dir would tighten its
    // (possibly sensitive) target. Refuse empty / the root `/` / ANY existing symlink, so a misuse can
    // never chmod a foreign directory through a link. A not-yet-created dir has no metadata (bind creates
    // it 0700); a real dedicated directory (the bin's fixed /tmp/twod-hsm-agent-contract) passes. A caller
    // passing a real SENSITIVE dir (e.g. /etc itself) is a blatant self-inflicted misuse out of scope —
    // "dedicated" is uncheckable; the bin uses a fixed dir and this fn is release-banned / test-only.
    let is_symlink = std::fs::symlink_metadata(private_dir).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    if private_dir.as_os_str().is_empty() || private_dir == Path::new("/") || is_symlink {
        return Err(ProtocolError::WireProtocol(
            "contract server: private_dir must be a dedicated real directory, not empty / the root \"/\" / a symlink",
        ));
    }
    if !install_reference_agent_keystore() {
        return Err(ProtocolError::WireProtocol(
            "contract server: reference keystore failed to install (validate/cap)",
        ));
    }
    // Behind the mutating preview features only: install the anti-rollback binding + a deviceless mock
    // commit channel so SIGN_FAUCET_DISPENSE / GENERATE_KEYS / CONFIGURE_TREASURY complete (seal → commit
    // → swap → emit) instead of failing closed. No-op when no mutating preview is enabled.
    install_mutating_op_support();
    let listener = crate::uds_listen::bind_unix_listener(socket_path, private_dir).map_err(ProtocolError::Io)?;
    let _ = writeln!(
        std::io::stderr(),
        "[info] twod-hsm-agent-contract-server: serving deviceless 0x40 on {} (TEST/DEV ONLY — no SNP, no anti-rollback)",
        socket_path.display()
    );
    for accepted in listener.incoming() {
        match accepted {
            Ok(mut stream) => {
                // Arm per-connection timeouts; a setup fault skips this connection WITHOUT backoff (not
                // fd pressure). serve_framed_pump runs the per-connection pump; any fault is contained.
                if configure_unix_session_timeouts(&mut stream).is_ok() {
                    if let Err(e) = serve_framed_pump(&mut stream, serve_one_agent_frame, SESSION_IDLE_TIMEOUT) {
                        let _ = writeln!(std::io::stderr(), "[info] agent contract server: connection closed ({e})");
                    }
                }
            }
            // accept(2) failed WITHOUT draining the backlog → bounded backoff (EMFILE/ENFILE anti-spin),
            // mirroring the SNP serial loop.
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "[warn] agent contract server: accept error ({}); skipping", e.kind());
                std::thread::sleep(crate::enclave_serve::ACCEPT_ERROR_BACKOFF);
            }
        }
    }
    unreachable!("UnixListener::incoming() is an infinite iterator")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    /// A full deviceless round-trip over an in-process UnixStream pair: frame a PUBLIC_IDENTITY request,
    /// drive `serve_one_agent_frame` via `serve_framed_pump`, and assert the reply body equals the TASK-22
    /// frozen `resp_public_identity_v1.bin` — proving the cross-platform serve glue + framing are correct
    /// without binding a socket or running an enclave.
    #[test]
    fn uds_pair_public_identity_round_trip() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        assert!(install_reference_agent_keystore());

        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        configure_unix_session_timeouts(&mut server).expect("arm server timeouts");

        // PUBLIC_IDENTITY(2) request for the reference transfer key_ref, framed as a 0x40 message.
        let k = |n: u64| Value::Integer(n.into());
        let mut env = Vec::new();
        ciborium::ser::into_writer(
            &Value::Map(vec![
                (k(1), Value::Integer((crate::agent_identity::AGENT_GATEWAY_VERSION as u64).into())),
                (k(2), Value::Integer(2u64.into())),
                (k(3), Value::Text(crate::agent_dispatch::COMMAND_DOMAIN.to_string())),
                (k(4), Value::Bytes(b"contract-test:public-identity".to_vec())),
                (k(6), Value::Bytes(crate::reference_keystore::REFERENCE_TRANSFER_KEY_REF.to_vec())),
            ]),
            &mut env,
        )
        .unwrap();
        let req_frame = crate::encode_message(crate::MessageType::AgentGateway, &env).unwrap();
        client.write_all(&req_frame).unwrap();
        // Close the write half so the pump reads exactly one frame, replies, then sees EOF and returns.
        client.shutdown(std::net::Shutdown::Write).unwrap();

        serve_framed_pump(&mut server, serve_one_agent_frame, SESSION_IDLE_TIMEOUT).expect("pump serves the frame then EOFs");

        // Read EXACTLY one length-prefixed reply frame (not read_to_end — `server` is still open, so
        // there is no EOF to wait for), decode it, and compare the body to the frozen golden.
        let reply = crate::read_framed_message(&mut client).expect("read one reply frame");
        let decoded = crate::decode_message(&reply).expect("reply is a valid 0x40 frame");
        assert_eq!(decoded.msg_type, crate::MessageType::AgentGateway, "reply is a 0x40 frame");
        let frozen: &[u8] = include_bytes!("../testvectors/agent-gateway/resp_public_identity_v1.bin");
        assert_eq!(decoded.payload.as_slice(), frozen, "round-trip PUBLIC_IDENTITY body == frozen golden");

        crate::agent_dispatch::reset_agent_keystore_for_tests();
    }

    /// A non-0x40 frame on the agent listener is a fail-closed wire reject (the accept loop drops the
    /// connection) — never an agent body for a misrouted type.
    #[test]
    fn non_0x40_frame_is_rejected() {
        // 0x01 = GetMeasurement (a producer type) framed; serve_one_agent_frame must reject it.
        let frame = crate::encode_message(crate::MessageType::GetMeasurement, b"x").unwrap();
        assert!(matches!(serve_one_agent_frame(&frame), Err(ProtocolError::WireProtocol(_))));
    }

    /// The full deviceless MUTATING round-trip: install the reference keystore + the anti-rollback binding
    /// + the mock commit channel, then dispatch the FROZEN TASK-22 GENERATE_KEYS request envelope (whose
    /// capability is signed by admin `[7;32]` for env `env-prod-0` and verifies against the reference
    /// config). The op completes the seal → commit → swap → emit seam — the mock channel signs the ack
    /// against the reference `anchor_root` — and returns a SUCCESS body (minted key list + sealed blob),
    /// NOT a `0x4x` error. Proves the contract server live-contract-tests the mutating lanes with the
    /// frozen vectors, deviceless.
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_round_trip_with_frozen_task22_cap() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        assert!(install_reference_agent_keystore());
        install_mutating_op_support();

        let env: &[u8] = include_bytes!("../testvectors/agent-gateway/req_generate_keys_v1.bin");
        let out = crate::agent_dispatch::handle_agent_gateway_frame(env);

        assert_eq!(
            crate::agent_dispatch::decode_agent_error_code(&out),
            None,
            "GENERATE_KEYS must succeed (not a 0x4x error) — the mock commit channel signed the ack",
        );
        let m = match ciborium::de::from_reader::<Value, _>(out.as_slice()).unwrap() {
            Value::Map(m) => m,
            _ => panic!("success body is a CBOR map"),
        };
        assert!(matches!(crate::agent_cbor::map_get(&m, 1), Some(Value::Array(_))), "key 1 = minted key list");
        assert!(matches!(crate::agent_cbor::map_get(&m, 2), Some(Value::Bytes(_))), "key 2 = sealed keystore blob");

        crate::agent_dispatch::reset_agent_keystore_for_tests();
        crate::agent_dispatch::reset_commit_channel_for_tests();
    }
}
