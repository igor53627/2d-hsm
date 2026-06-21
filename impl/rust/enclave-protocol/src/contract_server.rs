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
//!
//! **Downstream-2d notes.** (1) *Frozen-vector replayability is per-opcode.* Only the PRIVILEGED
//! `GENERATE_KEYS` / `CONFIGURE_TREASURY` frozen REQUESTS replay for SUCCESS — they carry NO `key_ref`,
//! only an admin-signed cap that verifies against the reference config (round-trip-proven by the tests
//! below). Every NON-privileged frozen request (`PUBLIC_IDENTITY` / `PROVE_IDENTITY` / `SIGN_TRANSFER` /
//! `SIGN_FAUCET_DISPENSE`) carries the TASK-22 filler `key_ref=[0x11;32]`, which the reference keystore
//! does NOT hold (its keys are `[0x33;32]` transfer / `[0x44;32]` treasury) — so replaying THOSE bytes
//! returns `0x42`, not success; they are wire-ENCODING vectors. The byte-exact frozen
//! `resp_public_identity_v1.bin` is reproduced by a SERVER-BUILT `PUBLIC_IDENTITY` request for `[0x33;32]`
//! (`REFERENCE_TRANSFER_KEY_REF`) — NOT by replaying the frozen request — as
//! `uds_pair_public_identity_round_trip` does; likewise the faucet lane is driven by a server-built
//! dispense at the reference treasury key (`sign_faucet_dispense_round_trip_*`). (2) *Serial serving.*
//! `run_contract_server` serves one connection at a time (`UnixListener::incoming`); a client holding a
//! connection monopolizes the slot — run one contract suite per server instance (or one server per suite).
//! One-suite-per-instance is the deliberate contract here (a dev harness, not multi-tenant): there is only
//! a `SESSION_IDLE_TIMEOUT`, NO max-session-lifetime / max-frames cap — the same serial-slot starvation
//! already tracked as a multi-tenant precondition for the SNP serve loop, intentionally out of scope.

use crate::enclave_serve::{
    configure_unix_session_timeouts, serve_framed_pump, SESSION_IDLE_TIMEOUT,
};
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
        return Err(ProtocolError::WireProtocol(
            "contract server: non-0x40 frame on the agent listener",
        ));
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
    any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-sign-faucet-preview"
    ),
    any(test, feature = "agent-contract-server")
))]
struct ReferenceCommitChannel {
    chain_id: u64,
    environment_identifier: String,
    signing_key: ed25519_dalek::SigningKey,
    /// slice-6-5 idempotency: request_id → (epoch, structural, marks). Commit-at-most-once per logical op.
    /// In-memory and NEVER reaped — fine for a dev/contract harness (the production anchor is the durable
    /// sequencer; this mock keeps no durable state). A very-long-lived contract server would grow this by
    /// one entry per distinct request_id; restart to reclaim.
    ledger: std::collections::HashMap<Vec<u8>, (u64, u64, [u8; 32])>,
}

#[cfg(all(
    any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-sign-faucet-preview"
    ),
    any(test, feature = "agent-contract-server")
))]
impl ReferenceCommitChannel {
    fn new() -> Self {
        let body = crate::reference_keystore::reference_keystore_body();
        Self {
            chain_id: body.config.twod_chain_id,
            // Partial move (not clone): `body` is owned and unused after this literal (gemini PR #91).
            environment_identifier: body.config.environment_identifier,
            signing_key: ed25519_dalek::SigningKey::from_bytes(
                &crate::reference_keystore::REFERENCE_ANCHOR_SEED,
            ),
            ledger: std::collections::HashMap::new(),
        }
    }

    /// Decode the 0x45 commit request, scope-guard the CONSTANT config (chain/env — no committing op
    /// mutates them), idempotency-ledger by request_id, and sign the ack with the anchor key.
    fn ack(&mut self, frame: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let req = crate::agent_boot_relay::decode_anchor_commit_request(frame)?;
        if req.chain_id != self.chain_id
            || req.environment_identifier != self.environment_identifier
        {
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
    any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-sign-faucet-preview"
    ),
    any(test, feature = "agent-contract-server")
))]
impl crate::agent_boot_relay::BootRelayChannel for ReferenceCommitChannel {
    fn round_trip(
        &mut self,
        frame: &[u8],
        _deadline: std::time::Instant,
    ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
        // Return the UNFRAMED signed ack; any local failure → coarse always-retryable transport error ⇒
        // the enclave fails the op CLOSED (never reaches swap/emit), matching the production contract.
        self.ack(frame).map_err(|_| {
            crate::agent_boot_driver::AnchorTransportError(
                "reference commit channel: ack computation failed",
            )
        })
    }
    fn marks_round_trip(
        &mut self,
        _frame: &[u8],
        _deadline: std::time::Instant,
    ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
        // The per-op commit path calls ONLY round_trip; an Err (not panic) keeps a misuse fail-closed.
        Err(crate::agent_boot_driver::AnchorTransportError(
            "reference commit channel: marks_round_trip not used on the per-op commit channel",
        ))
    }
}

/// Install the anti-rollback binding + the mock commit channel for the MUTATING preview lanes. A no-op
/// when no mutating preview is enabled (PUBLIC_IDENTITY / PROVE_IDENTITY / SIGN_TRANSFER need neither).
fn install_mutating_op_support() {
    #[cfg(all(
        any(
            feature = "agent-keygen-exec-preview",
            feature = "agent-configure-treasury-preview",
            feature = "agent-sign-faucet-preview"
        ),
        any(test, feature = "agent-contract-server")
    ))]
    {
        use std::io::Write as _;
        // Best-effort install-once: the reference body makes both succeed on a fresh process. A `false`
        // (each fn: "already installed") is SURFACED, not silently dropped — the mutating ops depend on
        // these globals, so a duplicate/misordered install that left one un-installed would otherwise show
        // only as an opaque 0x45/0x46 with no server-side signal (symmetry with the seal-root warn above).
        if !crate::agent_dispatch::install_anti_rollback_binding(
            crate::agent_dispatch::AntiRollbackBinding {
                epoch: 1,
                active: true,
            },
        ) {
            let _ = writeln!(
                std::io::stderr(),
                "[warn] contract server: anti-rollback binding not installed (already set?); mutating ops may fail closed (0x45)"
            );
        }
        if !crate::agent_dispatch::install_commit_channel(Box::new(ReferenceCommitChannel::new())) {
            let _ = writeln!(
                std::io::stderr(),
                "[warn] contract server: mock commit channel not installed (already set?); mutating ops may fail closed (0x46)"
            );
        }
    }
}

/// The bin's boot setup, extracted so an integration test can drive it in a NON-`cfg(test)` build (where
/// `seal_root::resolve_provisioning_root` has no fallback): seed the deviceless reference provisioning
/// root, install the reference keystore, and install the mutating-op support. `Err` iff the keystore
/// fails to install.
///
/// **Why the seal root (greptile PR #91 P1).** The mutating ops' `commit_before_emit` SEALS the candidate
/// keystore via `resolve_provisioning_root()` BEFORE the `0x45` anchor commit. This deviceless,
/// cross-platform server has NO SNP-firmware platform root, and `reference-seal-v1-root` cannot be enabled
/// (it pulls `ml-dsa-65`, which is compile-banned alongside `agent-gateway`). Under `cfg(test)` a fixture
/// root is resolved automatically — but the SHIPPED bin is NOT `cfg(test)`, so without an explicit install
/// every mutating op would fail closed (`0x46`) before its commit (the lib unit tests are green only via
/// that `cfg(test)` fallback). We therefore install the SAME committed fixture root
/// (`testvectors/seal_v1_provisioning_root.bin`) the `cfg(test)` path uses, so a sealed blob the bin
/// returns unseal-roundtrips. Best-effort install-once (a second call / an already-set platform root is
/// fine). Gated on the mutating previews — a read-only build never seals, so it needs no root.
pub fn prepare_contract_server() -> Result<(), ProtocolError> {
    #[cfg(any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-sign-faucet-preview"
    ))]
    {
        let reference_root: [u8; 32] =
            *include_bytes!("../testvectors/seal_v1_provisioning_root.bin");
        // Best-effort install-once. Surface a failure (not a silent `let _ =`) so a deviceless misconfig is
        // observable at runtime: if NO provisioning root ends up configured, the mutating ops fail closed
        // 0x46 — a 2d engineer should be able to tell that from a real reject. (An "already configured"
        // error is benign — a pre-set platform root resolves fine — hence a [warn], not a fatal.)
        if let Err(e) = crate::seal_root::set_pq_seal_v1_provisioning_root(reference_root) {
            use std::io::Write as _;
            let _ = writeln!(
                std::io::stderr(),
                "[warn] contract server: reference seal root not installed ({e}); mutating ops need a provisioning root (else 0x46)"
            );
        }
    }
    if !install_reference_agent_keystore() {
        return Err(ProtocolError::WireProtocol(
            "contract server: reference keystore failed to install (validate/cap)",
        ));
    }
    install_mutating_op_support();
    Ok(())
}

/// Bind the UDS socket at `socket_path` (parent `private_dir` chmod 0700, socket 0600), run
/// [`prepare_contract_server`] (seal root + reference keystore + mutating-op support), then serve 0x40
/// connections SERIALLY forever. Cross-platform: `std::os::unix` `UnixListener`, no vsock, no SNP boot.
/// Returns `Err` only on a fatal setup failure (keystore install / bind); a per-connection fault is
/// logged and the loop continues (never die on one client).
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
    let is_symlink = std::fs::symlink_metadata(private_dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    if private_dir.as_os_str().is_empty() || private_dir == Path::new("/") || is_symlink {
        return Err(ProtocolError::WireProtocol(
            "contract server: private_dir must be a dedicated real directory, not empty / the root \"/\" / a symlink",
        ));
    }
    // Seed the deviceless reference seal root (so mutating ops can seal — greptile PR #91 P1), install the
    // reference keystore (so PUBLIC_IDENTITY answers a real identity, not the empty-store 0x41), and the
    // mutating-op support (anti-rollback binding + mock commit channel; a no-op without a mutating preview).
    prepare_contract_server()?;
    let listener = crate::uds_listen::bind_unix_listener(socket_path, private_dir)
        .map_err(ProtocolError::Io)?;
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
                    if let Err(e) =
                        serve_framed_pump(&mut stream, serve_one_agent_frame, SESSION_IDLE_TIMEOUT)
                    {
                        let _ = writeln!(
                            std::io::stderr(),
                            "[info] agent contract server: connection closed ({e})"
                        );
                    }
                }
            }
            // accept(2) failed WITHOUT draining the backlog → bounded backoff (EMFILE/ENFILE anti-spin),
            // mirroring the SNP serial loop.
            Err(e) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "[warn] agent contract server: accept error ({}); skipping",
                    e.kind()
                );
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
                (
                    k(1),
                    Value::Integer((crate::agent_identity::AGENT_GATEWAY_VERSION as u64).into()),
                ),
                (k(2), Value::Integer(2u64.into())),
                (
                    k(3),
                    Value::Text(crate::agent_dispatch::COMMAND_DOMAIN.to_string()),
                ),
                (
                    k(4),
                    Value::Bytes(b"contract-test:public-identity".to_vec()),
                ),
                (
                    k(6),
                    Value::Bytes(crate::reference_keystore::REFERENCE_TRANSFER_KEY_REF.to_vec()),
                ),
            ]),
            &mut env,
        )
        .unwrap();
        let req_frame = crate::encode_message(crate::MessageType::AgentGateway, &env).unwrap();
        client.write_all(&req_frame).unwrap();
        // Close the write half so the pump reads exactly one frame, replies, then sees EOF and returns.
        client.shutdown(std::net::Shutdown::Write).unwrap();

        serve_framed_pump(&mut server, serve_one_agent_frame, SESSION_IDLE_TIMEOUT)
            .expect("pump serves the frame then EOFs");

        // Read EXACTLY one length-prefixed reply frame (not read_to_end — `server` is still open, so
        // there is no EOF to wait for), decode it, and compare the body to the frozen golden.
        let reply = crate::read_framed_message(&mut client).expect("read one reply frame");
        let decoded = crate::decode_message(&reply).expect("reply is a valid 0x40 frame");
        assert_eq!(
            decoded.msg_type,
            crate::MessageType::AgentGateway,
            "reply is a 0x40 frame"
        );
        let frozen: &[u8] =
            include_bytes!("../testvectors/agent-gateway/resp_public_identity_v1.bin");
        assert_eq!(
            decoded.payload.as_slice(),
            frozen,
            "round-trip PUBLIC_IDENTITY body == frozen golden"
        );

        crate::agent_dispatch::reset_agent_keystore_for_tests();
    }

    /// A non-0x40 frame on the agent listener is a fail-closed wire reject (the accept loop drops the
    /// connection) — never an agent body for a misrouted type.
    #[test]
    fn non_0x40_frame_is_rejected() {
        // 0x01 = GetMeasurement (a producer type) framed; serve_one_agent_frame must reject it.
        let frame = crate::encode_message(crate::MessageType::GetMeasurement, b"x").unwrap();
        assert!(matches!(
            serve_one_agent_frame(&frame),
            Err(ProtocolError::WireProtocol(_))
        ));
    }

    /// The full deviceless MUTATING round-trip: install the reference keystore + the anti-rollback binding
    /// + the mock commit channel, then dispatch the FROZEN TASK-22 GENERATE_KEYS request envelope (whose
    /// capability is signed by admin `[7;32]` for env `env-prod-0` and verifies against the reference
    /// config). The op completes the seal → commit → swap → emit seam — the mock channel signs the ack
    /// against the reference `anchor_root` — and returns a SUCCESS body (minted key list + sealed blob),
    /// NOT a `0x4x` error. Proves the contract server live-contract-tests the mutating lanes with the
    /// frozen vectors, deviceless.
    ///
    /// NB this is a `cfg(test)` lib test, so the seal step resolves the provisioning root via the
    /// `cfg(test)` fixture fallback. The SHIPPED bin is NOT `cfg(test)` and must install that root
    /// explicitly (`prepare_contract_server`) — covered by the non-`cfg(test)` integration test
    /// `tests/twod_hsm_agent_contract_server_seal.rs` (greptile PR #91 P1).
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
        assert!(
            matches!(crate::agent_cbor::map_get(&m, 1), Some(Value::Array(_))),
            "key 1 = minted key list"
        );
        assert!(
            matches!(crate::agent_cbor::map_get(&m, 2), Some(Value::Bytes(_))),
            "key 2 = sealed keystore blob"
        );

        crate::agent_dispatch::reset_agent_keystore_for_tests();
        crate::agent_dispatch::reset_commit_channel_for_tests();
    }

    /// CONFIGURE_TREASURY (set_limits) round-trip through the IDENTICAL `commit_before_emit` seam as
    /// GENERATE_KEYS, dispatching the FROZEN TASK-22 `req_configure_set_limits_v1.bin` (an admin-`[7;32]`-
    /// signed cap for env `env-prod-0` that verifies against the reference config — pinned analogously by
    /// `reference_keystore::task22_generate_keys_cap_verifies_against_reference_config`). A Structural-class
    /// commit; the success body is `{1: sealed_blob}` (key 1 = Bytes ⇒ NOT a `{1: code(int)}` error). Proves
    /// the mock channel serves a SECOND mutating opcode, not just GENERATE_KEYS.
    #[cfg(feature = "agent-configure-treasury-preview")]
    #[test]
    fn configure_treasury_round_trip_with_frozen_task22_cap() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        assert!(install_reference_agent_keystore());
        install_mutating_op_support();

        let env: &[u8] =
            include_bytes!("../testvectors/agent-gateway/req_configure_set_limits_v1.bin");
        let out = crate::agent_dispatch::handle_agent_gateway_frame(env);

        assert_eq!(
            crate::agent_dispatch::decode_agent_error_code(&out),
            None,
            "CONFIGURE_TREASURY must succeed (not a 0x4x error) — the mock commit channel signed the ack",
        );
        let m = match ciborium::de::from_reader::<Value, _>(out.as_slice()).unwrap() {
            Value::Map(m) => m,
            _ => panic!("success body is a CBOR map"),
        };
        assert!(
            matches!(crate::agent_cbor::map_get(&m, 1), Some(Value::Bytes(_))),
            "key 1 = sealed keystore blob"
        );

        crate::agent_dispatch::reset_agent_keystore_for_tests();
        crate::agent_dispatch::reset_commit_channel_for_tests();
    }

    /// SIGN_FAUCET_DISPENSE round-trip — the EpochOnly commit class (vs the Structural GENERATE/CONFIGURE
    /// above), exercising the OTHER `advance_commit_epoch` arm through the same mock channel.
    ///
    /// REPLAYABILITY (the frozen faucet REQUEST is encoding-only, not replay-for-success): it is a RUNTIME
    /// op bound to `key_ref=[0x11;32]`, which the reference keystore does NOT hold (treasury is at
    /// `[0x44;32]`) — so the handler's key-lookup rejects it `0x42` BEFORE it ever reaches the
    /// `from`/`to`/amount checks (the rejection is the absent key_ref, NOT the payload values). The
    /// privileged GENERATE_KEYS/CONFIGURE frozen requests, by contrast, carry an admin cap and NO `key_ref`,
    /// so they replay against the reference config for SUCCESS (see the two tests above). To exercise the
    /// faucet LANE this builds a dispense against the reference treasury key directly: `from` = its derived
    /// eth address, `to` = the reference transfer key's address (the only stored §2 known recipient), within the
    /// pre-funded reference caps (per_dispense 1e6 / gas 21000 / fee 1e9 / budget 1e7 — worst_case
    /// = 1000 + 21000·1 = 22000 ≤ budget). Success body is `{1: signed_rlp, …, 8: sealed_blob}`.
    #[cfg(feature = "agent-sign-faucet-preview")]
    #[test]
    fn sign_faucet_dispense_round_trip_against_reference_treasury() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        assert!(install_reference_agent_keystore());
        install_mutating_op_support();

        // Derive both eth addresses from the reference body's stored uncompressed pubkeys (no private
        // scalars needed): `from` = the treasury key, `to` = the transfer key (the §2 recipient allowlist).
        let body = crate::reference_keystore::reference_keystore_body();
        let addr_of = |kr: [u8; 32]| -> [u8; 20] {
            let pk: [u8; 65] = body
                .entries
                .iter()
                .find(|e| e.key_ref == kr)
                .unwrap()
                .public_identity
                .as_slice()
                .try_into()
                .unwrap();
            crate::secp256k1::eth_address_from_uncompressed(&pk).unwrap()
        };
        let from = addr_of(crate::reference_keystore::REFERENCE_TREASURY_KEY_REF);
        let to = addr_of(crate::reference_keystore::REFERENCE_TRANSFER_KEY_REF);
        // Canonical minimal big-endian (no leading zero) of a non-zero u64, the §2 amount/gas_price wire form.
        let min_be = |x: u64| -> Vec<u8> {
            let b = x.to_be_bytes();
            b[b.iter().position(|&c| c != 0).unwrap_or(7)..].to_vec()
        };
        let k = |n: u64| Value::Integer(n.into());
        // §2 dispense payload: the strict 8-field native-transfer map {1:chain,2:from,3:to,4:amount,5:nonce,
        // 6:gas_limit,7:gas_price,8:data(empty)} — mirrors `lab_agent_smoke::dispense_envelope`.
        let payload = Value::Map(vec![
            (k(1), k(crate::reference_keystore::REFERENCE_CHAIN_ID)),
            (k(2), Value::Bytes(from.to_vec())),
            (k(3), Value::Bytes(to.to_vec())),
            (k(4), Value::Bytes(min_be(1_000))),
            (k(5), k(0)),
            (k(6), k(21_000)),
            (k(7), Value::Bytes(min_be(1))),
            (k(8), Value::Bytes(Vec::new())),
        ]);
        let mut env = Vec::new();
        ciborium::ser::into_writer(
            &Value::Map(vec![
                (k(1), k(crate::agent_identity::AGENT_GATEWAY_VERSION as u64)),
                (k(2), k(5)),
                (
                    k(3),
                    Value::Text(crate::agent_dispatch::COMMAND_DOMAIN.to_string()),
                ),
                (
                    k(4),
                    Value::Bytes(b"contract-test:faucet-dispense".to_vec()),
                ),
                (
                    k(6),
                    Value::Bytes(crate::reference_keystore::REFERENCE_TREASURY_KEY_REF.to_vec()),
                ),
                (k(7), payload),
            ]),
            &mut env,
        )
        .unwrap();

        let out = crate::agent_dispatch::handle_agent_gateway_frame(&env);
        assert_eq!(
            crate::agent_dispatch::decode_agent_error_code(&out),
            None,
            "SIGN_FAUCET_DISPENSE must succeed (not a 0x4x error) — the mock commit channel signed the ack",
        );
        let m = match ciborium::de::from_reader::<Value, _>(out.as_slice()).unwrap() {
            Value::Map(m) => m,
            _ => panic!("success body is a CBOR map"),
        };
        assert!(
            matches!(crate::agent_cbor::map_get(&m, 1), Some(Value::Bytes(_))),
            "key 1 = signed tx RLP"
        );
        assert!(
            matches!(crate::agent_cbor::map_get(&m, 8), Some(Value::Bytes(_))),
            "key 8 = sealed keystore blob"
        );

        crate::agent_dispatch::reset_agent_keystore_for_tests();
        crate::agent_dispatch::reset_commit_channel_for_tests();
    }
}
