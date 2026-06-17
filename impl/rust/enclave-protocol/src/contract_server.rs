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
    // chmod it 0700. Refuse a root ("/") or empty private_dir so a misuse can never tighten the root
    // filesystem (the bin always passes a fixed dedicated dir; this guards other callers).
    if private_dir.as_os_str().is_empty() || private_dir == Path::new("/") {
        return Err(ProtocolError::WireProtocol(
            "contract server: private_dir must be a dedicated directory, not empty or the root \"/\"",
        ));
    }
    if !install_reference_agent_keystore() {
        return Err(ProtocolError::WireProtocol(
            "contract server: reference keystore failed to install (validate/cap)",
        ));
    }
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
}
