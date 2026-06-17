//! TASK-23 Slice 3 seal-root regression test (greptile PR #91 P1).
//!
//! The shipped `twod-hsm-agent-contract-server` bin enables `agent-contract-server` + the mutating
//! previews but NOT `reference-seal-v1-root` (that feature pulls `ml-dsa-65`, which is compile-banned
//! alongside `agent-gateway`), and it is NOT `cfg(test)`. So `seal_root::resolve_provisioning_root()` has
//! NO fallback in the real bin: without an explicit reference-root install, every mutating op fails closed
//! (`0x46`) in `commit_before_emit` BEFORE its `0x45` anchor commit. The lib unit tests are green only via
//! the `cfg(test)` seal-root fallback (a false green for the shipped path).
//!
//! This integration test links the lib WITHOUT `cfg(test)` (it is a separate crate), so it exercises
//! exactly that gap: it runs `prepare_contract_server()` — the SAME boot setup `run_contract_server`
//! performs, including the explicit reference-root install — then drives a FROZEN GENERATE_KEYS through
//! the shipped 0x40 serve glue and asserts SUCCESS. A regression that drops the seal-root install reverts
//! this to `0x46` here (where there is no test fallback), failing loudly.
//!
//! GENERATE_KEYS is the REPRESENTATIVE seal-path op: the seal-root install (`prepare_contract_server`) is
//! op-agnostic and CONFIGURE_TREASURY / SIGN_FAUCET_DISPENSE seal through the IDENTICAL `commit_before_emit`
//! seam, so one op proves the non-`cfg(test)` seal path for all three (the `cfg(test)` lib round-trips
//! already cover each opcode). Enabling only `agent-keygen-exec-preview` here keeps the lane minimal.
#![cfg(all(
    unix,
    feature = "agent-gateway",
    feature = "agent-contract-server",
    feature = "agent-keygen-exec-preview"
))]

use ciborium::value::Value;
use enclave_protocol as ep;

#[test]
fn shipped_setup_generate_keys_seals_and_commits_without_cfg_test_fallback() {
    // SAME boot setup the bin's run_contract_server performs: seed the deviceless reference provisioning
    // root + install the reference keystore + the mutating-op support (anti-rollback binding + mock commit
    // channel). In this non-cfg(test) build, resolve_provisioning_root() would Err without that root.
    ep::contract_server::prepare_contract_server().expect("contract-server boot setup installs");

    // Frame the FROZEN TASK-22 GENERATE_KEYS request (admin-`[7;32]` cap that verifies against the
    // reference config) and drive it through the shipped cross-platform 0x40 serve glue.
    let inner: &[u8] = include_bytes!("../testvectors/agent-gateway/req_generate_keys_v1.bin");
    let frame = ep::encode_message(ep::MessageType::AgentGateway, inner).expect("frame encodes");
    let reply = ep::contract_server::serve_one_agent_frame(&frame).expect("serve replies with a 0x40 frame");
    let decoded = ep::decode_message(&reply).expect("reply is a valid 0x40 frame");
    assert_eq!(decoded.msg_type, ep::MessageType::AgentGateway, "reply is a 0x40 frame");

    // `decode_agent_error_code` is `#[cfg(test)]`, so inspect the body CBOR directly: the agent band uses
    // `{1: code(int)}` for an error and `{1: <minted key array>, 2: blob}` for a GENERATE_KEYS success, so
    // key 1 being an Array vs an Integer cleanly distinguishes them.
    let body: Value =
        ciborium::de::from_reader(decoded.payload.as_slice()).expect("reply body is CBOR");
    let map = match body {
        Value::Map(m) => m,
        other => panic!("reply body is not a CBOR map: {other:?}"),
    };
    let key1 = map
        .iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == 1))
        .map(|(_, v)| v);

    // The crux: in a NON-cfg(test) build, key 1 = Integer means a 0x4x error — and the only way GENERATE_KEYS
    // reaches the seal step yet fails is `resolve_provisioning_root()` Err'ing (0x46) because no seal root
    // was installed. A minted-key Array proves prepare_contract_server's explicit reference-root install is
    // effective (greptile PR #91 P1 regression guard).
    assert!(
        matches!(key1, Some(Value::Array(_))),
        "GENERATE_KEYS must SUCCEED (key 1 = minted key array) in the non-cfg(test) build; got {key1:?} \
         — an Integer key 1 is an error code (0x46 = seal failed before the 0x45 commit, greptile P1)",
    );
}
