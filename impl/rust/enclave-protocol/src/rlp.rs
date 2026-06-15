//! Minimal RLP (Recursive Length Prefix) encoder for the Agent Gateway EIP-155 transfer signer
//! (TASK-7.6.4 / TASK-7.4 §1). Pure, allocation-only, **no external crate** — the no-new-crate policy
//! of the secp256k1 signer backend (`secp256k1.rs`) extends here (hand-rolled, not the `rlp` crate).
//!
//! Only the ENCODE direction exists: the enclave BUILDS the EIP-155 preimage / signed transaction
//! from structured fields and never decodes host-supplied RLP (no decode attack surface). Canonical
//! by construction — integers are minimal big-endian (no leading zero bytes), so the output
//! reproduces 2D `Chain.Crypto.Envelope.unsigned_rlp/1` byte-for-byte (pinned by the frozen
//! `ordinary_tx_v1.*` vectors).
//!
//! Two item kinds:
//! - [`encode_bytes`] — a "string" item: raw bytes kept verbatim (fixed-width fields that retain
//!   leading zeros, e.g. the 20-byte `to` address and `data`).
//! - [`encode_uint_minimal`] — an integer item: leading zero bytes stripped (`0` → empty string
//!   `0x80`), the canonical RLP integer encoding (nonce, gas_price, gas_limit, value, chain_id, v,
//!   r, s).
//!
//! Built only under the `agent-gateway` feature.

/// RLP-encode a byte string ("string" item): raw bytes, NOT minimised. Use for fixed-width fields
/// that keep their leading zeros (the 20-byte `to`, empty `data`).
pub(crate) fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_bytes_into(&mut out, bytes);
    out
}

fn encode_bytes_into(out: &mut Vec<u8>, bytes: &[u8]) {
    // A single byte in [0x00, 0x7f] is its own RLP encoding (no length prefix).
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        encode_length_into(out, bytes.len(), 0x80);
        out.extend_from_slice(bytes);
    }
}

/// RLP-encode a non-negative integer from its big-endian bytes, MINIMISED (leading zero bytes
/// stripped) — the canonical RLP integer encoding. `0` (all-zero or empty input) → the empty string
/// `0x80`. Use for nonce, gas_price, gas_limit, value, chain_id, v, r, s.
pub(crate) fn encode_uint_minimal(be_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_uint_minimal_into(&mut out, be_bytes);
    out
}

fn encode_uint_minimal_into(out: &mut Vec<u8>, be_bytes: &[u8]) {
    let first_nonzero = be_bytes.iter().position(|&b| b != 0).unwrap_or(be_bytes.len());
    encode_bytes_into(out, &be_bytes[first_nonzero..]);
}

/// RLP-encode a list from its already-encoded items (their concatenation is the list payload).
pub(crate) fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    // Compute the payload length up front so the header is written before the items are copied — no
    // intermediate concatenation buffer (one allocation; each item copied exactly once).
    let payload_len: usize = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(payload_len + 9); // payload + up to a 9-byte long-form header
    encode_length_into(&mut out, payload_len, 0xc0);
    for it in items {
        out.extend_from_slice(it);
    }
    out
}

/// RLP length prefix. `offset` is `0x80` for strings, `0xc0` for lists. For length < 56 the prefix is
/// a single byte `offset + len`; otherwise it is `offset + 55 + len_of_len` followed by the minimal
/// big-endian length.
fn encode_length_into(out: &mut Vec<u8>, len: usize, offset: u8) {
    if len < 56 {
        out.push(offset + len as u8);
    } else {
        let len_be = (len as u64).to_be_bytes();
        // len >= 56 ⇒ at least one non-zero byte. Use `expect` (not a silent `unwrap_or` fallback that
        // would emit a truncated length prefix) so a future refactor that ever feeds a smaller `len`
        // fails LOUDLY rather than producing a malformed RLP header.
        let first_nonzero = len_be
            .iter()
            .position(|&b| b != 0)
            .expect("len >= 56 always has a non-zero big-endian byte");
        let len_bytes = &len_be[first_nonzero..];
        out.push(offset + 55 + len_bytes.len() as u8);
        out.extend_from_slice(len_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn encode_bytes_single_small_byte_is_itself() {
        assert_eq!(encode_bytes(&[0x00]), vec![0x00]);
        assert_eq!(encode_bytes(&[0x7f]), vec![0x7f]);
        // 0x80 needs a length prefix (not < 0x80).
        assert_eq!(encode_bytes(&[0x80]), vec![0x81, 0x80]);
    }

    #[test]
    fn encode_bytes_empty_is_0x80() {
        assert_eq!(encode_bytes(&[]), vec![0x80]);
    }

    #[test]
    fn encode_bytes_keeps_leading_zeros() {
        // A "string" item (e.g. an address) is verbatim — leading zeros retained.
        let twenty = [0u8; 20];
        let enc = encode_bytes(&twenty);
        assert_eq!(enc[0], 0x80 + 20);
        assert_eq!(&enc[1..], &twenty);
    }

    #[test]
    fn encode_uint_minimal_strips_leading_zeros() {
        assert_eq!(encode_uint_minimal(&[0x00]), vec![0x80]); // 0 -> empty string
        assert_eq!(encode_uint_minimal(&[]), vec![0x80]);
        assert_eq!(encode_uint_minimal(&[0x00, 0x00, 0x05]), vec![0x05]); // small int -> itself
        assert_eq!(encode_uint_minimal(&[0x00, 0x80]), vec![0x81, 0x80]);
        // gas_price 1e9 = 0x3b9aca00
        assert_eq!(hexs(&encode_uint_minimal(&0x3b9aca00u64.to_be_bytes())), "843b9aca00");
        // gas_limit 21000 = 0x5208
        assert_eq!(hexs(&encode_uint_minimal(&21000u64.to_be_bytes())), "825208");
        // chain_id 11565 = 0x2d2d
        assert_eq!(hexs(&encode_uint_minimal(&11565u64.to_be_bytes())), "822d2d");
    }

    #[test]
    fn encode_list_short_header() {
        // [ "" ] -> 0xc1 0x80
        assert_eq!(encode_list(&[encode_bytes(&[])]), vec![0xc1, 0x80]);
    }

    #[test]
    fn encode_list_long_header_boundary() {
        // A 56-byte payload crosses into the long-form list header (0xf7 + 1, len 0x38).
        let item = encode_bytes(&[0xaa; 55]); // 0xb7? no: 55 < 56 -> 0x80+55=0xb7 prefix, +55 bytes = 56 total
        assert_eq!(item.len(), 56);
        let list = encode_list(&[item]);
        assert_eq!(list[0], 0xf8, "long-form list header");
        assert_eq!(list[1], 56, "one length byte = 56");
        assert_eq!(list.len(), 2 + 56);
    }

    /// The canonical EIP-155 unsigned preimage for `ordinary_tx_v1` must be reproduced byte-for-byte
    /// directly from the RLP primitives (the encoder's golden anchor; the full structured builder is
    /// exercised in `agent_transfer`).
    #[test]
    fn reproduces_ordinary_tx_v1_preimage() {
        let to = hex_to_vec("70997970c51812dc3a010c7d01b50e0d17dc79c8");
        let preimage = encode_list(&[
            encode_uint_minimal(&0u64.to_be_bytes()),          // nonce 0
            encode_uint_minimal(&1_000_000_000u64.to_be_bytes()), // gas_price 1e9
            encode_uint_minimal(&21_000u64.to_be_bytes()),     // gas_limit
            encode_bytes(&to),                                 // to (20B raw)
            encode_uint_minimal(&1_000_000_000_000_000_000u64.to_be_bytes()), // value 1e18
            encode_bytes(&[]),                                 // data empty
            encode_uint_minimal(&11565u64.to_be_bytes()),      // chain_id
            encode_uint_minimal(&[]),                          // EIP-155 trailing r
            encode_uint_minimal(&[]),                          // EIP-155 trailing s
        ]);
        assert_eq!(
            hexs(&preimage),
            "ed80843b9aca008252089470997970c51812dc3a010c7d01b50e0d17dc79c8880de0b6b3a764000080822d2d8080"
        );
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
