//! Shared CBOR helpers for the **host-supplied Agent Gateway wire maps** (the 0x40 envelope, the
//! §10.5 capability map, and the TASK-7.7 anchor freshness response). Centralizes the int-keyed map
//! accessors that were duplicated across `agent_capability`, `agent_dispatch`, and `agent_anchor`,
//! plus a strict **canonical**-CBOR decoder ([`strict_decode_map`]) so the structural/signature
//! checks bind the exact wire bytes rather than a lenient re-encoding.
//!
//! **Scope — untrusted host wire input only.** Do **not** route the sealed `pq-agent-keystore-v1`
//! body through [`strict_decode_map`]: that blob is serde-CBOR (a struct map, not a canonical
//! int-keyed map) and lives behind the AEAD, so canonicalizing it would reject valid blobs.
//!
//! The accessors are deliberately **error-agnostic** (they return `Option`/`bool`): each caller maps
//! a `None`/`false` onto its own error band — `AgentError::Malformed` (`0x40`, the §10.9 anti-oracle
//! surface) for dispatch/capability, `AnchorError::Malformed` (coarse boot-ceremony band) for the
//! anchor handshake.

use ciborium::value::Value;

/// Look up an integer-keyed entry in a CBOR map (first match; callers reject duplicate keys up front
/// via [`check_strict_keys`], so first-match is unambiguous).
pub(crate) fn map_get(map: &[(Value, Value)], key: u64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if u64::try_from(*i).ok() == Some(key)))
        .map(|(_, v)| v)
}

/// A CBOR integer that fits an unsigned 64-bit value (negative or oversized ⇒ `None`).
pub(crate) fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    }
}

/// A CBOR byte string.
pub(crate) fn as_bytes(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

/// A CBOR byte string of exactly `N` bytes.
pub(crate) fn as_bytes_n<const N: usize>(v: &Value) -> Option<[u8; N]> {
    as_bytes(v).and_then(|b| b.try_into().ok())
}

/// A CBOR byte string of exactly 32 bytes (the common digest / key / nonce width).
pub(crate) fn as_bytes32(v: &Value) -> Option<[u8; 32]> {
    as_bytes_n::<32>(v)
}

/// Strict integer-key check for a decoded wire map: every key is an integer accepted by `allowed`
/// and **no key repeats**. Returns `false` on any violation so the caller can map it to its own
/// `Malformed` band. Supports keys in `1..=16` (every agent-gateway schema uses keys ≤ 13); a key of
/// `0` or `> 16` is rejected **before** the bitmask shift, so a hostile key can never trigger a shift
/// over/underflow (the `allowed` predicate is checked first, but the explicit bound is defence in
/// depth against a future over-wide predicate).
pub(crate) fn check_strict_keys(map: &[(Value, Value)], allowed: impl Fn(u64) -> bool) -> bool {
    let mut seen: u16 = 0;
    for (k, _) in map {
        let Some(n) = as_u64(k) else {
            return false;
        };
        if !allowed(n) || !(1..=16).contains(&n) {
            return false;
        }
        let bit = 1u16 << (n - 1);
        if seen & bit != 0 {
            return false; // duplicate key
        }
        seen |= bit;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(n: i64) -> Value {
        Value::Integer(n.into())
    }

    #[test]
    fn map_get_finds_int_keys_only() {
        let m = vec![(int(1), Value::Integer(7.into())), (int(2), Value::Text("x".into()))];
        assert_eq!(as_u64(map_get(&m, 1).unwrap()), Some(7));
        assert!(map_get(&m, 3).is_none());
        // a text key never matches an integer lookup
        let m2 = vec![(Value::Text("1".into()), Value::Integer(7.into()))];
        assert!(map_get(&m2, 1).is_none());
    }

    #[test]
    fn as_u64_rejects_negative_and_nonint() {
        assert_eq!(as_u64(&Value::Integer(5.into())), Some(5));
        assert_eq!(as_u64(&Value::Integer((-1i64).into())), None);
        assert_eq!(as_u64(&Value::Text("5".into())), None);
        assert_eq!(as_u64(&Value::Bytes(vec![5])), None);
    }

    #[test]
    fn as_bytes_n_enforces_exact_length() {
        assert_eq!(as_bytes_n::<4>(&Value::Bytes(vec![1, 2, 3, 4])), Some([1, 2, 3, 4]));
        assert_eq!(as_bytes_n::<4>(&Value::Bytes(vec![1, 2, 3])), None);
        assert_eq!(as_bytes_n::<4>(&Value::Bytes(vec![1, 2, 3, 4, 5])), None);
        assert_eq!(as_bytes32(&Value::Bytes(vec![0xab; 32])), Some([0xab; 32]));
        assert_eq!(as_bytes32(&Value::Bytes(vec![0xab; 31])), None);
        assert!(as_bytes_n::<4>(&Value::Text("abcd".into())).is_none());
    }

    #[test]
    fn check_strict_keys_per_predicate() {
        // capability allow-set 1..=13
        let cap_ok: Vec<(Value, Value)> = (1..=13).map(|k| (int(k), int(0))).collect();
        assert!(check_strict_keys(&cap_ok, |n| (1..=13).contains(&n)));
        // dispatch allow-set 1..=7
        let disp_ok: Vec<(Value, Value)> = (1..=7).map(|k| (int(k), int(0))).collect();
        assert!(check_strict_keys(&disp_ok, |n| (1..=7).contains(&n)));
        // anchor allow-set 1..=9 || 13
        let anchor_ok: Vec<(Value, Value)> =
            (1..=9).chain(std::iter::once(13)).map(|k| (int(k), int(0))).collect();
        assert!(check_strict_keys(&anchor_ok, |n| (1..=9).contains(&n) || n == 13));
    }

    #[test]
    fn check_strict_keys_rejects_unknown_dup_and_nonint() {
        let allow = |n: u64| (1..=7).contains(&n);
        // unknown key 8
        assert!(!check_strict_keys(&[(int(1), int(0)), (int(8), int(0))], allow));
        // duplicate key 1
        assert!(!check_strict_keys(&[(int(1), int(0)), (int(1), int(0))], allow));
        // non-integer key
        assert!(!check_strict_keys(&[(Value::Text("1".into()), int(0))], allow));
    }

    #[test]
    fn check_strict_keys_zero_key_no_panic() {
        // key 0 must be rejected without panicking on the (n-1) shift, even if a (buggy) predicate
        // were to allow it.
        assert!(!check_strict_keys(&[(int(0), int(0))], |_| true));
        // an empty map is vacuously strict.
        assert!(check_strict_keys(&[], |n: u64| (1..=7).contains(&n)));
    }
}
