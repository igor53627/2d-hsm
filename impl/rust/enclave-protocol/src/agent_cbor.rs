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
/// `Malformed` band. Supports keys in `1..=64` (every agent-gateway schema uses keys ≤ 13; the bound
/// matches `MAX_MAP_ENTRIES`); a key of `0` or `> 64` is rejected **before** the bitmask shift, so a
/// hostile key can never trigger a shift over/underflow (the `allowed` predicate is checked first, but
/// the explicit bound is defence in depth against a future over-wide predicate).
pub(crate) fn check_strict_keys(map: &[(Value, Value)], allowed: impl Fn(u64) -> bool) -> bool {
    let mut seen: u64 = 0;
    for (k, _) in map {
        let Some(n) = as_u64(k) else {
            return false;
        };
        if !allowed(n) || !(1..=64).contains(&n) {
            return false;
        }
        let bit = 1u64 << (n - 1);
        if seen & bit != 0 {
            return false; // duplicate key
        }
        seen |= bit;
    }
    true
}

// Caps for the strict decoder. Host input is already bounded by MAX_MESSAGE_SIZE (1 MiB); these keep
// a hostile-but-small frame from forcing deep recursion or large pre-allocations, and are far above
// any legitimate agent-gateway message (largest schema is the 13-key capability map; values are tiny).
// FORWARD-COMPAT: these are silent hard limits — a conformant, correctly-signed message that exceeds
// any of them is rejected as `Malformed`. If a future agent-gateway schema legitimately needs a larger
// map/array, deeper nesting, or a bigger string/bytes field (e.g. a marks vector or an attestation
// blob), raise the relevant constant in lockstep with that schema change.
const MAX_CBOR_DEPTH: usize = 4; // legit envelope nests to depth 2 (cap@5 / payload@7 submaps)
const MAX_MAP_ENTRIES: u64 = 64;
const MAX_ARRAY_ENTRIES: u64 = 64;
const MAX_STR_LEN: u64 = 4096; // per-field caps are <= 64 B; 4 KiB is generous headroom

/// Hand-rolled **strict canonical CBOR** reader (RFC 8949 §4.2.1) for untrusted host wire maps. It
/// produces a [`Value`] only after the *entire* item passes, so the caller's signature/structural
/// checks bind the exact wire bytes. Returns `Err(())` (the caller maps it to its own `Malformed`)
/// on any non-canonical or malformed input.
struct StrictParser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl StrictParser<'_> {
    fn u8(&mut self) -> Result<u8, ()> {
        let b = *self.buf.get(self.pos).ok_or(())?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], ()> {
        let end = self.pos.checked_add(n).ok_or(())?;
        let s = self.buf.get(self.pos..end).ok_or(())?;
        self.pos = end;
        Ok(s)
    }

    /// Read a CBOR head, enforcing shortest-form argument encoding (canonical). Rejects indefinite
    /// length (minor 31) and the reserved minors 28–30.
    fn head(&mut self) -> Result<(u8, u64), ()> {
        let ib = self.u8()?;
        let major = ib >> 5;
        let minor = ib & 0x1f;
        let arg = match minor {
            0..=23 => u64::from(minor),
            24 => {
                let v = u64::from(self.u8()?);
                if v < 24 {
                    return Err(()); // not shortest-form
                }
                v
            }
            25 => {
                let b = self.take(2)?;
                let v = u64::from(u16::from_be_bytes([b[0], b[1]]));
                if v <= u64::from(u8::MAX) {
                    return Err(());
                }
                v
            }
            26 => {
                let b = self.take(4)?;
                let v = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if v <= u64::from(u16::MAX) {
                    return Err(());
                }
                v
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes(b.try_into().map_err(|_| ())?);
                if v <= u64::from(u32::MAX) {
                    return Err(());
                }
                v
            }
            _ => return Err(()), // 28,29,30 reserved; 31 indefinite-length
        };
        Ok((major, arg))
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn item(&mut self, depth: usize) -> Result<Value, ()> {
        if depth > MAX_CBOR_DEPTH {
            return Err(());
        }
        let (major, arg) = self.head()?;
        match major {
            0 => Ok(Value::Integer(arg.into())), // unsigned int
            1 => {
                // negative int = -1 - arg
                let n = -1i128 - i128::from(arg);
                Ok(Value::Integer(n.try_into().map_err(|_| ())?))
            }
            2 => {
                if arg > MAX_STR_LEN {
                    return Err(());
                }
                Ok(Value::Bytes(self.take(arg as usize)?.to_vec()))
            }
            3 => {
                if arg > MAX_STR_LEN {
                    return Err(());
                }
                let s = core::str::from_utf8(self.take(arg as usize)?).map_err(|_| ())?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                if arg > MAX_ARRAY_ENTRIES || arg as usize > self.remaining() {
                    return Err(());
                }
                let mut out = Vec::with_capacity(arg as usize);
                for _ in 0..arg {
                    out.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(out))
            }
            5 => {
                // Each entry is a (key, value) = at least 2 bytes; bound by 2×arg before allocating.
                if arg > MAX_MAP_ENTRIES || 2 * (arg as usize) > self.remaining() {
                    return Err(());
                }
                let mut out: Vec<(Value, Value)> = Vec::with_capacity(arg as usize);
                let mut last_key: Option<(usize, usize)> = None;
                for _ in 0..arg {
                    let key_start = self.pos;
                    let k = self.item(depth + 1)?;
                    let key_end = self.pos;
                    // Canonical map ordering: keys strictly ascending by ENCODED-key bytes (RFC 8949
                    // §4.2.1), which simultaneously rejects duplicates and out-of-order keys.
                    if let Some((ps, pe)) = last_key {
                        if self.buf[key_start..key_end] <= self.buf[ps..pe] {
                            return Err(());
                        }
                    }
                    last_key = Some((key_start, key_end));
                    let v = self.item(depth + 1)?;
                    out.push((k, v));
                }
                Ok(Value::Map(out))
            }
            7 => match arg {
                // simple values: only the booleans are part of the agent-gateway wire format (the
                // §10.5 capability `is_recovery`, key 12). null/undefined/simple/all floats are
                // rejected (head() already rejected the non-shortest float/simple encodings).
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                _ => Err(()),
            },
            _ => Err(()), // major 6 (tag) is rejected
        }
    }
}

/// Strict-canonical-CBOR decode of host bytes into a top-level int-keyed map. Rejects non-shortest
/// integers, indefinite-length items, duplicate or out-of-order map keys, reserved/tag/float items,
/// over-deep nesting, oversize strings/collections, and trailing bytes. The top item MUST be a
/// definite-length map. See the module doc: **wire input only — never the sealed keystore body.**
pub(crate) fn strict_decode_map(bytes: &[u8]) -> Result<Vec<(Value, Value)>, ()> {
    let mut p = StrictParser { buf: bytes, pos: 0 };
    let v = p.item(1)?;
    if p.pos != bytes.len() {
        return Err(()); // trailing bytes
    }
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(()),
    }
}

// -------------------------------------------------------------------------------------------------
// Marks-payload strict decoder (TASK-7.7 5b-2e). The anti-rollback `marks_digest` is a SHA3 hash —
// non-invertible — so the AdoptForward path must fetch the RAW marks (the host-relayed, anchor-signed
// counter/spend high-water) and re-hash them to compare against the anchor's signed digest. That
// requires DECODING the FROZEN-v1 marks payload (`agent_keystore::encode_marks_payload`) back into
// rows + spend + recovery-counter. This is the inverse of that encoder.
//
// Why a DEDICATED decoder, not `strict_decode_map`:
//   1. The counter-row array legitimately reaches `MAX_COUNTER_ENTRIES` (65_536) — far above the
//      shared `MAX_ARRAY_ENTRIES`/`MAX_MAP_ENTRIES`=64 DoS bound. We parameterize the array cap
//      (`max_rows`) into THIS reader only; the shared cap stays for every other agent wire map.
//   2. The marks nest (top-map → key-1 array → row array → scalars) reaches the `MAX_CBOR_DEPTH`=4
//      ceiling EXACTLY via `item()` recursion — fragile. This reader does an EXPLICIT typed row walk
//      (never `item()` recursion), so a one-level-deeper variant (a nested array/map where a scalar
//      is expected) fails the per-element type check structurally, with no reliance on the depth slack.
// It reuses the SAME `StrictParser` head/canonicality discipline (shortest-form, no indefinite/tag/
// float, exact byte accounting) — only the container walk is marks-specific.
// -------------------------------------------------------------------------------------------------

/// One decoded counter high-water row (env folded out — reconstructed from config by the seeder).
// Staged (5b-2e commit 1/8): the AdoptForward caller that consumes these lands in commit 4. The test
// build use-checks every item; allow dead-code only in the non-test lib build (the agent_anchor /
// agent_boot staging convention). Remove when the driver execute arm wires them.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedRow {
    pub authority: [u8; 32],
    pub scope_class: u8,
    pub scope_target: Vec<u8>,
    pub highest_accepted_counter: u64,
}

/// The decoded marks payload — the 4 surfaces the AdoptForward seed overwrites (counters, both
/// spends, strict_recovery_counter). Env is folded out of the wire; entries/config/audit/epoch/
/// structural_version are NOT carried by marks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedMarks {
    pub rows: Vec<DecodedRow>,
    pub cumulative_native_spend: [u8; 32],
    pub lifetime_spend: [u8; 32],
    pub strict_recovery_counter: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl StrictParser<'_> {
    /// Read a canonical CBOR head and require it be `expected_major`, returning the argument.
    fn typed_head(&mut self, expected_major: u8) -> Result<u64, ()> {
        let (major, arg) = self.head()?;
        if major != expected_major {
            return Err(());
        }
        Ok(arg)
    }

    /// Read a canonical unsigned integer (major 0).
    fn uint(&mut self) -> Result<u64, ()> {
        self.typed_head(0)
    }

    /// Read a canonical byte string (major 2) of at most `max` bytes.
    fn bstr(&mut self, max: usize) -> Result<Vec<u8>, ()> {
        let len = self.typed_head(2)? as usize;
        if len > max {
            return Err(());
        }
        Ok(self.take(len)?.to_vec())
    }

    /// Read a canonical byte string (major 2) of exactly `N` bytes.
    fn bstr_exact<const N: usize>(&mut self) -> Result<[u8; N], ()> {
        let len = self.typed_head(2)? as usize;
        if len != N {
            return Err(());
        }
        self.take(N)?.try_into().map_err(|_| ())
    }

    /// Read a canonical text string (major 3, UTF-8 enforced) of at most `max` bytes.
    fn text(&mut self, max: usize) -> Result<String, ()> {
        let len = self.typed_head(3)? as usize;
        if len > max {
            return Err(());
        }
        core::str::from_utf8(self.take(len)?).map(|s| s.to_owned()).map_err(|_| ())
    }
}

/// Strict-decode a FROZEN-v1 marks payload (the inverse of `encode_marks_payload`). `max_rows` bounds
/// the counter-row array (callers pass `MAX_COUNTER_ENTRIES`). Fail-closed `Err(())` on ANY deviation:
/// non-canonical encoding, wrong key order/set, wrong element types, an over-cap row array, a
/// `scope_class` that does not fit `u8`, an over-cap `scope_target`, or trailing bytes. Keys are read
/// POSITIONALLY in the fixed `1,2,3,4` order (strictly ascending == canonical), so dup/out-of-order
/// keys cannot pass. `scope_target`/`authority` use the shared `MAX_STR_LEN`/exact-32 bounds.
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 1/8; the driver caller lands in commit 4
pub(crate) fn strict_decode_marks_payload(
    bytes: &[u8],
    max_rows: usize,
) -> Result<DecodedMarks, ()> {
    let mut p = StrictParser { buf: bytes, pos: 0 };
    // Top: map(4), keys 1..=4 in canonical ascending order.
    if p.typed_head(5)? != 4 {
        return Err(());
    }
    // key 1 -> array(rows); each row = array(4) [authority(bstr32), scope_class(uint), scope_target(bstr), counter(uint)]
    if p.uint()? != 1 {
        return Err(());
    }
    let n_rows = p.typed_head(4)? as usize;
    if n_rows > max_rows || n_rows > p.remaining() {
        return Err(()); // cap + a cheap lower-bound alloc guard (each row is >= 1 byte)
    }
    let mut rows = Vec::with_capacity(n_rows);
    for _ in 0..n_rows {
        if p.typed_head(4)? != 4 {
            return Err(()); // each row is exactly array(4)
        }
        let authority = p.bstr_exact::<32>()?;
        // scope_class is encoded as a CBOR uint (e.g. 200 -> 0x18 0xC8), NOT a raw byte; range-check
        // it fits u8 — a blind cast would silently corrupt scope semantics.
        let scope_class = u8::try_from(p.uint()?).map_err(|_| ())?;
        let scope_target = p.bstr(MAX_STR_LEN as usize)?;
        let highest_accepted_counter = p.uint()?;
        rows.push(DecodedRow { authority, scope_class, scope_target, highest_accepted_counter });
    }
    // key 2 -> cumulative_native_spend (bstr 32); key 3 -> lifetime_spend (bstr 32); key 4 -> strict_recovery_counter (uint)
    if p.uint()? != 2 {
        return Err(());
    }
    let cumulative_native_spend = p.bstr_exact::<32>()?;
    if p.uint()? != 3 {
        return Err(());
    }
    let lifetime_spend = p.bstr_exact::<32>()?;
    if p.uint()? != 4 {
        return Err(());
    }
    let strict_recovery_counter = p.uint()?;
    if p.pos != bytes.len() {
        return Err(()); // trailing bytes
    }
    Ok(DecodedMarks { rows, cumulative_native_spend, lifetime_spend, strict_recovery_counter })
}

/// The strict-decoded OUTER fields of an `anchor_root`-signed marks response (5b-2e), keys
/// `{1,2,3,4,5,6,13}` in canonical ascending order. The crypto/scope/nonce/epoch checks live in
/// `agent_anchor::verify_marks_response_bytes`; this layer only binds the exact canonical wire bytes.
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 2/8
#[derive(Debug, Clone)]
pub(crate) struct MarksRespFields {
    pub version: u64,
    pub chain_id: u64,
    pub environment_identifier: String,
    pub epoch: u64,
    pub nonce: [u8; 32],
    pub marks_payload: Vec<u8>,
    pub signature: [u8; 64],
}

/// Strict-canonical decode of a marks-response envelope. DEDICATED (not `strict_decode_map`) because
/// key 6 (`marks_payload`) legitimately exceeds the shared `MAX_STR_LEN`=4096 bstr cap — a non-trivial
/// counter table is multi-KiB — so key 6 is bounded by `max_payload` (the caller's
/// `MAX_MARKS_PAYLOAD_LEN`) while every other field keeps the strict head/canonicality discipline and
/// the shared bounds. Keys read POSITIONALLY (`1,2,3,4,5,6,13`, strictly ascending == canonical), so
/// dup/out-of-order keys cannot pass. The shared `strict_decode_map`'s 4096 bstr cap stays intact for
/// every other agent wire map (the freshness response included).
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 2/8
pub(crate) fn strict_decode_marks_response(
    bytes: &[u8],
    max_payload: usize,
) -> Result<MarksRespFields, ()> {
    let mut p = StrictParser { buf: bytes, pos: 0 };
    if p.typed_head(5)? != 7 {
        return Err(()); // map(7): keys {1..=6, 13}
    }
    if p.uint()? != 1 {
        return Err(());
    }
    let version = p.uint()?;
    if p.uint()? != 2 {
        return Err(());
    }
    let chain_id = p.uint()?;
    if p.uint()? != 3 {
        return Err(());
    }
    let environment_identifier = p.text(MAX_STR_LEN as usize)?;
    if p.uint()? != 4 {
        return Err(());
    }
    let epoch = p.uint()?;
    if p.uint()? != 5 {
        return Err(());
    }
    let nonce = p.bstr_exact::<32>()?;
    if p.uint()? != 6 {
        return Err(());
    }
    let marks_payload = p.bstr(max_payload)?;
    if p.uint()? != 13 {
        return Err(());
    }
    let signature = p.bstr_exact::<64>()?;
    if p.pos != bytes.len() {
        return Err(()); // trailing bytes
    }
    Ok(MarksRespFields { version, chain_id, environment_identifier, epoch, nonce, marks_payload, signature })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(n: i64) -> Value {
        Value::Integer(n.into())
    }

    /// Canonically encode a Value via ciborium (which emits shortest-form / definite-length).
    fn enc(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(v, &mut out).unwrap();
        out
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

    #[test]
    fn strict_decode_accepts_canonical_map() {
        let m = Value::Map(vec![
            (int(1), Value::Integer(7.into())),
            (int(2), Value::Text("env".into())),
            (int(3), Value::Bytes(vec![0xab; 4])),
        ]);
        let decoded = strict_decode_map(&enc(&m)).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(as_u64(map_get(&decoded, 1).unwrap()), Some(7));
        assert_eq!(as_bytes(map_get(&decoded, 3).unwrap()), Some(&[0xab; 4][..]));
    }

    #[test]
    fn strict_decode_rejects_non_shortest_int_value_and_key() {
        // {1: 1} with the VALUE encoded non-shortest (0x18 0x01 instead of 0x01).
        assert!(strict_decode_map(&[0xa1, 0x01, 0x18, 0x01]).is_err());
        // canonical sibling decodes.
        assert!(strict_decode_map(&[0xa1, 0x01, 0x01]).is_ok());
        // {1: 0} with the KEY encoded non-shortest (0x18 0x01).
        assert!(strict_decode_map(&[0xa1, 0x18, 0x01, 0x00]).is_err());
    }

    #[test]
    fn strict_decode_rejects_indefinite_length() {
        assert!(strict_decode_map(&[0xbf, 0x01, 0x00, 0xff]).is_err()); // indefinite map
        assert!(strict_decode_map(&[0xa1, 0x01, 0x5f, 0x41, 0x00, 0xff]).is_err()); // indef bstr value
        assert!(strict_decode_map(&[0xa1, 0x01, 0x9f, 0x00, 0xff]).is_err()); // indef array value
    }

    #[test]
    fn strict_decode_rejects_break_and_reserved_minors() {
        assert!(strict_decode_map(&[0xff]).is_err()); // lone break
        assert!(strict_decode_map(&[0xa1, 0x01, 0x1c]).is_err()); // reserved minor 28 on a value
    }

    #[test]
    fn strict_decode_rejects_duplicate_and_out_of_order_keys() {
        assert!(strict_decode_map(&[0xa2, 0x01, 0x00, 0x01, 0x00]).is_err()); // dup key 1
        assert!(strict_decode_map(&[0xa2, 0x02, 0x00, 0x01, 0x00]).is_err()); // 2 before 1
        assert!(strict_decode_map(&[0xa2, 0x01, 0x00, 0x02, 0x00]).is_ok()); // ascending
    }

    #[test]
    fn strict_decode_rejects_trailing_bytes_and_non_map_top() {
        assert!(strict_decode_map(&[0xa1, 0x01, 0x00, 0x00]).is_err()); // trailing 0x00
        assert!(strict_decode_map(&[0x01]).is_err()); // top is an int
        assert!(strict_decode_map(&[0x80]).is_err()); // top is an array
    }

    #[test]
    fn strict_decode_rejects_tag_and_float_but_accepts_bool() {
        assert!(strict_decode_map(&[0xa1, 0x01, 0xc0, 0x00]).is_err()); // tag (major 6)
        assert!(strict_decode_map(&[0xa1, 0x01, 0xf9, 0x3c, 0x00]).is_err()); // float16 1.0
        assert!(strict_decode_map(&[0xa1, 0x01, 0xf6]).is_err()); // null (major 7, unused)
        assert!(strict_decode_map(&[0xa1, 0x01, 0xf7]).is_err()); // undefined (major 7, unused)
        // booleans ARE part of the wire format (capability is_recovery, key 12).
        let t = strict_decode_map(&[0xa1, 0x01, 0xf5]).unwrap(); // {1: true}
        assert_eq!(map_get(&t, 1), Some(&Value::Bool(true)));
        let f = strict_decode_map(&[0xa1, 0x01, 0xf4]).unwrap(); // {1: false}
        assert_eq!(map_get(&f, 1), Some(&Value::Bool(false)));
    }

    #[test]
    fn strict_decode_enforces_depth_and_size_caps() {
        // 5 nested maps exceeds MAX_CBOR_DEPTH (4).
        let mut v = Value::Integer(0.into());
        for _ in 0..5 {
            v = Value::Map(vec![(int(1), v)]);
        }
        assert!(strict_decode_map(&enc(&v)).is_err());
        // declared byte-string length 5000 > MAX_STR_LEN (4096) -> reject (header 0x59 0x13 0x88).
        let mut over = vec![0xa1, 0x01, 0x59, 0x13, 0x88];
        over.extend(std::iter::repeat(0u8).take(5000));
        assert!(strict_decode_map(&over).is_err());
    }

    #[test]
    fn strict_decode_supports_negative_int_value() {
        // {1: -1} canonical = a1 01 20.
        let decoded = strict_decode_map(&[0xa1, 0x01, 0x20]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(as_u64(map_get(&decoded, 1).unwrap()), None); // accessor still guards negatives
    }

    #[test]
    fn strict_decode_validates_nested_submap_recursively() {
        // {1: {2:0, 1:0}} nested keys out of order -> reject (D2 recursion).
        assert!(strict_decode_map(&[0xa1, 0x01, 0xa2, 0x02, 0x00, 0x01, 0x00]).is_err());
        // {1: {1: <non-shortest 1>}} nested non-canonical int -> reject.
        assert!(strict_decode_map(&[0xa1, 0x01, 0xa1, 0x01, 0x18, 0x01]).is_err());
        // canonical nested submap -> ok.
        assert!(strict_decode_map(&[0xa1, 0x01, 0xa1, 0x01, 0x00]).is_ok());
    }

    // ---- marks-payload strict decoder (5b-2e) ----

    const ROWS_CAP: usize = 65_536; // == MAX_COUNTER_ENTRIES (the caller's bound)

    /// Build a canonical marks payload from rows + spends + recovery counter, exactly mirroring
    /// `encode_marks_payload`'s grammar — so the decoder is exercised against the real wire shape.
    fn marks_bytes(
        rows: &[([u8; 32], u8, &[u8], u64)],
        cum: [u8; 32],
        life: [u8; 32],
        rec: u64,
    ) -> Vec<u8> {
        let mut o = Vec::new();
        super::super::agent_capability::put_uint(&mut o, 5, 4); // map(4)
        super::super::agent_capability::put_uint(&mut o, 0, 1); // key 1
        super::super::agent_capability::put_uint(&mut o, 4, rows.len() as u64); // array(rows)
        for (auth, sc, tgt, ctr) in rows {
            super::super::agent_capability::put_uint(&mut o, 4, 4); // array(4)
            super::super::agent_capability::put_bytes(&mut o, auth);
            super::super::agent_capability::put_uint(&mut o, 0, u64::from(*sc));
            super::super::agent_capability::put_bytes(&mut o, tgt);
            super::super::agent_capability::put_uint(&mut o, 0, *ctr);
        }
        super::super::agent_capability::put_uint(&mut o, 0, 2);
        super::super::agent_capability::put_bytes(&mut o, &cum);
        super::super::agent_capability::put_uint(&mut o, 0, 3);
        super::super::agent_capability::put_bytes(&mut o, &life);
        super::super::agent_capability::put_uint(&mut o, 0, 4);
        super::super::agent_capability::put_uint(&mut o, 0, rec);
        o
    }

    #[test]
    fn marks_decode_genesis_and_multi_row_round_trip() {
        // Genesis golden: A4 01 80 02 5820 00*32 03 5820 00*32 04 00 (empty rows, zero spend/recovery).
        let genesis = marks_bytes(&[], [0; 32], [0; 32], 0);
        let g = strict_decode_marks_payload(&genesis, ROWS_CAP).unwrap();
        assert!(g.rows.is_empty());
        assert_eq!(g.cumulative_native_spend, [0; 32]);
        assert_eq!(g.lifetime_spend, [0; 32]);
        assert_eq!(g.strict_recovery_counter, 0);

        // Multi-row with a 200 scope_class (the 0x18 0xC8 uint case) + a non-empty scope_target.
        let bytes = marks_bytes(
            &[([0x11; 32], 200, b"target-a", 5), ([0x22; 32], 0, b"", 9_000_000_000)],
            [0xaa; 32],
            [0xbb; 32],
            42,
        );
        let d = strict_decode_marks_payload(&bytes, ROWS_CAP).unwrap();
        assert_eq!(d.rows.len(), 2);
        assert_eq!(d.rows[0], DecodedRow { authority: [0x11; 32], scope_class: 200, scope_target: b"target-a".to_vec(), highest_accepted_counter: 5 });
        assert_eq!(d.rows[1].highest_accepted_counter, 9_000_000_000);
        assert_eq!(d.cumulative_native_spend, [0xaa; 32]);
        assert_eq!(d.lifetime_spend, [0xbb; 32]);
        assert_eq!(d.strict_recovery_counter, 42);
    }

    #[test]
    fn marks_decode_rejects_scope_class_over_255() {
        // scope_class = 256 (0x19 0x01 0x00) does NOT fit u8 -> reject (silent-corruption trap).
        let mut o = Vec::new();
        super::super::agent_capability::put_uint(&mut o, 5, 4);
        super::super::agent_capability::put_uint(&mut o, 0, 1);
        super::super::agent_capability::put_uint(&mut o, 4, 1); // 1 row
        super::super::agent_capability::put_uint(&mut o, 4, 4);
        super::super::agent_capability::put_bytes(&mut o, &[0x11; 32]);
        super::super::agent_capability::put_uint(&mut o, 0, 256); // scope_class = 256
        super::super::agent_capability::put_bytes(&mut o, b"x");
        super::super::agent_capability::put_uint(&mut o, 0, 5);
        super::super::agent_capability::put_uint(&mut o, 0, 2);
        super::super::agent_capability::put_bytes(&mut o, &[0; 32]);
        super::super::agent_capability::put_uint(&mut o, 0, 3);
        super::super::agent_capability::put_bytes(&mut o, &[0; 32]);
        super::super::agent_capability::put_uint(&mut o, 0, 4);
        super::super::agent_capability::put_uint(&mut o, 0, 0);
        assert!(strict_decode_marks_payload(&o, ROWS_CAP).is_err());
    }

    #[test]
    fn marks_decode_rejects_over_cap_rows_but_decodes_above_shared_array_cap() {
        // A 1-row array with the declared count claiming 70 rows but only 1 present -> remaining()
        // guard (and would be a count mismatch) rejects.
        let mut over = Vec::new();
        super::super::agent_capability::put_uint(&mut over, 5, 4);
        super::super::agent_capability::put_uint(&mut over, 0, 1);
        super::super::agent_capability::put_uint(&mut over, 4, (ROWS_CAP + 1) as u64); // > cap
        assert!(strict_decode_marks_payload(&over, ROWS_CAP).is_err());

        // 70 GENUINE rows (> the shared MAX_ARRAY_ENTRIES=64) DECODE — proving the marks reader uses
        // its own larger cap, NOT the shared 64-array bound.
        let rows: Vec<([u8; 32], u8, &[u8], u64)> =
            (0..70u16).map(|i| ([i as u8; 32], 0u8, b"x".as_slice(), u64::from(i))).collect();
        let bytes = marks_bytes(&rows, [0; 32], [0; 32], 0);
        assert_eq!(strict_decode_marks_payload(&bytes, ROWS_CAP).unwrap().rows.len(), 70);
        // ...while the SHARED strict_decode_map still rejects a 65-key map (shared cap intact).
        let mut big_map = Vec::new();
        super::super::agent_capability::put_uint(&mut big_map, 5, 65);
        for k in 1..=65u64 {
            super::super::agent_capability::put_uint(&mut big_map, 0, k);
            super::super::agent_capability::put_uint(&mut big_map, 0, 0);
        }
        assert!(strict_decode_map(&big_map).is_err());
    }

    #[test]
    fn marks_decode_rejects_noncanonical_dup_and_trailing() {
        let base = marks_bytes(&[([0x11; 32], 1, b"x", 5)], [0; 32], [0; 32], 0);
        assert!(strict_decode_marks_payload(&base, ROWS_CAP).is_ok());
        // trailing byte -> reject.
        let mut trailing = base.clone();
        trailing.push(0x00);
        assert!(strict_decode_marks_payload(&trailing, ROWS_CAP).is_err());
        // non-shortest recovery counter (0x18 0x00 instead of 0x00 for the last key's value) -> reject.
        let mut nonshort = Vec::new();
        super::super::agent_capability::put_uint(&mut nonshort, 5, 4);
        super::super::agent_capability::put_uint(&mut nonshort, 0, 1);
        super::super::agent_capability::put_uint(&mut nonshort, 4, 0);
        super::super::agent_capability::put_uint(&mut nonshort, 0, 2);
        super::super::agent_capability::put_bytes(&mut nonshort, &[0; 32]);
        super::super::agent_capability::put_uint(&mut nonshort, 0, 3);
        super::super::agent_capability::put_bytes(&mut nonshort, &[0; 32]);
        super::super::agent_capability::put_uint(&mut nonshort, 0, 4);
        nonshort.extend_from_slice(&[0x18, 0x00]); // non-shortest 0
        assert!(strict_decode_marks_payload(&nonshort, ROWS_CAP).is_err());
    }

    #[test]
    fn marks_decode_rejects_wrong_key_order_and_set() {
        // Swap keys 2 and 3's positions (3 before 2) -> the positional check (uint()? != 2) rejects.
        let mut o = Vec::new();
        super::super::agent_capability::put_uint(&mut o, 5, 4);
        super::super::agent_capability::put_uint(&mut o, 0, 1);
        super::super::agent_capability::put_uint(&mut o, 4, 0);
        super::super::agent_capability::put_uint(&mut o, 0, 3); // key 3 where 2 is expected
        super::super::agent_capability::put_bytes(&mut o, &[0; 32]);
        super::super::agent_capability::put_uint(&mut o, 0, 2);
        super::super::agent_capability::put_bytes(&mut o, &[0; 32]);
        super::super::agent_capability::put_uint(&mut o, 0, 4);
        super::super::agent_capability::put_uint(&mut o, 0, 0);
        assert!(strict_decode_marks_payload(&o, ROWS_CAP).is_err());
    }

    #[test]
    fn marks_decode_rejects_one_level_deeper_row_element() {
        // A row whose first element is a nested array (depth+1) instead of the authority bstr.
        // The explicit typed walk requires major-2 (bstr) at that position -> reject, with NO reliance
        // on the depth-4 slack (the depth-slack regression guard, D5).
        let mut o = Vec::new();
        super::super::agent_capability::put_uint(&mut o, 5, 4);
        super::super::agent_capability::put_uint(&mut o, 0, 1);
        super::super::agent_capability::put_uint(&mut o, 4, 1); // 1 row
        super::super::agent_capability::put_uint(&mut o, 4, 4); // row array(4)
        super::super::agent_capability::put_uint(&mut o, 4, 0); // element 0 is an array(0), NOT a bstr
        // (the rest is unreachable — decode fails at the first element)
        assert!(strict_decode_marks_payload(&o, ROWS_CAP).is_err());
    }
}
