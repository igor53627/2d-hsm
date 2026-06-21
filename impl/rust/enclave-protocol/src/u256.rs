//! Checked 256-bit unsigned integer arithmetic over big-endian `[u8; 32]` (TASK-15 / TASK-7.4 §2).
//!
//! EVM value/gas fields and the faucet spend counters are `u256` (the 2D native-token domain), wider
//! than Rust's `u128`. The sealed keystore already stores them as **big-endian `[u8; 32]`**
//! (`FaucetState`), so this module operates on that fixed representation directly — no newtype. The
//! *wire* form, by contrast, is a MINIMAL big-endian byte string (`agent_cbor::as_u256_minimal_be`,
//! `0..=32` bytes); [`from_minimal_be`] is the single bridge that right-aligns it into `[u8; 32]`, so a
//! caller never hand-rolls the padding (an easy place to mis-align). Pure, only `core` (no `std`/alloc),
//! **no external crate** (the crate's hand-rolled / pure-RustCrypto policy, cf. `rlp.rs` / `secp256k1.rs`).
//!
//! **Checked, never wrapping.** Every operation returns `None` on overflow past 2²⁵⁶−1 so the faucet
//! fails CLOSED: a *wrapping* add would let a huge spend wrap to a small value and slip under a sealed
//! cap — a fund drain. Comparisons need no helper here — `[u8; 32]`'s derived `Ord` is lexicographic
//! from index 0 = the most-significant byte = big-endian NUMERIC order (the same property the
//! `secp256k1` low-S check relies on); see `ord_is_big_endian_numeric` below.
//!
//! Generic primitives only — the faucet worst-case cost (`amount + gas_limit*gas_price`) is composed
//! from these in the faucet dispense handler (slice 15-3), keeping this module domain-agnostic.
//!
//! Built only under the `agent-gateway` feature. The live consumer is the `agent-sign-faucet-preview`
//! SIGN_FAUCET_DISPENSE handler (slice 15-3b) — directly (`from_minimal_be`) and via
//! `FaucetState::accept_and_debit` (`from_u64`/`checked_add`/`checked_mul_u64`). So the allow is
//! CONDITIONAL: with the faucet preview ON these have a live non-test caller (`#[cfg_attr(not(...))]`
//! drops the allow, proving the wiring); with it OFF the base `agent-gateway` build keeps the allow
//! (only the in-module tests exercise them).

/// Lift a `u64` into a big-endian `u256` (`[u8; 32]`), right-aligned into the 8 low bytes.
#[cfg_attr(not(feature = "agent-sign-faucet-preview"), allow(dead_code))]
pub(crate) fn from_u64(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&x.to_be_bytes());
    out
}

/// Right-align a big-endian byte string into a fixed `u256` (`[u8; 32]`). `None` iff longer than 32
/// bytes (an over-width value — fail closed, never truncate). The single place the wire→arithmetic
/// padding lives, so the faucet handler (15-3) doesn't reinvent the right-alignment. (Empty input ⇒
/// zero, matching the wire's empty-string-is-zero convention.)
///
/// This is a pure arithmetic LIFT — it does NOT re-validate canonical minimality (no leading zero):
/// that is the DECODE layer's job, owned once by `agent_cbor::as_u256_minimal_be` (the actual caller),
/// so re-checking here would both duplicate that logic and wrongly reject a legitimately-32-byte value
/// that happens to have a high zero byte. Numerically a leading zero changes nothing — `[0x00, 0x01]`
/// and `[0x01]` both lift to the value 1.
#[cfg_attr(not(feature = "agent-sign-faucet-preview"), allow(dead_code))]
pub(crate) fn from_minimal_be(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

/// Checked `u256 + u256`. `None` iff the true sum exceeds 2²⁵⁶−1 (a carry out of the top byte).
#[cfg_attr(not(feature = "agent-sign-faucet-preview"), allow(dead_code))]
pub(crate) fn checked_add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    // Big-endian: index 31 is the least-significant byte. Add LSB→MSB, propagating the carry.
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    if carry == 0 {
        Some(out)
    } else {
        None // a leftover carry out of byte 0 ⇒ overflow past 256 bits
    }
}

/// Checked `u256 * u64`. `None` iff the true product exceeds 2²⁵⁶−1. This is the faucet worst-case
/// `gas_limit (u64) * gas_price (u256)` term (commutative — pass `gas_price` as `a`, `gas_limit` as `b`).
#[cfg_attr(not(feature = "agent-sign-faucet-preview"), allow(dead_code))]
pub(crate) fn checked_mul_u64(a: &[u8; 32], b: u64) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    // Schoolbook multiply, one base-256 digit (byte) of `a` at a time, LSB→MSB. The running `carry`
    // holds the high part of `a[i]*b + carry`; it stays below ~2^65 (≈ 2^64 · 256/255), so the `u128`
    // accumulator (and `prod`, < 2^73) never themselves overflow.
    let mut carry: u128 = 0;
    for i in (0..32).rev() {
        let prod = a[i] as u128 * b as u128 + carry;
        out[i] = prod as u8;
        carry = prod >> 8;
    }
    if carry == 0 {
        Some(out)
    } else {
        None // a leftover carry ⇒ the product needed more than 256 bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `u128` lifted to big-endian `[u8; 32]` (right-aligned into the low 16 bytes) — the test oracle.
    fn be(x: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&x.to_be_bytes());
        out
    }
    /// A `u128` lifted into the HIGH 16 bytes (indices 0..16) — i.e. `x * 2^128`. The companion oracle
    /// to [`be`] that lets the u128-backed cross-checks reach byte indices 0..15, so carry propagation
    /// and digit placement through the high half are actually value-verified (not just the low half).
    fn hi(x: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&x.to_be_bytes());
        out
    }
    const MAX: [u8; 32] = [0xff; 32]; // 2^256 - 1
    fn two_pow_255() -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = 0x80;
        x
    }

    #[test]
    fn from_u64_right_aligned() {
        assert_eq!(from_u64(0), [0u8; 32]);
        assert_eq!(from_u64(1), be(1));
        assert_eq!(from_u64(0x0102_0304_0506_0708), be(0x0102_0304_0506_0708));
        assert_eq!(from_u64(u64::MAX), be(u64::MAX as u128));
    }

    #[test]
    fn from_minimal_be_right_aligns_and_caps_width() {
        assert_eq!(from_minimal_be(&[]), Some(be(0)), "empty = zero");
        assert_eq!(from_minimal_be(&[0x01]), Some(be(1)));
        assert_eq!(
            from_minimal_be(&[0xde, 0xad]),
            Some(be(0xdead)),
            "right-aligned big-endian"
        );
        // agrees with from_u64 on a value's minimal encoding (256 = 0x01,0x00).
        assert_eq!(from_minimal_be(&[0x01, 0x00]), Some(from_u64(256)));
        // full 32-byte width is accepted verbatim.
        assert_eq!(from_minimal_be(&[0xff; 32]), Some(MAX));
        // over-width (33 bytes) ⇒ fail closed, never truncate.
        assert_eq!(from_minimal_be(&[0x01; 33]), None);
    }

    #[test]
    fn add_known_values() {
        assert_eq!(checked_add(&be(0), &be(0)), Some(be(0)));
        assert_eq!(checked_add(&be(5), &be(0)), Some(be(5)));
        assert_eq!(checked_add(&be(255), &be(1)), Some(be(256))); // carry across a byte
        assert_eq!(checked_add(&be(0xffff), &be(1)), Some(be(0x1_0000)));
    }

    #[test]
    fn add_cross_checks_u128() {
        // For operands whose sum fits u128, the 256-bit add must match native u128 addition.
        let vals = [
            0u128,
            1,
            7,
            255,
            256,
            0xffff_ffff,
            u64::MAX as u128,
            (u64::MAX as u128) + 1,
            u128::MAX / 3,
        ];
        for &a in &vals {
            for &b in &vals {
                if let Some(s) = a.checked_add(b) {
                    assert_eq!(checked_add(&be(a), &be(b)), Some(be(s)), "{a} + {b}");
                }
            }
        }
    }

    #[test]
    fn add_overflow_is_none() {
        assert_eq!(
            checked_add(&MAX, &be(0)),
            Some(MAX),
            "boundary: +0 does not overflow"
        );
        assert_eq!(checked_add(&MAX, &be(1)), None, "2^256-1 + 1 overflows");
        assert_eq!(checked_add(&MAX, &MAX), None);
        // 2^255 + 2^255 = 2^256 overflows
        assert_eq!(checked_add(&two_pow_255(), &two_pow_255()), None);
    }

    #[test]
    fn mul_known_values() {
        assert_eq!(checked_mul_u64(&be(0), 5), Some(be(0)));
        assert_eq!(checked_mul_u64(&be(5), 0), Some(be(0)));
        assert_eq!(checked_mul_u64(&be(7), 1), Some(be(7)));
        assert_eq!(checked_mul_u64(&be(255), 256), Some(be(255 * 256)));
        assert_eq!(
            checked_mul_u64(&be(1), u64::MAX),
            Some(be(u64::MAX as u128))
        );
    }

    #[test]
    fn mul_cross_checks_u128() {
        // For products that fit u128, the 256-bit multiply must match native u128 multiplication.
        let avals = [0u128, 1, 255, 0xffff, u32::MAX as u128, u64::MAX as u128];
        let bvals = [0u64, 1, 2, 255, 1_000_000_000, u64::MAX];
        for &a in &avals {
            for &b in &bvals {
                if let Some(p) = a.checked_mul(b as u128) {
                    assert_eq!(checked_mul_u64(&be(a), b), Some(be(p)), "{a} * {b}");
                }
            }
        }
    }

    #[test]
    fn mul_overflow_is_none() {
        assert_eq!(checked_mul_u64(&MAX, 0), Some(be(0)));
        assert_eq!(
            checked_mul_u64(&MAX, 1),
            Some(MAX),
            "boundary: *1 does not overflow"
        );
        assert_eq!(checked_mul_u64(&MAX, 2), None, "(2^256-1)*2 overflows");
        assert_eq!(
            checked_mul_u64(&two_pow_255(), 2),
            None,
            "2^255 * 2 = 2^256 overflows"
        );
        // 2^255 * 1 stays in range; * (just past the fit) overflows.
        assert_eq!(checked_mul_u64(&two_pow_255(), 1), Some(two_pow_255()));
    }

    #[test]
    fn add_carries_through_high_bytes() {
        // `hi(x)` = x*2^128 lives in bytes 0..16, so these cross-checks value-verify carry propagation
        // through the HIGH half — the range that distinguishes u256 from u128 (the low-half `be()`
        // cross-checks never touch bytes 0..15).
        let vals = [
            0u128,
            1,
            255,
            0xffff,
            u64::MAX as u128,
            (u64::MAX as u128) + 1,
            u128::MAX / 4,
        ];
        for &a in &vals {
            for &b in &vals {
                if let Some(s) = a.checked_add(b) {
                    // (a*2^128) + (b*2^128) = (a+b)*2^128, in range iff a+b fits u128.
                    assert_eq!(checked_add(&hi(a), &hi(b)), Some(hi(s)), "hi {a} + hi {b}");
                }
            }
        }
        // A carry that propagates the FULL width (byte 31 → byte 0): (2^248 - 1) + 1 = 2^248.
        let mut almost = [0xffu8; 32];
        almost[0] = 0x00; // bytes 1..=31 = 0xff ⇒ 2^248 - 1
        let mut two_248 = [0u8; 32];
        two_248[0] = 0x01; // 2^248
        assert_eq!(
            checked_add(&almost, &from_u64(1)),
            Some(two_248),
            "full-width carry chain"
        );
        // A high-half carry OUT of byte 0 overflows: (2^128-1 + 1)*2^128 = 2^256.
        assert_eq!(
            checked_add(&hi(u128::MAX), &hi(1)),
            None,
            "carry out of byte 0 ⇒ overflow"
        );
    }

    #[test]
    fn mul_carries_through_high_bytes() {
        // (x*2^128) * b = (x*b)*2^128 — verifies the schoolbook carry/placement through the high half,
        // in range iff x*b fits u128 (else the product ≥ 2^256).
        let avals = [0u128, 1, 255, 0xffff, u32::MAX as u128, u64::MAX as u128];
        let bvals = [0u64, 1, 2, 255, 1_000_000_000, u64::MAX];
        for &a in &avals {
            for &b in &bvals {
                if let Some(p) = a.checked_mul(b as u128) {
                    assert_eq!(checked_mul_u64(&hi(a), b), Some(hi(p)), "hi {a} * {b}");
                }
            }
        }
        // `a` with nonzero bytes spanning the FULL width (not just the low 8 the be()-cross-check uses):
        // 2^248 * 256 = 2^256 overflows; 2^240 * 256 = 2^248 stays in range and shifts one byte up.
        let mut two_240 = [0u8; 32];
        two_240[1] = 0x01; // 2^240
        let mut two_248 = [0u8; 32];
        two_248[0] = 0x01; // 2^248
        assert_eq!(
            checked_mul_u64(&two_240, 256),
            Some(two_248),
            "high-byte left-shift by one byte"
        );
        let mut two_248_in = [0u8; 32];
        two_248_in[0] = 0x01;
        assert_eq!(
            checked_mul_u64(&two_248_in, 256),
            None,
            "2^248 * 256 = 2^256 overflows"
        );
    }

    #[test]
    fn ord_is_big_endian_numeric() {
        // The load-bearing comparison property callers rely on (no custom compare needed): `[u8; 32]`
        // Ord == big-endian numeric order.
        assert!(be(1) < be(2));
        assert!(be(256) > be(255));
        assert!(be(u64::MAX as u128) < be((u64::MAX as u128) + 1));
        // A most-significant-byte difference dominates any lower-byte difference.
        let mut hi_byte0 = [0u8; 32];
        hi_byte0[0] = 1; // 2^248
        assert!(MAX > hi_byte0, "2^256-1 (byte0=0xff) > 2^248 (byte0=0x01)");
        assert!(
            MAX > be(u128::MAX),
            "any 256-bit value with a high byte set exceeds a 128-bit value"
        );
        assert!(
            hi(1) > be(u128::MAX),
            "2^128 > 2^128-1 across the half boundary"
        );
    }
}
