//! Agent Gateway structured ordinary-transfer signing (TASK-7.6.4 / `AGENT_K1_SIGN_TRANSFER`).
//!
//! Builds the canonical **EIP-155 unsigned-transaction RLP preimage** from STRUCTURED semantic
//! fields (never a caller-supplied digest) and signs it with the selected `agent_transfer_k1` key
//! over a keccak256 prehash via the secp256k1 RFC-6979 low-S recoverable signer. Mirrors
//! `agent_identity` (the EIP-191 PROVE_IDENTITY signer): same no-generic-digest discipline, a
//! different domain — an RLP **list** whose first byte is `>= 0xc0`, structurally disjoint from the
//! `0x19` identity-proof preimage (`0x19 < 0xc0`), so neither can be coerced into the other (§4).
//!
//! Reproduces 2D `Chain.Crypto.Envelope.unsigned_rlp/1` byte-for-byte (pinned by `ordinary_tx_v1.*`):
//! `RLP([nonce, gas_price, gas_limit, to, value, data, chain_id, «», «»])` → keccak256 →
//! `v = chain_id*2 + 35 + recovery_id`, wire `RLP([nonce, gas_price, gas_limit, to, value, data, v, r, s])`.
//! `data` is empty in the MVP (the dispatch handler enforces it before building these fields).
//!
//! Built only under the `agent-gateway` feature.

use crate::rlp;
use crate::secp256k1::{
    eth_address_from_uncompressed, keccak256, recover_pubkey_uncompressed, Keypair,
    RecoverableSignature,
};

/// Structured ordinary-transfer fields — the semantic inputs to the EIP-155 preimage.
///
/// `value` and `gas_price` are EVM `u256` carried as their MINIMAL big-endian bytes (0..=32 bytes,
/// no leading zero; empty = zero — the dispatch layer validates that canonical form). `nonce`,
/// `gas_limit`, `chain_id` originate as `u64`. `to` is the raw 20-byte recipient (kept verbatim,
/// leading zeros retained). `data` is implicitly empty (MVP, enforced upstream).
pub struct EthTransferFields {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub to: [u8; 20],
    /// `value` (amount), minimal big-endian, ≤ 32 bytes.
    pub value_be: Vec<u8>,
    /// `gas_price` (the legacy fee field = `effective_max_fee_rate`), minimal big-endian, ≤ 32 bytes.
    pub gas_price_be: Vec<u8>,
}

/// Errors from transfer signing. Coarse (the dispatch layer collapses all of these into a single
/// §10.9 band code — no oracle detail leaks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignTransferError {
    /// `value`/`gas_price` exceeded the `u256` width (> 32 bytes). Fail closed, never truncate (§2 AC#8).
    ValueTooWide,
    /// `v = chain_id*2 + 35 + recovery_id` overflowed `u64` (impossible for the sealed chain_id; a
    /// guard for the `pub` primitive called with an absurd chain_id).
    ChainIdOverflow,
    /// Signing failed (incl. the ~2^-128 x-reduced recovery_id rejection in `sign_prehashed`).
    Sign,
    /// Post-sign recovery did not yield the signer's own address — must never happen for a
    /// self-generated signature; fail closed rather than emit an unverifiable signature.
    RecoveryMismatch,
}

/// A signed ordinary transfer: the recoverable signature, the EIP-155 `v`, the keccak256 signing
/// hash, the broadcastable signed-transaction RLP, and the signer's own derived `from` address.
pub struct SignedTransfer {
    pub signature: RecoverableSignature,
    pub v: u64,
    pub signing_hash: [u8; 32],
    pub signed_rlp: Vec<u8>,
    pub from: [u8; 20],
}

/// The 9-field EIP-155 unsigned-transaction preimage (the keccak256 input).
fn unsigned_preimage(f: &EthTransferFields) -> Vec<u8> {
    rlp::encode_list(&[
        rlp::encode_uint_minimal(&f.nonce.to_be_bytes()),
        rlp::encode_uint_minimal(&f.gas_price_be),
        rlp::encode_uint_minimal(&f.gas_limit.to_be_bytes()),
        rlp::encode_bytes(&f.to),
        rlp::encode_uint_minimal(&f.value_be),
        rlp::encode_bytes(&[]), // data empty (MVP)
        rlp::encode_uint_minimal(&f.chain_id.to_be_bytes()),
        rlp::encode_uint_minimal(&[]), // EIP-155 trailing empty (r placeholder)
        rlp::encode_uint_minimal(&[]), // EIP-155 trailing empty (s placeholder)
    ])
}

/// The 9-field signed-transaction RLP `[nonce, gas_price, gas_limit, to, value, data, v, r, s]`
/// (the broadcastable artifact). `r`/`s` are minimally re-encoded (leading zeros stripped, §1).
fn signed_rlp(f: &EthTransferFields, sig: &RecoverableSignature, v: u64) -> Vec<u8> {
    rlp::encode_list(&[
        rlp::encode_uint_minimal(&f.nonce.to_be_bytes()),
        rlp::encode_uint_minimal(&f.gas_price_be),
        rlp::encode_uint_minimal(&f.gas_limit.to_be_bytes()),
        rlp::encode_bytes(&f.to),
        rlp::encode_uint_minimal(&f.value_be),
        rlp::encode_bytes(&[]), // data empty (MVP)
        rlp::encode_uint_minimal(&v.to_be_bytes()),
        rlp::encode_uint_minimal(&sig.r),
        rlp::encode_uint_minimal(&sig.s),
    ])
}

/// Sign an ordinary EIP-155 transfer with `keypair` over the structured `fields`.
///
/// The bound `from` is derived from `keypair` (on-curve by construction), never caller-supplied —
/// the dispatch layer separately verifies the request's claimed `from` equals this derived address
/// before calling. The post-sign invariant (§1 AC#3) recovers the produced signature and asserts it
/// recovers `from`; a self-generated signature always does, so a mismatch fails closed.
///
/// **`pub(crate)`** (mirrors `secp256k1::sign_prehashed`): the only caller-reachable route to live
/// transfer signing is the `agent-sign-transfer-preview`-gated dispatch handler, so a library/bin
/// consumer cannot reach this fund-moving primitive without the production gate (codex review 7523). The
/// `#[allow(dead_code)]` covers the base `agent-gateway` lib build, where the (preview-gated) sole
/// non-test caller is compiled out.
#[allow(dead_code)]
pub(crate) fn sign_transfer(
    keypair: &Keypair,
    fields: &EthTransferFields,
) -> Result<SignedTransfer, SignTransferError> {
    if fields.value_be.len() > 32 || fields.gas_price_be.len() > 32 {
        return Err(SignTransferError::ValueTooWide);
    }
    let from = keypair.eth_address();
    let preimage = unsigned_preimage(fields);
    let signing_hash = keccak256(&preimage);
    let signature = keypair
        .sign_prehashed(&signing_hash)
        .map_err(|_| SignTransferError::Sign)?;
    // EIP-155 v = chain_id*2 + 35 + recovery_id (recovery_id ∈ {0,1}); checked so the `pub` primitive
    // can never wrap on an absurd chain_id (the sealed chain_id is small; this is defense-in-depth).
    let v = fields
        .chain_id
        .checked_mul(2)
        .and_then(|x| x.checked_add(35))
        .and_then(|x| x.checked_add(signature.recovery_id as u64))
        .ok_or(SignTransferError::ChainIdOverflow)?;
    let signed = signed_rlp(fields, &signature, v);
    // Post-sign invariant (§1 AC#3): recovery of (r,s,recovery_id) over the signing hash must recover
    // `from` (the 2D verifier's path). Always holds for a self-generated signature.
    let recovered = recover_pubkey_uncompressed(&signing_hash, &signature)
        .map_err(|_| SignTransferError::Sign)?;
    let recovered_addr =
        eth_address_from_uncompressed(&recovered).map_err(|_| SignTransferError::Sign)?;
    if recovered_addr != from {
        return Err(SignTransferError::RecoveryMismatch);
    }
    Ok(SignedTransfer {
        signature,
        v,
        signing_hash,
        signed_rlp: signed,
        from,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const ORD: &str = include_str!("../testvectors/agent-gateway/ordinary_tx_v1.json");
    const KEYS: &str = include_str!("../testvectors/agent-gateway/keys.json");
    const PREIMAGE_BIN: &[u8] =
        include_bytes!("../testvectors/agent-gateway/ordinary_tx_v1.preimage.bin");
    const SIGNED_BIN: &[u8] =
        include_bytes!("../testvectors/agent-gateway/ordinary_tx_v1.signed.bin");
    const SIGNING_HASH_BIN: &[u8] =
        include_bytes!("../testvectors/agent-gateway/ordinary_tx_v1.signing_hash.bin");

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
    }

    fn transfer_keypair() -> Keypair {
        let k: Value = serde_json::from_str(KEYS).unwrap();
        let sk: [u8; 32] = unhex(k["transfer_key"]["privkey"].as_str().unwrap())
            .try_into()
            .unwrap();
        Keypair::from_secret_bytes(&sk).unwrap()
    }

    /// Build `EthTransferFields` from the frozen `ordinary_tx_v1` semantic fields.
    fn golden_fields() -> EthTransferFields {
        let o: Value = serde_json::from_str(ORD).unwrap();
        let f = &o["fields"];
        let to: [u8; 20] = unhex(f["to"].as_str().unwrap()).try_into().unwrap();
        // value/gas_price minimal-BE (the values fit u64 in this vector).
        let value_be = minimal_be(f["value"].as_u64().unwrap());
        let gas_price_be = minimal_be(f["gas_price"].as_u64().unwrap());
        EthTransferFields {
            chain_id: o["chain_id"].as_u64().unwrap(),
            nonce: f["nonce"].as_u64().unwrap(),
            gas_limit: f["gas_limit"].as_u64().unwrap(),
            to,
            value_be,
            gas_price_be,
        }
    }

    fn minimal_be(x: u64) -> Vec<u8> {
        let b = x.to_be_bytes();
        let first = b.iter().position(|&y| y != 0).unwrap_or(b.len());
        b[first..].to_vec()
    }

    #[test]
    fn preimage_and_hash_match_golden() {
        let pre = unsigned_preimage(&golden_fields());
        assert_eq!(pre[0] >= 0xc0, true, "RLP list head >= 0xc0");
        assert_eq!(
            pre, PREIMAGE_BIN,
            "preimage byte-exact vs ordinary_tx_v1.preimage.bin"
        );
        assert_eq!(
            keccak256(&pre).as_slice(),
            SIGNING_HASH_BIN,
            "signing hash byte-exact"
        );
    }

    #[test]
    fn sign_transfer_matches_golden_and_recovers_from() {
        let o: Value = serde_json::from_str(ORD).unwrap();
        let signed = sign_transfer(&transfer_keypair(), &golden_fields()).unwrap();

        // signature byte-exact + low-S + v + recovery_id
        let sig = &o["signature"];
        assert_eq!(
            signed.signature.r.to_vec(),
            unhex(sig["r"].as_str().unwrap()),
            "r"
        );
        assert_eq!(
            signed.signature.s.to_vec(),
            unhex(sig["s"].as_str().unwrap()),
            "s"
        );
        assert_eq!(
            signed.signature.recovery_id as u64,
            sig["recovery_id"].as_u64().unwrap(),
            "recovery_id"
        );
        assert_eq!(
            signed.v,
            sig["v_eip155"].as_u64().unwrap(),
            "v = chain_id*2+35+rid"
        );
        assert_eq!(
            signed.signing_hash.as_slice(),
            SIGNING_HASH_BIN,
            "signing hash"
        );

        // signed RLP byte-exact (the broadcastable artifact) + from
        assert_eq!(
            signed.signed_rlp, SIGNED_BIN,
            "signed_rlp byte-exact vs ordinary_tx_v1.signed.bin"
        );
        assert_eq!(
            format!("0x{}", hex::encode(signed.from)),
            o["fields"]["from"].as_str().unwrap(),
            "from = derived signer address"
        );
        assert_eq!(
            format!("0x{}", hex::encode(signed.from)),
            o["recovered_from"].as_str().unwrap(),
            "from == recovered_from"
        );
    }

    #[test]
    fn deterministic_signing() {
        let a = sign_transfer(&transfer_keypair(), &golden_fields()).unwrap();
        let b = sign_transfer(&transfer_keypair(), &golden_fields()).unwrap();
        assert_eq!(a.signature, b.signature, "RFC6979 deterministic");
        assert_eq!(a.signed_rlp, b.signed_rlp);
    }

    #[test]
    fn value_too_wide_rejected() {
        let mut f = golden_fields();
        f.value_be = vec![0xffu8; 33]; // 33 bytes > u256
        assert!(matches!(
            sign_transfer(&transfer_keypair(), &f),
            Err(SignTransferError::ValueTooWide)
        ));
        let mut g = golden_fields();
        g.gas_price_be = vec![0x01u8; 33];
        assert!(matches!(
            sign_transfer(&transfer_keypair(), &g),
            Err(SignTransferError::ValueTooWide)
        ));
    }

    #[test]
    fn chain_id_overflow_rejected() {
        let mut f = golden_fields();
        f.chain_id = u64::MAX; // 2*MAX+35 overflows u64
        assert!(matches!(
            sign_transfer(&transfer_keypair(), &f),
            Err(SignTransferError::ChainIdOverflow)
        ));
    }

    #[test]
    fn max_width_u256_value_signs() {
        // A genuine 32-byte value/gas_price (boundary, not over-width) signs without error.
        let mut f = golden_fields();
        f.value_be = vec![0x01u8; 32];
        f.gas_price_be = vec![0x02u8; 32];
        let signed = sign_transfer(&transfer_keypair(), &f).unwrap();
        // recovery==from invariant still holds (checked inside sign_transfer; getting Ok proves it).
        assert_eq!(signed.from, transfer_keypair().eth_address());
    }

    #[test]
    fn max_width_u64_fields_sign() {
        // nonce/gas_limit at u64::MAX exercise the full 8-byte minimal-BE RLP integer (0x88 + 8×0xff) —
        // the golden vector only has nonce=0 (→0x80) and gas_limit=21000 (→2 bytes), so this covers the
        // all-high-bytes boundary the golden never produces.
        let mut f = golden_fields();
        f.nonce = u64::MAX;
        f.gas_limit = u64::MAX;
        let pre = unsigned_preimage(&f);
        assert!(
            pre.windows(9)
                .any(|w| w == [0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            "u64::MAX RLP-encodes as 0x88 followed by 8 0xff bytes"
        );
        // The recovery==from invariant still holds at max width (Ok proves it — it is checked inside).
        let signed = sign_transfer(&transfer_keypair(), &f).unwrap();
        assert_eq!(signed.from, transfer_keypair().eth_address());
    }

    #[test]
    fn domain_disjoint_from_identity_proof() {
        // The transfer preimage is an RLP list (head >= 0xc0); the identity proof is EIP-191 (0x19).
        let pre = unsigned_preimage(&golden_fields());
        assert!(pre[0] >= 0xc0, "transfer head >= 0xc0");
        assert!(pre[0] != 0x19, "never the EIP-191 domain byte");
    }
}
