//! secp256k1 primitives for the Agent Gateway signer backend (TASK-7.6.1).
//!
//! Pure crypto only — keygen, uncompressed SEC1 public key, eth + TRON address derivation,
//! and RFC 6979 deterministic, low-S, recoverable ECDSA signing over a precomputed 32-byte
//! keccak256 hash. There is intentionally **no** generic/arbitrary-digest entry point, no
//! keystore, and no opcode/dispatch surface (those are TASK-7.6.2+). Callers in later
//! increments build the structured EIP-155 / EIP-191 preimage and pass only its keccak256 hash.
//!
//! Built only under the `agent-gateway` feature, so it never compiles into the producer
//! ML-DSA signing path (role isolation).

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha2::Digest as _;
use sha3::{Digest as _, Keccak256};
use zeroize::Zeroize;

/// Errors from the secp256k1 primitives. Deliberately coarse (no oracle detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secp256k1Error {
    /// Platform CSPRNG unavailable during keygen.
    Csprng,
    /// Secret scalar invalid (zero or >= group order).
    InvalidSecret,
    /// Signing failed.
    Sign,
    /// Signature/recovery-id malformed or public-key recovery failed.
    Recover,
}

/// A secp256k1 keypair held inside the enclave boundary.
///
/// `SigningKey` wraps a `NonZeroScalar` that zeroizes on drop (RustCrypto `ZeroizeOnDrop`), so
/// the secret scalar is scrubbed when the `Keypair` is dropped without a manual `Zeroizing`
/// buffer (cf. the ML-DSA `Zeroizing` discipline in `mldsa65.rs`).
pub struct Keypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

/// A low-S, recoverable ECDSA signature: 32-byte `r`, 32-byte `s`, and `recovery_id` in {0,1}.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverableSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

impl Keypair {
    /// Generate a fresh keypair from the platform CSPRNG (`getrandom`), rejection-sampling until
    /// the 32 random bytes form a valid non-zero scalar `< n`. The transient stack bytes are
    /// zeroized; the secret lives only inside the zeroize-on-drop `SigningKey`.
    pub fn generate() -> Result<Self, Secp256k1Error> {
        let mut bytes = [0u8; 32];
        let signing_key = loop {
            getrandom::getrandom(&mut bytes).map_err(|_| Secp256k1Error::Csprng)?;
            match SigningKey::from_slice(&bytes) {
                Ok(sk) => break sk,
                Err(_) => {
                    // invalid scalar (zero or >= n) — scrub and retry
                    bytes.zeroize();
                    continue;
                }
            }
        };
        bytes.zeroize();
        let verifying_key = *signing_key.verifying_key();
        Ok(Self { signing_key, verifying_key })
    }

    /// Construct from a 32-byte secret scalar (e.g. a test vector). Rejects invalid scalars.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Result<Self, Secp256k1Error> {
        let signing_key =
            SigningKey::from_slice(secret).map_err(|_| Secp256k1Error::InvalidSecret)?;
        let verifying_key = *signing_key.verifying_key();
        Ok(Self { signing_key, verifying_key })
    }

    /// Uncompressed SEC1 public key: `0x04 || X(32) || Y(32)` (65 bytes).
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out.copy_from_slice(self.verifying_key.to_encoded_point(false).as_bytes());
        out
    }

    /// 2D / Ethereum 20-byte address: `keccak256(X || Y)[12..32]`.
    pub fn eth_address(&self) -> [u8; 20] {
        eth_address_from_uncompressed(&self.public_key_uncompressed())
    }

    /// TRON address: Base58Check(`0x41 || body20`) over the same 20-byte body (unified account).
    pub fn tron_address(&self) -> String {
        tron_address_from_body(&self.eth_address())
    }

    /// RFC 6979 deterministic, low-S normalized, recoverable signature over a 32-byte prehash.
    ///
    /// **Crate-internal** (`pub(crate)`): there is intentionally no public, caller-reachable signing
    /// entry point that takes an arbitrary digest — that is the no-generic-digest invariant. The
    /// public, structured EIP-155 / EIP-191 signers (TASK-7.6.3/7.6.4) build the keccak256 preimage
    /// internally and call this primitive; external crates cannot reach it.
    // Staged: the only non-test in-crate callers (the structured signers) land in TASK-7.6.3/7.6.4,
    // so a plain lib build has no caller yet — allow the dead-code lint until they do.
    #[allow(dead_code)]
    pub(crate) fn sign_prehashed(
        &self,
        hash32: &[u8; 32],
    ) -> Result<RecoverableSignature, Secp256k1Error> {
        let (sig, rid): (Signature, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(hash32)
            .map_err(|_| Secp256k1Error::Sign)?;
        // ecdsa `SigningKey` normalizes S to the low half by default; `rid` accounts for the flip.
        // Reject the (astronomically rare) x-reduced recovery ids 2/3: EIP-155 `v = chain_id*2+35+rid`
        // expects y-parity only (0/1), so fail closed rather than emit a `v` the 2D verifier rejects.
        let recovery_id = rid.to_byte();
        if recovery_id > 1 {
            return Err(Secp256k1Error::Sign);
        }
        let bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Ok(RecoverableSignature { r, s, recovery_id })
    }
}

/// keccak256 helper.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// eth address from an uncompressed SEC1 pubkey (`0x04 || X || Y`): `keccak256(X || Y)[12..32]`.
pub fn eth_address_from_uncompressed(pubkey65: &[u8; 65]) -> [u8; 20] {
    let hash = keccak256(&pubkey65[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// TRON Base58Check address from the 20-byte body: Base58(`0x41 || body || dsha256(0x41||body)[..4]`).
pub fn tron_address_from_body(body20: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(0x41);
    payload.extend_from_slice(body20);
    let h1 = sha2::Sha256::digest(&payload);
    let h2 = sha2::Sha256::digest(h1);
    payload.extend_from_slice(&h2[..4]);
    bs58::encode(payload).into_string()
}

/// Recover the signer's uncompressed SEC1 pubkey from a recoverable signature over a 32-byte prehash.
pub fn recover_pubkey_uncompressed(
    hash32: &[u8; 32],
    sig: &RecoverableSignature,
) -> Result<[u8; 65], Secp256k1Error> {
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&sig.r);
    rs[32..].copy_from_slice(&sig.s);
    let signature = Signature::from_slice(&rs).map_err(|_| Secp256k1Error::Recover)?;
    let rid = RecoveryId::from_byte(sig.recovery_id).ok_or(Secp256k1Error::Recover)?;
    let vk = VerifyingKey::recover_from_prehash(hash32, &signature, rid)
        .map_err(|_| Secp256k1Error::Recover)?;
    let mut out = [0u8; 65];
    out.copy_from_slice(vk.to_encoded_point(false).as_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const KEYS: &str = include_str!("../testvectors/agent-gateway/keys.json");
    const ORD: &str = include_str!("../testvectors/agent-gateway/ordinary_tx_v1.json");
    const IDP: &str = include_str!("../testvectors/agent-gateway/identity_proof_v1.json");

    /// secp256k1 n/2, big-endian — the low-S boundary (EIP-2).
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.trim_start_matches("0x")).expect("valid hex")
    }
    fn unhex32(s: &str) -> [u8; 32] {
        let v = unhex(s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }
    fn is_low_s(s: &[u8; 32]) -> bool {
        *s <= HALF_N // [u8;32] Ord is big-endian numeric here
    }
    fn keypair(name: &str) -> Keypair {
        let k: Value = serde_json::from_str(KEYS).unwrap();
        Keypair::from_secret_bytes(&unhex32(k[name]["privkey"].as_str().unwrap())).unwrap()
    }

    #[test]
    fn keys_json_address_derivation() {
        let k: Value = serde_json::from_str(KEYS).unwrap();
        for name in ["transfer_key", "treasury_key"] {
            let e = &k[name];
            let kp = Keypair::from_secret_bytes(&unhex32(e["privkey"].as_str().unwrap())).unwrap();
            assert_eq!(
                kp.public_key_uncompressed().to_vec(),
                unhex(e["pubkey_uncompressed_sec1"].as_str().unwrap()),
                "{name} pubkey"
            );
            assert_eq!(
                kp.eth_address().to_vec(),
                unhex(e["eth_address"].as_str().unwrap()),
                "{name} eth"
            );
            assert_eq!(kp.tron_address(), e["tron_address"].as_str().unwrap(), "{name} tron");
        }
    }

    #[test]
    fn ordinary_tx_signing_matches_golden() {
        let o: Value = serde_json::from_str(ORD).unwrap();
        let preimage = unhex(o["unsigned_rlp_preimage"].as_str().unwrap());
        let h = keccak256(&preimage);
        assert_eq!(
            h.to_vec(),
            unhex(o["signing_hash_keccak256"].as_str().unwrap()),
            "signing hash"
        );
        let sig = keypair("transfer_key").sign_prehashed(&h).unwrap();
        let s = &o["signature"];
        assert_eq!(sig.r.to_vec(), unhex(s["r"].as_str().unwrap()), "r");
        assert_eq!(sig.s.to_vec(), unhex(s["s"].as_str().unwrap()), "s");
        assert_eq!(sig.recovery_id as u64, s["recovery_id"].as_u64().unwrap(), "recovery_id");
        assert!(is_low_s(&sig.s), "low-S");
        let chain_id = o["chain_id"].as_u64().unwrap();
        assert_eq!(
            chain_id * 2 + 35 + sig.recovery_id as u64,
            s["v_eip155"].as_u64().unwrap(),
            "v = chain_id*2+35+rid"
        );
        let rec = recover_pubkey_uncompressed(&h, &sig).unwrap();
        assert_eq!(
            eth_address_from_uncompressed(&rec).to_vec(),
            unhex(o["recovered_from"].as_str().unwrap()),
            "recovered from"
        );
    }

    #[test]
    fn identity_proof_signing_matches_golden() {
        let p: Value = serde_json::from_str(IDP).unwrap();
        let preimage = unhex(p["preimage"].as_str().unwrap());
        assert_eq!(preimage[0], 0x19, "EIP-191 domain byte");
        let h = keccak256(&preimage);
        assert_eq!(
            h.to_vec(),
            unhex(p["signing_hash_keccak256"].as_str().unwrap()),
            "identity hash"
        );
        let sig = keypair("transfer_key").sign_prehashed(&h).unwrap();
        let s = &p["signature"];
        assert_eq!(sig.r.to_vec(), unhex(s["r"].as_str().unwrap()), "id r");
        assert_eq!(sig.s.to_vec(), unhex(s["s"].as_str().unwrap()), "id s");
        assert_eq!(sig.recovery_id as u64, s["recovery_id"].as_u64().unwrap(), "id rid");
        assert!(is_low_s(&sig.s), "id low-S");
    }

    #[test]
    fn rfc6979_deterministic_and_low_s() {
        let kp = keypair("transfer_key");
        let h = keccak256(b"determinism check");
        let a = kp.sign_prehashed(&h).unwrap();
        let b = kp.sign_prehashed(&h).unwrap();
        assert_eq!(a, b, "RFC6979 deterministic");
        assert!(is_low_s(&a.s));
    }

    #[test]
    fn generate_signs_and_recovers() {
        let kp = Keypair::generate().unwrap();
        let h = keccak256(b"fresh key roundtrip");
        let sig = kp.sign_prehashed(&h).unwrap();
        assert!(is_low_s(&sig.s));
        let rec = recover_pubkey_uncompressed(&h, &sig).unwrap();
        assert_eq!(rec.to_vec(), kp.public_key_uncompressed().to_vec(), "recover == signer pubkey");
    }

    #[test]
    fn domain_bytes_disjoint() {
        let o: Value = serde_json::from_str(ORD).unwrap();
        let p: Value = serde_json::from_str(IDP).unwrap();
        let eth_head = unhex(o["unsigned_rlp_preimage"].as_str().unwrap())[0];
        let id_head = unhex(p["preimage"].as_str().unwrap())[0];
        assert!(eth_head >= 0xc0, "eth RLP list head >= 0xc0");
        assert_eq!(id_head, 0x19, "identity EIP-191 0x19");
        assert!(id_head < 0xc0 && eth_head != id_head, "disjoint domains");
    }
}
