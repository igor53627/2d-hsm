//! `pq-agent-backup-v1` — the Agent Gateway disaster-recovery (DR) backup KEM-DEM envelope (TASK-13b).
//!
//! This is the PURE crypto primitive (no dispatch / opcode / keystore-handler coupling): an HPKE-style
//! KEM-DEM blob that wraps an opaque payload to the operator's OFFLINE ML-KEM-1024 recovery public key.
//!
//! ```text
//! 1. (kem_ct, ss) = ML-KEM-1024.Encaps(recovery_encaps_key)   -- ss is a FRESH 32B secret, producer-uncontrollable
//! 2. payload_key  = SHA3-256(b"2d-hsm-agent-backup-v1-key" ‖ ss)
//! 3. blob_ct      = ChaCha20Poly1305(payload_key, payload_nonce, payload, AAD)
//! ```
//!
//! The enclave seals only the recovery **public** key (keystore config); the ML-KEM decapsulation private
//! key lives OFFLINE in operator custody and never enters a runtime TEE. So a fully compromised runtime
//! that exfiltrates every sealed + in-memory enclave secret STILL cannot decrypt a DR backup — the blob's
//! confidentiality is rooted in the offline recovery key, NOT the SNP seal root (AC#13). Distinct magic
//! `2DAGTBK\0` + KDF domain mean a backup blob can never be cross-parsed as the sealed keystore
//! (`2DAGTKS\0`) or the producer blob (`2DHSMV1\0`), and the three key families never collide even from
//! one root. Spec: `backlog/docs/agent-gateway-keystore-backup-format.md`.
//!
//! Slice 1 (this module): the primitive + its tests. The EXPORT_BACKUP dispatch handler, the audit-ring
//! drain, and the frozen golden vector land in later 13b slices. Release-banned behind
//! `agent-backup-export-preview` until TASK-18 (see lib.rs).

// Slice 1 ships the primitive ahead of its only non-test consumer (the EXPORT_BACKUP handler, 13b Slice 4),
// so the `pub(crate)` seal fns + constants are exercised by this module's tests but otherwise un-called in a
// non-test build. Remove this allow when Slice 4 wires `seal_backup_blob` into `handle_export_backup`.
#![allow(dead_code)]

use crate::ProtocolError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ml_kem::{EncapsulationKey, MlKem1024};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// Magic for the DR backup blob — distinct from the keystore (`2DAGTKS\0`) and producer (`2DHSMV1\0`).
const BACKUP_MAGIC: &[u8; 8] = b"2DAGTBK\0";
/// Backup blob format version — versioned INDEPENDENTLY of the keystore `format_version`.
const BACKUP_FORMAT_VERSION: u16 = 1;
/// Domain-separated DEM-key KDF label — distinct from the keystore/producer seal labels (AC#19).
const BACKUP_KDF_DOMAIN: &[u8] = b"2d-hsm-agent-backup-v1-key";
/// ML-KEM-1024 (FIPS 203) encapsulation-key length — matches the keystore's wrapping-key validation.
pub(crate) const ML_KEM_1024_ENCAPS_KEY_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext (encapsulation) length — fixed by the parameter set, so the blob needs no
/// length prefix for `kem_ct`.
pub(crate) const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;
/// ChaCha20Poly1305 nonce length (96-bit). Fixed-zero is cryptographically safe here: `ss` is fresh per
/// `Encaps`, so the DEM key is unique per backup (one message per key, like the one-shot producer seal).
const PAYLOAD_NONCE_LEN: usize = 12;

/// Fail-closed errors. Never panics, never best-effort-parses; every length/version/magic/crypto failure
/// returns an `Err` so a caller fails the op closed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BackupError {
    /// Recovery encapsulation key is not exactly `ML_KEM_1024_ENCAPS_KEY_LEN` bytes.
    InvalidEncapsKeyLen,
    /// Recovery encapsulation key failed ML-KEM decoding validation.
    InvalidEncapsKey,
    /// DEM (ChaCha20Poly1305) encryption failed.
    Encrypt,
    /// Blob too short / truncated for its declared framing.
    Truncated,
    /// Wrong magic — not a `pq-agent-backup-v1` blob.
    BadMagic,
    /// Unknown/unsupported `backup_format_version` (rejected BEFORE any decapsulation/decrypt).
    UnsupportedVersion,
}

impl From<BackupError> for ProtocolError {
    fn from(_: BackupError) -> Self {
        // Coarse mapping — the wire layer never distinguishes backup sub-errors (anti-oracle); the
        // dispatch handler maps to the agent error band. Slice 1 only uses this for the module boundary.
        ProtocolError::WireProtocol("agent backup: blob construction/parse failed")
    }
}

/// Derive the DEM key `SHA3-256(domain ‖ ss)` into a pre-zeroed `Zeroizing` buffer (copy_from_slice, NOT
/// `Zeroizing::new(finalize().into())` which would leave an unscrubbed `[u8; 32]` stack temporary —
/// mirrors `seal_root.rs` / the producer `derive_aead_key`).
fn derive_payload_key(ss: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha3_256::new();
    hasher.update(BACKUP_KDF_DOMAIN);
    hasher.update(ss);
    let digest = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    key
}

/// Build the AEAD AAD in the SPEC field order (`magic ‖ version ‖ recovery_key_id ‖ chain_id ‖ env ‖
/// kem_ct ‖ key_refs_manifest`) — binds the KEM encapsulation AND the environment into payload
/// authentication, so a `testnet` blob cannot be restored into a `mainnet` enclave and a mutated `kem_ct`
/// fails decryption (HPKE RFC 9180 practice). The field VALUES (not the on-disk length prefixes) go in.
fn build_aad(
    recovery_key_id: &[u8],
    chain_id: u64,
    environment_identifier: &str,
    kem_ct: &[u8],
    key_refs_manifest: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        BACKUP_MAGIC.len() + 2 + recovery_key_id.len() + 8 + environment_identifier.len() + kem_ct.len() + key_refs_manifest.len(),
    );
    aad.extend_from_slice(BACKUP_MAGIC);
    aad.extend_from_slice(&BACKUP_FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(recovery_key_id);
    aad.extend_from_slice(&chain_id.to_be_bytes());
    aad.extend_from_slice(environment_identifier.as_bytes());
    aad.extend_from_slice(kem_ct);
    aad.extend_from_slice(key_refs_manifest);
    aad
}

/// Encapsulate to the recovery public key using an explicit 32-byte message `m`. ML-KEM `Encaps` draws a
/// fresh 32-byte `m` then derives `(kem_ct, ss)` deterministically from `m` + the public key; passing `m`
/// explicitly is EXACTLY what the crate's `encapsulate_with_rng` does internally (it draws `m`, then calls
/// this), but lets the production caller source `m` from the TEE CSPRNG (getrandom) and a golden-vector
/// caller pin a fixed `m` for byte-exactness. Returns the encapsulation `kem_ct` + the shared secret `ss`.
fn encapsulate_to_recovery_key(
    recovery_encaps_key: &[u8],
    m: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), BackupError> {
    if recovery_encaps_key.len() != ML_KEM_1024_ENCAPS_KEY_LEN {
        return Err(BackupError::InvalidEncapsKeyLen);
    }
    // Exact-length encoded key Array; the length is already checked, but try_into also guards it.
    let encoded: ml_kem::Key<EncapsulationKey<MlKem1024>> =
        recovery_encaps_key.try_into().map_err(|_| BackupError::InvalidEncapsKeyLen)?;
    let ek = EncapsulationKey::<MlKem1024>::new(&encoded).map_err(|_| BackupError::InvalidEncapsKey)?;
    let m_arr = ml_kem::B32::from(*m);
    let (kem_ct, ss) = ek.encapsulate_deterministic(&m_arr);
    let mut ss_buf = Zeroizing::new([0u8; 32]);
    ss_buf.copy_from_slice(ss.as_slice());
    Ok((kem_ct.as_slice().to_vec(), ss_buf))
}

/// Append a length-prefixed (`u16` BE) field to the blob.
fn put_lp16(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u16).to_be_bytes());
    out.extend_from_slice(field);
}

/// Append a length-prefixed (`u32` BE) field to the blob (for the variable manifest / ciphertext).
fn put_lp32(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Seal a `pq-agent-backup-v1` blob with an EXPLICIT encaps message `m` (deterministic — used by both the
/// production path with a getrandom `m` and the golden-vector path with a fixed `m`).
///
/// On-disk layout (all multi-byte integers big-endian):
/// `magic(8) ‖ version(u16) ‖ lp16(recovery_key_id) ‖ chain_id(u64) ‖ lp16(env) ‖ kem_ct(1568) ‖
///  lp32(key_refs_manifest) ‖ payload_nonce(12) ‖ lp32(dem_ciphertext)`.
/// `payload` is OPAQUE here (Slice 4 defines its contents: agent secret scalars + restorable metadata,
/// EXCLUDING producer ML-DSA material / runtime creds / the seal root).
fn seal_backup_blob_with_m(
    recovery_encaps_key: &[u8],
    recovery_key_id: &[u8],
    chain_id: u64,
    environment_identifier: &str,
    key_refs_manifest: &[u8],
    payload: &[u8],
    m: &[u8; 32],
) -> Result<Vec<u8>, BackupError> {
    let (kem_ct, ss) = encapsulate_to_recovery_key(recovery_encaps_key, m)?;
    let payload_key = derive_payload_key(&ss[..]);
    let aad = build_aad(recovery_key_id, chain_id, environment_identifier, &kem_ct, key_refs_manifest);

    let payload_nonce = [0u8; PAYLOAD_NONCE_LEN];
    let cipher = ChaCha20Poly1305::new_from_slice(&payload_key[..]).map_err(|_| BackupError::Encrypt)?;
    let dem_ct = cipher
        .encrypt(Nonce::from_slice(&payload_nonce), Payload { msg: payload, aad: &aad })
        .map_err(|_| BackupError::Encrypt)?;

    let mut blob = Vec::with_capacity(
        BACKUP_MAGIC.len() + 2 + 2 + recovery_key_id.len() + 8 + 2 + environment_identifier.len()
            + kem_ct.len() + 4 + key_refs_manifest.len() + PAYLOAD_NONCE_LEN + 4 + dem_ct.len(),
    );
    blob.extend_from_slice(BACKUP_MAGIC);
    blob.extend_from_slice(&BACKUP_FORMAT_VERSION.to_be_bytes());
    put_lp16(&mut blob, recovery_key_id);
    blob.extend_from_slice(&chain_id.to_be_bytes());
    put_lp16(&mut blob, environment_identifier.as_bytes());
    blob.extend_from_slice(&kem_ct);
    put_lp32(&mut blob, key_refs_manifest);
    blob.extend_from_slice(&payload_nonce);
    put_lp32(&mut blob, &dem_ct);

    // Export self-check (AC#3): the just-minted blob must re-parse to its own magic + supported version
    // BEFORE we hand it back, so a layout/length bug fails closed at the source rather than shipping a blob
    // the recovery side cannot parse.
    reject_unparseable_header(&blob)?;
    Ok(blob)
}

/// Seal a `pq-agent-backup-v1` blob, drawing the encaps message `m` from the TEE CSPRNG (getrandom).
/// `payload` is opaque (see [`seal_backup_blob_with_m`]).
pub(crate) fn seal_backup_blob(
    recovery_encaps_key: &[u8],
    recovery_key_id: &[u8],
    chain_id: u64,
    environment_identifier: &str,
    key_refs_manifest: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let mut m = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut m[..]).map_err(|_| BackupError::Encrypt)?;
    seal_backup_blob_with_m(
        recovery_encaps_key,
        recovery_key_id,
        chain_id,
        environment_identifier,
        key_refs_manifest,
        payload,
        &m,
    )
}

/// Fail-closed header check BEFORE any decapsulation/decrypt (mirrors the producer's unknown-version
/// reject): wrong magic ⇒ `BadMagic`; unsupported version ⇒ `UnsupportedVersion`; too short ⇒ `Truncated`.
/// Used as the export self-check and as the first gate of any future parse path.
fn reject_unparseable_header(blob: &[u8]) -> Result<(), BackupError> {
    if blob.len() < BACKUP_MAGIC.len() + 2 {
        return Err(BackupError::Truncated);
    }
    if &blob[..BACKUP_MAGIC.len()] != BACKUP_MAGIC {
        return Err(BackupError::BadMagic);
    }
    let version = u16::from_be_bytes([blob[BACKUP_MAGIC.len()], blob[BACKUP_MAGIC.len() + 1]]);
    if version != BACKUP_FORMAT_VERSION {
        return Err(BackupError::UnsupportedVersion);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::Decapsulate as _;
    use ml_kem::{DecapsulationKey, KeyExport as _};

    /// Test-only deterministic ML-KEM-1024 recovery keypair from a 64-byte seed. The DECAPSULATION key is
    /// the OFFLINE operator secret — it exists in tests ONLY to prove the round-trip; it is NEVER in any
    /// production path (the enclave only ever holds the public encapsulation key).
    fn recovery_keypair(seed64: &[u8; 64]) -> (Vec<u8>, DecapsulationKey<MlKem1024>) {
        let seed = ml_kem::Seed::from(*seed64);
        let dk = DecapsulationKey::<MlKem1024>::from_seed(seed);
        let ek = dk.encapsulation_key();
        (ek.to_bytes().as_slice().to_vec(), dk)
    }

    /// The OFFLINE recovery side: parse the blob, decapsulate `kem_ct` with the recovery private key,
    /// re-derive the DEM key + AAD, and ChaCha20Poly1305-open the payload. Test-only — proves the KEM-DEM
    /// round-trip; this code never runs in the enclave (which holds no decapsulation key).
    fn open_backup_blob_offline(
        dk: &DecapsulationKey<MlKem1024>,
        blob: &[u8],
    ) -> Result<Vec<u8>, BackupError> {
        reject_unparseable_header(blob)?;
        let mut p = BACKUP_MAGIC.len() + 2;
        let read_lp16 = |buf: &[u8], p: &mut usize| -> Result<Vec<u8>, BackupError> {
            if buf.len() < *p + 2 { return Err(BackupError::Truncated); }
            let n = u16::from_be_bytes([buf[*p], buf[*p + 1]]) as usize;
            *p += 2;
            if buf.len() < *p + n { return Err(BackupError::Truncated); }
            let v = buf[*p..*p + n].to_vec();
            *p += n;
            Ok(v)
        };
        let read_lp32 = |buf: &[u8], p: &mut usize| -> Result<Vec<u8>, BackupError> {
            if buf.len() < *p + 4 { return Err(BackupError::Truncated); }
            let n = u32::from_be_bytes([buf[*p], buf[*p + 1], buf[*p + 2], buf[*p + 3]]) as usize;
            *p += 4;
            if buf.len() < *p + n { return Err(BackupError::Truncated); }
            let v = buf[*p..*p + n].to_vec();
            *p += n;
            Ok(v)
        };
        let recovery_key_id = read_lp16(blob, &mut p)?;
        if blob.len() < p + 8 { return Err(BackupError::Truncated); }
        let chain_id = u64::from_be_bytes(blob[p..p + 8].try_into().unwrap());
        p += 8;
        let env = read_lp16(blob, &mut p)?;
        let env = String::from_utf8(env).map_err(|_| BackupError::Truncated)?;
        if blob.len() < p + ML_KEM_1024_CIPHERTEXT_LEN { return Err(BackupError::Truncated); }
        let kem_ct = blob[p..p + ML_KEM_1024_CIPHERTEXT_LEN].to_vec();
        p += ML_KEM_1024_CIPHERTEXT_LEN;
        let manifest = read_lp32(blob, &mut p)?;
        if blob.len() < p + PAYLOAD_NONCE_LEN { return Err(BackupError::Truncated); }
        let payload_nonce = blob[p..p + PAYLOAD_NONCE_LEN].to_vec();
        p += PAYLOAD_NONCE_LEN;
        let dem_ct = read_lp32(blob, &mut p)?;

        let ct_arr: ml_kem::Ciphertext<MlKem1024> =
            kem_ct.as_slice().try_into().map_err(|_| BackupError::Truncated)?;
        // ML-KEM decapsulation is infallible by design (implicit rejection yields a pseudo-random ss on a
        // bad ct rather than erroring); a wrong key / mutated ct therefore surfaces as an AEAD tag failure
        // below, never as a silent success.
        let ss = dk.decapsulate(&ct_arr);
        let payload_key = derive_payload_key(ss.as_slice());
        let aad = build_aad(&recovery_key_id, chain_id, &env, &kem_ct, &manifest);
        let cipher = ChaCha20Poly1305::new_from_slice(&payload_key[..]).map_err(|_| BackupError::Encrypt)?;
        cipher
            .decrypt(Nonce::from_slice(&payload_nonce), Payload { msg: &dem_ct, aad: &aad })
            .map_err(|_| BackupError::Truncated)
    }

    const SEED: [u8; 64] = [0x5a; 64];
    const M: [u8; 32] = [0x42; 32];
    const RID: &[u8] = b"recovery-key-id-v1";
    const ENV: &str = "env-prod-0";
    const CHAIN: u64 = 11565;
    const MANIFEST: &[u8] = b"\x82\x44\x33\x33\x33\x33\x44\x44\x44\x44\x44"; // opaque-to-slice-1 stand-in
    const SECRET: [u8; 32] = [0x77; 32]; // a "known agent scalar" pattern for the no-leak test

    fn payload() -> Vec<u8> {
        let mut p = b"agent-backup-payload:".to_vec();
        p.extend_from_slice(&SECRET);
        p
    }

    fn seal_fixed() -> (Vec<u8>, DecapsulationKey<MlKem1024>) {
        let (ek, dk) = recovery_keypair(&SEED);
        let blob = seal_backup_blob_with_m(&ek, RID, CHAIN, ENV, MANIFEST, &payload(), &M).unwrap();
        (blob, dk)
    }

    /// (a) KEM-DEM round-trip: Encaps→KDF→AEAD then Decaps→KDF→AEAD recovers the payload byte-exact.
    #[test]
    fn kem_dem_round_trip_recovers_payload() {
        let (blob, dk) = seal_fixed();
        assert_eq!(open_backup_blob_offline(&dk, &blob).unwrap(), payload());
    }

    /// (b) AC#7 no-plaintext-leak: the known secret scalar pattern does NOT appear anywhere in the blob.
    #[test]
    fn no_plaintext_secret_in_blob() {
        let (blob, _dk) = seal_fixed();
        assert!(
            !blob.windows(SECRET.len()).any(|w| w == SECRET),
            "the agent secret scalar must not appear in the opaque backup blob (AC#7)",
        );
    }

    /// (c) AC#13 DR-independence: a blob wrapped to recovery key R1 is NOT openable with a DIFFERENT
    /// recovery key R2 (the SNP seal root is not even key material of the right type — decaps with the
    /// wrong key yields a different ss ⇒ the AEAD tag fails).
    #[test]
    fn blob_not_openable_with_wrong_recovery_key() {
        let (blob, _dk1) = seal_fixed();
        let (_ek2, dk2) = recovery_keypair(&[0x11; 64]);
        assert!(open_backup_blob_offline(&dk2, &blob).is_err());
    }

    /// (d) Wrong-magic + unknown-version reject BEFORE any decrypt.
    #[test]
    fn header_rejects_before_decrypt() {
        let (mut blob, _dk) = seal_fixed();
        // wrong magic
        let mut wrong_magic = blob.clone();
        wrong_magic[0] = b'X';
        assert_eq!(reject_unparseable_header(&wrong_magic), Err(BackupError::BadMagic));
        // unknown version (bump the u16 at offset 8)
        blob[BACKUP_MAGIC.len() + 1] = 0xFF;
        assert_eq!(reject_unparseable_header(&blob), Err(BackupError::UnsupportedVersion));
        // truncated
        assert_eq!(reject_unparseable_header(&blob[..4]), Err(BackupError::Truncated));
    }

    /// (e) AAD-binding: mutating an AAD field (chain_id here) makes the offline AEAD-open fail (the
    /// recovery side recomputes the AAD from the blob, so a host that flips chain_id breaks authentication).
    #[test]
    fn mutating_chain_id_breaks_aead() {
        let (blob, dk) = seal_fixed();
        // chain_id sits right after lp16(recovery_key_id): magic(8)+ver(2)+2+len(RID)+[8 BE chain].
        let chain_off = BACKUP_MAGIC.len() + 2 + 2 + RID.len();
        let mut tampered = blob.clone();
        tampered[chain_off] ^= 0x01;
        assert!(open_backup_blob_offline(&dk, &tampered).is_err());
    }

    /// (e') AAD-binding: mutating `kem_ct` breaks decryption (kem_ct is bound into the AAD, and decaps of a
    /// mutated ct yields a different ss too — either way the open fails, never silently succeeds).
    #[test]
    fn mutating_kem_ct_breaks_open() {
        let (blob, dk) = seal_fixed();
        let kem_off = BACKUP_MAGIC.len() + 2 + 2 + RID.len() + 8 + 2 + ENV.len();
        let mut tampered = blob.clone();
        tampered[kem_off] ^= 0x01;
        assert!(open_backup_blob_offline(&dk, &tampered).is_err());
    }

    /// (f) Wrong-length encaps key fails closed (no panic, no partial work).
    #[test]
    fn wrong_length_encaps_key_fails_closed() {
        let short = vec![0u8; ML_KEM_1024_ENCAPS_KEY_LEN - 1];
        assert_eq!(
            seal_backup_blob_with_m(&short, RID, CHAIN, ENV, MANIFEST, &payload(), &M).err(),
            Some(BackupError::InvalidEncapsKeyLen),
        );
    }

    /// (g) Deterministic mint with a fixed `m` is byte-stable across calls (precondition for the slice-3
    /// frozen golden vector).
    #[test]
    fn deterministic_mint_is_byte_stable() {
        let (ek, _dk) = recovery_keypair(&SEED);
        let a = seal_backup_blob_with_m(&ek, RID, CHAIN, ENV, MANIFEST, &payload(), &M).unwrap();
        let b = seal_backup_blob_with_m(&ek, RID, CHAIN, ENV, MANIFEST, &payload(), &M).unwrap();
        assert_eq!(a, b, "fixed m ⇒ byte-identical blob");
    }

    /// Cross-family magic isolation: the backup magic is none of the keystore/producer magics.
    #[test]
    fn backup_magic_is_distinct() {
        assert_ne!(BACKUP_MAGIC, b"2DAGTKS\0");
        assert_ne!(BACKUP_MAGIC, b"2DHSMV1\0");
    }

    /// Belt: a from-scratch random seal (production path) also round-trips (exercises getrandom `m`).
    #[test]
    fn random_seal_round_trips() {
        let (ek, dk) = recovery_keypair(&[0x99; 64]);
        let blob = seal_backup_blob(&ek, RID, CHAIN, ENV, MANIFEST, &payload()).unwrap();
        assert_eq!(open_backup_blob_offline(&dk, &blob).unwrap(), payload());
    }
}
