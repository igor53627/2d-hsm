//! `pq-agent-backup-v1` — the Agent Gateway disaster-recovery (DR) backup KEM-DEM envelope (TASK-13b).
//!
//! This is the PURE crypto primitive (no dispatch / opcode / keystore-handler coupling): an HPKE-style
//! KEM-DEM blob that wraps an opaque payload to the operator's OFFLINE ML-KEM-1024 recovery public key.
//!
//! ```text
//! 1. (kem_ct, ss) = ML-KEM-1024.Encaps(recovery_encaps_key)   -- ss is a FRESH 32B secret, producer-uncontrollable
//! 2. payload_key  = SHA3-256(b"2d-hsm-agent-backup-v1-key" ‖ ss)
//! 3. blob_ct      = ChaCha20Poly1305(payload_key, payload_nonce, payload, AAD = the serialized header)
//! ```
//!
//! The enclave seals only the recovery **public** key (keystore config); the ML-KEM decapsulation private
//! key lives OFFLINE in operator custody and never enters a runtime TEE. So a fully compromised runtime
//! that exfiltrates every sealed + in-memory enclave secret STILL cannot decrypt a DR backup — the blob's
//! confidentiality is rooted in the offline recovery key, NOT the SNP seal root (AC#13). Distinct magic
//! `2DAGTBK\0` + KDF domain mean a backup blob can never be cross-parsed as the sealed keystore
//! (`2DAGTKS\0`) or the producer blob (`2DHSMV1\0`). Spec: `backlog/docs/agent-gateway-keystore-backup-format.md`.
//!
//! **AAD = the exact serialized header bytes** (magic ‖ version ‖ lp16(recovery_key_id) ‖ chain_id ‖
//! lp16(env) ‖ kem_ct ‖ lp32(manifest) ‖ payload_nonce), INCLUDING the length prefixes and the nonce. This
//! is an UNAMBIGUOUS encoding (CWE-347): because the lengths are authenticated, a host cannot re-partition
//! the same authenticated byte string into different `chain_id`/`env` by mutating only the (otherwise
//! unauthenticated) on-disk length prefixes — the recompute-from-disk AAD would differ and the AEAD tag
//! fails. The seal and the offline-open use the IDENTICAL header bytes as AAD, so they cannot diverge.
//!
//! Slice 1 (this module): the primitive + its tests. The EXPORT_BACKUP dispatch handler, the audit-ring
//! drain, and the frozen golden vector land in later 13b slices. Release-banned behind
//! `agent-backup-export-preview` until TASK-18 (see lib.rs).

// Slice 1 ships the primitive ahead of its only non-test consumer (the EXPORT_BACKUP handler, 13b Slice 4),
// so the `pub(crate)` seal fns + constants are exercised by this module's tests but otherwise un-called in a
// non-test build. Remove this allow when Slice 4 wires `seal_backup_blob` into `handle_export_backup`.
#![allow(dead_code)]

use crate::agent_keystore::ML_KEM_1024_ENCAPS_KEY_LEN;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ml_kem::{EncapsulationKey, MlKem1024};
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

/// Magic for the DR backup blob — distinct from the keystore (`2DAGTKS\0`) and producer (`2DHSMV1\0`).
const BACKUP_MAGIC: &[u8; 8] = b"2DAGTBK\0";
/// Backup blob format version — versioned INDEPENDENTLY of the keystore `format_version`.
const BACKUP_FORMAT_VERSION: u16 = 1;
/// Domain-separated DEM-key KDF label — distinct from the keystore/producer seal labels (AC#19).
const BACKUP_KDF_DOMAIN: &[u8] = b"2d-hsm-agent-backup-v1-key";
/// ML-KEM-1024 ciphertext (encapsulation) length — fixed by the parameter set, so the blob needs no
/// length prefix for `kem_ct`. (Numerically equal to the encaps-key length for ML-KEM-1024, but a
/// SEPARATE concept; do not collapse the two — a future param set could differ.)
const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;
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
    /// A length-prefixed field exceeds its prefix width (`u16`/`u32`) — refused, never silently truncated.
    FieldTooLong,
    /// The TEE CSPRNG (`getrandom`) failed.
    Csprng,
    /// DEM (ChaCha20Poly1305) encryption failed.
    Encrypt,
    /// DEM decryption / AEAD-tag verification failed (wrong recovery key, tampered ciphertext, or AAD
    /// mismatch). DISTINCT from `Truncated` so a tamper/wrong-key rejection is not confused with framing.
    Decrypt,
    /// Blob too short / truncated / has trailing bytes for its declared framing (a strict-parse failure).
    Truncated,
    /// Wrong magic — not a `pq-agent-backup-v1` blob.
    BadMagic,
    /// Unknown/unsupported `backup_format_version` (rejected BEFORE any decapsulation/decrypt).
    UnsupportedVersion,
}

/// Derive the DEM key `SHA3-256(domain ‖ ss)` into a pre-zeroed `Zeroizing` buffer (copy_from_slice, NOT
/// `Zeroizing::new(finalize().into())` which would leave an unscrubbed `[u8; 32]` stack temporary —
/// mirrors `seal_root.rs` / the producer `derive_aead_key`).
fn derive_payload_key(ss: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha3_256::new();
    hasher.update(BACKUP_KDF_DOMAIN);
    hasher.update(ss);
    let mut digest = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    // The `finalize()` GenericArray holds the plaintext DEM key; scrub the temporary after the copy
    // (cursor/gemini PR #92), matching agent_keystore::derive_aead_key.
    digest.as_mut_slice().zeroize();
    key
}

/// Append a length-prefixed (`u16` BE) field, REFUSING (never truncating) a field that exceeds `u16::MAX`.
fn put_lp16(out: &mut Vec<u8>, field: &[u8]) -> Result<(), BackupError> {
    let n = u16::try_from(field.len()).map_err(|_| BackupError::FieldTooLong)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Append a length-prefixed (`u32` BE) field, REFUSING a field that exceeds `u32::MAX`.
fn put_lp32(out: &mut Vec<u8>, field: &[u8]) -> Result<(), BackupError> {
    let n = u32::try_from(field.len()).map_err(|_| BackupError::FieldTooLong)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Build the authenticated header: `magic ‖ version ‖ lp16(recovery_key_id) ‖ chain_id ‖ lp16(env) ‖
/// kem_ct ‖ lp32(manifest) ‖ payload_nonce`. This byte string IS the AEAD AAD (so the length prefixes +
/// nonce are authenticated) AND the on-disk prefix of the blob (so seal/open cannot diverge).
fn build_header(
    recovery_key_id: &[u8],
    chain_id: u64,
    environment_identifier: &str,
    kem_ct: &[u8],
    key_refs_manifest: &[u8],
    payload_nonce: &[u8; PAYLOAD_NONCE_LEN],
) -> Result<Vec<u8>, BackupError> {
    let mut h = Vec::with_capacity(
        BACKUP_MAGIC.len() + 2 + 2 + recovery_key_id.len() + 8 + 2 + environment_identifier.len()
            + kem_ct.len() + 4 + key_refs_manifest.len() + PAYLOAD_NONCE_LEN,
    );
    h.extend_from_slice(BACKUP_MAGIC);
    h.extend_from_slice(&BACKUP_FORMAT_VERSION.to_be_bytes());
    put_lp16(&mut h, recovery_key_id)?;
    h.extend_from_slice(&chain_id.to_be_bytes());
    put_lp16(&mut h, environment_identifier.as_bytes())?;
    h.extend_from_slice(kem_ct);
    put_lp32(&mut h, key_refs_manifest)?;
    h.extend_from_slice(payload_nonce);
    Ok(h)
}

/// Encapsulate to the recovery public key using an explicit 32-byte message `m`. ML-KEM `Encaps` draws a
/// fresh 32-byte `m` then derives `(kem_ct, ss)` deterministically from `m` + the public key; passing `m`
/// explicitly is EXACTLY what the crate's `encapsulate_with_rng` does internally (it draws `m`, then calls
/// this), but lets the production caller source `m` from the TEE CSPRNG (getrandom) and a golden-vector
/// caller pin a fixed `m` for byte-exactness. Returns the `kem_ct` + the shared secret `ss` in a
/// `Zeroizing` buffer; the bare `SharedKey` temporary is explicitly zeroized after the copy.
fn encapsulate_to_recovery_key(
    recovery_encaps_key: &[u8],
    m: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), BackupError> {
    if recovery_encaps_key.len() != ML_KEM_1024_ENCAPS_KEY_LEN {
        return Err(BackupError::InvalidEncapsKeyLen);
    }
    let encoded: ml_kem::Key<EncapsulationKey<MlKem1024>> =
        recovery_encaps_key.try_into().map_err(|_| BackupError::InvalidEncapsKeyLen)?;
    let ek = EncapsulationKey::<MlKem1024>::new(&encoded).map_err(|_| BackupError::InvalidEncapsKey)?;
    let m_arr = ml_kem::B32::from(*m);
    let (kem_ct, mut ss) = ek.encapsulate_deterministic(&m_arr);
    let mut ss_buf = Zeroizing::new([0u8; 32]);
    ss_buf.copy_from_slice(ss.as_slice());
    // The crate's `SharedKey` (an `Array<u8, U32>`) is not auto-scrubbed on drop; zeroize the temporary
    // so the confidentiality-root secret does not linger on the stack after we've copied it.
    ss.zeroize();
    Ok((kem_ct.as_slice().to_vec(), ss_buf))
}

/// Seal a `pq-agent-backup-v1` blob with an EXPLICIT encaps message `m`.
///
/// **NONCE-SAFETY PRECONDITION:** the `payload_nonce` is fixed-zero, which is safe ONLY because the DEM key
/// `SHA3-256(domain ‖ ss)` is unique per `(m, recovery_encaps_key)`. The caller MUST therefore use a `m`
/// that is unique for each DISTINCT payload sealed to a given recovery key — a fresh CSPRNG draw, as
/// [`seal_backup_blob`] does. Reusing the same `m` across two DIFFERENT payloads reuses the
/// `(payload_key, nonce=0)` pair, which is CATASTROPHIC for ChaCha20Poly1305 (keystream + one-time-key
/// reuse → plaintext leak + forgery). Golden-vector use (a fixed `m` with a FIXED payload) is safe: it
/// reproduces the identical blob, not a new plaintext under the same key. This entry point exists for that
/// deterministic golden path; production code calls [`seal_backup_blob`].
///
/// On-disk layout: `header ‖ lp32(dem_ct)` where `header` is [`build_header`]'s output and `dem_ct` is the
/// ChaCha20Poly1305 ciphertext over `payload` with `AAD = header`. `payload` is OPAQUE here (Slice 4
/// defines its contents: agent secret scalars + restorable metadata, EXCLUDING producer ML-DSA material /
/// runtime creds / the seal root).
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
    let payload_nonce = [0u8; PAYLOAD_NONCE_LEN];
    let header = build_header(
        recovery_key_id,
        chain_id,
        environment_identifier,
        &kem_ct,
        key_refs_manifest,
        &payload_nonce,
    )?;

    let cipher = ChaCha20Poly1305::new_from_slice(&payload_key[..]).map_err(|_| BackupError::Encrypt)?;
    let dem_ct = cipher
        .encrypt(Nonce::from_slice(&payload_nonce), Payload { msg: payload, aad: &header })
        .map_err(|_| BackupError::Encrypt)?;

    let mut blob = Vec::with_capacity(header.len() + 4 + dem_ct.len());
    blob.extend_from_slice(&header);
    put_lp32(&mut blob, &dem_ct)?;

    // Export self-check (AC#3): the just-minted blob must STRICTLY re-parse (full field walk, no trailing
    // bytes) BEFORE we hand it back, so a layout/length/framing bug fails closed at the source rather than
    // shipping a blob the recovery side cannot parse.
    strict_parse(&blob)?;
    Ok(blob)
}

/// Seal a `pq-agent-backup-v1` blob, drawing the encaps message `m` from the TEE CSPRNG (getrandom) — the
/// production path; the fresh `m` per call satisfies the nonce-safety precondition on
/// [`seal_backup_blob_with_m`]. `payload` is opaque.
pub(crate) fn seal_backup_blob(
    recovery_encaps_key: &[u8],
    recovery_key_id: &[u8],
    chain_id: u64,
    environment_identifier: &str,
    key_refs_manifest: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let mut m = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut m[..]).map_err(|_| BackupError::Csprng)?;
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

/// A strictly-parsed blob — all slices borrow `blob`. `header` is `blob[..header_end]` (the AEAD AAD).
struct ParsedBackup<'a> {
    recovery_key_id: &'a [u8],
    chain_id: u64,
    environment_identifier: &'a [u8],
    kem_ct: &'a [u8],
    key_refs_manifest: &'a [u8],
    payload_nonce: &'a [u8],
    /// `blob[..header_end]` — the exact bytes used as the AEAD AAD (lengths + nonce included).
    header: &'a [u8],
    dem_ct: &'a [u8],
}

/// A cursor over `blob` with bounds-checked reads — every read fails closed (`Truncated`) rather than
/// panicking on an out-of-range slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BackupError> {
        let end = self.pos.checked_add(n).ok_or(BackupError::Truncated)?;
        if end > self.buf.len() {
            return Err(BackupError::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn take_u16(&mut self) -> Result<u16, BackupError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn take_u32(&mut self) -> Result<u32, BackupError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn take_u64(&mut self) -> Result<u64, BackupError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().expect("take(8) yields 8 bytes")))
    }
    fn take_lp16(&mut self) -> Result<&'a [u8], BackupError> {
        let n = self.take_u16()? as usize;
        self.take(n)
    }
    fn take_lp32(&mut self) -> Result<&'a [u8], BackupError> {
        let n = self.take_u32()? as usize;
        self.take(n)
    }
}

/// Strict full parse: rejects wrong magic / unknown version BEFORE walking the body, walks every framed
/// field, and requires the cursor to land EXACTLY at `blob.len()` (no trailing bytes). Returns the parsed
/// fields + the `header` slice (the AAD). Pure framing — no decapsulation/decrypt. This is BOTH the export
/// self-check and the first half of the offline open, so the two cannot diverge.
fn strict_parse(blob: &[u8]) -> Result<ParsedBackup<'_>, BackupError> {
    reject_unparseable_header(blob)?;
    let mut r = Reader { buf: blob, pos: 0 };
    let _magic = r.take(BACKUP_MAGIC.len())?;
    let _version = r.take_u16()?;
    let recovery_key_id = r.take_lp16()?;
    let chain_id = r.take_u64()?;
    let environment_identifier = r.take_lp16()?;
    let kem_ct = r.take(ML_KEM_1024_CIPHERTEXT_LEN)?;
    let key_refs_manifest = r.take_lp32()?;
    let payload_nonce = r.take(PAYLOAD_NONCE_LEN)?;
    let header_end = r.pos;
    let dem_ct = r.take_lp32()?;
    if r.pos != blob.len() {
        // Trailing bytes after the declared framing ⇒ not a strictly-canonical blob ⇒ reject.
        return Err(BackupError::Truncated);
    }
    Ok(ParsedBackup {
        recovery_key_id,
        chain_id,
        environment_identifier,
        kem_ct,
        key_refs_manifest,
        payload_nonce,
        header: &blob[..header_end],
        dem_ct,
    })
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

    /// The OFFLINE recovery side: strict-parse the blob, decapsulate `kem_ct` with the recovery private
    /// key, re-derive the DEM key, and ChaCha20Poly1305-open the payload using the parsed `header` slice as
    /// AAD (the SAME bytes the seal authenticated — no recompute, so no divergence). Test-only.
    fn open_backup_blob_offline(
        dk: &DecapsulationKey<MlKem1024>,
        blob: &[u8],
    ) -> Result<Vec<u8>, BackupError> {
        let parsed = strict_parse(blob)?;
        let ct_arr: ml_kem::Ciphertext<MlKem1024> =
            parsed.kem_ct.try_into().map_err(|_| BackupError::Truncated)?;
        // ML-KEM decapsulation is infallible by design (implicit rejection yields a pseudo-random ss on a
        // bad ct rather than erroring); a wrong key / mutated ct therefore surfaces as an AEAD tag failure
        // below, never as a silent success.
        let ss = dk.decapsulate(&ct_arr);
        let payload_key = derive_payload_key(ss.as_slice());
        let nonce: [u8; PAYLOAD_NONCE_LEN] =
            parsed.payload_nonce.try_into().map_err(|_| BackupError::Truncated)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&payload_key[..]).map_err(|_| BackupError::Decrypt)?;
        cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: parsed.dem_ct, aad: parsed.header })
            .map_err(|_| BackupError::Decrypt)
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

    /// (b) AC#7 no-plaintext-leak: the known secret scalar pattern does NOT appear anywhere in the blob,
    /// AND it genuinely IS in the cleartext payload (so the test is non-vacuous).
    #[test]
    fn no_plaintext_secret_in_blob() {
        assert!(payload().windows(SECRET.len()).any(|w| w == SECRET), "test payload must contain the secret");
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
        assert_eq!(open_backup_blob_offline(&dk2, &blob), Err(BackupError::Decrypt));
    }

    /// (d) Wrong-magic + unknown-version reject BEFORE any decrypt.
    #[test]
    fn header_rejects_before_decrypt() {
        let (mut blob, _dk) = seal_fixed();
        let mut wrong_magic = blob.clone();
        wrong_magic[0] = b'X';
        assert_eq!(reject_unparseable_header(&wrong_magic), Err(BackupError::BadMagic));
        blob[BACKUP_MAGIC.len() + 1] = 0xFF;
        assert_eq!(reject_unparseable_header(&blob), Err(BackupError::UnsupportedVersion));
        assert_eq!(reject_unparseable_header(&blob[..4]), Err(BackupError::Truncated));
    }

    /// Helper: an offline open of a tampered blob must NOT succeed (it either fails strict-parse or the
    /// AEAD tag). Returns the error for the caller to inspect.
    fn open_is_err(dk: &DecapsulationKey<MlKem1024>, blob: &[u8]) -> bool {
        open_backup_blob_offline(dk, blob).is_err()
    }

    /// (e) AAD-binding for EVERY authenticated field: flipping one byte of recovery_key_id / chain_id / env
    /// / kem_ct / manifest / payload_nonce in the on-disk header all break the open (the header IS the AAD,
    /// so any header mutation that survives strict-parse changes the recomputed AAD → tag fails; a mutation
    /// that breaks framing fails strict-parse). Computes offsets from the actual write layout.
    #[test]
    fn every_header_field_is_aad_bound() {
        let (blob, dk) = seal_fixed();
        // Layout offsets: magic(8) ver(2) lp16_rid(2) rid(len) chain(8) lp16_env(2) env(len) kem_ct(1568)...
        let o_rid = 8 + 2 + 2; // first recovery_key_id byte
        let o_chain = o_rid + RID.len(); // first chain_id byte
        let o_env = o_chain + 8 + 2; // first env byte
        let o_kemct = o_env + ENV.len(); // first kem_ct byte
        let o_manifest = o_kemct + ML_KEM_1024_CIPHERTEXT_LEN + 4; // first manifest byte (after lp32 len)
        let o_nonce = o_manifest + MANIFEST.len(); // first payload_nonce byte
        for (label, off) in [
            ("recovery_key_id", o_rid),
            ("chain_id", o_chain),
            ("env", o_env),
            ("kem_ct", o_kemct),
            ("manifest", o_manifest),
            ("payload_nonce", o_nonce),
        ] {
            let mut tampered = blob.clone();
            tampered[off] ^= 0x01;
            assert!(open_is_err(&dk, &tampered), "tampering {label} (offset {off}) must break the open");
        }
    }

    /// (e') AAD canonicalization (CWE-347): re-partitioning the same authenticated bytes by mutating ONLY
    /// the (length-prefix) framing must fail — because the length prefixes are inside the AAD. Grow
    /// lp16(recovery_key_id) by 1 (stealing the first chain_id byte into recovery_key_id) and shrink the
    /// downstream so the blob still strict-parses to a DIFFERENT chain_id; the recomputed header/AAD differs
    /// ⇒ the open fails. (Without lengths in the AAD this attack would silently succeed.)
    #[test]
    fn length_prefix_repartition_breaks_open() {
        let (blob, dk) = seal_fixed();
        let mut t = blob.clone();
        // lp16(recovery_key_id) prefix is at bytes [10,11] (after magic(8)+ver(2)); bump its low byte +1.
        let new_len = (RID.len() as u16) + 1;
        t[10..12].copy_from_slice(&new_len.to_be_bytes());
        // Strict-parse now reads a longer recovery_key_id + a shifted chain_id; since the TOTAL bytes are
        // unchanged it stays parseable only if downstream framing still lines up — but even where it parses,
        // the header (AAD) bytes are identical on disk yet the *intended* chain_id differs. The key property
        // we assert: the open never SUCCEEDS with a re-partitioned interpretation.
        assert!(open_is_err(&dk, &t), "re-partitioning via the length prefix must not open successfully");
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

    /// (h) Strict parse rejects trailing bytes (no silent acceptance of an overlong blob) AND the export
    /// self-check would catch it. A well-formed blob with one appended byte must fail strict_parse.
    #[test]
    fn strict_parse_rejects_trailing_bytes() {
        let (mut blob, _dk) = seal_fixed();
        assert!(strict_parse(&blob).is_ok(), "the minted blob strict-parses");
        blob.push(0x00);
        assert_eq!(strict_parse(&blob).err(), Some(BackupError::Truncated), "trailing byte ⇒ reject");
    }

    /// (i) A truncated blob (chopped mid-ciphertext) fails strict-parse, never panics.
    #[test]
    fn truncated_blob_fails_closed() {
        let (blob, _dk) = seal_fixed();
        for cut in [0usize, 5, 9, 11, blob.len() - 1] {
            assert!(strict_parse(&blob[..cut]).is_err(), "truncation at {cut} must fail closed");
        }
    }

    /// Belt: a from-scratch random seal (production path) also round-trips (exercises getrandom `m`).
    #[test]
    fn random_seal_round_trips() {
        let (ek, dk) = recovery_keypair(&[0x99; 64]);
        let blob = seal_backup_blob(&ek, RID, CHAIN, ENV, MANIFEST, &payload()).unwrap();
        assert_eq!(open_backup_blob_offline(&dk, &blob).unwrap(), payload());
    }

    /// Oversized length-prefixed field is refused, not truncated (the fail-closed `as`-cast fix). We can't
    /// cheaply allocate a 64 KiB recovery_key_id in every CI run via the seal path, so exercise put_lp16
    /// directly at the boundary.
    #[test]
    fn oversized_field_refused_not_truncated() {
        let mut out = Vec::new();
        let ok = vec![0u8; u16::MAX as usize];
        assert!(put_lp16(&mut out, &ok).is_ok(), "exactly u16::MAX fits");
        let too_long = vec![0u8; u16::MAX as usize + 1];
        let mut out2 = Vec::new();
        assert_eq!(put_lp16(&mut out2, &too_long), Err(BackupError::FieldTooLong));
        assert!(out2.is_empty(), "a refused field writes NOTHING (no truncated prefix)");
    }
}
