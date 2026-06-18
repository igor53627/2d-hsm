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
use serde::{Deserialize, Serialize};
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
    /// Deterministic-CBOR (de)serialization of the restore-ingress payload failed (4c-2a) — a
    /// framing/encoding fault, fail-closed rather than shipping/accepting a malformed payload.
    Serialization,
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
    let mut m_arr = ml_kem::B32::from(*m);
    let (kem_ct, mut ss) = ek.encapsulate_deterministic(&m_arr);
    let mut ss_buf = Zeroizing::new([0u8; 32]);
    ss_buf.copy_from_slice(ss.as_slice());
    // Scrub BOTH the crate's `SharedKey` AND the `B32` copy of the encaps message `m` (neither an
    // `Array<u8, U32>` auto-scrubs on drop): `m` together with the public recovery key deterministically
    // re-derives `ss`, so a residual `m_arr` is as sensitive as `ss` itself (codex/gemini PR #92).
    ss.zeroize();
    m_arr.zeroize();
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
        // Direct indexing (like take_u16/take_u32) — no `.expect()` panic surface on untrusted bytes, even
        // though take(8) already guarantees the length (defense for a TEE parser that must never panic).
        Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
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

// ===========================================================================================
// restore-ingress-v1 — the EXPORT_BACKUP payload (TASK-13b slice 4c-2a). This is the OPAQUE
// `payload` that [`seal_backup_blob`] wraps in the KEM-DEM envelope: the RESTORABLE agent state a
// fresh enclave needs to reconstitute the agent, EXCLUDING enclave-specific anti-rollback anchor
// state and the operator's own recovery key. Frozen contract `2d-hsm-restore-ingress-v1` — the
// (deferred) RESTORE_BACKUP ingress decoder parses it; freezing it now settles the format before the
// restore handler exists. Deterministic CBOR (serde declaration-field order, all `Vec`, no maps),
// magic+version prefixed for fail-closed header detection on the restore side.
//
// INCLUDE: config identity subset (chain/env/authorities/config_version/authority_epoch) + entries
// (FULL, incl. the secret scalars — the point of the backup) + counters + faucet + strict_recovery
// + audit RECORDS (incl. the export's own event). EXCLUDE: anchor_root + the seal root (enclave
// anti-rollback anchor; a restored enclave gets its own), backup_recovery_wrapping_pubkey (the
// operator's OWN key), freshness_epoch + structural_version (enclave-relative to THIS anchor; the
// restore ceremony governs forward progress via strict_recovery_counter), and the audit ring CURSORS
// last_exported_seq/next_seq/capacity (enclave-local; the records ARE the reviewable history).
// ===========================================================================================

/// Magic for the restore-ingress PAYLOAD — distinct from the backup ENVELOPE (`2DAGTBK\0`), the
/// keystore (`2DAGTKS\0`), and the producer (`2DHSMV1\0`). The payload is the plaintext INSIDE the
/// envelope's DEM ciphertext; a distinct magic means a decrypted payload can never be cross-parsed
/// as another blob type.
const RESTORE_INGRESS_MAGIC: &[u8; 8] = b"2DRIGV1\0";
/// Versioned INDEPENDENTLY of the backup envelope + keystore `format_version`.
const RESTORE_INGRESS_FORMAT_VERSION: u16 = 1;
/// Domain for the deterministic, host-uncontrollable recovery-key id.
const RECOVERY_KEY_ID_DOMAIN: &[u8] = b"2d-hsm-agent-backup-v1-recovery-key-id";
/// Recovery-key-id length (truncated SHA3-256) — enough to identify WHICH offline key without
/// reproducing it.
const RECOVERY_KEY_ID_LEN: usize = 16;

/// The config-identity SUBSET carried in a DR backup. EXCLUDES `anchor_root` (enclave anti-rollback
/// anchor) and `backup_recovery_wrapping_pubkey` (the operator's OWN key) — neither is restorable
/// agent state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreConfigSubset {
    pub twod_chain_id: u64,
    pub environment_identifier: String,
    pub admin_authority_pk: [u8; 32],
    pub recovery_authority_pk: [u8; 32],
    pub monotonic_treasury_config_version: u64,
    pub authority_epoch: u64,
}

/// The restore-ingress payload DATA (the CBOR body, after the magic+version prefix). Reuses the
/// keystore's own `KeyEntry`/`CounterEntry`/`FaucetState`/`AuditRecord` types so the restore decoder
/// reconstructs them directly. `entries` carry the secret scalars (zeroized on drop, as in the body).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreIngressData {
    pub config: RestoreConfigSubset,
    pub entries: Vec<crate::agent_keystore::KeyEntry>,
    pub counters: Vec<crate::agent_keystore::CounterEntry>,
    pub faucet: crate::agent_keystore::FaucetState,
    pub strict_recovery_counter: u64,
    pub audit_records: Vec<crate::agent_keystore::AuditRecord>,
}

/// Body-ordered intersection of the keystore's entries with `requested_refs` — the SINGLE source of
/// the exported ref ordering, so [`build_restore_ingress_payload`] and [`build_key_refs_manifest`]
/// can never disagree on which refs (and in which order) were exported. Order follows the BODY (not
/// the request), so the payload is a deterministic function of the body for a given ref SET. A "full"
/// export passes every body ref; the caller (4c-2b) resolves the EXPORT selector to `requested_refs`.
pub(crate) fn selected_key_refs(
    body: &crate::agent_keystore::KeystoreBody,
    requested_refs: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    body.entries
        .iter()
        .filter(|e| requested_refs.contains(&e.key_ref))
        .map(|e| e.key_ref)
        .collect()
}

/// A `std::io::Write` sink that COUNTS bytes without retaining them — used to pre-size the
/// secret-bearing payload buffer so the real serialization never reallocates (mirrors
/// `agent_keystore::seal_body`'s `CountingWriter`).
struct CountingWriter(usize);
impl std::io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Build the `restore-ingress-v1` payload bytes (`magic ‖ version_be ‖ deterministic-CBOR`) from a
/// keystore body, including the entries named by `ordered_refs` (from [`selected_key_refs`]) IN
/// `ordered_refs` ORDER — so the payload entry order is identical to the [`build_key_refs_manifest`]
/// order built from the SAME `ordered_refs` (the manifest↔payload ordering invariant is structural,
/// not by-convention). A ref absent from the body fails closed (the caller resolves the selector via
/// `selected_key_refs`, which only yields body refs; a missing ref here is an internal invariant break).
///
/// Returns `Zeroizing` because the payload carries the secret scalars. **Pre-sized** (a counting pass
/// that retains no bytes, then a single exact-capacity allocation): a growing `Zeroizing<Vec>` would
/// reallocate mid-serialization, and `realloc` frees the old buffer WITHOUT zeroizing it — leaking
/// already-written secret bytes to the allocator. With exact capacity the buffer never reallocates, so
/// the only plaintext copy lives in the one scrubbed-on-drop buffer. Self-checks a strict re-parse.
pub(crate) fn build_restore_ingress_payload(
    body: &crate::agent_keystore::KeystoreBody,
    ordered_refs: &[[u8; 32]],
) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    // Map each ref → its entry in ORDERED_REFS order (not a body-order filter), so payload-entry order
    // == manifest order for the same `ordered_refs`. Fail closed if a ref is not in the body.
    let mut entries = Vec::with_capacity(ordered_refs.len());
    for r in ordered_refs {
        let entry = body
            .entries
            .iter()
            .find(|e| &e.key_ref == r)
            .ok_or(BackupError::Serialization)?;
        entries.push(entry.clone());
    }
    let data = RestoreIngressData {
        config: RestoreConfigSubset {
            twod_chain_id: body.config.twod_chain_id,
            environment_identifier: body.config.environment_identifier.clone(),
            admin_authority_pk: body.config.admin_authority_pk,
            recovery_authority_pk: body.config.recovery_authority_pk,
            monotonic_treasury_config_version: body.config.monotonic_treasury_config_version,
            authority_epoch: body.config.authority_epoch,
        },
        entries,
        counters: body.counters.clone(),
        faucet: body.faucet.clone(),
        strict_recovery_counter: body.strict_recovery_counter,
        audit_records: body.audit.records.clone(),
    };
    // Pass 1: count the CBOR length (the CountingWriter discards bytes — no secret retained).
    let mut counter = CountingWriter(0);
    ciborium::ser::into_writer(&data, &mut counter).map_err(|_| BackupError::Serialization)?;
    let prefix_len = RESTORE_INGRESS_MAGIC.len() + 2;
    // Pass 2: serialize into an EXACT-capacity Zeroizing buffer (no reallocation → no leaked secret copy).
    let mut out = Zeroizing::new(Vec::with_capacity(prefix_len + counter.0));
    out.extend_from_slice(RESTORE_INGRESS_MAGIC);
    out.extend_from_slice(&RESTORE_INGRESS_FORMAT_VERSION.to_be_bytes());
    ciborium::ser::into_writer(&data, &mut *out).map_err(|_| BackupError::Serialization)?;
    // Both passes must encode the same length; a mismatch means pass 2 exceeded the reserved capacity
    // (reallocated, leaking a copy) or encoding is non-deterministic — either way a bug.
    debug_assert_eq!(out.len(), prefix_len + counter.0, "restore-ingress CBOR length mismatch between passes");
    // Self-check: the just-built payload must STRICTLY re-parse (magic+version+CBOR, no trailing).
    let _ = parse_restore_ingress(&out)?;
    Ok(out)
}

/// Strict restore-side parse of a `restore-ingress-v1` payload: reject wrong magic / unsupported
/// version BEFORE decoding, then decode exactly one CBOR value with NO trailing bytes
/// (`deny_unknown_fields` on every struct rejects unexpected fields). Fail-closed on any deviation.
pub(crate) fn parse_restore_ingress(payload: &[u8]) -> Result<RestoreIngressData, BackupError> {
    if payload.len() < RESTORE_INGRESS_MAGIC.len() + 2 {
        return Err(BackupError::Truncated);
    }
    if &payload[..RESTORE_INGRESS_MAGIC.len()] != RESTORE_INGRESS_MAGIC.as_slice() {
        return Err(BackupError::BadMagic);
    }
    let version = u16::from_be_bytes([payload[8], payload[9]]);
    if version != RESTORE_INGRESS_FORMAT_VERSION {
        return Err(BackupError::UnsupportedVersion);
    }
    let cbor = &payload[RESTORE_INGRESS_MAGIC.len() + 2..];
    let mut cursor = std::io::Cursor::new(cbor);
    let data: RestoreIngressData =
        ciborium::de::from_reader(&mut cursor).map_err(|_| BackupError::Serialization)?;
    if cursor.position() as usize != cbor.len() {
        return Err(BackupError::Truncated); // trailing bytes after the one CBOR value
    }
    Ok(data)
}

/// The canonical key-refs MANIFEST bound into the blob header (and thus the AAD): a deterministic CBOR
/// array of the 32-byte refs in the SAME (body) order as the payload entries. Authenticated by the
/// envelope AEAD, so the host cannot alter the exported set; the restore side matches it against the
/// request selector. Built from the SAME `ordered_refs` as the payload, so the two cannot disagree.
pub(crate) fn build_key_refs_manifest(ordered_refs: &[[u8; 32]]) -> Result<Vec<u8>, BackupError> {
    let arr: Vec<ciborium::value::Value> =
        ordered_refs.iter().map(|r| ciborium::value::Value::Bytes(r.to_vec())).collect();
    let mut out = Vec::new();
    ciborium::ser::into_writer(&ciborium::value::Value::Array(arr), &mut out)
        .map_err(|_| BackupError::Serialization)?;
    Ok(out)
}

/// Deterministic, host-uncontrollable recovery-key id: `SHA3-256(domain ‖ encaps_key)[..16]`. Derived
/// from the SEALED recovery pubkey, so the host cannot substitute the id; it labels WHICH offline key
/// a blob is encapsulated to without reproducing the key.
pub(crate) fn derive_recovery_key_id(recovery_encaps_key: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(RECOVERY_KEY_ID_DOMAIN);
    h.update(recovery_encaps_key);
    h.finalize()[..RECOVERY_KEY_ID_LEN].to_vec()
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

    /// (e') CWE-347 re-partition: mutating ONLY the length-prefix framing to re-partition the same bytes
    /// into a DIFFERENT chain_id/env must never open successfully. The original bug had TWO holes (the AAD
    /// omitted the length prefixes AND the parser was non-strict); BOTH are now closed, so this attack is
    /// rejected by whichever layer fires first. Here the PRIMARY defense is the strict canonical parse:
    /// growing lp16(recovery_key_id) shifts the fixed-width chain_id + the 1568-byte kem_ct offset, so the
    /// downstream framing no longer lines up (a bad lp32 length / a non-`len()` cursor) and `strict_parse`
    /// rejects before any decrypt. The SECOND layer — the length prefixes being inside the AAD — is what
    /// makes any re-partition that *did* survive framing also fail the AEAD tag; that layer is exercised
    /// structurally (AAD = the full header slice) and by `every_header_field_is_aad_bound`.
    #[test]
    fn length_prefix_repartition_breaks_open() {
        let (blob, dk) = seal_fixed();
        let mut t = blob.clone();
        // lp16(recovery_key_id) prefix is at bytes [10,11] (after magic(8)+ver(2)); bump its low byte +1.
        let new_len = (RID.len() as u16) + 1;
        t[10..12].copy_from_slice(&new_len.to_be_bytes());
        assert!(open_is_err(&dk, &t), "re-partitioning via the length prefix must not open successfully");
        // And it is specifically the strict parse that catches THIS re-partition (the framing misaligns):
        assert!(strict_parse(&t).is_err(), "re-partition misaligns the fixed-width framing ⇒ strict_parse rejects");
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

    /// (i') Corrupted AEAD tag (framing preserved) fails specifically with `Decrypt` — the AC#3
    /// corrupted-tag rejection. Flipping the final ciphertext byte leaves the lp32(dem_ct) length (and all
    /// framing) intact, so `strict_parse` still passes; the AEAD tag check is what rejects it.
    #[test]
    fn corrupted_tag_fails_with_decrypt() {
        let (mut blob, dk) = seal_fixed();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(strict_parse(&blob).is_ok(), "flipping a tag byte preserves the framing");
        assert_eq!(open_backup_blob_offline(&dk, &blob), Err(BackupError::Decrypt));
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

    // ─── Slice 3: frozen pq-agent-backup-v1 golden vector + ML-KEM recovery-keypair fixture ───
    // The frozen blob (`agent_backup_v1.bin`) pins the byte-exact ENVELOPE wire format for downstream 2d;
    // the recovery-keypair fixtures (`..._recovery_keypair_v1.{encaps,decaps}.bin`) let a consumer open it
    // offline + verify DR-independence. ALL TEST KEYS ONLY. The PAYLOAD here is the opaque slice-1 stand-in
    // (`payload()`); its restorable contents are defined in slice 4 — this vector freezes the envelope, not
    // the payload semantics. Determinism: fixed keypair `SEED` + fixed encaps message `M` + fixed-zero nonce.

    fn golden_backup_blob() -> Vec<u8> {
        let (encaps, _dk) = recovery_keypair(&SEED);
        seal_backup_blob_with_m(&encaps, RID, CHAIN, ENV, MANIFEST, &payload(), &M).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        // Delegate to the `hex` crate (a dev-dep, in the test graph) rather than a hand-rolled per-byte
        // format! loop (gemini PR #94). `hex::` resolves to the crate (type namespace), not this fn.
        hex::encode(bytes)
    }

    #[test]
    fn agent_backup_v1_golden_is_byte_exact() {
        // The in-source deterministic mint and the committed bytes must agree byte-for-byte — any AAD /
        // framing / layout drift flips this. Plus the literal version byte + an offline round-trip proving
        // the committed blob opens with the committed recovery key.
        let committed: &[u8] = include_bytes!("../testvectors/agent-gateway/agent_backup_v1.bin");
        assert_eq!(
            golden_backup_blob().as_slice(),
            committed,
            "backup golden drifted; if intentional, regen via `regen_agent_backup_golden_vector -- --ignored` \
             and re-mint the .json sidecar in the same commit",
        );
        assert_eq!(&committed[8..10], &[0x00, 0x01], "backup_format_version 1 (literal BE u16)");
        let (_ek, dk) = recovery_keypair(&SEED);
        assert_eq!(open_backup_blob_offline(&dk, committed).unwrap(), payload(), "committed blob opens");
    }

    #[test]
    fn agent_backup_recovery_keypair_fixtures_consistent() {
        // The committed recovery keypair: `decaps.bin` = the 64-byte ML-KEM keypair seed (the OFFLINE
        // secret — TEST ONLY), `encaps.bin` = the 1568-byte encapsulation (public) key. Couple both to the
        // in-source `SEED` and pin decaps→encaps consistency (`from_seed(seed).encapsulation_key()`).
        let committed_encaps: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_backup_recovery_keypair_v1.encaps.bin");
        let committed_decaps: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_backup_recovery_keypair_v1.decaps.bin");
        assert_eq!(committed_decaps, SEED, "decaps fixture is the recovery keypair seed");
        assert_eq!(committed_encaps.len(), ML_KEM_1024_ENCAPS_KEY_LEN, "encaps key is 1568 bytes");
        let (encaps, _dk) = recovery_keypair(&SEED);
        assert_eq!(committed_encaps, encaps.as_slice(), "encaps fixture == keypair-from-seed encaps key");
        let seed: [u8; 64] = committed_decaps.try_into().expect("decaps fixture is 64 bytes");
        let dk = DecapsulationKey::<MlKem1024>::from_seed(ml_kem::Seed::from(seed));
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            committed_encaps,
            "the committed decaps seed reconstructs a key whose public half == the committed encaps fixture",
        );
    }

    #[test]
    fn agent_backup_v1_sidecar_matches() {
        // Couple the descriptive `.json` sidecar fields to the source-of-truth constants (specific fields,
        // not substrings) so a regen that forgets the manual `.json` re-mint ships a stale sidecar but
        // fails CI here.
        use sha2::{Digest, Sha256};
        let blob: &[u8] = include_bytes!("../testvectors/agent-gateway/agent_backup_v1.bin");
        let encaps: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_backup_recovery_keypair_v1.encaps.bin");
        let sidecar = include_str!("../testvectors/agent-gateway/agent_backup_v1.json");
        let v: serde_json::Value =
            serde_json::from_str(sidecar).expect("backup sidecar must be valid JSON");
        assert_eq!(v["blob_sha256"].as_str(), Some(hex(&Sha256::digest(blob)).as_str()), "sidecar blob_sha256 drift");
        assert_eq!(v["blob_len_bytes"].as_u64(), Some(blob.len() as u64), "sidecar blob_len_bytes drift");
        assert_eq!(v["backup_format_version"].as_u64(), Some(u64::from(BACKUP_FORMAT_VERSION)), "sidecar version drift");
        assert_eq!(v["magic"].as_str().map(str::as_bytes), Some(BACKUP_MAGIC.as_slice()), "sidecar magic drift");
        assert_eq!(v["chain_id"].as_u64(), Some(CHAIN), "sidecar chain_id drift");
        assert_eq!(v["environment_identifier"].as_str(), Some(ENV), "sidecar env drift");
        assert_eq!(v["recovery_key_id_hex"].as_str(), Some(hex(RID).as_str()), "sidecar recovery_key_id drift");
        assert_eq!(v["key_refs_manifest_hex"].as_str(), Some(hex(MANIFEST).as_str()), "sidecar manifest drift");
        assert_eq!(v["payload_nonce_hex"].as_str(), Some(hex(&[0u8; PAYLOAD_NONCE_LEN]).as_str()), "sidecar nonce drift");
        assert_eq!(v["recovery_keypair_seed_hex"].as_str(), Some(hex(&SEED).as_str()), "sidecar keypair seed drift");
        assert_eq!(v["kem_encaps_message_m_hex"].as_str(), Some(hex(&M).as_str()), "sidecar encaps-message m drift");
        // recovery_encaps_key_{len,sha256} are the ONLY integrity witnesses for encaps.bin in the sidecar
        // (the encaps key is NOT embedded in the blob, so blob_sha256 does not cover it).
        assert_eq!(v["recovery_encaps_key_len"].as_u64(), Some(encaps.len() as u64), "sidecar encaps_key_len drift");
        assert_eq!(
            v["recovery_encaps_key_sha256"].as_str(),
            Some(hex(&Sha256::digest(encaps)).as_str()),
            "sidecar recovery_encaps_key_sha256 drift",
        );
    }

    /// REGEN (manual): `cargo test --features agent-backup-export-preview \
    /// regen_agent_backup_golden_vector -- --ignored --nocapture`, then commit the 4 testvector files.
    /// A deliberate envelope-format / version change re-mints the blob, the recovery-keypair fixtures, AND
    /// the `.json` sidecar in the same commit.
    #[test]
    #[ignore]
    fn regen_agent_backup_golden_vector() {
        use sha2::{Digest, Sha256};
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/agent-gateway/");
        let (encaps, _dk) = recovery_keypair(&SEED);
        let blob = golden_backup_blob();
        std::fs::write(format!("{dir}agent_backup_recovery_keypair_v1.encaps.bin"), &encaps).unwrap();
        std::fs::write(format!("{dir}agent_backup_recovery_keypair_v1.decaps.bin"), SEED).unwrap();
        std::fs::write(format!("{dir}agent_backup_v1.bin"), &blob).unwrap();
        let sidecar = serde_json::json!({
            "description": "TASK-13b pq-agent-backup-v1 DR-backup KEM-DEM golden vector (envelope wire format). \
                            TEST KEYS ONLY — the recovery decaps seed is a public test constant. The payload \
                            is an opaque slice-1 stand-in; its restorable contents are defined in slice 4.",
            "blob_sha256": hex(&Sha256::digest(&blob)),
            "blob_len_bytes": blob.len(),
            "backup_format_version": BACKUP_FORMAT_VERSION,
            "magic": "2DAGTBK\u{0000}",
            "recovery_key_id_hex": hex(RID),
            "chain_id": CHAIN,
            "environment_identifier": ENV,
            "key_refs_manifest_hex": hex(MANIFEST),
            "payload_nonce_hex": hex(&[0u8; PAYLOAD_NONCE_LEN]),
            "recovery_keypair_seed_hex": hex(&SEED),
            "kem_encaps_message_m_hex": hex(&M),
            "recovery_encaps_key_len": encaps.len(),
            "recovery_encaps_key_sha256": hex(&Sha256::digest(&encaps)),
        });
        std::fs::write(
            format!("{dir}agent_backup_v1.json"),
            serde_json::to_string_pretty(&sidecar).unwrap() + "\n",
        )
        .unwrap();
        eprintln!("wrote backup golden vector ({}-byte blob) + keypair fixtures + sidecar -> {dir}", blob.len());
    }

    // ─── restore-ingress-v1 payload format (TASK-13b slice 4c-2a) ───

    /// A keystore body with two keys + counters/faucet/audit, plus DELIBERATELY-set EXCLUDED fields
    /// (`anchor_root = [0xAA; 32]`, `freshness_epoch = 9`, `structural_version = 7`,
    /// `last_exported_seq` cursor) so the exclusion tests can prove they never reach the payload.
    fn body_with_two_keys() -> crate::agent_keystore::KeystoreBody {
        use crate::agent_keystore::*;
        let entry = |refb: u8, scalar: u8| KeyEntry {
            key_ref: [refb; 32],
            purpose: KeyPurpose::AgentTransferK1,
            algorithm: KeyAlgorithm::Secp256k1,
            public_identity: {
                let mut p = vec![0x04u8; 65];
                p[1] = refb;
                p
            },
            secret_scalar: Zeroizing::new(vec![scalar; 32]),
            creation_metadata: CreationMetadata { config_version: 3, counter_snapshot: 0, batch_id: 1 },
            backup_export_metadata: BackupExportMetadata::default(),
        };
        KeystoreBody {
            config: KeystoreConfig {
                twod_chain_id: 11565,
                environment_identifier: "testnet".to_string(),
                admin_authority_pk: [0xa1; 32],
                recovery_authority_pk: [0xa2; 32],
                backup_recovery_wrapping_pubkey: vec![0xb0; ML_KEM_1024_ENCAPS_KEY_LEN],
                monotonic_treasury_config_version: 3,
                authority_epoch: 0,
                anchor_root: [0xAA; 32], // EXCLUDED — exclusion test asserts this 32-byte run is absent
            },
            entries: vec![entry(0x11, 0x77), entry(0x22, 0x88)],
            counters: vec![CounterEntry {
                authority: [0xa1; 32],
                environment_identifier: "testnet".to_string(),
                scope_class: 0,
                scope_target: b"generate_transfer".to_vec(),
                highest_accepted_counter: 1,
            }],
            faucet: FaucetState {
                per_dispense_max_amount: [0; 32],
                max_gas_limit: 21000,
                max_effective_gas_fee_rate: 100,
                cumulative_native_spend: [0; 32],
                lifetime_spend: [0; 32],
                circuit_breaker_threshold: None,
                cumulative_signing_budget: [0; 32],
            },
            audit: AuditRing {
                records: vec![AuditRecord {
                    seq: 1,
                    op: 1,
                    authority: [0xa1; 32],
                    counter: 1,
                    config_version: 3,
                    scope_class: 0,
                    scope_target: b"generate_transfer".to_vec(),
                    request_id: vec![0x11; 16],
                }],
                capacity: 64,
                last_exported_seq: 0, // EXCLUDED cursor
                next_seq: 2,          // EXCLUDED cursor
            },
            freshness_epoch: 9,     // EXCLUDED — enclave-relative anti-rollback
            structural_version: 7,  // EXCLUDED — enclave-relative anti-rollback
            strict_recovery_counter: 4,
        }
    }

    /// Full export round-trips through the KEM-DEM envelope and the offline-open + strict restore parse,
    /// preserving every INCLUDED field (entries incl. secret scalars, counters, faucet, strict_recovery,
    /// audit records, config-identity subset).
    #[test]
    fn restore_ingress_round_trips_through_seal_and_offline_open() {
        let body = body_with_two_keys();
        let refs = selected_key_refs(&body, &[[0x11; 32], [0x22; 32]]);
        assert_eq!(refs, vec![[0x11; 32], [0x22; 32]], "all refs in body order");
        let payload = build_restore_ingress_payload(&body, &refs).unwrap();
        let manifest = build_key_refs_manifest(&refs).unwrap();
        let (ek, dk) = recovery_keypair(&[0x42; 64]);
        let kid = derive_recovery_key_id(&ek);
        let blob = seal_backup_blob(
            &ek,
            &kid,
            body.config.twod_chain_id,
            &body.config.environment_identifier,
            &manifest,
            &payload,
        )
        .unwrap();
        let opened = open_backup_blob_offline(&dk, &blob).unwrap();
        let data = parse_restore_ingress(&opened).unwrap();
        assert_eq!(data.entries, body.entries, "entries (incl. secret scalars) preserved");
        assert_eq!(data.counters, body.counters);
        assert_eq!(data.faucet, body.faucet);
        assert_eq!(data.strict_recovery_counter, 4);
        assert_eq!(data.audit_records, body.audit.records, "audit records (full provenance) preserved");
        assert_eq!(data.config.twod_chain_id, 11565);
        assert_eq!(data.config.admin_authority_pk, [0xa1; 32]);
        assert_eq!(data.config.recovery_authority_pk, [0xa2; 32]);
        assert_eq!(data.config.monotonic_treasury_config_version, 3);
        assert_eq!(data.config.authority_epoch, 0);
    }

    /// The payload EXCLUDES the enclave-specific anchor + anti-rollback state and the operator key.
    /// STRUCTURAL check (decode the CBOR + assert the field SET) — a raw byte-scan can't prove this
    /// because ciborium serializes `[u8;N]`/`Vec<u8>` as CBOR integer-ARRAYS (each `0xAA` → `0x18 0xAA`),
    /// so an included `anchor_root` would never appear as a contiguous `[0xAA;32]` run. The type system
    /// (`RestoreConfigSubset`/`RestoreIngressData` + `deny_unknown_fields`) is the real guarantee; this
    /// pins the exact field set so a regression that re-added an excluded field fails here.
    #[test]
    fn restore_ingress_payload_excludes_anchor_and_anti_rollback_state() {
        let body = body_with_two_keys(); // anchor_root=[0xAA;32], freshness=9, structural=7 set as sentinels
        let refs = selected_key_refs(&body, &[[0x11; 32], [0x22; 32]]);
        let payload = build_restore_ingress_payload(&body, &refs).unwrap();
        let cbor = &payload[RESTORE_INGRESS_MAGIC.len() + 2..];
        let val: ciborium::value::Value =
            ciborium::de::from_reader(cbor).expect("payload body is a CBOR value");
        let map_keys = |v: &ciborium::value::Value| -> Vec<String> {
            match v {
                ciborium::value::Value::Map(m) => m
                    .iter()
                    .map(|(k, _)| match k {
                        ciborium::value::Value::Text(s) => s.clone(),
                        other => panic!("non-text CBOR map key: {other:?}"),
                    })
                    .collect(),
                other => panic!("expected a CBOR map, got {other:?}"),
            }
        };
        let top = map_keys(&val);
        assert_eq!(top.len(), 6, "exactly 6 top-level fields (no anti-rollback / ring-cursor extras)");
        for excluded in ["freshness_epoch", "structural_version", "audit", "next_seq", "capacity"] {
            assert!(!top.contains(&excluded.to_string()), "top-level excludes `{excluded}`");
        }
        assert!(top.contains(&"audit_records".to_string()), "audit RECORDS are included");
        let config = match &val {
            ciborium::value::Value::Map(m) => m
                .iter()
                .find(|(k, _)| matches!(k, ciborium::value::Value::Text(s) if s == "config"))
                .map(|(_, v)| v.clone())
                .expect("config field present"),
            _ => unreachable!(),
        };
        let cfg = map_keys(&config);
        assert_eq!(cfg.len(), 6, "exactly 6 config fields");
        for excluded in ["anchor_root", "backup_recovery_wrapping_pubkey"] {
            assert!(!cfg.contains(&excluded.to_string()), "config excludes `{excluded}`");
        }
        assert!(parse_restore_ingress(&payload).is_ok());
    }

    /// A selective export (a subset of key_refs) includes ONLY the selected entries, but keeps the global
    /// agent state (counters/faucet/audit) in full; the manifest reflects the selected set.
    #[test]
    fn restore_ingress_selective_export_includes_only_selected_entries() {
        let body = body_with_two_keys();
        let refs = selected_key_refs(&body, &[[0x22; 32]]); // only the second key
        assert_eq!(refs, vec![[0x22; 32]], "body-ordered selected ref");
        let payload = build_restore_ingress_payload(&body, &refs).unwrap();
        let data = parse_restore_ingress(&payload).unwrap();
        assert_eq!(data.entries.len(), 1, "only the selected key");
        assert_eq!(data.entries[0].key_ref, [0x22; 32]);
        assert_eq!(data.counters, body.counters, "global counters still full");
        assert_eq!(data.audit_records, body.audit.records, "global audit still full");
        assert_ne!(
            build_key_refs_manifest(&refs).unwrap(),
            build_key_refs_manifest(&[[0x11; 32], [0x22; 32]]).unwrap(),
            "manifest reflects the selected set, not the full set"
        );
    }

    /// Strict restore-side parse fails closed on bad magic / unsupported version / trailing / truncation.
    #[test]
    fn parse_restore_ingress_fails_closed() {
        let body = body_with_two_keys();
        let refs = selected_key_refs(&body, &[[0x11; 32], [0x22; 32]]);
        let good = build_restore_ingress_payload(&body, &refs).unwrap();
        let mut bad_magic = good.to_vec();
        bad_magic[0] ^= 0x01;
        assert_eq!(parse_restore_ingress(&bad_magic), Err(BackupError::BadMagic));
        let mut bad_ver = good.to_vec();
        bad_ver[9] = 0xff;
        assert_eq!(parse_restore_ingress(&bad_ver), Err(BackupError::UnsupportedVersion));
        let mut trailing = good.to_vec();
        trailing.push(0x00);
        assert_eq!(parse_restore_ingress(&trailing), Err(BackupError::Truncated), "trailing byte rejected");
        assert_eq!(parse_restore_ingress(&good[..5]), Err(BackupError::Truncated), "truncated header rejected");
    }

    /// The recovery-key id is deterministic and bound to the encaps key (host cannot substitute it).
    #[test]
    fn recovery_key_id_is_deterministic_and_key_bound() {
        let (ek1, _) = recovery_keypair(&[0x42; 64]);
        let (ek2, _) = recovery_keypair(&[0x43; 64]);
        assert_eq!(derive_recovery_key_id(&ek1), derive_recovery_key_id(&ek1), "deterministic");
        assert_ne!(derive_recovery_key_id(&ek1), derive_recovery_key_id(&ek2), "bound to the key");
        assert_eq!(derive_recovery_key_id(&ek1).len(), RECOVERY_KEY_ID_LEN);
    }

    // ─── 4c-2a: frozen restore-ingress-v1 PAYLOAD golden (the cross-component restore contract) ───
    // Freezes the byte-exact restore-ingress-v1 PAYLOAD over the deterministic `body_with_two_keys()`, so
    // this enclave and the (downstream) RESTORE decoder agree on the format forever. Distinct from
    // `agent_backup_v1.bin` (which freezes the KEM-DEM ENVELOPE); this freezes the PAYLOAD the envelope
    // wraps. TEST DATA ONLY (the entries carry fixed test secret scalars). `SEED` is the shared
    // recovery-keypair seed from the envelope golden above.

    fn golden_restore_ingress_payload() -> Vec<u8> {
        let body = body_with_two_keys();
        let refs = selected_key_refs(&body, &[[0x11; 32], [0x22; 32]]);
        build_restore_ingress_payload(&body, &refs).unwrap().to_vec()
    }

    #[test]
    fn restore_ingress_v1_golden_is_byte_exact() {
        let committed: &[u8] = include_bytes!("../testvectors/agent-gateway/restore_ingress_v1.bin");
        assert_eq!(
            golden_restore_ingress_payload().as_slice(),
            committed,
            "restore-ingress golden drifted; if intentional, regen via \
             `regen_restore_ingress_golden_vector -- --ignored` and re-mint the .json in the same commit",
        );
        assert_eq!(&committed[..8], RESTORE_INGRESS_MAGIC.as_slice(), "magic 2DRIGV1\\0");
        assert_eq!(&committed[8..10], &[0x00, 0x01], "restore_ingress_format_version 1 (literal BE u16)");
        // Field-level check of the COMMITTED bytes against LITERAL expected values (not against a fresh
        // mint) — so a builder bug frozen into the .bin is caught here, not masked by mint==committed.
        let data = parse_restore_ingress(committed).expect("committed payload strictly parses");
        assert_eq!(data.entries.len(), 2, "2 keys");
        assert_eq!(data.entries[0].key_ref, [0x11; 32], "entry 0 ref");
        assert_eq!(&data.entries[0].secret_scalar[..], &[0x77; 32], "entry 0 secret scalar preserved");
        assert_eq!(data.entries[1].key_ref, [0x22; 32], "entry 1 ref");
        assert_eq!(&data.entries[1].secret_scalar[..], &[0x88; 32], "entry 1 secret scalar preserved");
        assert_eq!(data.config.twod_chain_id, 11565, "config chain_id");
        assert_eq!(data.config.monotonic_treasury_config_version, 3, "config version");
        assert_eq!(data.config.admin_authority_pk, [0xa1; 32], "admin pk");
        assert_eq!(data.strict_recovery_counter, 4, "strict_recovery_counter");
        assert_eq!(data.audit_records.len(), 1, "1 audit record");
        assert_eq!(data.audit_records[0].request_id, vec![0x11; 16], "audit record request_id");
    }

    #[test]
    fn restore_ingress_v1_sidecar_matches() {
        use sha2::{Digest, Sha256};
        let payload: &[u8] = include_bytes!("../testvectors/agent-gateway/restore_ingress_v1.bin");
        let sidecar = include_str!("../testvectors/agent-gateway/restore_ingress_v1.json");
        let v: serde_json::Value =
            serde_json::from_str(sidecar).expect("restore-ingress sidecar must be valid JSON");
        assert_eq!(v["payload_sha256"].as_str(), Some(hex(&Sha256::digest(payload)).as_str()), "sha256 drift");
        assert_eq!(v["payload_len_bytes"].as_u64(), Some(payload.len() as u64), "len drift");
        assert_eq!(
            v["restore_ingress_format_version"].as_u64(),
            Some(u64::from(RESTORE_INGRESS_FORMAT_VERSION)),
            "version drift",
        );
        assert_eq!(v["magic"].as_str().map(str::as_bytes), Some(RESTORE_INGRESS_MAGIC.as_slice()), "magic drift");
        // recovery_key_id over the shared fixed SEED encaps key (pins the derivation for downstream 2d).
        let (encaps, _dk) = recovery_keypair(&SEED);
        assert_eq!(
            v["recovery_key_id_hex"].as_str(),
            Some(hex(&derive_recovery_key_id(&encaps)).as_str()),
            "recovery_key_id drift",
        );
        let refs = selected_key_refs(&body_with_two_keys(), &[[0x11; 32], [0x22; 32]]);
        assert_eq!(
            v["key_refs_manifest_hex"].as_str(),
            Some(hex(&build_key_refs_manifest(&refs).unwrap()).as_str()),
            "manifest drift",
        );
    }

    /// REGEN (manual): `cargo test --features agent-backup-export-preview \
    /// regen_restore_ingress_golden_vector -- --ignored --nocapture`, then commit the 2 testvector files.
    /// A deliberate payload-format / version change re-mints the .bin AND the .json sidecar in one commit.
    #[test]
    #[ignore]
    fn regen_restore_ingress_golden_vector() {
        use sha2::{Digest, Sha256};
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/agent-gateway/");
        let payload = golden_restore_ingress_payload();
        std::fs::write(format!("{dir}restore_ingress_v1.bin"), &payload).unwrap();
        let (encaps, _dk) = recovery_keypair(&SEED);
        let refs = selected_key_refs(&body_with_two_keys(), &[[0x11; 32], [0x22; 32]]);
        let sidecar = serde_json::json!({
            "description": "TASK-13b restore-ingress-v1 DR-backup PAYLOAD golden (the plaintext the KEM-DEM \
                            envelope wraps; the downstream RESTORE_BACKUP decoder parses it). TEST DATA ONLY \
                            — entries carry fixed test secret scalars.",
            "payload_sha256": hex(&Sha256::digest(&payload)),
            "payload_len_bytes": payload.len(),
            "restore_ingress_format_version": RESTORE_INGRESS_FORMAT_VERSION,
            "magic": "2DRIGV1\u{0000}",
            "recovery_key_id_hex": hex(&derive_recovery_key_id(&encaps)),
            "key_refs_manifest_hex": hex(&build_key_refs_manifest(&refs).unwrap()),
            "recovery_keypair_seed_hex": hex(&SEED),
        });
        std::fs::write(
            format!("{dir}restore_ingress_v1.json"),
            serde_json::to_string_pretty(&sidecar).unwrap() + "\n",
        )
        .unwrap();
        eprintln!("wrote restore-ingress golden ({}-byte payload) + sidecar -> {dir}", payload.len());
    }
}
