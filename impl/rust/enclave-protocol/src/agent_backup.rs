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
use ml_kem::kem::Decapsulate as _;
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem1024};
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
        BACKUP_MAGIC.len()
            + 2
            + 2
            + recovery_key_id.len()
            + 8
            + 2
            + environment_identifier.len()
            + kem_ct.len()
            + 4
            + key_refs_manifest.len()
            + PAYLOAD_NONCE_LEN,
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
    let encoded: ml_kem::Key<EncapsulationKey<MlKem1024>> = recovery_encaps_key
        .try_into()
        .map_err(|_| BackupError::InvalidEncapsKeyLen)?;
    let ek =
        EncapsulationKey::<MlKem1024>::new(&encoded).map_err(|_| BackupError::InvalidEncapsKey)?;
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

    let cipher =
        ChaCha20Poly1305::new_from_slice(&payload_key[..]).map_err(|_| BackupError::Encrypt)?;
    let dem_ct = cipher
        .encrypt(
            Nonce::from_slice(&payload_nonce),
            Payload {
                msg: payload,
                aad: &header,
            },
        )
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
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
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
/// anchor), `backup_recovery_wrapping_pubkey` (the operator's OWN key), and the TASK-18
/// `enclave_scope_id`/`fleet_scope_id` cap-scope identities (enclave-local, like `anchor_root`) —
/// none is restorable agent state.
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
    debug_assert_eq!(
        out.len(),
        prefix_len + counter.0,
        "restore-ingress CBOR length mismatch between passes"
    );
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
    // Version offset is relative to the magic length (the leading guard ensures both bytes are in bounds),
    // so a future magic-length change can't silently mis-read or panic here.
    let ver_off = RESTORE_INGRESS_MAGIC.len();
    let version = u16::from_be_bytes([payload[ver_off], payload[ver_off + 1]]);
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
    let arr: Vec<ciborium::value::Value> = ordered_refs
        .iter()
        .map(|r| ciborium::value::Value::Bytes(r.to_vec()))
        .collect();
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

// ===========================================================================================
// restore-ingress ENVELOPE — `2d-hsm-agent-restore-ingress-v1` (TASK-24 / AC#1). The SECOND KEM-DEM
// layer of the DR recovery ceremony: the operator's offline environment re-wraps the (offline-decrypted)
// restore-ingress-v1 PAYLOAD to the DESTINATION TEE's ATTESTED EPHEMERAL ML-KEM-1024 public key, so the
// plaintext agent scalars exist ONLY inside the attested destination TEE and never touch the untrusted
// host (ceremony steps (iii)/(iv), keystore-backup-format §"Fresh / newly-provisioned TEE").
//
// This is the SAME KEM-DEM construction as the backup ENVELOPE ([`seal_backup_blob`]), but to the
// destination's EPHEMERAL key and with a STRONGER, ceremony-specific AAD' that binds the re-wrap to the
// destination's attested identity + the original backup's authenticated manifest/digest:
//   (ingress_kem_ct, ss') = ML-KEM-1024.Encaps(dest_ephemeral_encaps_key)
//   ingress_key          = SHA3-256(b"2d-hsm-agent-restore-ingress-v1" ‖ 0x00 ‖ ss')
//   dem_ct               = ChaCha20Poly1305(ingress_key, ingress_nonce, restore_ingress_payload, AAD')
//   AAD'                 = magic ‖ version ‖ lp16(dest_measurement) ‖ chain_id ‖ lp16(env) ‖
//                          manifest_hash(32) ‖ original_backup_digest(32) ‖ ingress_kem_ct(1568) ‖
//                          ingress_nonce(12)
//
// AAD' is the EXACT serialized header bytes (length prefixes + nonce INCLUDED) — the SAME CWE-347
// discipline as the backup envelope ([`build_header`]): because the lengths are authenticated, a host
// cannot re-partition the same authenticated byte string into a different `chain_id`/`env`/`measurement`
// by mutating only the on-disk length prefixes. The spec's AAD' field LIST is the SEMANTIC content; the
// authenticated ENCODING is the full header (a deliberate, stricter-than-literal-spec choice that matches
// the backup envelope so the two cannot diverge in discipline).
//
// Nonce safety: `ingress_nonce` is fixed-zero, safe ONLY because `ss'` is fresh per `Encaps` (the
// operator draws a fresh encaps message `m'` per re-wrap), so the DEM key is unique per ingress envelope
// — the SAME one-message-per-key argument as [`seal_backup_blob_with_m`]. Reusing one `m'` across two
// different payloads would reuse `(ingress_key, nonce=0)` → catastrophic ChaCha20Poly1305 keystream
// reuse; the production re-wrap draws `m'` from the operator HSM's CSPRNG, and the golden path uses a
// fixed `m'` with a FIXED payload (reproduces the identical envelope, not a new plaintext under the key).
//
// SCOPE (TASK-24 AC#12): the operator-side OFFLINE re-wrap (ML-KEM private-key custody + the re-encrypt
// step) is EXPLICITLY OUT of scope — it lives in the operator HSM, never in a production TEE. This slice
// ships the DESTINATION-side [`open_restore_ingress_envelope`] (the production path the RESTORE_BACKUP
// handler calls) + a TEST-ONLY [`seal_restore_ingress_envelope_with_m`] (gated to `mod tests`) for the
// golden round-trip + the AAD' tamper tests — the same primitive-ahead-of-consumer shape as slice-1
// [`seal_backup_blob`]. The handler (Slice 2) does the SEMANTIC AAD' checks: `dest_measurement == OWN`,
// `chain_id`/`env == sealed config`, `manifest_hash`/`backup_digest == recomputed`.
// ===========================================================================================

/// Magic for the restore-ingress ENVELOPE — distinct from the backup envelope (`2DAGTBK\0`), the
/// restore-ingress PAYLOAD (`2DRIGV1\0`), the keystore (`2DAGTKS\0`), and the producer (`2DHSMV1\0`).
/// The envelope WRAPS the `2DRIGV1\0` payload in a second KEM-DEM layer; a distinct magic means an
/// ingress envelope can never be cross-parsed as the payload it wraps or as a backup blob.
const RESTORE_INGRESS_ENVELOPE_MAGIC: &[u8; 8] = b"2DAGRIE\0";
/// Versioned INDEPENDENTLY of the backup envelope, the restore-ingress payload, and the keystore.
const RESTORE_INGRESS_ENVELOPE_FORMAT_VERSION: u16 = 1;
/// DEM-key KDF domain for the ingress envelope — the label from the spec's ceremony definition
/// (`ingress_key = SHA3-256(b"2d-hsm-agent-restore-ingress-v1" ‖ 0x00 ‖ ss')`; the `0x00` is the prefix-free
/// separator added by [`hash_domain_tag`]). DISTINCT from the backup DEM domain
/// (`2d-hsm-agent-backup-v1-key`), so an `ss'` shared secret can never derive a valid key for the other
/// layer (domain separation between the two KEM-DEM wraps).
const RESTORE_INGRESS_KDF_DOMAIN: &[u8] = b"2d-hsm-agent-restore-ingress-v1";
/// Domain for the key-refs manifest hash carried in AAD'. Domain-separated so a manifest hash can never
/// collide with a backup digest or a KDF output for the same input bytes.
const MANIFEST_HASH_DOMAIN: &[u8] = b"2d-hsm-agent-restore-ingress-v1-manifest-hash";
/// Domain for the original-backup digest carried in AAD'. Binds "this is the exact `pq-agent-backup-v1`
/// blob the operator decapsulated" into the authenticated header, so the destination can refuse a re-wrap
/// of a DIFFERENT backup than the one the recovery authority authorized.
const BACKUP_DIGEST_DOMAIN: &[u8] = b"2d-hsm-agent-restore-ingress-v1-backup-digest";
/// SHA3-256 output length (the manifest hash + the backup digest are fixed-width, no length prefix).
const SHA3_256_LEN: usize = 32;
/// ChaCha20Poly1305 ingress-nonce length (96-bit). Fixed-zero is safe — see the nonce-safety note above.
const INGRESS_NONCE_LEN: usize = 12;

/// Update the hasher with a domain tag followed by a `0x00` separator byte — makes every ingress
/// domain transcript STRUCTURALLY prefix-free: none of the ASCII domain constants contains `\x00`, so the
/// `0x00` unambiguously terminates the domain label and `domain1 ‖ 0x00 ‖ data1 == domain2 ‖ 0x00 ‖ data2`
/// implies `domain1 == domain2` AND `data1 == data2`. This resolves the `RESTORE_INGRESS_KDF_DOMAIN`-
/// is-a-prefix-of-the-hash-domains ambiguity structurally (claude-code + compact-codex Low, raised twice)
/// rather than relying on SHA3-256 collision resistance alone. The backup envelope's older
/// [`derive_payload_key`] keeps its frozen non-prefix-free `domain ‖ ss` shape; the ingress domains adopt
/// the stricter form because they are new (not yet frozen at the first commit of this slice).
fn hash_domain_tag(hasher: &mut Sha3_256, domain: &[u8]) {
    hasher.update(domain);
    hasher.update(&[0x00]);
}

/// Derive the ingress DEM key `SHA3-256(domain ‖ 0x00 ‖ ss')` into a pre-zeroed `Zeroizing` buffer — the
/// ingress twin of [`derive_payload_key`] (different domain + the prefix-free separator ⇒ a different key
/// for the same `ss`, so the two KEM-DEM layers are cryptographically disjoint). Scrubs the `finalize()`
/// temporary after the copy.
fn derive_ingress_key(ss: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha3_256::new();
    hash_domain_tag(&mut hasher, RESTORE_INGRESS_KDF_DOMAIN);
    hasher.update(ss);
    let mut digest = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    key
}

/// The authenticated key-refs manifest hash: `SHA3-256(MANIFEST_HASH_DOMAIN ‖ 0x00 ‖ manifest)`. Domain-
/// separated + prefix-free so the destination can match the envelope's authenticated manifest against the
/// request's manifest set-wise without confusing it with the backup digest or the DEM key. `pub(crate)`
/// so the Slice-2 handler recomputes the EXPECTED hash from the request's canonical manifest for the AAD'
/// semantic check.
pub(crate) fn compute_manifest_hash(manifest: &[u8]) -> [u8; SHA3_256_LEN] {
    let mut hasher = Sha3_256::new();
    hash_domain_tag(&mut hasher, MANIFEST_HASH_DOMAIN);
    hasher.update(manifest);
    let mut out = [0u8; SHA3_256_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// The authenticated original-backup digest: `SHA3-256(BACKUP_DIGEST_DOMAIN ‖ 0x00 ‖ original_backup_blob)`.
/// `original_backup_blob` is the FULL `pq-agent-backup-v1` bytes (magic `2DAGTBK\0` …) the operator
/// decapsulated offline; binding its digest into AAD' ties the ingress re-wrap to the EXACT backup the
/// recovery authority authorized, so a re-wrap of a different backup under the same ceremony fails the
/// destination's semantic check. `pub(crate)` so the Slice-2 handler recomputes the EXPECTED digest.
pub(crate) fn compute_original_backup_digest(original_backup_blob: &[u8]) -> [u8; SHA3_256_LEN] {
    let mut hasher = Sha3_256::new();
    hash_domain_tag(&mut hasher, BACKUP_DIGEST_DOMAIN);
    hasher.update(original_backup_blob);
    let mut out = [0u8; SHA3_256_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Build the authenticated ingress header (IS the AEAD AAD'): `magic ‖ version ‖ lp16(dest_measurement)
/// ‖ chain_id(u64) ‖ lp16(environment_identifier) ‖ manifest_hash(32) ‖ original_backup_digest(32) ‖
/// ingress_kem_ct(1568) ‖ ingress_nonce(12)`. The on-disk prefix of the envelope AND the AAD, so seal
/// and open cannot diverge (mirrors [`build_header`]).
#[allow(clippy::too_many_arguments)]
fn build_ingress_header(
    dest_measurement: &[u8],
    chain_id: u64,
    environment_identifier: &str,
    manifest_hash: &[u8; SHA3_256_LEN],
    original_backup_digest: &[u8; SHA3_256_LEN],
    ingress_kem_ct: &[u8],
    ingress_nonce: &[u8; INGRESS_NONCE_LEN],
) -> Result<Vec<u8>, BackupError> {
    let mut h = Vec::with_capacity(
        RESTORE_INGRESS_ENVELOPE_MAGIC.len()
            + 2
            + 2
            + dest_measurement.len()
            + 8
            + 2
            + environment_identifier.len()
            + SHA3_256_LEN
            + SHA3_256_LEN
            + ingress_kem_ct.len()
            + INGRESS_NONCE_LEN,
    );
    h.extend_from_slice(RESTORE_INGRESS_ENVELOPE_MAGIC);
    h.extend_from_slice(&RESTORE_INGRESS_ENVELOPE_FORMAT_VERSION.to_be_bytes());
    put_lp16(&mut h, dest_measurement)?;
    h.extend_from_slice(&chain_id.to_be_bytes());
    put_lp16(&mut h, environment_identifier.as_bytes())?;
    h.extend_from_slice(manifest_hash);
    h.extend_from_slice(original_backup_digest);
    h.extend_from_slice(ingress_kem_ct);
    h.extend_from_slice(ingress_nonce);
    Ok(h)
}

/// A strictly-parsed ingress envelope — all slices borrow `blob`. `header` is `blob[..header_end]` (AAD').
struct ParsedIngressEnvelope<'a> {
    dest_measurement: &'a [u8],
    chain_id: u64,
    environment_identifier: &'a [u8],
    manifest_hash: &'a [u8; SHA3_256_LEN],
    original_backup_digest: &'a [u8; SHA3_256_LEN],
    ingress_kem_ct: &'a [u8],
    ingress_nonce: &'a [u8],
    /// `blob[..header_end]` — the exact bytes used as the AEAD AAD' (lengths + nonce included).
    header: &'a [u8],
    dem_ct: &'a [u8],
}

/// Strict full parse of a `restore-ingress-v1` ENVELOPE: rejects wrong magic / unknown version BEFORE
/// walking the body, walks every framed field, and requires the cursor to land EXACTLY at `blob.len()`.
/// Pure framing — no decapsulation/decrypt. BOTH the seal self-check and the first half of the open, so
/// the two cannot diverge (mirrors [`strict_parse`]).
fn strict_parse_ingress_envelope(blob: &[u8]) -> Result<ParsedIngressEnvelope<'_>, BackupError> {
    if blob.len() < RESTORE_INGRESS_ENVELOPE_MAGIC.len() + 2 {
        return Err(BackupError::Truncated);
    }
    if &blob[..RESTORE_INGRESS_ENVELOPE_MAGIC.len()] != RESTORE_INGRESS_ENVELOPE_MAGIC.as_slice() {
        return Err(BackupError::BadMagic);
    }
    let ver_off = RESTORE_INGRESS_ENVELOPE_MAGIC.len();
    let version = u16::from_be_bytes([blob[ver_off], blob[ver_off + 1]]);
    if version != RESTORE_INGRESS_ENVELOPE_FORMAT_VERSION {
        return Err(BackupError::UnsupportedVersion);
    }
    let mut r = Reader { buf: blob, pos: 0 };
    let _magic = r.take(RESTORE_INGRESS_ENVELOPE_MAGIC.len())?;
    let _version = r.take_u16()?;
    let dest_measurement = r.take_lp16()?;
    let chain_id = r.take_u64()?;
    let environment_identifier = r.take_lp16()?;
    let manifest_hash: &[u8; SHA3_256_LEN] = r
        .take(SHA3_256_LEN)?
        .try_into()
        .map_err(|_| BackupError::Truncated)?;
    let original_backup_digest: &[u8; SHA3_256_LEN] = r
        .take(SHA3_256_LEN)?
        .try_into()
        .map_err(|_| BackupError::Truncated)?;
    let ingress_kem_ct = r.take(ML_KEM_1024_CIPHERTEXT_LEN)?;
    let ingress_nonce = r.take(INGRESS_NONCE_LEN)?;
    let header_end = r.pos;
    let dem_ct = r.take_lp32()?;
    if r.pos != blob.len() {
        return Err(BackupError::Truncated); // trailing bytes ⇒ not strictly canonical
    }
    Ok(ParsedIngressEnvelope {
        dest_measurement,
        chain_id,
        environment_identifier,
        manifest_hash,
        original_backup_digest,
        ingress_kem_ct,
        ingress_nonce,
        header: &blob[..header_end],
        dem_ct,
    })
}

/// The result of opening a `restore-ingress-v1` envelope: the decrypted `restore-ingress-v1` PAYLOAD
/// (the plaintext agent scalars + restorable state, in a scrubbed-on-drop buffer) PLUS the authenticated
/// AAD' fields the Slice-2 handler semantically checks (measurement/chain/env identity + manifest/digest
/// match). Every field here was authenticated by the AEAD tag (it is in the AAD' header), so a host
/// tamper of any field either fails the tag or fails strict-parse — the handler can trust these values
/// as the operator's authenticated intent and need only compare them against its OWN state.
pub(crate) struct OpenedRestoreIngress {
    /// The `restore-ingress-v1` payload (magic `2DRIGV1\0` …); feed to [`parse_restore_ingress`].
    pub payload: Zeroizing<Vec<u8>>,
    /// The destination attestation/measurement bound into AAD' (handler checks `== OWN`).
    pub dest_measurement: Vec<u8>,
    /// The `chain_id` bound into AAD' (handler checks `== sealed config`).
    pub chain_id: u64,
    /// The `environment_identifier` bound into AAD' (handler checks `== sealed config`).
    pub environment_identifier: Vec<u8>,
    /// The key-refs manifest hash bound into AAD' (handler checks `== compute_manifest_hash(own)`).
    pub manifest_hash: [u8; SHA3_256_LEN],
    /// The original-backup digest bound into AAD' (handler checks `== compute_original_backup_digest`).
    pub original_backup_digest: [u8; SHA3_256_LEN],
}

/// The DESTINATION-Tee production path (TASK-24 AC#1 ceremony step (iv)): strict-parse the
/// `2d-hsm-agent-restore-ingress-v1` envelope, decapsulate `ingress_kem_ct` with the destination's
/// EPHEMERAL private key, re-derive the ingress DEM key, and ChaCha20Poly1305-open the payload using the
/// parsed `header` slice as AAD' (the SAME bytes the seal authenticated — no recompute, so no divergence).
/// Returns the plaintext payload + the authenticated AAD' fields for the handler's semantic checks.
///
/// The ephemeral `dk` is the destination enclave's attested keypair (generated + bound to the enclave's
/// attestation at boot/provisioning — the lifecycle is the Slice-2 handler's concern; this primitive takes
/// it as a parameter, mirroring how [`seal_backup_blob`] takes the recovery encaps key). ML-KEM
/// decapsulation is infallible (implicit rejection yields a pseudo-random `ss'` on a bad ct), so a wrong
/// ephemeral key / mutated `ingress_kem_ct` surfaces as the AEAD tag failure below, never a silent
/// success. EVERY failure (framing, decap-then-tag) returns `Err` — the handler fails the op closed with
/// NO partial import. Consumed by the Slice-2 `handle_restore_backup`; `allow(dead_code)` until then.
#[allow(dead_code)]
pub(crate) fn open_restore_ingress_envelope(
    dk: &DecapsulationKey<MlKem1024>,
    blob: &[u8],
) -> Result<OpenedRestoreIngress, BackupError> {
    let parsed = strict_parse_ingress_envelope(blob)?;
    let ct_arr: ml_kem::Ciphertext<MlKem1024> = parsed
        .ingress_kem_ct
        .try_into()
        .map_err(|_| BackupError::Truncated)?;
    // Infallible ML-KEM decap (implicit rejection on a bad ct ⇒ pseudo-random ss' ⇒ tag fails below).
    let mut ss_prime = dk.decapsulate(&ct_arr);
    let ingress_key = derive_ingress_key(ss_prime.as_slice());
    // Scrub the ML-KEM shared secret now that the DEM key is derived — `ss'` is sensitive key material
    // (with the ephemeral private key it re-derives the DEM key), so it must not linger in enclave memory
    // past the derive. Symmetric with `encapsulate_to_recovery_key`'s `ss.zeroize()` on the seal side
    // (claude-code/compact Medium: the decap path zeroizes too, not just the encaps path).
    ss_prime.zeroize();
    let nonce: [u8; INGRESS_NONCE_LEN] = parsed
        .ingress_nonce
        .try_into()
        .map_err(|_| BackupError::Truncated)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&ingress_key[..]).map_err(|_| BackupError::Decrypt)?;
    let payload_bytes = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: parsed.dem_ct,
                aad: parsed.header,
            },
        )
        .map_err(|_| BackupError::Decrypt)?;
    Ok(OpenedRestoreIngress {
        payload: Zeroizing::new(payload_bytes),
        dest_measurement: parsed.dest_measurement.to_vec(),
        chain_id: parsed.chain_id,
        environment_identifier: parsed.environment_identifier.to_vec(),
        manifest_hash: *parsed.manifest_hash,
        original_backup_digest: *parsed.original_backup_digest,
    })
}

/// Fail-closed errors for [`apply_restore_to_body`] (never a partial/silent apply).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RestoreApplyError {
    /// AC#7: the RESTORE-time `audit_capacity` is smaller than the restored `audit_records.len()` —
    /// refuse, NEVER truncate the restored reviewable history.
    AuditCapacityOverflow,
    /// AC#6: `strict_recovery_counter` forward-only advance (`max(local, backup) + 1`) overflows `u64`.
    MonotonicOverflow,
}

/// TASK-24 AC#3/#7 (+ AC#6 strict_recovery): apply a decoded [`RestoreIngressData`] to a keystore body —
/// wholesale-REPLACE the restorable state, reconstruct the EXCLUDED audit cursors enclave-locally, and
/// advance `strict_recovery_counter` forward-only. Pure transform (no I/O, no validate — the handler
/// validates + seals). EVERY error path returns `Err` with NO partial mutation (the capacity gate runs
/// before any field write).
///
/// **Wholesale-replaces** (AC#3): the config-IDENTITY subset (`twod_chain_id`/`environment_identifier`/
/// `admin_authority_pk`/`recovery_authority_pk`/`monotonic_treasury_config_version`/`authority_epoch`) +
/// `entries` (incl. the secret scalars — the point of the backup) + `counters` + `faucet` + audit RECORDS
/// + `strict_recovery_counter` (advanced, AC#6). **Never touches the EXCLUDED surfaces**: `anchor_root`,
/// `backup_recovery_wrapping_pubkey`, `enclave_scope_id`, `fleet_scope_id` (enclave-local identity — the
/// payload carries none), and `freshness_epoch`/`structural_version` (enclave-relative; the handler's
/// `advance_commit_epoch(true)` bumps them — AC#4, the `local+1` strategy).
///
/// **Audit cursors** (AC#7): reconstructed enclave-locally — `next_seq = max(record.seq)+1` (or 1 if
/// none), `last_exported_seq = next_seq-1` (the restored ring starts FULLY drained), `capacity` from the
/// RESTORE-time policy arg (NOT the backup). `capacity < records.len()` ⇒ `AuditCapacityOverflow` (fail
/// closed, never truncate — AC#14).
///
/// **AC#6 NOTE**: this installs the backup's `counters` + `faucet` as the AC#3 base. The handler's AC#6
/// gate (the authenticated-high-water seeding via the 5b-2e raw-marks channel) OVERRIDES/VALIDATES the
/// spend/counter high-water BEFORE commit — it never trusts the possibly-stale backup alone for those
/// marks. `strict_recovery_counter` IS advanced forward-only here (the clear part of AC#6): the new value
/// is strictly `> max(local, backup)` — a fresh TEE (local 0) restores to `backup+1`, a re-restore to
/// `max(local, backup)+1`.
pub(crate) fn apply_restore_to_body(
    body: &mut crate::agent_keystore::KeystoreBody,
    data: &RestoreIngressData,
    audit_capacity: u32,
) -> Result<(), RestoreApplyError> {
    // AC#7: capacity gate FIRST (before any write) — fail closed, NEVER truncate restored records.
    if (audit_capacity as usize) < data.audit_records.len() {
        return Err(RestoreApplyError::AuditCapacityOverflow);
    }
    // AC#7: reconstruct the EXCLUDED cursors enclave-locally (the payload carries records, not cursors).
    let next_seq = data
        .audit_records
        .iter()
        .map(|r| r.seq)
        .max()
        .map(|m| m.saturating_add(1))
        .unwrap_or(1);
    let last_exported_seq = next_seq - 1; // restored ring starts fully drained (next_seq >= 1 ⇒ no underflow)

    // AC#3: wholesale-replace the config-IDENTITY subset. The enclave-local identity fields
    // (anchor_root / backup_recovery_wrapping_pubkey / enclave_scope_id / fleet_scope_id) are EXCLUDED —
    // the payload carries none; they stay the restoring enclave's own.
    body.config.twod_chain_id = data.config.twod_chain_id;
    body.config.environment_identifier = data.config.environment_identifier.clone();
    body.config.admin_authority_pk = data.config.admin_authority_pk;
    body.config.recovery_authority_pk = data.config.recovery_authority_pk;
    body.config.monotonic_treasury_config_version = data.config.monotonic_treasury_config_version;
    body.config.authority_epoch = data.config.authority_epoch;

    body.entries = data.entries.clone();
    body.counters = data.counters.clone();
    body.faucet = data.faucet.clone();
    body.audit.records = data.audit_records.clone();
    body.audit.capacity = audit_capacity;
    body.audit.next_seq = next_seq;
    body.audit.last_exported_seq = last_exported_seq;

    // AC#6 (strict_recovery): forward-only advance — strictly > the current highest of (local, backup).
    let highest = body
        .strict_recovery_counter
        .max(data.strict_recovery_counter);
    body.strict_recovery_counter = highest
        .checked_add(1)
        .ok_or(RestoreApplyError::MonotonicOverflow)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let ct_arr: ml_kem::Ciphertext<MlKem1024> = parsed
            .kem_ct
            .try_into()
            .map_err(|_| BackupError::Truncated)?;
        // ML-KEM decapsulation is infallible by design (implicit rejection yields a pseudo-random ss on a
        // bad ct rather than erroring); a wrong key / mutated ct therefore surfaces as an AEAD tag failure
        // below, never as a silent success.
        let ss = dk.decapsulate(&ct_arr);
        let payload_key = derive_payload_key(ss.as_slice());
        let nonce: [u8; PAYLOAD_NONCE_LEN] = parsed
            .payload_nonce
            .try_into()
            .map_err(|_| BackupError::Truncated)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(&payload_key[..]).map_err(|_| BackupError::Decrypt)?;
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: parsed.dem_ct,
                    aad: parsed.header,
                },
            )
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
        assert!(
            payload().windows(SECRET.len()).any(|w| w == SECRET),
            "test payload must contain the secret"
        );
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
        assert_eq!(
            open_backup_blob_offline(&dk2, &blob),
            Err(BackupError::Decrypt)
        );
    }

    /// (d) Wrong-magic + unknown-version reject BEFORE any decrypt.
    #[test]
    fn header_rejects_before_decrypt() {
        let (mut blob, _dk) = seal_fixed();
        let mut wrong_magic = blob.clone();
        wrong_magic[0] = b'X';
        assert_eq!(
            reject_unparseable_header(&wrong_magic),
            Err(BackupError::BadMagic)
        );
        blob[BACKUP_MAGIC.len() + 1] = 0xFF;
        assert_eq!(
            reject_unparseable_header(&blob),
            Err(BackupError::UnsupportedVersion)
        );
        assert_eq!(
            reject_unparseable_header(&blob[..4]),
            Err(BackupError::Truncated)
        );
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
            assert!(
                open_is_err(&dk, &tampered),
                "tampering {label} (offset {off}) must break the open"
            );
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
        assert!(
            open_is_err(&dk, &t),
            "re-partitioning via the length prefix must not open successfully"
        );
        // And it is specifically the strict parse that catches THIS re-partition (the framing misaligns):
        assert!(
            strict_parse(&t).is_err(),
            "re-partition misaligns the fixed-width framing ⇒ strict_parse rejects"
        );
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
        assert_eq!(
            strict_parse(&blob).err(),
            Some(BackupError::Truncated),
            "trailing byte ⇒ reject"
        );
    }

    /// (i') Corrupted AEAD tag (framing preserved) fails specifically with `Decrypt` — the AC#3
    /// corrupted-tag rejection. Flipping the final ciphertext byte leaves the lp32(dem_ct) length (and all
    /// framing) intact, so `strict_parse` still passes; the AEAD tag check is what rejects it.
    #[test]
    fn corrupted_tag_fails_with_decrypt() {
        let (mut blob, dk) = seal_fixed();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(
            strict_parse(&blob).is_ok(),
            "flipping a tag byte preserves the framing"
        );
        assert_eq!(
            open_backup_blob_offline(&dk, &blob),
            Err(BackupError::Decrypt)
        );
    }

    /// (i) A truncated blob (chopped mid-ciphertext) fails strict-parse, never panics.
    #[test]
    fn truncated_blob_fails_closed() {
        let (blob, _dk) = seal_fixed();
        for cut in [0usize, 5, 9, 11, blob.len() - 1] {
            assert!(
                strict_parse(&blob[..cut]).is_err(),
                "truncation at {cut} must fail closed"
            );
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
        assert_eq!(
            put_lp16(&mut out2, &too_long),
            Err(BackupError::FieldTooLong)
        );
        assert!(
            out2.is_empty(),
            "a refused field writes NOTHING (no truncated prefix)"
        );
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
        assert_eq!(
            &committed[8..10],
            &[0x00, 0x01],
            "backup_format_version 1 (literal BE u16)"
        );
        let (_ek, dk) = recovery_keypair(&SEED);
        assert_eq!(
            open_backup_blob_offline(&dk, committed).unwrap(),
            payload(),
            "committed blob opens"
        );
    }

    #[test]
    fn agent_backup_recovery_keypair_fixtures_consistent() {
        // The committed recovery keypair: `decaps.bin` = the 64-byte ML-KEM keypair seed (the OFFLINE
        // secret — TEST ONLY), `encaps.bin` = the 1568-byte encapsulation (public) key. Couple both to the
        // in-source `SEED` and pin decaps→encaps consistency (`from_seed(seed).encapsulation_key()`).
        let committed_encaps: &[u8] = include_bytes!(
            "../testvectors/agent-gateway/agent_backup_recovery_keypair_v1.encaps.bin"
        );
        let committed_decaps: &[u8] = include_bytes!(
            "../testvectors/agent-gateway/agent_backup_recovery_keypair_v1.decaps.bin"
        );
        assert_eq!(
            committed_decaps, SEED,
            "decaps fixture is the recovery keypair seed"
        );
        assert_eq!(
            committed_encaps.len(),
            ML_KEM_1024_ENCAPS_KEY_LEN,
            "encaps key is 1568 bytes"
        );
        let (encaps, _dk) = recovery_keypair(&SEED);
        assert_eq!(
            committed_encaps,
            encaps.as_slice(),
            "encaps fixture == keypair-from-seed encaps key"
        );
        let seed: [u8; 64] = committed_decaps
            .try_into()
            .expect("decaps fixture is 64 bytes");
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
        let encaps: &[u8] = include_bytes!(
            "../testvectors/agent-gateway/agent_backup_recovery_keypair_v1.encaps.bin"
        );
        let sidecar = include_str!("../testvectors/agent-gateway/agent_backup_v1.json");
        let v: serde_json::Value =
            serde_json::from_str(sidecar).expect("backup sidecar must be valid JSON");
        assert_eq!(
            v["blob_sha256"].as_str(),
            Some(hex(&Sha256::digest(blob)).as_str()),
            "sidecar blob_sha256 drift"
        );
        assert_eq!(
            v["blob_len_bytes"].as_u64(),
            Some(blob.len() as u64),
            "sidecar blob_len_bytes drift"
        );
        assert_eq!(
            v["backup_format_version"].as_u64(),
            Some(u64::from(BACKUP_FORMAT_VERSION)),
            "sidecar version drift"
        );
        assert_eq!(
            v["magic"].as_str().map(str::as_bytes),
            Some(BACKUP_MAGIC.as_slice()),
            "sidecar magic drift"
        );
        assert_eq!(
            v["chain_id"].as_u64(),
            Some(CHAIN),
            "sidecar chain_id drift"
        );
        assert_eq!(
            v["environment_identifier"].as_str(),
            Some(ENV),
            "sidecar env drift"
        );
        assert_eq!(
            v["recovery_key_id_hex"].as_str(),
            Some(hex(RID).as_str()),
            "sidecar recovery_key_id drift"
        );
        assert_eq!(
            v["key_refs_manifest_hex"].as_str(),
            Some(hex(MANIFEST).as_str()),
            "sidecar manifest drift"
        );
        assert_eq!(
            v["payload_nonce_hex"].as_str(),
            Some(hex(&[0u8; PAYLOAD_NONCE_LEN]).as_str()),
            "sidecar nonce drift"
        );
        assert_eq!(
            v["recovery_keypair_seed_hex"].as_str(),
            Some(hex(&SEED).as_str()),
            "sidecar keypair seed drift"
        );
        assert_eq!(
            v["kem_encaps_message_m_hex"].as_str(),
            Some(hex(&M).as_str()),
            "sidecar encaps-message m drift"
        );
        // recovery_encaps_key_{len,sha256} are the ONLY integrity witnesses for encaps.bin in the sidecar
        // (the encaps key is NOT embedded in the blob, so blob_sha256 does not cover it).
        assert_eq!(
            v["recovery_encaps_key_len"].as_u64(),
            Some(encaps.len() as u64),
            "sidecar encaps_key_len drift"
        );
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
        std::fs::write(
            format!("{dir}agent_backup_recovery_keypair_v1.encaps.bin"),
            &encaps,
        )
        .unwrap();
        std::fs::write(
            format!("{dir}agent_backup_recovery_keypair_v1.decaps.bin"),
            SEED,
        )
        .unwrap();
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
        eprintln!(
            "wrote backup golden vector ({}-byte blob) + keypair fixtures + sidecar -> {dir}",
            blob.len()
        );
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
            creation_metadata: CreationMetadata {
                config_version: 3,
                counter_snapshot: 0,
                batch_id: 1,
            },
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
                enclave_scope_id: [0xe1; 32], // EXCLUDED from the restore payload (config subset)
                fleet_scope_id: [0xf1; 32], // EXCLUDED from the restore payload (config subset)
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
            freshness_epoch: 9,    // EXCLUDED — enclave-relative anti-rollback
            structural_version: 7, // EXCLUDED — enclave-relative anti-rollback
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
        assert_eq!(
            data.entries, body.entries,
            "entries (incl. secret scalars) preserved"
        );
        assert_eq!(data.counters, body.counters);
        assert_eq!(data.faucet, body.faucet);
        assert_eq!(data.strict_recovery_counter, 4);
        assert_eq!(
            data.audit_records, body.audit.records,
            "audit records (full provenance) preserved"
        );
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
        assert_eq!(
            top.len(),
            6,
            "exactly 6 top-level fields (no anti-rollback / ring-cursor extras)"
        );
        for excluded in [
            "freshness_epoch",
            "structural_version",
            "audit",
            "next_seq",
            "capacity",
        ] {
            assert!(
                !top.contains(&excluded.to_string()),
                "top-level excludes `{excluded}`"
            );
        }
        assert!(
            top.contains(&"audit_records".to_string()),
            "audit RECORDS are included"
        );
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
        for excluded in [
            "anchor_root",
            "backup_recovery_wrapping_pubkey",
            "enclave_scope_id",
            "fleet_scope_id",
        ] {
            assert!(
                !cfg.contains(&excluded.to_string()),
                "config excludes `{excluded}`"
            );
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
        assert_eq!(
            data.audit_records, body.audit.records,
            "global audit still full"
        );
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
        assert_eq!(
            parse_restore_ingress(&bad_magic),
            Err(BackupError::BadMagic)
        );
        let mut bad_ver = good.to_vec();
        bad_ver[9] = 0xff;
        assert_eq!(
            parse_restore_ingress(&bad_ver),
            Err(BackupError::UnsupportedVersion)
        );
        let mut trailing = good.to_vec();
        trailing.push(0x00);
        assert_eq!(
            parse_restore_ingress(&trailing),
            Err(BackupError::Truncated),
            "trailing byte rejected"
        );
        assert_eq!(
            parse_restore_ingress(&good[..5]),
            Err(BackupError::Truncated),
            "truncated header rejected"
        );
    }

    /// The recovery-key id is deterministic and bound to the encaps key (host cannot substitute it).
    #[test]
    fn recovery_key_id_is_deterministic_and_key_bound() {
        let (ek1, _) = recovery_keypair(&[0x42; 64]);
        let (ek2, _) = recovery_keypair(&[0x43; 64]);
        assert_eq!(
            derive_recovery_key_id(&ek1),
            derive_recovery_key_id(&ek1),
            "deterministic"
        );
        assert_ne!(
            derive_recovery_key_id(&ek1),
            derive_recovery_key_id(&ek2),
            "bound to the key"
        );
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
        build_restore_ingress_payload(&body, &refs)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn restore_ingress_v1_golden_is_byte_exact() {
        let committed: &[u8] =
            include_bytes!("../testvectors/agent-gateway/restore_ingress_v1.bin");
        assert_eq!(
            golden_restore_ingress_payload().as_slice(),
            committed,
            "restore-ingress golden drifted; if intentional, regen via \
             `regen_restore_ingress_golden_vector -- --ignored` and re-mint the .json in the same commit",
        );
        assert_eq!(
            &committed[..8],
            RESTORE_INGRESS_MAGIC.as_slice(),
            "magic 2DRIGV1\\0"
        );
        assert_eq!(
            &committed[8..10],
            &[0x00, 0x01],
            "restore_ingress_format_version 1 (literal BE u16)"
        );
        // Field-level check of the COMMITTED bytes against LITERAL expected values (not against a fresh
        // mint) — so a builder bug frozen into the .bin is caught here, not masked by mint==committed.
        let data = parse_restore_ingress(committed).expect("committed payload strictly parses");
        assert_eq!(data.entries.len(), 2, "2 keys");
        assert_eq!(data.entries[0].key_ref, [0x11; 32], "entry 0 ref");
        assert_eq!(
            &data.entries[0].secret_scalar[..],
            &[0x77; 32],
            "entry 0 secret scalar preserved"
        );
        assert_eq!(data.entries[1].key_ref, [0x22; 32], "entry 1 ref");
        assert_eq!(
            &data.entries[1].secret_scalar[..],
            &[0x88; 32],
            "entry 1 secret scalar preserved"
        );
        assert_eq!(data.config.twod_chain_id, 11565, "config chain_id");
        assert_eq!(
            data.config.monotonic_treasury_config_version, 3,
            "config version"
        );
        assert_eq!(data.config.admin_authority_pk, [0xa1; 32], "admin pk");
        assert_eq!(data.strict_recovery_counter, 4, "strict_recovery_counter");
        assert_eq!(data.audit_records.len(), 1, "1 audit record");
        assert_eq!(
            data.audit_records[0].request_id,
            vec![0x11; 16],
            "audit record request_id"
        );
    }

    #[test]
    fn restore_ingress_v1_sidecar_matches() {
        use sha2::{Digest, Sha256};
        let payload: &[u8] = include_bytes!("../testvectors/agent-gateway/restore_ingress_v1.bin");
        let sidecar = include_str!("../testvectors/agent-gateway/restore_ingress_v1.json");
        let v: serde_json::Value =
            serde_json::from_str(sidecar).expect("restore-ingress sidecar must be valid JSON");
        assert_eq!(
            v["payload_sha256"].as_str(),
            Some(hex(&Sha256::digest(payload)).as_str()),
            "sha256 drift"
        );
        assert_eq!(
            v["payload_len_bytes"].as_u64(),
            Some(payload.len() as u64),
            "len drift"
        );
        assert_eq!(
            v["restore_ingress_format_version"].as_u64(),
            Some(u64::from(RESTORE_INGRESS_FORMAT_VERSION)),
            "version drift",
        );
        assert_eq!(
            v["magic"].as_str().map(str::as_bytes),
            Some(RESTORE_INGRESS_MAGIC.as_slice()),
            "magic drift"
        );
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
        eprintln!(
            "wrote restore-ingress golden ({}-byte payload) + sidecar -> {dir}",
            payload.len()
        );
    }

    // ─── TASK-24 / AC#1: restore-ingress ENVELOPE (the attested second KEM-DEM layer) ───
    // The ceremony re-wrap of the restore-ingress-v1 PAYLOAD to the destination's attested EPHEMERAL
    // ML-KEM-1024 key. The operator-side seal is OUT of scope (AC#12); this TEST-ONLY seal exists to
    // drive the golden round-trip + the AAD' tamper tests (mirroring `open_backup_blob_offline`). The
    // production path is the destination-side `open_restore_ingress_envelope` (above).

    /// Destination ephemeral keypair seed — DISTINCT from the recovery `SEED` so the two ceremony roles
    /// (offline recovery decap key vs attested destination ephemeral key) never share test material.
    /// `recovery_keypair` is a generic ML-KEM-1024 keypair-from-seed; reused here for the ephemeral role.
    const DEST_EPHEMERAL_SEED: [u8; 64] = [0x6c; 64];
    /// The operator's encaps message `m'` for the ingress re-wrap — DISTINCT from the backup `M` so the
    /// two KEM-DEM layers draw different shared secrets even over identical key material.
    const INGRESS_M: [u8; 32] = [0x43; 32];
    /// The destination TEE's attested measurement bound into AAD' (a test stand-in for the real 48-byte
    /// SNP launch measurement; non-empty + variable-length to exercise the lp16 framing).
    const DEST_MEASUREMENT: &[u8] = b"dest-tee-measurement-v1";

    /// TEST-ONLY deterministic seal of a `restore-ingress-v1` ENVELOPE to the destination ephemeral key
    /// (the operator's offline re-wrap, ceremony step (iii)). Mirrors [`seal_backup_blob_with_m`]:
    /// `(ingress_kem_ct, ss') = Encaps(dest_ephemeral_encaps_key, m')`, then ChaCha20Poly1305 with AAD' =
    /// the full header. Self-checks a strict re-parse. The encapsulation reuses [`encapsulate_to_recovery_key`]
    /// — it is the GENERIC ML-KEM Encaps-to-a-public-key (the "recovery" in the name is the backup role;
    /// the operation is key-independent), so a separate copy would be pure duplication.
    #[allow(clippy::too_many_arguments)]
    fn seal_restore_ingress_envelope_with_m(
        dest_ephemeral_encaps_key: &[u8],
        dest_measurement: &[u8],
        chain_id: u64,
        environment_identifier: &str,
        manifest_hash: &[u8; SHA3_256_LEN],
        original_backup_digest: &[u8; SHA3_256_LEN],
        payload: &[u8],
        m: &[u8; 32],
    ) -> Result<Vec<u8>, BackupError> {
        let (ingress_kem_ct, ss_prime) = encapsulate_to_recovery_key(dest_ephemeral_encaps_key, m)?;
        let ingress_key = derive_ingress_key(&ss_prime[..]);
        let ingress_nonce = [0u8; INGRESS_NONCE_LEN];
        let header = build_ingress_header(
            dest_measurement,
            chain_id,
            environment_identifier,
            manifest_hash,
            original_backup_digest,
            &ingress_kem_ct,
            &ingress_nonce,
        )?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(&ingress_key[..]).map_err(|_| BackupError::Encrypt)?;
        let dem_ct = cipher
            .encrypt(
                Nonce::from_slice(&ingress_nonce),
                Payload {
                    msg: payload,
                    aad: &header,
                },
            )
            .map_err(|_| BackupError::Encrypt)?;
        let mut blob = Vec::with_capacity(header.len() + 4 + dem_ct.len());
        blob.extend_from_slice(&header);
        put_lp32(&mut blob, &dem_ct)?;
        // Self-check: the just-minted envelope must STRICTLY re-parse before hand-back (mirrors
        // `seal_backup_blob_with_m`'s `strict_parse(&blob)?` self-check).
        strict_parse_ingress_envelope(&blob)?;
        Ok(blob)
    }

    /// Build the golden ingress envelope: the frozen `restore_ingress_v1.bin` PAYLOAD re-wrapped to the
    /// fixed destination ephemeral key, with AAD' binding the frozen `agent_backup_v1.bin` digest + the
    /// payload's own manifest hash. Cross-references BOTH prior goldens (payload + backup envelope) so the
    /// ceremony path is one coherent frozen artifact, not three independent ones.
    fn golden_restore_ingress_envelope() -> Vec<u8> {
        let (dest_encaps, _dest_dk) = recovery_keypair(&DEST_EPHEMERAL_SEED);
        let payload: &[u8] = include_bytes!("../testvectors/agent-gateway/restore_ingress_v1.bin");
        let backup_blob: &[u8] = include_bytes!("../testvectors/agent-gateway/agent_backup_v1.bin");
        let refs = selected_key_refs(&body_with_two_keys(), &[[0x11; 32], [0x22; 32]]);
        let manifest = build_key_refs_manifest(&refs).unwrap();
        let manifest_hash = compute_manifest_hash(&manifest);
        let backup_digest = compute_original_backup_digest(backup_blob);
        seal_restore_ingress_envelope_with_m(
            &dest_encaps,
            DEST_MEASUREMENT,
            CHAIN,
            ENV,
            &manifest_hash,
            &backup_digest,
            payload,
            &INGRESS_M,
        )
        .unwrap()
    }

    /// (a) Ceremony KEM-DEM round-trip: seal (operator re-wrap) → open (destination decap) recovers the
    /// restore-ingress-v1 payload byte-exact AND surfaces every authenticated AAD' field for the handler.
    #[test]
    fn ingress_envelope_round_trips_and_surfaces_aad_fields() {
        let (dest_encaps, dest_dk) = recovery_keypair(&DEST_EPHEMERAL_SEED);
        let payload: &[u8] = include_bytes!("../testvectors/agent-gateway/restore_ingress_v1.bin");
        let backup_blob: &[u8] = include_bytes!("../testvectors/agent-gateway/agent_backup_v1.bin");
        let refs = selected_key_refs(&body_with_two_keys(), &[[0x11; 32], [0x22; 32]]);
        let manifest = build_key_refs_manifest(&refs).unwrap();
        let manifest_hash = compute_manifest_hash(&manifest);
        let backup_digest = compute_original_backup_digest(backup_blob);
        let envelope = seal_restore_ingress_envelope_with_m(
            &dest_encaps,
            DEST_MEASUREMENT,
            CHAIN,
            ENV,
            &manifest_hash,
            &backup_digest,
            payload,
            &INGRESS_M,
        )
        .unwrap();
        let opened = open_restore_ingress_envelope(&dest_dk, &envelope).unwrap();
        assert_eq!(
            opened.payload.as_slice(),
            payload,
            "payload recovered byte-exact"
        );
        assert_eq!(
            opened.dest_measurement, DEST_MEASUREMENT,
            "measurement surfaced"
        );
        assert_eq!(opened.chain_id, CHAIN, "chain_id surfaced");
        assert_eq!(
            opened.environment_identifier,
            ENV.as_bytes(),
            "env surfaced"
        );
        assert_eq!(
            opened.manifest_hash, manifest_hash,
            "manifest hash surfaced"
        );
        assert_eq!(
            opened.original_backup_digest, backup_digest,
            "backup digest surfaced"
        );
    }

    /// (b) AC#7 no-plaintext-leak at the ENVELOPE layer. The envelope wraps an OPAQUE payload, so this
    /// feeds it a RAW payload carrying a known contiguous 32-byte secret (mirroring `no_plaintext_secret_
    /// in_blob` for the backup envelope) — NOT the CBOR `restore_ingress_v1.bin`, whose `Vec<u8>` scalars
    /// serialize as CBOR integer-arrays (`0x18 0x77` per byte — see agent_keystore.rs ~line 272) and so
    /// are never a contiguous `[0x77;32]` run. The raw payload makes the non-vacuous assertion possible;
    /// the AEAD ciphertext hides the secret from the envelope either way. Uses a DISTINCT encaps message
    /// `m'` (NOT `INGRESS_M`) so this envelope does not share `(ingress_key, nonce=0)` with the golden —
    /// the test corpus should exemplify the one-message-per-key discipline the module documents.
    #[test]
    fn ingress_envelope_no_plaintext_secret_leak() {
        let (dest_encaps, _dest_dk) = recovery_keypair(&DEST_EPHEMERAL_SEED);
        let secret = [0x77; 32];
        let mut raw_payload = b"restore-ingress-test-payload:".to_vec();
        raw_payload.extend_from_slice(&secret);
        let backup_blob: &[u8] = include_bytes!("../testvectors/agent-gateway/agent_backup_v1.bin");
        let manifest_hash = compute_manifest_hash(b"test-manifest");
        let backup_digest = compute_original_backup_digest(backup_blob);
        let envelope = seal_restore_ingress_envelope_with_m(
            &dest_encaps,
            DEST_MEASUREMENT,
            CHAIN,
            ENV,
            &manifest_hash,
            &backup_digest,
            &raw_payload,
            &[0x44; 32], // DISTINCT m' — not INGRESS_M; avoids (key, nonce) reuse with the golden
        )
        .unwrap();
        assert!(
            raw_payload.windows(secret.len()).any(|w| w == secret),
            "test payload must contain the contiguous secret (non-vacuous)"
        );
        assert!(
            !envelope.windows(secret.len()).any(|w| w == secret),
            "the contiguous secret must not appear in the opaque ingress envelope (AC#7)"
        );
    }

    /// (c) Wrong destination ephemeral key ⇒ decap yields a pseudo-random ss' ⇒ the AEAD tag fails
    /// (ML-KEM implicit rejection never errors; the wrong-key surface is ALWAYS the tag failure).
    #[test]
    fn ingress_envelope_wrong_ephemeral_key_fails() {
        let envelope = golden_restore_ingress_envelope();
        let (_other_encaps, other_dk) = recovery_keypair(&[0x99; 64]);
        assert_eq!(
            open_restore_ingress_envelope(&other_dk, &envelope).err(),
            Some(BackupError::Decrypt),
            "an envelope sealed to one ephemeral key must not open with another"
        );
    }

    /// (d) Cross-magic: a `2DAGTBK\0` backup ENVELOPE and a `2DRIGV1\0` PAYLOAD are both rejected by the
    /// ingress envelope parser on magic BEFORE any decap (format-level separation, AC#2). Likewise a bare
    /// ingress envelope fed to the backup parser fails on magic.
    #[test]
    fn ingress_envelope_cross_magic_rejected_before_decap() {
        let backup_blob: &[u8] = include_bytes!("../testvectors/agent-gateway/agent_backup_v1.bin");
        let payload: &[u8] = include_bytes!("../testvectors/agent-gateway/restore_ingress_v1.bin");
        assert_eq!(
            strict_parse_ingress_envelope(backup_blob).err(),
            Some(BackupError::BadMagic),
            "a backup envelope is not an ingress envelope"
        );
        assert_eq!(
            strict_parse_ingress_envelope(payload).err(),
            Some(BackupError::BadMagic),
            "a restore-ingress PAYLOAD is not an ingress envelope"
        );
        let envelope = golden_restore_ingress_envelope();
        assert_eq!(
            strict_parse(&envelope).err(),
            Some(BackupError::BadMagic),
            "an ingress envelope is not a backup envelope (symmetric separation)"
        );
    }

    /// (e) Unknown version rejected BEFORE any decap (parallel to the backup envelope). Version != 1 has
    /// no migration window (the payload format's hard-reject rule carries to the envelope).
    #[test]
    fn ingress_envelope_unknown_version_rejected_before_decap() {
        let mut envelope = golden_restore_ingress_envelope();
        envelope[RESTORE_INGRESS_ENVELOPE_MAGIC.len() + 1] = 0xFF;
        assert_eq!(
            strict_parse_ingress_envelope(&envelope).err(),
            Some(BackupError::UnsupportedVersion)
        );
    }

    /// (f) AAD'-binding for EVERY authenticated header field: flipping one byte of dest_measurement /
    /// chain_id / env / manifest_hash / backup_digest / ingress_kem_ct / ingress_nonce each break the open
    /// (the header IS the AAD', so any mutation that survives strict-parse changes the recomputed AAD' →
    /// the tag fails; a mutation that breaks framing fails strict-parse). Offsets computed from the layout.
    #[test]
    fn every_ingress_aad_field_is_bound() {
        let (dest_encaps, dest_dk) = recovery_keypair(&DEST_EPHEMERAL_SEED);
        let payload: &[u8] = include_bytes!("../testvectors/agent-gateway/restore_ingress_v1.bin");
        let refs = selected_key_refs(&body_with_two_keys(), &[[0x11; 32], [0x22; 32]]);
        let manifest = build_key_refs_manifest(&refs).unwrap();
        let manifest_hash = compute_manifest_hash(&manifest);
        let backup_digest = compute_original_backup_digest(include_bytes!(
            "../testvectors/agent-gateway/agent_backup_v1.bin"
        ));
        let envelope = seal_restore_ingress_envelope_with_m(
            &dest_encaps,
            DEST_MEASUREMENT,
            CHAIN,
            ENV,
            &manifest_hash,
            &backup_digest,
            payload,
            &INGRESS_M,
        )
        .unwrap();
        // Layout offsets (big-endian; lp16/lp32 = u16/u32 length-prefix):
        // magic(8) ver(2) lp16_meas(2) meas[..] chain(8) lp16_env(2) env[..] manifest(32) digest(32)
        // kem_ct(1568) nonce(12) [header end] lp32_dem(4) dem[..]
        let o_meas = 8 + 2 + 2; // first dest_measurement byte (after magic+ver+lp16)
        let o_chain = o_meas + DEST_MEASUREMENT.len();
        let o_env = o_chain + 8 + 2; // first env byte (after chain_id + lp16)
        let o_manifest = o_env + ENV.len();
        let o_digest = o_manifest + SHA3_256_LEN;
        let o_kemct = o_digest + SHA3_256_LEN;
        let o_nonce = o_kemct + ML_KEM_1024_CIPHERTEXT_LEN;
        for (label, off) in [
            ("dest_measurement", o_meas),
            ("chain_id", o_chain),
            ("env", o_env),
            ("manifest_hash", o_manifest),
            ("backup_digest", o_digest),
            ("ingress_kem_ct", o_kemct),
            ("ingress_nonce", o_nonce),
        ] {
            let mut tampered = envelope.clone();
            tampered[off] ^= 0x01;
            assert!(
                open_restore_ingress_envelope(&dest_dk, &tampered).is_err(),
                "tampering AAD' field {label} (offset {off}) must break the open"
            );
        }
    }

    /// (f') CWE-347 re-partition: mutating ONLY the lp16(dest_measurement) length prefix to re-partition
    /// the same authenticated bytes into a different measurement/chain_id must never open successfully.
    /// The strict canonical parse catches it (the shifted framing misaligns the fixed-width chain_id +
    /// 1568-byte kem_ct) — the SAME two-layer defense as the backup envelope (`length_prefix_repartition_
    /// breaks_open`): strict-parse first, AAD'-tag second.
    #[test]
    fn ingress_length_prefix_repartition_breaks_open() {
        let envelope = golden_restore_ingress_envelope();
        let mut t = envelope.clone();
        // lp16(dest_measurement) prefix is at bytes [10,11] (after magic(8)+ver(2)); bump its low byte +1.
        let new_len = (DEST_MEASUREMENT.len() as u16) + 1;
        t[10..12].copy_from_slice(&new_len.to_be_bytes());
        assert!(
            open_restore_ingress_envelope(&recovery_keypair(&DEST_EPHEMERAL_SEED).1, &t).is_err(),
            "re-partitioning via the length prefix must not open successfully"
        );
        assert!(
            strict_parse_ingress_envelope(&t).is_err(),
            "re-partition misaligns the fixed-width framing ⇒ strict_parse rejects"
        );
    }

    /// (g) Trailing bytes / truncation after the declared framing ⇒ `Truncated` (strict canonical parse).
    #[test]
    fn ingress_envelope_trailing_and_truncated_rejected() {
        let envelope = golden_restore_ingress_envelope();
        let mut trailing = envelope.clone();
        trailing.push(0x00);
        assert_eq!(
            strict_parse_ingress_envelope(&trailing).err(),
            Some(BackupError::Truncated),
            "trailing byte rejected"
        );
        assert_eq!(
            strict_parse_ingress_envelope(&envelope[..12]).err(),
            Some(BackupError::Truncated),
            "truncated header rejected"
        );
    }

    /// (h) Domain separation: the three ingress domains (the KDF `RESTORE_INGRESS_KDF_DOMAIN` + the two
    /// hash domains `MANIFEST_HASH_DOMAIN` / `BACKUP_DIGEST_DOMAIN`) are DISTINCT strings, so for any one
    /// input they yield distinct SHA3-256 outputs — a shared secret / manifest / backup blob cannot be
    /// confused across the three uses. The KDF↔backup-DEM disjointness (a shared `ss` derives a different
    /// ingress vs backup key) is the cryptographically load-bearing one; the KDF↔hash disjointness pins
    /// the in-code claim that no two ingress domains collide for the same bytes. All three ingress domains
    /// are STRUCTURALLY prefix-free via the `0x00` separator in [`hash_domain_tag`] (none of the ASCII
    /// domain labels contains `\x00`), so disjointness holds by construction, not just SHA3-256 collision
    /// resistance — the older backup envelope's [`derive_payload_key`] keeps its frozen non-prefix-free
    /// shape; the ingress domains adopt the stricter form (claude-code + compact-codex Low).
    #[test]
    fn ingress_domains_are_pairwise_disjoint() {
        let ss = [0xaa; 32]; // arbitrary shared secret, reused as the "data" for every domain
        let backup_key = derive_payload_key(&ss);
        let ingress_key = derive_ingress_key(&ss);
        let manifest_hash_of_ss = compute_manifest_hash(&ss);
        let backup_digest_of_ss = compute_original_backup_digest(&ss);
        assert_ne!(
            backup_key.as_ref(),
            ingress_key.as_ref(),
            "ingress KDF ≠ backup DEM key"
        );
        assert_ne!(
            ingress_key.as_ref(),
            &manifest_hash_of_ss[..],
            "ingress KDF domain ≠ manifest-hash domain for the same bytes"
        );
        assert_ne!(
            ingress_key.as_ref(),
            &backup_digest_of_ss[..],
            "ingress KDF domain ≠ backup-digest domain for the same bytes"
        );
        assert_ne!(
            manifest_hash_of_ss, backup_digest_of_ss,
            "manifest-hash domain ≠ backup-digest domain for the same bytes"
        );
        // CRAFTED-INPUT regression for the prefix-free separator (claude-code + compact-codex round-2
        // Low): the same-input assertions above pass even WITHOUT the 0x00 separator (distinct domain
        // strings alone separate them), so they do not pin the prefix-free property. These crafted inputs
        // construct the EXACT byte-stream collision a missing separator would create:
        //   WITHOUT 0x00: derive_ingress_key("-manifest-hash" ‖ x) hashes "...v1" ‖ "-manifest-hash" ‖ x,
        //   == compute_manifest_hash(x) hashing "...v1-manifest-hash" ‖ x — a COLLISION. WITH the 0x00
        //   separator the transcripts diverge (the 0x00 lands between "...v1" and the suffix). So these
        //   assertions FAIL if someone removes `hash_domain_tag`'s separator — a true regression guard.
        let x = [0xbb; 16];
        let mut crafted_manifest = b"-manifest-hash".to_vec();
        crafted_manifest.extend_from_slice(&x);
        let mut crafted_digest = b"-backup-digest".to_vec();
        crafted_digest.extend_from_slice(&x);
        assert_ne!(
            derive_ingress_key(&crafted_manifest).as_ref(),
            &compute_manifest_hash(&x)[..],
            "prefix-free: ingress KDF over '-manifest-hash'‖x ≠ manifest hash over x (would collide without 0x00)"
        );
        assert_ne!(
            derive_ingress_key(&crafted_digest).as_ref(),
            &compute_original_backup_digest(&x)[..],
            "prefix-free: ingress KDF over '-backup-digest'‖x ≠ backup digest over x (would collide without 0x00)"
        );
        // And the symmetric craft: compute_manifest_hash over the backup-digest suffix vs the backup digest.
        let mut crafted_digest_via_manifest = b"-backup-digest".to_vec();
        crafted_digest_via_manifest.extend_from_slice(&x);
        assert_ne!(
            compute_manifest_hash(&crafted_digest_via_manifest),
            compute_original_backup_digest(&x),
            "prefix-free: manifest hash over '-backup-digest'‖x ≠ backup digest over x"
        );
    }

    /// (i) Deterministic mint with a fixed `m'` is byte-stable (precondition for the frozen golden).
    #[test]
    fn ingress_envelope_deterministic_mint_is_byte_stable() {
        let a = golden_restore_ingress_envelope();
        let b = golden_restore_ingress_envelope();
        assert_eq!(a, b, "fixed m' + fixed keypair ⇒ byte-identical envelope");
    }

    // ── frozen restore-ingress ENVELOPE golden vector (AC#1) ──
    // The committed envelope (`restore_ingress_envelope_v1.bin`) pins the byte-exact ENVELOPE wire format
    // for the ceremony path; the dest-ephemeral keypair fixtures (`..._dest_ephemeral_keypair_v1.{encaps,
    // decaps}.bin`) let a consumer open it offline + verify the ceremony round-trip. Cross-references the
    // restore_ingress_v1.bin PAYLOAD (the wrapped plaintext) + agent_backup_v1.bin (the digested backup).
    // ALL TEST KEYS ONLY.

    #[test]
    fn restore_ingress_envelope_v1_golden_is_byte_exact() {
        let committed: &[u8] =
            include_bytes!("../testvectors/agent-gateway/restore_ingress_envelope_v1.bin");
        assert_eq!(
            golden_restore_ingress_envelope().as_slice(),
            committed,
            "ingress envelope golden drifted; if intentional, regen via \
             `regen_restore_ingress_envelope_golden_vector -- --ignored` and re-mint the .json + keypair \
             fixtures in the same commit",
        );
        assert_eq!(
            &committed[..RESTORE_INGRESS_ENVELOPE_MAGIC.len()],
            RESTORE_INGRESS_ENVELOPE_MAGIC.as_slice(),
            "magic 2DAGRIE\\0"
        );
        assert_eq!(
            &committed
                [RESTORE_INGRESS_ENVELOPE_MAGIC.len()..RESTORE_INGRESS_ENVELOPE_MAGIC.len() + 2],
            &[0x00, 0x01],
            "restore_ingress_envelope_format_version 1 (literal BE u16)"
        );
        // The committed envelope opens with the committed dest ephemeral key + recovers the committed
        // payload byte-exact (the full ceremony round-trip over frozen artifacts).
        let (_dest_encaps, dest_dk) = recovery_keypair(&DEST_EPHEMERAL_SEED);
        let opened = open_restore_ingress_envelope(&dest_dk, committed).unwrap();
        let payload: &[u8] = include_bytes!("../testvectors/agent-gateway/restore_ingress_v1.bin");
        assert_eq!(
            opened.payload.as_slice(),
            payload,
            "committed envelope opens to the committed payload"
        );
        assert_eq!(
            opened.dest_measurement, DEST_MEASUREMENT,
            "committed measurement"
        );
        assert_eq!(opened.chain_id, CHAIN, "committed chain_id");
    }

    #[test]
    fn restore_ingress_envelope_dest_ephemeral_keypair_fixtures_consistent() {
        // `decaps.bin` = the 64-byte dest ephemeral keypair seed (the OFFLINE-equivalent test secret —
        // in the live ceremony this key is GENERATED inside the destination TEE, never off-device; the
        // fixture exists only so a consumer can open the golden envelope). `encaps.bin` = the 1568-byte
        // attested ephemeral public key the operator re-wraps to.
        let committed_encaps: &[u8] = include_bytes!(
            "../testvectors/agent-gateway/restore_ingress_dest_ephemeral_keypair_v1.encaps.bin"
        );
        let committed_decaps: &[u8] = include_bytes!(
            "../testvectors/agent-gateway/restore_ingress_dest_ephemeral_keypair_v1.decaps.bin"
        );
        assert_eq!(
            committed_decaps, DEST_EPHEMERAL_SEED,
            "decaps fixture is the dest ephemeral seed"
        );
        assert_eq!(
            committed_encaps.len(),
            ML_KEM_1024_ENCAPS_KEY_LEN,
            "encaps key is 1568 bytes"
        );
        let (encaps, _dk) = recovery_keypair(&DEST_EPHEMERAL_SEED);
        assert_eq!(
            committed_encaps,
            encaps.as_slice(),
            "encaps fixture == keypair-from-seed encaps key"
        );
        let seed: [u8; 64] = committed_decaps
            .try_into()
            .expect("decaps fixture is 64 bytes");
        let dk = DecapsulationKey::<MlKem1024>::from_seed(ml_kem::Seed::from(seed));
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            committed_encaps,
            "the committed decaps seed reconstructs a key whose public half == the committed encaps fixture",
        );
    }

    #[test]
    fn restore_ingress_envelope_v1_sidecar_matches() {
        use sha2::{Digest, Sha256};
        let envelope: &[u8] =
            include_bytes!("../testvectors/agent-gateway/restore_ingress_envelope_v1.bin");
        let dest_encaps: &[u8] = include_bytes!(
            "../testvectors/agent-gateway/restore_ingress_dest_ephemeral_keypair_v1.encaps.bin"
        );
        let backup_blob: &[u8] = include_bytes!("../testvectors/agent-gateway/agent_backup_v1.bin");
        let sidecar = include_str!("../testvectors/agent-gateway/restore_ingress_envelope_v1.json");
        let v: serde_json::Value =
            serde_json::from_str(sidecar).expect("ingress envelope sidecar must be valid JSON");
        assert_eq!(
            v["envelope_sha256"].as_str(),
            Some(hex(&Sha256::digest(envelope)).as_str()),
            "sidecar envelope_sha256 drift"
        );
        assert_eq!(
            v["envelope_len_bytes"].as_u64(),
            Some(envelope.len() as u64),
            "sidecar len drift"
        );
        assert_eq!(
            v["restore_ingress_envelope_format_version"].as_u64(),
            Some(u64::from(RESTORE_INGRESS_ENVELOPE_FORMAT_VERSION)),
            "sidecar version drift"
        );
        assert_eq!(
            v["magic"].as_str().map(str::as_bytes),
            Some(RESTORE_INGRESS_ENVELOPE_MAGIC.as_slice()),
            "sidecar magic drift"
        );
        assert_eq!(
            v["chain_id"].as_u64(),
            Some(CHAIN),
            "sidecar chain_id drift"
        );
        assert_eq!(
            v["environment_identifier"].as_str(),
            Some(ENV),
            "sidecar env drift"
        );
        assert_eq!(
            v["dest_measurement_hex"].as_str(),
            Some(hex(DEST_MEASUREMENT).as_str()),
            "sidecar dest_measurement drift"
        );
        assert_eq!(
            v["ingress_nonce_hex"].as_str(),
            Some(hex(&[0u8; INGRESS_NONCE_LEN]).as_str()),
            "sidecar nonce drift"
        );
        let refs = selected_key_refs(&body_with_two_keys(), &[[0x11; 32], [0x22; 32]]);
        let manifest = build_key_refs_manifest(&refs).unwrap();
        assert_eq!(
            v["manifest_hash_hex"].as_str(),
            Some(hex(&compute_manifest_hash(&manifest)).as_str()),
            "sidecar manifest_hash drift"
        );
        assert_eq!(
            v["original_backup_digest_hex"].as_str(),
            Some(hex(&compute_original_backup_digest(backup_blob)).as_str()),
            "sidecar backup_digest drift"
        );
        assert_eq!(
            v["dest_ephemeral_keypair_seed_hex"].as_str(),
            Some(hex(&DEST_EPHEMERAL_SEED).as_str()),
            "sidecar dest ephemeral seed drift"
        );
        assert_eq!(
            v["kem_encaps_message_m_hex"].as_str(),
            Some(hex(&INGRESS_M).as_str()),
            "sidecar encaps-message m' drift"
        );
        assert_eq!(
            v["dest_ephemeral_encaps_key_len"].as_u64(),
            Some(dest_encaps.len() as u64),
            "sidecar dest encaps_key_len drift"
        );
        assert_eq!(
            v["dest_ephemeral_encaps_key_sha256"].as_str(),
            Some(hex(&Sha256::digest(dest_encaps)).as_str()),
            "sidecar dest encaps_key_sha256 drift"
        );
    }

    /// REGEN (manual): `cargo test --features agent-backup-export-preview \
    /// regen_restore_ingress_envelope_golden_vector -- --ignored --nocapture`, then commit the 4 testvector
    /// files (envelope .bin + .json + the dest-ephemeral keypair .encaps/.decaps). A deliberate envelope-
    /// format / version change re-mints all four in the same commit.
    #[test]
    #[ignore]
    fn regen_restore_ingress_envelope_golden_vector() {
        use sha2::{Digest, Sha256};
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/agent-gateway/");
        let (dest_encaps, _dest_dk) = recovery_keypair(&DEST_EPHEMERAL_SEED);
        let envelope = golden_restore_ingress_envelope();
        std::fs::write(
            format!("{dir}restore_ingress_dest_ephemeral_keypair_v1.encaps.bin"),
            &dest_encaps,
        )
        .unwrap();
        std::fs::write(
            format!("{dir}restore_ingress_dest_ephemeral_keypair_v1.decaps.bin"),
            DEST_EPHEMERAL_SEED,
        )
        .unwrap();
        std::fs::write(format!("{dir}restore_ingress_envelope_v1.bin"), &envelope).unwrap();
        let backup_blob: &[u8] = include_bytes!("../testvectors/agent-gateway/agent_backup_v1.bin");
        let refs = selected_key_refs(&body_with_two_keys(), &[[0x11; 32], [0x22; 32]]);
        let manifest = build_key_refs_manifest(&refs).unwrap();
        let sidecar = serde_json::json!({
            "description": "TASK-24 restore-ingress ENVELOPE golden vector — the attested second KEM-DEM \
                            layer (2d-hsm-agent-restore-ingress-v1). The operator re-wraps the \
                            restore_ingress_v1.bin PAYLOAD to the destination TEE's attested EPHEMERAL \
                            ML-KEM-1024 key; AAD' binds the dest measurement + chain/env + manifest hash + \
                            the agent_backup_v1.bin digest. TEST KEYS ONLY — the dest ephemeral decaps \
                            seed is a public test constant (in the live ceremony this key is GENERATED \
                            inside the destination TEE, never off-device).",
            "envelope_sha256": hex(&Sha256::digest(&envelope)),
            "envelope_len_bytes": envelope.len(),
            "restore_ingress_envelope_format_version": RESTORE_INGRESS_ENVELOPE_FORMAT_VERSION,
            "magic": "2DAGRIE\u{0000}",
            "chain_id": CHAIN,
            "environment_identifier": ENV,
            "dest_measurement_hex": hex(DEST_MEASUREMENT),
            "manifest_hash_hex": hex(&compute_manifest_hash(&manifest)),
            "original_backup_digest_hex": hex(&compute_original_backup_digest(backup_blob)),
            "ingress_nonce_hex": hex(&[0u8; INGRESS_NONCE_LEN]),
            "dest_ephemeral_keypair_seed_hex": hex(&DEST_EPHEMERAL_SEED),
            "kem_encaps_message_m_hex": hex(&INGRESS_M),
            "dest_ephemeral_encaps_key_len": dest_encaps.len(),
            "dest_ephemeral_encaps_key_sha256": hex(&Sha256::digest(&dest_encaps)),
        });
        std::fs::write(
            format!("{dir}restore_ingress_envelope_v1.json"),
            serde_json::to_string_pretty(&sidecar).unwrap() + "\n",
        )
        .unwrap();
        eprintln!(
            "wrote restore-ingress ENVELOPE golden ({}-byte envelope) + dest-ephemeral keypair fixtures + sidecar -> {dir}",
            envelope.len()
        );
    }

    // ─── TASK-24 AC#3/#7/#6: apply_restore_to_body (the wholesale-replace + cursor reconstruction) ───

    /// A restore target body with DELIBERATELY distinct EXCLUDED sentinels (`anchor_root=[0xCC;32]`,
    /// `enclave_scope_id=[0xce;32]`, `fleet_scope_id=[0xcf;32]`, `backup_recovery_wrapping_pubkey=[0xd0;…]`,
    /// `freshness_epoch=100`, `structural_version=50`, `strict_recovery_counter=10`) so the exclusion +
    /// forward-only + untouched-anchor-state assertions are non-vacuous.
    fn restore_target_body() -> crate::agent_keystore::KeystoreBody {
        use crate::agent_keystore::*;
        let mut body = body_with_two_keys(); // baseline (will be wholesale-replaced)
        body.config.anchor_root = [0xCC; 32]; // EXCLUDED — must survive the restore
        body.config.enclave_scope_id = [0xCE; 32]; // EXCLUDED
        body.config.fleet_scope_id = [0xCF; 32]; // EXCLUDED
        body.config.backup_recovery_wrapping_pubkey = vec![0xD0; ML_KEM_1024_ENCAPS_KEY_LEN]; // EXCLUDED
        body.freshness_epoch = 100; // EXCLUDED (handler's advance_commit_epoch bumps it)
        body.structural_version = 50; // EXCLUDED (local+1 handler bump)
        body.strict_recovery_counter = 10; // the LOCAL high-water (AC#6 forward-only gate)
        body
    }

    /// A RestoreIngressData round-tripped through the frozen payload format (realistic — not hand-built).
    fn sample_restore_data() -> RestoreIngressData {
        let body = body_with_two_keys(); // source body (chain 11565, env "testnet", 2 keys, 1 audit rec)
        let refs = selected_key_refs(&body, &[[0x11; 32], [0x22; 32]]);
        let payload = build_restore_ingress_payload(&body, &refs).unwrap();
        parse_restore_ingress(&payload).unwrap()
    }

    /// AC#3: wholesale-replace entries/config-identity/counters/faucet/audit-records; the EXCLUDED
    /// enclave-local identity (anchor_root/scope_ids/wrapping pubkey) + freshness/structural are PRESERVED
    /// (the restoring enclave's own — the payload carries none).
    #[test]
    fn apply_restore_wholesale_replaces_and_preserves_excluded() {
        let mut target = restore_target_body();
        let data = sample_restore_data();
        apply_restore_to_body(&mut target, &data, 64).unwrap();
        // Replaced: config-identity subset + entries + counters + faucet.
        assert_eq!(target.config.twod_chain_id, 11565);
        assert_eq!(target.config.environment_identifier, "testnet");
        assert_eq!(target.entries.len(), 2, "entries replaced");
        assert_eq!(target.entries[0].key_ref, [0x11; 32]);
        assert_eq!(
            &target.entries[0].secret_scalar[..],
            &[0x77; 32],
            "secret scalar restored"
        );
        assert_eq!(target.counters, data.counters, "counters replaced");
        assert_eq!(target.faucet, data.faucet, "faucet replaced");
        assert_eq!(
            target.audit.records, data.audit_records,
            "audit records replaced"
        );
        // PRESERVED (excluded — the restoring enclave's own identity, never in the payload).
        assert_eq!(
            target.config.anchor_root, [0xCC; 32],
            "anchor_root preserved (excluded)"
        );
        assert_eq!(
            target.config.enclave_scope_id, [0xCE; 32],
            "enclave_scope_id preserved"
        );
        assert_eq!(
            target.config.fleet_scope_id, [0xCF; 32],
            "fleet_scope_id preserved"
        );
        assert_eq!(
            target.config.backup_recovery_wrapping_pubkey,
            vec![0xD0; crate::agent_keystore::ML_KEM_1024_ENCAPS_KEY_LEN],
            "wrapping pubkey preserved"
        );
        assert_eq!(
            target.freshness_epoch, 100,
            "freshness_epoch untouched (handler bumps it)"
        );
        assert_eq!(
            target.structural_version, 50,
            "structural_version untouched (local+1 handler bump)"
        );
    }

    /// AC#7: audit cursors reconstructed enclave-locally — next_seq=max(seq)+1, last_exported_seq=
    /// next_seq-1 (fully drained), capacity from the RESTORE-time policy (NOT the backup).
    #[test]
    fn apply_restore_reconstructs_audit_cursors() {
        let mut target = restore_target_body();
        let data = sample_restore_data();
        // body_with_two_keys has ONE audit record (seq=1) ⇒ next_seq=2, last_exported_seq=1.
        apply_restore_to_body(&mut target, &data, 128).unwrap();
        assert_eq!(
            target.audit.capacity, 128,
            "capacity from restore-time policy, not the backup"
        );
        let max_seq = data.audit_records.iter().map(|r| r.seq).max().unwrap();
        assert_eq!(
            target.audit.next_seq,
            max_seq + 1,
            "next_seq = max(record.seq)+1"
        );
        assert_eq!(
            target.audit.last_exported_seq,
            target.audit.next_seq - 1,
            "fully drained"
        );
    }

    /// AC#6 (strict_recovery): forward-only — new = max(local, backup)+1. Local high-water (10) vs the
    /// backup's value ⇒ strictly past both.
    #[test]
    fn apply_restore_strict_recovery_advances_forward_only() {
        let mut target = restore_target_body(); // local strict_recovery_counter = 10
        let mut data = sample_restore_data();
        // Case 1: backup (4) < local (10) ⇒ new = 11 (local + 1).
        data.strict_recovery_counter = 4;
        apply_restore_to_body(&mut target, &data, 64).unwrap();
        assert_eq!(
            target.strict_recovery_counter, 11,
            "local(10) > backup(4) ⇒ new = 11"
        );
        // Case 2: a re-restore where the backup now exceeds local — new = max(local, backup)+1.
        target.strict_recovery_counter = 3;
        data.strict_recovery_counter = 8;
        apply_restore_to_body(&mut target, &data, 64).unwrap();
        assert_eq!(
            target.strict_recovery_counter, 9,
            "max(3,8)+1 = 9 (strictly past both)"
        );
    }

    /// AC#7/#14: capacity < records.len() ⇒ AuditCapacityOverflow, fail closed, NO partial mutation.
    #[test]
    fn apply_restore_capacity_overflow_fails_closed_no_truncation() {
        let mut target = restore_target_body();
        let pre = target.clone();
        let data = sample_restore_data(); // 1 audit record
                                          // capacity 0 < 1 record ⇒ overflow.
        assert_eq!(
            apply_restore_to_body(&mut target, &data, 0),
            Err(RestoreApplyError::AuditCapacityOverflow),
            "capacity overflow ⇒ fail closed"
        );
        assert_eq!(
            target, pre,
            "NO partial mutation on the capacity-overflow path"
        );
    }

    /// AC#7 edge: an empty audit-records backup ⇒ next_seq=1, last_exported_seq=0 (a fresh ring).
    #[test]
    fn apply_restore_empty_audit_records_yields_fresh_cursors() {
        let mut target = restore_target_body();
        let mut data = sample_restore_data();
        data.audit_records.clear();
        apply_restore_to_body(&mut target, &data, 64).unwrap();
        assert!(target.audit.records.is_empty());
        assert_eq!(target.audit.next_seq, 1, "empty ⇒ next_seq=1");
        assert_eq!(
            target.audit.last_exported_seq, 0,
            "empty ⇒ last_exported_seq=0"
        );
    }
}
