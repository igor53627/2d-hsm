//! SEV-SNP attestation report: fetch via configfs-tsm and extract the launch measurement.
//!
//! TASK-5 Phase 3 (AC#4): make `GET_MEASUREMENT` return the real TEE launch measurement for the
//! SNP production profile instead of a placeholder label.
//!
//! Field offsets are the AMD SEV-SNP `ATTESTATION_REPORT` ABI, verified against a live report
//! captured on aya (EPYC 9375F, AMD OVMF; report version 5). The report is obtained through
//! `configfs-tsm` (`/sys/kernel/config/tsm/report`) as plain file I/O — no ioctl — which keeps
//! this in the crate's `#![forbid(unsafe_code)]` boundary.

use crate::ProtocolError;

// ---- ATTESTATION_REPORT field layout (bytes) ----
// pub(crate) so the reference verifier (snp_verify) reuses the single source of truth for offsets.
pub(crate) const REPORT_DATA_OFFSET: usize = 0x50;
const REPORT_DATA_LEN: usize = 64;
pub(crate) const MEASUREMENT_OFFSET: usize = 0x90;
/// SNP launch measurement length (48 bytes, SHA-384-sized).
pub const SNP_MEASUREMENT_LEN: usize = 48;
/// Shortest report we accept: it must at least cover the measurement field.
pub(crate) const MIN_REPORT_LEN: usize = MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN;

/// configfs-tsm report directory (Linux >= 6.7 with the SNP guest TSM provider loaded).
const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";
/// Fixed configfs entry name for this enclave's one boot-time report. Since (4a) (cooperative boot
/// fetch deleted) this fixed entry is EXCLUSIVELY the unbounded producer/GET_MEASUREMENT path's —
/// only `RealTsmFs` via [`fetch_report`] touches it; the quote child self-names `twod-hsm-q-<pid>`
/// (see [`TSM_QUOTE_ENTRY_PREFIX`]). Code MAY rely on this exclusivity (§8 claim flipped TRUE) —
/// scoped honestly: the prefix-discrimination half is TEST-PINNED (structural), while the
/// only-`fetch_report`-mints-the-fixed-name half holds by current-caller absence (`fetch_report_with`
/// is pub(crate) and unconditional): a NEW in-crate caller of `fetch_report_with` re-audits this
/// exclusivity or forfeits it — two concurrent fixed-entry users would race the leading stale-clear
/// against each other's in-flight create→write→read on the SAME directory.
const TSM_ENTRY_NAME: &str = "twod-hsm";
/// Domain separation for the `report_data` binding (so it is not a bare key hash).
const REPORT_DATA_DOMAIN: &[u8] = b"2d-hsm-snp-report-data-v1";

/// Prefix for the killable quote CHILD's self-named configfs entries (TASK-7.7 5b-2b-ii(d), §8 revised
/// pin): `twod-hsm-q-<child_pid>`. STRICTLY LONGER than the bare producer name `twod-hsm`, so the
/// child-side prefix GC can never match (and never remove) the producer/GET_MEASUREMENT entry.
#[cfg(feature = "agent-gateway")]
pub(crate) const TSM_QUOTE_ENTRY_PREFIX: &str = "twod-hsm-q-";

/// The quote child's self-named unique entry path: `{TSM_REPORT_DIR}/{PREFIX}{own pid}`. Live-pid
/// uniqueness forbids collision among live children (a wedged unreaped child still holds its pid), and
/// post-reap pid recycling is harmless: the child's own sequence starts with a stale-clear of exactly
/// this name. No parent→child name plumbing exists at all — the child self-names (deletes the env
/// injection/path-validation surface the parent-minted alternative would need).
#[cfg(feature = "agent-gateway")]
#[cfg_attr(not(test), allow(dead_code))] // consumer = the triple-gated quote_subprocess child mode
pub(crate) fn quote_child_entry_path() -> String {
    format!("{TSM_REPORT_DIR}/{TSM_QUOTE_ENTRY_PREFIX}{}", std::process::id())
}

/// CHILD-ONLY best-effort orphan GC (path-parameterized so tempdir tests can exercise it): remove every
/// directory under `dir` whose name starts with [`TSM_QUOTE_ENTRY_PREFIX`]. EVERY error is skipped
/// silently — EBUSY on a still-wedged sibling's held entry is EXPECTED (≤ ABANDONED_CHILD_BUDGET such
/// children can be live, §8), an absent dir means off-SNP; GC never blocks on, gates, or fails the
/// attempt, and is never required to prove all orphans were removed. MUST only ever run inside the
/// killable child — a parent-side readdir/rmdir against a wedged provider could block uninterruptibly
/// (the §8 no-parent-configfs-I/O rule).
#[cfg(feature = "agent-gateway")]
#[cfg_attr(not(test), allow(dead_code))] // consumer = the triple-gated quote_subprocess child mode
pub(crate) fn gc_quote_entries_best_effort(dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // absent/unreadable dir (off-SNP) — never an error
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with(TSM_QUOTE_ENTRY_PREFIX) {
            let _ = std::fs::remove_dir(entry.path()); // best-effort; EBUSY on a held entry is EXPECTED
        }
    }
}

/// [`gc_quote_entries_best_effort`] at the real configfs-tsm report dir — the form
/// `agent_quote_child_main` calls.
#[cfg(feature = "agent-gateway")]
// Plain allow (not cfg_attr(not(test))): the only caller is the TRIPLE-gated child entrypoint, and no
// deviceless test can exercise this real-/sys-dir binding — under agent-gateway-only test builds it is
// legitimately consumer-free and must stay warning-silent there too.
#[allow(dead_code)]
pub(crate) fn gc_quote_entries_default() {
    gc_quote_entries_best_effort(std::path::Path::new(TSM_REPORT_DIR));
}

/// Upper bound on the configfs-tsm `auxblob` (VCEK→ASK→ARK chain) we will carry in
/// GET_MEASUREMENT. A real chain is a few KB; this is generous headroom while staying well under
/// `MAX_MESSAGE_SIZE` once the report + pq_pubkey are added.
// `pub(crate)` so the agent boot-relay request encoder (TASK-7.7 5b-2) bounds its outbound cert_chain
// against the single source of truth rather than re-declaring 64 KiB.
pub(crate) const MAX_CERT_CHAIN_LEN: usize = 64 * 1024;

/// The outblob post-check triage messages — pub(crate) consts (NOT inline literals) because the quote
/// CHILD's ERR-code refinement (`quote_subprocess::child_err_code`) matches on them: a single source
/// makes cross-file drift structurally impossible (the previous transcribed-copy + self-referential
/// pin-test arrangement guaranteed nothing).
pub(crate) const OUTBLOB_OVERSIZE_MSG: &str = "SNP attestation: outblob exceeds max size";
pub(crate) const OUTBLOB_SHORT_MSG: &str = "SNP attestation: outblob shorter than ABI minimum";

/// Upper bound on the configfs-tsm `outblob` (the `ATTESTATION_REPORT`). A real report is ~1184 B
/// (version 5); 8 KiB is ample headroom for future report versions and matches the relay-path quote bound
/// (`agent_boot_relay::MAX_QUOTE_REPORT_LEN`). Enforced cap-before-alloc on the configfs read so a buggy/
/// wedged provider cannot force an unbounded heap allocation in the memory-constrained TEE.
///
/// Independent of `agent_boot_relay::MAX_ANCHOR_RESPONSE_LEN` (4 KiB): that bounds the *signed response*
/// the relay returns, a different artifact on the other leg — the two caps need not track each other.
pub(crate) const MAX_OUTBLOB_LEN: usize = 8192;

/// Extract the 48-byte launch measurement from a raw SNP `ATTESTATION_REPORT`.
pub fn measurement_from_report(report: &[u8]) -> Result<[u8; SNP_MEASUREMENT_LEN], ProtocolError> {
    if report.len() < MIN_REPORT_LEN {
        return Err(ProtocolError::PqSigningUnavailable(
            "SNP report shorter than ABI minimum (measurement field)",
        ));
    }
    let mut m = [0u8; SNP_MEASUREMENT_LEN];
    m.copy_from_slice(&report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN]);
    Ok(m)
}

/// Read the 64-byte `report_data` field a report carries (the value the guest requested).
pub fn report_data_from_report(report: &[u8]) -> Result<[u8; REPORT_DATA_LEN], ProtocolError> {
    if report.len() < REPORT_DATA_OFFSET + REPORT_DATA_LEN {
        return Err(ProtocolError::PqSigningUnavailable(
            "SNP report shorter than ABI minimum (report_data field)",
        ));
    }
    let mut rd = [0u8; REPORT_DATA_LEN];
    rd.copy_from_slice(&report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_LEN]);
    Ok(rd)
}

/// 64-byte `report_data` binding the producer PQ key into the attestation (domain-separated
/// SHA3-512 of the public key). Putting this in the report ties the signed measurement to the
/// exact `pq_pubkey` the enclave advertises, so a relying party cannot replay a report from a
/// different key.
pub fn report_data_for_pubkey(pq_pubkey: &[u8]) -> [u8; REPORT_DATA_LEN] {
    use sha3::{Digest, Sha3_512};
    let mut h = Sha3_512::new();
    h.update(REPORT_DATA_DOMAIN);
    h.update(pq_pubkey);
    h.finalize().into()
}

/// The configfs-tsm filesystem operations, behind a seam so the cleanup orchestration in
/// [`fetch_report_with`] is unit-testable WITHOUT a live `/sys/kernel/config/tsm` (the cleanup-on-error
/// invariant — entry removed even when a step fails mid-sequence — is the defect-prone part and the
/// only one that leaks a stale configfs entry if wrong). Configfs is touched by exactly TWO code surfaces,
/// both in this file: [`RealTsmFs`] (the seam ops) and the seam-BYPASSING
/// [`gc_quote_entries_best_effort`] (child-mode-only orphan sweep — see its doc; §8 forbids it
/// parent-side). Auditors of the no-parent-configfs rule must check BOTH.
pub(crate) trait TsmFs {
    /// Best-effort remove (== `fs::remove_dir`, ignore error) — used to clear a stale entry and to clean up.
    fn remove_entry(&self, entry: &str);
    fn create_entry(&self, entry: &str) -> Result<(), ProtocolError>;
    fn write_inblob(&self, entry: &str, data: &[u8; REPORT_DATA_LEN]) -> Result<(), ProtocolError>;
    fn read_outblob(&self, entry: &str) -> Result<Vec<u8>, ProtocolError>;
    /// Best-effort: returns the `auxblob` cert chain, or empty on absence/unreadable/oversize.
    fn read_auxblob(&self, entry: &str) -> Vec<u8>;
}

/// The real configfs-tsm implementation (one of exactly TWO configfs touchers — the other is the
/// child-only GC; see the seam doc above). `pub(crate)` SOLELY for the quote-child binding in
/// `quote_subprocess::agent_quote_child_main` — any other caller, ESPECIALLY anything reachable from
/// the parent boot path, violates the §8 no-parent-configfs rule (a parent-side configfs op against a
/// wedged provider can block uninterruptibly). Methods
/// are lifted verbatim from the previous `fetch_report`/`fetch_report_inner`; safe file I/O (no ioctl,
/// no unsafe). Exercised live only on an SNP guest (aya); compiles + returns interface-absent errors
/// everywhere else.
pub(crate) struct RealTsmFs;
impl TsmFs for RealTsmFs {
    fn remove_entry(&self, entry: &str) {
        let _ = std::fs::remove_dir(entry);
    }
    fn create_entry(&self, entry: &str) -> Result<(), ProtocolError> {
        std::fs::create_dir(entry).map_err(|_| {
            ProtocolError::PqSigningUnavailable(
                "SNP attestation unavailable: cannot create configfs-tsm report entry \
                 (needs kernel >= 6.7 and the sev-guest TSM provider)",
            )
        })
    }
    fn write_inblob(&self, entry: &str, data: &[u8; REPORT_DATA_LEN]) -> Result<(), ProtocolError> {
        use std::io::Write;
        let mut inblob = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("{entry}/inblob"))
            .map_err(|_| ProtocolError::PqSigningUnavailable("SNP attestation: cannot open inblob"))?;
        inblob.write_all(data).map_err(|_| {
            ProtocolError::PqSigningUnavailable("SNP attestation: cannot write report_data")
        })
    }
    fn read_outblob(&self, entry: &str) -> Result<Vec<u8>, ProtocolError> {
        use std::io::Read;
        let file = std::fs::File::open(format!("{entry}/outblob"))
            .map_err(|_| ProtocolError::PqSigningUnavailable("SNP attestation: cannot open outblob"))?;
        // Cap-before-alloc (configfs is in the TCB, but match the module's bounded-read discipline so a
        // buggy/wedged provider can't force an unbounded heap alloc in the memory-constrained TEE): read at
        // most MAX_OUTBLOB_LEN+1, so an over-large stream is DETECTED (errored) — not silently truncated
        // into a malformed report the relay would then sign over.
        let mut buf = Vec::new();
        file.take((MAX_OUTBLOB_LEN + 1) as u64)
            .read_to_end(&mut buf)
            .map_err(|_| ProtocolError::PqSigningUnavailable("SNP attestation: cannot read outblob"))?;
        if buf.len() > MAX_OUTBLOB_LEN {
            return Err(ProtocolError::PqSigningUnavailable(OUTBLOB_OVERSIZE_MSG));
        }
        Ok(buf)
    }
    fn read_auxblob(&self, entry: &str) -> Vec<u8> {
        use std::io::Read;
        // VCEK→ASK→ARK cert chain. Best-effort: absent/unreadable/oversize → empty (the verifier can
        // fetch the chain from AMD KDS by VCEK serial). Cap-before-alloc at `MAX_CERT_CHAIN_LEN` (read at
        // most +1 to detect oversize) so an implausibly large auxblob can't force an unbounded alloc, nor
        // push the GET_MEASUREMENT response frame past `MAX_MESSAGE_SIZE` (nor the boot-relay request frame
        // past its own bound, which reuses this same constant).
        let file = match std::fs::File::open(format!("{entry}/auxblob")) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let mut buf = Vec::new();
        match file.take((MAX_CERT_CHAIN_LEN + 1) as u64).read_to_end(&mut buf) {
            Ok(_) if buf.len() <= MAX_CERT_CHAIN_LEN => buf,
            _ => Vec::new(),
        }
    }
}

/// SNP quote fetch over a [`TsmFs`] seam — UNBOUNDED ((4a) deleted the cooperative `Option<Instant>`
/// deadline plumbing; the hard wall-clock bound is the killable subprocess — `HardBoundedQuoteProducer`
/// via `quote_subprocess`, per the revised §8 pin: "kernel timeout" was eliminated, a worker thread can
/// only abandon a stuck reader). On **every** path it **unconditionally cleans up** the entry — the
/// cleanup is the last statement, so an error mid-sequence still leaves no stale `twod-hsm` entry; the
/// leading stale-clear covers a previous crashed boot.
pub(crate) fn fetch_report_with<F: TsmFs>(
    fs: &F,
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let entry = format!("{TSM_REPORT_DIR}/{TSM_ENTRY_NAME}");
    fetch_report_with_at(fs, &entry, report_data)
}

/// Entry-path-parameterized core of [`fetch_report_with`]: the killable quote CHILD fetches at its own
/// unique self-named `twod-hsm-q-<pid>` path ((d-ii)) while the producer path keeps the fixed name
/// above (FakeTsmFs ignores entry strings, so the sequence tests pin both shapes). UNBOUNDED BY
/// SIGNATURE — (4a) deleted the cooperative `deadline: Option<Instant>` parameter, landing the
/// previously recorded narrowing as a structural fact: the parent's pipe poll + SIGKILL is the only
/// bound on the child path; any future deadline-bearing caller must reintroduce its own bounded
/// variant AND its own fast-path. Body: stale-clear → inner sequence → UNCONDITIONAL trailing cleanup
/// on every path.
pub(crate) fn fetch_report_with_at<F: TsmFs>(
    fs: &F,
    entry_path: &str,
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    fs.remove_entry(entry_path); // clear any stale entry from a previous crashed boot
    let result = fetch_report_inner_with(fs, entry_path, report_data);
    fs.remove_entry(entry_path); // UNCONDITIONAL cleanup — last statement on every path
    result
}

fn fetch_report_inner_with<F: TsmFs>(
    fs: &F,
    entry: &str,
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    fs.create_entry(entry)?;
    fs.write_inblob(entry, report_data)?;
    let report = fs.read_outblob(entry)?;
    if report.len() < MIN_REPORT_LEN {
        return Err(ProtocolError::PqSigningUnavailable(OUTBLOB_SHORT_MSG));
    }
    // MAX post-check HERE (not only inside RealTsmFs::read_outblob): the seam contract must hold for
    // EVERY TsmFs impl, the child's code-5 refinement must be reachable through the REAL fetch path
    // devicelessly, and the encoder-reject arm downstream becomes structurally unreachable for the
    // report half. (RealTsmFs's cap-before-alloc read stays — defense in depth at the alloc boundary.)
    if report.len() > MAX_OUTBLOB_LEN {
        return Err(ProtocolError::PqSigningUnavailable(OUTBLOB_OVERSIZE_MSG));
    }
    let cert_chain = fs.read_auxblob(entry);
    Ok((report, cert_chain))
}

/// Fetch a fresh SNP `ATTESTATION_REPORT` via configfs-tsm, binding `report_data` (64 bytes).
///
/// Returns `(report, cert_chain)` where `cert_chain` is the configfs-tsm `auxblob` — the VCEK→ASK→ARK
/// certificate chain a relying party needs to verify the report's signature against the AMD root (see
/// `backlog/docs/snp-attestation-verifier-policy.md`). The chain is best-effort (absent → empty `Vec`).
/// The error path includes "interface absent", so callers on non-SNP/dev hosts can fall back to a
/// placeholder.
///
/// **Unbounded** — the producer GET_MEASUREMENT path keeps its historical no-timeout contract. The
/// boot-relay quote path does NOT come through here: it is the killable-subprocess
/// `HardBoundedQuoteProducer` (`quote_subprocess`) — the cooperative deadline-bounded variant
/// (`fetch_report_deadline`) was deleted in (4a).
pub fn fetch_report(report_data: &[u8; REPORT_DATA_LEN]) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    fetch_report_with(&RealTsmFs, report_data)
}

/// Boot-captured SNP attestation: `(launch_measurement, raw_report, cert_chain)`.
/// `cert_chain` (configfs-tsm `auxblob`) may be empty when the provider didn't populate it.
pub type SnpAttestation = ([u8; SNP_MEASUREMENT_LEN], Vec<u8>, Vec<u8>);

/// Fetch the SNP report bound to `pq_pubkey` and return `(measurement, raw_report, cert_chain)`.
pub fn fetch_measurement_and_report(pq_pubkey: &[u8]) -> Result<SnpAttestation, ProtocolError> {
    let report_data = report_data_for_pubkey(pq_pubkey);
    let (report, cert_chain) = fetch_report(&report_data)?;
    let measurement = verify_and_extract_measurement(&report, &report_data)?;
    Ok((measurement, report, cert_chain))
}

/// Verify the report echoes the requested `report_data` (the key binding) before trusting its
/// measurement, then extract the measurement. Rejects a stale or misrouted report whose
/// `report_data` does not match what we asked for.
fn verify_and_extract_measurement(
    report: &[u8],
    expected_report_data: &[u8; REPORT_DATA_LEN],
) -> Result<[u8; SNP_MEASUREMENT_LEN], ProtocolError> {
    let echoed = report_data_from_report(report)?;
    if &echoed != expected_report_data {
        return Err(ProtocolError::PqSigningUnavailable(
            "SNP report_data does not echo the requested key binding",
        ));
    }
    measurement_from_report(report)
}

// ---- boot-time capture + cache ----

struct CachedAttestation {
    measurement: [u8; SNP_MEASUREMENT_LEN],
    report: Vec<u8>,
    cert_chain: Vec<u8>,
}

/// One SNP report captured at enclave boot (bound to the installed PQ key).
static SNP_ATTESTATION: std::sync::Mutex<Option<CachedAttestation>> =
    std::sync::Mutex::new(None);

/// Boot hook: fetch the SNP report bound to `pq_pubkey` once and cache
/// `(measurement, report, cert_chain)`. Propagates the fetch error (e.g. interface absent) so the
/// caller can log + fall back.
pub fn boot_fetch_and_cache(pq_pubkey: &[u8]) -> Result<(), ProtocolError> {
    let (measurement, report, cert_chain) = fetch_measurement_and_report(pq_pubkey)?;
    let mut guard = SNP_ATTESTATION
        .lock()
        .map_err(|_| ProtocolError::PqSigningUnavailable("SNP attestation cache poisoned"))?;
    *guard = Some(CachedAttestation {
        measurement,
        report,
        cert_chain,
    });
    Ok(())
}

/// The boot-captured `(measurement, raw_report, cert_chain)`, if an SNP report was obtained at
/// startup. `cert_chain` may be empty when the provider did not populate `auxblob`.
pub fn cached_attestation() -> Option<SnpAttestation> {
    let guard = SNP_ATTESTATION.lock().ok()?;
    guard
        .as_ref()
        .map(|c| (c.measurement, c.report.clone(), c.cert_chain.clone()))
}

#[cfg(test)]
pub(crate) fn set_cached_attestation_for_tests(
    measurement: [u8; SNP_MEASUREMENT_LEN],
    report: Vec<u8>,
    cert_chain: Vec<u8>,
) {
    if let Ok(mut g) = SNP_ATTESTATION.lock() {
        *g = Some(CachedAttestation {
            measurement,
            report,
            cert_chain,
        });
    }
}

#[cfg(test)]
pub(crate) fn reset_cached_attestation_for_tests() {
    if let Ok(mut g) = SNP_ATTESTATION.lock() {
        *g = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real SNP ATTESTATION_REPORT captured on aya (EPYC 9375F, AMD OVMF; report version 5),
    // requested with report_data = 0x00..0x3f. See backlog/tasks/task-5 Phase 3 notes.
    const GOLDEN: &[u8] = include_bytes!("../testvectors/snp_report_golden_v5.bin");
    const GOLDEN_MEASUREMENT_HEX: &str = "3e39e33ab71f37ec9391fb285620dc5e50b67dd7cb59447726138596f9c502ed971ae0d095ea2ab3f93a8b8f6016b488";

    #[test]
    fn golden_report_shape() {
        assert_eq!(GOLDEN.len(), 1184);
        // version field (u32 LE) at offset 0x00 is 5 for this capture.
        assert_eq!(u32::from_le_bytes(GOLDEN[0..4].try_into().unwrap()), 5);
    }

    #[test]
    fn measurement_from_golden_report() {
        let m = measurement_from_report(GOLDEN).unwrap();
        assert_eq!(m.len(), SNP_MEASUREMENT_LEN);
        assert_eq!(hex::encode(m), GOLDEN_MEASUREMENT_HEX);
    }

    #[test]
    fn report_data_field_matches_capture_anchor() {
        // The capture embedded report_data = 0x00..0x3f at offset 0x50 — proves the offset.
        let rd = report_data_from_report(GOLDEN).unwrap();
        let expected: Vec<u8> = (0u8..64).collect();
        assert_eq!(rd.as_slice(), expected.as_slice());
    }

    #[test]
    fn measurement_rejects_short_report() {
        assert!(measurement_from_report(&[0u8; MEASUREMENT_OFFSET]).is_err());
        assert!(measurement_from_report(&[]).is_err());
        // Exactly long enough succeeds.
        assert!(measurement_from_report(&[0u8; MIN_REPORT_LEN]).is_ok());
    }

    #[test]
    fn verify_and_extract_accepts_matching_report_data() {
        let expected: [u8; REPORT_DATA_LEN] = (0u8..64).collect::<Vec<_>>().try_into().unwrap();
        let m = verify_and_extract_measurement(GOLDEN, &expected).unwrap();
        assert_eq!(hex::encode(m), GOLDEN_MEASUREMENT_HEX);
    }

    #[test]
    fn verify_and_extract_rejects_mismatched_report_data() {
        let wrong = [0xFFu8; REPORT_DATA_LEN];
        assert!(verify_and_extract_measurement(GOLDEN, &wrong).is_err());
    }

    #[test]
    fn report_data_binding_is_deterministic_64_bytes_and_key_specific() {
        let a = report_data_for_pubkey(b"producer-pubkey-bytes");
        let b = report_data_for_pubkey(b"producer-pubkey-bytes");
        assert_eq!(a, b);
        assert_eq!(a.len(), REPORT_DATA_LEN);
        assert_ne!(a, report_data_for_pubkey(b"a-different-pubkey"));
        // Domain separation: not a bare hash of the key.
        use sha3::{Digest, Sha3_512};
        let bare: [u8; 64] = Sha3_512::digest(b"producer-pubkey-bytes").into();
        assert_ne!(a, bare);
    }

    // ---- fetch orchestration + unconditional cleanup over the TsmFs seam (TASK-7.7 5b-2; no live configfs needed) ----

    use std::cell::RefCell;

    /// Records the ordered sequence of seam calls and is configurable per step.
    struct FakeTsmFs {
        create_ok: bool,
        write_err: bool,
        outblob_err: bool,
        outblob: Vec<u8>,
        auxblob: Vec<u8>,
        calls: RefCell<Vec<&'static str>>,
    }
    impl FakeTsmFs {
        fn ok() -> Self {
            Self {
                create_ok: true,
                write_err: false,
                outblob_err: false,
                outblob: vec![0xa5; MIN_REPORT_LEN],
                auxblob: vec![0xc7; 16],
                calls: RefCell::new(Vec::new()),
            }
        }
    }
    impl TsmFs for FakeTsmFs {
        fn remove_entry(&self, _entry: &str) {
            self.calls.borrow_mut().push("remove");
        }
        fn create_entry(&self, _entry: &str) -> Result<(), ProtocolError> {
            self.calls.borrow_mut().push("create");
            if self.create_ok {
                Ok(())
            } else {
                Err(ProtocolError::PqSigningUnavailable("fake create fail"))
            }
        }
        fn write_inblob(&self, _entry: &str, _data: &[u8; REPORT_DATA_LEN]) -> Result<(), ProtocolError> {
            self.calls.borrow_mut().push("write");
            if self.write_err {
                Err(ProtocolError::PqSigningUnavailable("fake write fail"))
            } else {
                Ok(())
            }
        }
        fn read_outblob(&self, _entry: &str) -> Result<Vec<u8>, ProtocolError> {
            self.calls.borrow_mut().push("outblob");
            if self.outblob_err {
                Err(ProtocolError::PqSigningUnavailable("fake outblob fail"))
            } else {
                Ok(self.outblob.clone())
            }
        }
        fn read_auxblob(&self, _entry: &str) -> Vec<u8> {
            self.calls.borrow_mut().push("aux");
            self.auxblob.clone()
        }
    }

    fn err_msg(r: Result<(Vec<u8>, Vec<u8>), ProtocolError>) -> &'static str {
        match r {
            Err(ProtocolError::PqSigningUnavailable(m)) => m,
            other => panic!("expected PqSigningUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn fetch_success_returns_report_and_auxblob_and_cleans_up() {
        let fs = FakeTsmFs::ok();
        let (report, aux) = fetch_report_with(&fs, &[1u8; REPORT_DATA_LEN]).unwrap();
        assert_eq!(report.len(), MIN_REPORT_LEN);
        assert_eq!(aux, vec![0xc7; 16]);
        // Pin the FULL orchestration sequence the doc promises (stale-clear → create → write → outblob
        // → aux → unconditional cleanup), not just the remove count. (This is also the producer path's
        // full-sequence pin — the once-separate None-deadline test became identical when (4a) deleted
        // the parameter.)
        assert_eq!(
            *fs.calls.borrow(),
            vec!["remove", "create", "write", "outblob", "aux", "remove"]
        );
    }

    #[test]
    fn fetch_cleans_up_on_create_failure() {
        let mut fs = FakeTsmFs::ok();
        fs.create_ok = false;
        assert!(fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN]).is_err());
        // create failed, but the unconditional cleanup still ran — exact sequence pins the path.
        assert_eq!(*fs.calls.borrow(), vec!["remove", "create", "remove"]);
    }

    #[test]
    fn fetch_cleans_up_on_write_failure() {
        // write_inblob errors mid-sequence: the unconditional cleanup still runs (trailing "remove"), and
        // outblob/aux are never reached. Pins the stale-entry-leak guard for the write leg too.
        let mut fs = FakeTsmFs::ok();
        fs.write_err = true;
        let r = fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN]);
        assert_eq!(err_msg(r), "fake write fail");
        assert_eq!(*fs.calls.borrow(), vec!["remove", "create", "write", "remove"]);
    }

    #[test]
    fn fetch_cleans_up_on_outblob_failure() {
        let mut fs = FakeTsmFs::ok();
        fs.outblob_err = true;
        assert!(fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN]).is_err());
        assert_eq!(*fs.calls.borrow(), vec!["remove", "create", "write", "outblob", "remove"]);
    }

    #[test]
    fn fetch_short_outblob_is_error_and_cleans_up() {
        let mut fs = FakeTsmFs::ok();
        fs.outblob = vec![0u8; MIN_REPORT_LEN - 1]; // one byte short of the ABI minimum
        let r = fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN]);
        assert_eq!(err_msg(r), "SNP attestation: outblob shorter than ABI minimum");
        assert_eq!(*fs.calls.borrow(), vec!["remove", "create", "write", "outblob", "remove"]);
    }

    /// (d-ii) quote-child naming/GC tests live HERE (not in the triple-gated quote_subprocess) so the
    /// items they exercise are test-used in EVERY agent-gateway combo — no dead-code warnings in the
    /// agent-gateway-only CI lanes.
    #[cfg(feature = "agent-gateway")]
    mod quote_child_naming {
        use super::super::*;

        #[test]
        fn quote_entry_prefix_can_never_match_the_producer_entry() {
            // STRUCTURAL pin of the §8 "GC can never remove the producer entry" rule (prose + a
            // stale-literal test would survive a rename; this fails the moment the relation breaks).
            assert!(
                !TSM_ENTRY_NAME.starts_with(TSM_QUOTE_ENTRY_PREFIX),
                "the fixed producer entry name must never match the quote-child GC prefix"
            );
            assert!(
                TSM_QUOTE_ENTRY_PREFIX.len() > TSM_ENTRY_NAME.len(),
                "prefix strictly longer than the bare producer name (the documented invariant)"
            );
        }

        #[test]
        fn quote_child_entry_path_is_prefixed_own_pid() {
            let path = quote_child_entry_path();
            assert_eq!(
                path,
                format!("{TSM_REPORT_DIR}/{TSM_QUOTE_ENTRY_PREFIX}{}", std::process::id()),
                "self-named path = report dir + prefix + OWN pid"
            );
        }

        #[test]
        fn gc_removes_prefix_only_spares_fixed_name() {
            // Regression: GC nuking the fixed producer entry (GET_MEASUREMENT breakage) or unrelated
            // names. Spares the REAL const (not a transcribed literal).
            let dir = tempfile::tempdir().unwrap();
            for name in ["twod-hsm-q-123", "twod-hsm-q-99999", TSM_ENTRY_NAME, "unrelated"] {
                std::fs::create_dir(dir.path().join(name)).unwrap();
            }
            gc_quote_entries_best_effort(dir.path());
            assert!(!dir.path().join("twod-hsm-q-123").exists(), "prefixed orphan removed");
            assert!(!dir.path().join("twod-hsm-q-99999").exists(), "prefixed orphan removed");
            assert!(dir.path().join(TSM_ENTRY_NAME).exists(), "the FIXED producer entry is spared");
            assert!(dir.path().join("unrelated").exists(), "unrelated names spared");
        }

        #[test]
        fn gc_tolerates_unremovable_and_absent_dir() {
            // Regression: GC failure gating the boot attempt — a held (EBUSY-class) entry and an
            // absent dir must both be silent no-ops.
            let dir = tempfile::tempdir().unwrap();
            let held = dir.path().join("twod-hsm-q-7");
            std::fs::create_dir(&held).unwrap();
            std::fs::write(held.join("inner"), b"x").unwrap(); // non-empty => remove_dir fails
            gc_quote_entries_best_effort(dir.path()); // must not panic/Err
            assert!(held.exists(), "unremovable entry skipped, not an error");
            gc_quote_entries_best_effort(std::path::Path::new("/nonexistent/2d-hsm-gc-test"));
        }
    }
}
