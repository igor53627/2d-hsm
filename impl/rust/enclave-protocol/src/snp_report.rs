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
/// Fixed configfs entry name for this enclave's one boot-time report.
const TSM_ENTRY_NAME: &str = "twod-hsm";
/// Domain separation for the `report_data` binding (so it is not a bare key hash).
const REPORT_DATA_DOMAIN: &[u8] = b"2d-hsm-snp-report-data-v1";

/// Upper bound on the configfs-tsm `auxblob` (VCEK→ASK→ARK chain) we will carry in
/// GET_MEASUREMENT. A real chain is a few KB; this is generous headroom while staying well under
/// `MAX_MESSAGE_SIZE` once the report + pq_pubkey are added.
// `pub(crate)` so the agent boot-relay request encoder (TASK-7.7 5b-2) bounds its outbound cert_chain
// against the single source of truth rather than re-declaring 64 KiB.
pub(crate) const MAX_CERT_CHAIN_LEN: usize = 64 * 1024;

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

/// The configfs-tsm filesystem operations, behind a seam so the deadline + cleanup orchestration in
/// [`fetch_report_with`] is unit-testable WITHOUT a live `/sys/kernel/config/tsm` (the cleanup-on-timeout
/// invariant — entry removed even when the deadline fires mid-sequence — is the defect-prone part and the
/// only one that leaks a stale configfs entry if wrong). [`RealTsmFs`] is the ONLY configfs-touching code.
pub(crate) trait TsmFs {
    /// Best-effort remove (== `fs::remove_dir`, ignore error) — used to clear a stale entry and to clean up.
    fn remove_entry(&self, entry: &str);
    fn create_entry(&self, entry: &str) -> Result<(), ProtocolError>;
    fn write_inblob(&self, entry: &str, data: &[u8; REPORT_DATA_LEN]) -> Result<(), ProtocolError>;
    fn read_outblob(&self, entry: &str) -> Result<Vec<u8>, ProtocolError>;
    /// Best-effort: returns the `auxblob` cert chain, or empty on absence/unreadable/oversize.
    fn read_auxblob(&self, entry: &str) -> Vec<u8>;
}

/// The real configfs-tsm implementation (the only code that touches `/sys/kernel/config/tsm`). Methods
/// are lifted verbatim from the previous `fetch_report`/`fetch_report_inner`; safe file I/O (no ioctl,
/// no unsafe). Exercised live only on an SNP guest (aya); compiles + returns interface-absent errors
/// everywhere else.
struct RealTsmFs;
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
            return Err(ProtocolError::PqSigningUnavailable(
                "SNP attestation: outblob exceeds max size",
            ));
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

/// `None` deadline ⇒ unbounded (no check) — the producer `fetch_report` path keeps its historical
/// unbounded contract. `Some(d)` ⇒ the agent boot-relay path bounds the *gaps* between fs ops.
fn check_deadline(deadline: Option<std::time::Instant>) -> Result<(), ProtocolError> {
    if let Some(d) = deadline {
        if std::time::Instant::now() >= d {
            return Err(ProtocolError::PqSigningUnavailable("SNP quote fetch deadline exceeded"));
        }
    }
    Ok(())
}

/// SNP quote fetch over a [`TsmFs`] seam, optionally deadline-bounded. With `Some(deadline)`: fast-paths
/// a past deadline (no fs touched) and checks the deadline between each configfs step. With `None`: fully
/// unbounded (the producer path's historical behavior — preserved so this slice does NOT change
/// GET_MEASUREMENT). On **every** path it **unconditionally cleans up** the entry — the cleanup is the
/// last statement, so an error or mid-sequence timeout still leaves no stale `twod-hsm` entry. Per-step
/// checks bound the *gaps* between fs ops; a single in-kernel `read(outblob)` that blocks forever is not
/// interruptible under `#![forbid(unsafe_code)]` (a hard bound needs a *cancellable boundary* — the
/// **killable subprocess**, the only sanctioned option per the revised §8 pin ("kernel timeout" was
/// eliminated: configfs-tsm offers none; a plain worker thread can only abandon a stuck reader) — the
/// harness LANDED in 5b-2b-ii(d-i) — `quote_subprocess` — with the configfs child
/// mode following in (d-ii); the stale-clear covers the leak meanwhile).
pub(crate) fn fetch_report_with<F: TsmFs>(
    fs: &F,
    report_data: &[u8; REPORT_DATA_LEN],
    deadline: Option<std::time::Instant>,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    // Distinct from the per-step `check_deadline` in the inner fn: this outer guard fires BEFORE the
    // stale-clear `remove_entry`, so an already-past deadline touches NO fs at all (the "fast path",
    // pinned by `fetch_past_deadline_fast_path_touches_no_fs`). The inner checks then bound the gaps
    // between ops. Different message ("already past" vs "exceeded") to localize which guard tripped.
    if let Some(d) = deadline {
        if std::time::Instant::now() >= d {
            return Err(ProtocolError::PqSigningUnavailable("SNP quote fetch deadline already past"));
        }
    }
    let entry = format!("{TSM_REPORT_DIR}/{TSM_ENTRY_NAME}");
    fetch_report_with_at(fs, &entry, report_data, deadline)
}

/// Entry-path-parameterized core of [`fetch_report_with`] (refactor-only split for 5b-2b-ii(d): the
/// killable quote CHILD fetches at its own unique self-named `twod-hsm-q-<pid>` path — (d-ii) — while the
/// producer path keeps the fixed name above; FakeTsmFs ignores entry strings, so the existing sequence
/// tests pin this split moved nothing). Body unchanged: stale-clear → inner sequence → UNCONDITIONAL
/// trailing cleanup on every path (incl. timeout). **NB: the past-deadline "touches NO fs" fast-path
/// stays in the WRAPPER above** — a direct `_at` caller with an already-lapsed `Some(deadline)` still
/// performs the stale-clear `remove_entry` before the first in-sequence check (recorded narrowing; moot
/// in practice: the (d-ii) child calls with `None`/unbounded, and the cooperative `Option<Instant>`
/// plumbing is deletion-approved — any future deadline-bearing direct caller must add its own
/// fast-path).
fn fetch_report_with_at<F: TsmFs>(
    fs: &F,
    entry_path: &str,
    report_data: &[u8; REPORT_DATA_LEN],
    deadline: Option<std::time::Instant>,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    fs.remove_entry(entry_path); // clear any stale entry from a previous crashed boot
    let result = fetch_report_inner_with(fs, entry_path, report_data, deadline);
    fs.remove_entry(entry_path); // UNCONDITIONAL cleanup — last statement on every path (incl. timeout)
    result
}

fn fetch_report_inner_with<F: TsmFs>(
    fs: &F,
    entry: &str,
    report_data: &[u8; REPORT_DATA_LEN],
    deadline: Option<std::time::Instant>,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    check_deadline(deadline)?;
    fs.create_entry(entry)?;
    check_deadline(deadline)?;
    fs.write_inblob(entry, report_data)?;
    check_deadline(deadline)?;
    let report = fs.read_outblob(entry)?;
    if report.len() < MIN_REPORT_LEN {
        return Err(ProtocolError::PqSigningUnavailable(
            "SNP attestation: outblob shorter than ABI minimum",
        ));
    }
    check_deadline(deadline)?;
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
/// **Unbounded** (deadline `None`) — this is the producer GET_MEASUREMENT path and keeps its historical
/// no-timeout contract unchanged (refactor-only over [`fetch_report_with`]); the deadline-bounded variant
/// for the agent boot relay is [`fetch_report_deadline`], so a wall-clock bound is never silently imposed
/// on the unrelated producer measurement.
pub fn fetch_report(report_data: &[u8; REPORT_DATA_LEN]) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    fetch_report_with(&RealTsmFs, report_data, None)
}

/// Like [`fetch_report`] but bounded by a caller-supplied absolute `deadline` — the entrypoint the agent
/// boot-relay quote producer (TASK-7.7 5b-2) calls so the seam's deadline contract is honored.
///
/// **`pub(crate)` + `agent-gateway`-gated deliberately** (its only caller is
/// `agent_boot_relay::SnpQuoteProducer::fetch`, itself `agent-gateway`-only): the deadline here is
/// best-effort/cooperative — it does NOT hard-bound a wedged in-kernel `read(outblob)` until 5b-2b-ii lands
/// a cancellable boundary — so this MUST NOT be wired into a live serve/boot path from outside the crate.
/// Crate-private visibility *type-enforces* that obligation (the doc'd "must not wire externally" is now a
/// compile error, not just prose); the feature gate keeps it from being dead code in the non-agent builds.
/// The unbounded producer [`fetch_report`] stays `pub` — the legitimate GET_MEASUREMENT path with no
/// wall-clock contract to violate.
#[cfg(feature = "agent-gateway")]
pub(crate) fn fetch_report_deadline(
    report_data: &[u8; REPORT_DATA_LEN],
    deadline: std::time::Instant,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    fetch_report_with(&RealTsmFs, report_data, Some(deadline))
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

    // ---- deadline-aware fetch over the TsmFs seam (TASK-7.7 5b-2; no live configfs needed) ----

    use std::cell::RefCell;
    use std::time::{Duration, Instant};

    fn past() -> Instant {
        // Direct subtraction: on any real monotonic clock `now()` is far past the `Instant` epoch, so this
        // never overflows — and unlike `checked_sub(..).unwrap_or_else(Instant::now)` it can never silently
        // yield a NON-past instant that turns a fast-path test into a fluke (greptile P2).
        Instant::now() - Duration::from_secs(1)
    }
    fn future() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// Records the ordered sequence of seam calls and is configurable per step.
    struct FakeTsmFs {
        create_ok: bool,
        write_err: bool,
        outblob_err: bool,
        outblob: Vec<u8>,
        auxblob: Vec<u8>,
        /// If set, `create_entry` busy-waits until `now >= this` before returning — lets a test make the
        /// deadline lapse *mid-sequence* (after create) deterministically, so the post-create
        /// `check_deadline` fires and the unconditional cleanup is exercised on the timeout path.
        create_spin_until: Option<Instant>,
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
                create_spin_until: None,
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
            if let Some(t) = self.create_spin_until {
                // Sleep (don't burn a core) until the deadline is crossed, so the post-create check trips
                // deterministically. The caller's generous margin dwarfs any plausible scheduler preemption
                // between computing the deadline and the outer fast-path check, so the mid-sequence path is
                // hit reliably even on a loaded CI box.
                let now = Instant::now();
                if now < t {
                    std::thread::sleep(t - now);
                }
            }
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
    fn fetch_past_deadline_fast_path_touches_no_fs() {
        let fs = FakeTsmFs::ok();
        let r = fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN], Some(past()));
        assert_eq!(err_msg(r), "SNP quote fetch deadline already past");
        assert!(fs.calls.borrow().is_empty(), "no fs op when the deadline is already past");
    }

    #[test]
    fn fetch_success_returns_report_and_auxblob_and_cleans_up() {
        let fs = FakeTsmFs::ok();
        let (report, aux) = fetch_report_with(&fs, &[1u8; REPORT_DATA_LEN], Some(future())).unwrap();
        assert_eq!(report.len(), MIN_REPORT_LEN);
        assert_eq!(aux, vec![0xc7; 16]);
        // Pin the FULL orchestration sequence the doc promises (stale-clear → create → write → outblob
        // → aux → unconditional cleanup), not just the remove count.
        assert_eq!(
            *fs.calls.borrow(),
            vec!["remove", "create", "write", "outblob", "aux", "remove"]
        );
    }

    #[test]
    fn fetch_unbounded_none_deadline_runs_full_sequence() {
        // The producer path (deadline None): no fast-path, no per-step checks, full success sequence —
        // proves `fetch_report`'s historical unbounded contract is preserved.
        let fs = FakeTsmFs::ok();
        assert!(fetch_report_with(&fs, &[2u8; REPORT_DATA_LEN], None).is_ok());
        assert_eq!(
            *fs.calls.borrow(),
            vec!["remove", "create", "write", "outblob", "aux", "remove"]
        );
    }

    #[test]
    fn fetch_cleans_up_on_create_failure() {
        let mut fs = FakeTsmFs::ok();
        fs.create_ok = false;
        assert!(fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN], Some(future())).is_err());
        // create failed, but the unconditional cleanup still ran — exact sequence pins the path.
        assert_eq!(*fs.calls.borrow(), vec!["remove", "create", "remove"]);
    }

    #[test]
    fn fetch_cleans_up_on_write_failure() {
        // write_inblob errors mid-sequence: the unconditional cleanup still runs (trailing "remove"), and
        // outblob/aux are never reached. Pins the stale-entry-leak guard for the write leg too.
        let mut fs = FakeTsmFs::ok();
        fs.write_err = true;
        let r = fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN], Some(future()));
        assert_eq!(err_msg(r), "fake write fail");
        assert_eq!(*fs.calls.borrow(), vec!["remove", "create", "write", "remove"]);
    }

    #[test]
    fn fetch_cleans_up_on_outblob_failure() {
        let mut fs = FakeTsmFs::ok();
        fs.outblob_err = true;
        assert!(fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN], Some(future())).is_err());
        assert_eq!(*fs.calls.borrow(), vec!["remove", "create", "write", "outblob", "remove"]);
    }

    #[test]
    fn fetch_short_outblob_is_error_and_cleans_up() {
        let mut fs = FakeTsmFs::ok();
        fs.outblob = vec![0u8; MIN_REPORT_LEN - 1]; // one byte short of the ABI minimum
        let r = fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN], Some(future()));
        assert_eq!(err_msg(r), "SNP attestation: outblob shorter than ABI minimum");
        assert_eq!(*fs.calls.borrow(), vec!["remove", "create", "write", "outblob", "remove"]);
    }

    #[test]
    fn fetch_cleans_up_on_mid_sequence_deadline_timeout() {
        // Deadline is in the future at the outer fast-path check (so create runs), but `create_entry`
        // busy-waits across it, so the post-create `check_deadline` fires: this exercises the cleanup on a
        // deadline-lapse *between* fs ops (not just an op-error path). The trailing "remove" proves no
        // stale entry leaks even when the timeout lands mid-sequence; write/outblob/aux never run.
        let mut fs = FakeTsmFs::ok();
        let dl = Instant::now() + Duration::from_millis(50);
        fs.create_spin_until = Some(dl);
        let r = fetch_report_with(&fs, &[0u8; REPORT_DATA_LEN], Some(dl));
        assert_eq!(err_msg(r), "SNP quote fetch deadline exceeded");
        assert_eq!(*fs.calls.borrow(), vec!["remove", "create", "remove"]);
    }

    #[test]
    fn check_deadline_past_err_future_ok_none_ok() {
        assert!(check_deadline(Some(past())).is_err());
        assert!(check_deadline(Some(future())).is_ok());
        assert!(check_deadline(None).is_ok(), "None is unbounded — never errors");
    }
}
