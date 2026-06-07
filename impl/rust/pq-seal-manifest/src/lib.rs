//! Multi-host pq-seal v1 manifest: a set of host-specific sealed producer-key blobs, each AEAD-bound
//! to one host's 32-byte provisioning root (derived per-chip by `snp-derive-root`). At boot the
//! selector computes a commitment to its own derived root and picks the matching blob; the blob's
//! AEAD tag re-authenticates on unseal, so the manifest itself need NOT be trusted — a wrong or
//! tampered entry simply fails to unseal (fail-closed).
//!
//! Why a commitment and not the root: the root is secret. `root_commitment` is a one-way SHA3-256
//! over a 256-bit key — safe to publish — and lets selection be O(1) and diagnosable ("host not
//! provisioned") instead of N blind unseal attempts. Selection is trustless because the commitment
//! is computed from the caller's OWN derived root, never from a host-supplied value.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Domain for the per-host root commitment. Distinct from `snp-derive-root`'s root-DERIVATION domain
/// (`2d-hsm-pq-seal-v1-root`) so the published commitment can never collide with a derivation input.
const COMMITMENT_DOMAIN: &[u8] = b"2d-hsm-pq-seal-manifest-commitment-v1";
/// Current manifest schema version.
pub const MANIFEST_VERSION: u32 = 1;
/// Canonical manifest filename (placed alongside the `blobs/` directory it references).
pub const MANIFEST_FILENAME: &str = "pq-seal-manifest.json";

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest version {0} unsupported (expected {MANIFEST_VERSION})")]
    Version(u32),
    #[error("no manifest entry matches this host's provisioning root (host not provisioned)")]
    NoMatch,
    #[error("{0} manifest entries match this host's root (expected exactly 1)")]
    Ambiguous(usize),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// `SHA3-256(domain ‖ root)` — a publishable one-way commitment to a host's 32-byte provisioning
/// root. Used as the selection key in the manifest.
pub fn root_commitment(root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(COMMITMENT_DOMAIN);
    h.update(root);
    h.finalize().into()
}

/// One host's sealed-blob entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Human-readable label (hostname / chip_id). **Advisory only** — operator/diagnostics; it is
    /// NEVER used to select a blob (that would let the untrusted host steer selection).
    pub label: String,
    /// Hex `SHA3-256` commitment to this host's provisioning root (see [`root_commitment`]).
    pub root_commitment: String,
    /// Path to the sealed blob, relative to the manifest file's directory.
    pub blob: String,
}

/// The manifest: one entry per provisioned host, all sealing the same producer key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    /// Hex of the launch measurement the blobs were sealed against. **Advisory** — the unseal step
    /// re-checks the measurement via the blob's AAD; this field is for operator sanity only.
    pub measurement: String,
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// Parse + version-check a manifest from JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        let m: Manifest = serde_json::from_slice(bytes)?;
        if m.version != MANIFEST_VERSION {
            return Err(ManifestError::Version(m.version));
        }
        Ok(m)
    }

    /// Serialize as pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String, ManifestError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Select the entry whose `root_commitment` matches this host's derived root. Trustless: the
    /// commitment is recomputed here from the caller's own secret `root`. Errors if no entry matches
    /// (host not provisioned) or — defensively — if more than one does.
    pub fn select(&self, root: &[u8; 32]) -> Result<&Entry, ManifestError> {
        let want = hex::encode(root_commitment(root));
        let mut matches = self
            .entries
            .iter()
            .filter(|e| e.root_commitment.eq_ignore_ascii_case(&want));
        let first = matches.next().ok_or(ManifestError::NoMatch)?;
        match matches.count() {
            0 => Ok(first),
            extra => Err(ManifestError::Ambiguous(extra + 1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn commitment_is_deterministic_and_domain_separated() {
        let r = root(7);
        assert_eq!(root_commitment(&r), root_commitment(&r));
        // Different root → different commitment.
        assert_ne!(root_commitment(&r), root_commitment(&root(8)));
        // Domain-separated: not a bare SHA3-256(root).
        let bare: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(r);
            h.finalize().into()
        };
        assert_ne!(root_commitment(&r), bare);
    }

    fn manifest_of(roots: &[(&str, [u8; 32])]) -> Manifest {
        Manifest {
            version: MANIFEST_VERSION,
            measurement: "abcd".into(),
            entries: roots
                .iter()
                .map(|(label, r)| Entry {
                    label: (*label).into(),
                    root_commitment: hex::encode(root_commitment(r)),
                    blob: format!("blobs/{label}.sealed"),
                })
                .collect(),
        }
    }

    #[test]
    fn select_picks_the_matching_host() {
        let m = manifest_of(&[("aya", root(1)), ("host2", root(2))]);
        assert_eq!(m.select(&root(1)).unwrap().label, "aya");
        assert_eq!(m.select(&root(2)).unwrap().label, "host2");
    }

    #[test]
    fn select_rejects_unprovisioned_host() {
        let m = manifest_of(&[("aya", root(1))]);
        assert!(matches!(m.select(&root(99)), Err(ManifestError::NoMatch)));
    }

    #[test]
    fn select_rejects_ambiguous_manifest() {
        // Two entries with the same commitment (malformed) → refuse rather than pick one.
        let m = manifest_of(&[("a", root(1)), ("b", root(1))]);
        assert!(matches!(
            m.select(&root(1)),
            Err(ManifestError::Ambiguous(2))
        ));
    }

    #[test]
    fn json_round_trip_and_version_check() {
        let m = manifest_of(&[("aya", root(1))]);
        let json = m.to_json_pretty().unwrap();
        let back = Manifest::from_json(json.as_bytes()).unwrap();
        assert_eq!(back.entries[0].label, "aya");
        // Wrong version rejected.
        let bad = json.replace("\"version\": 1", "\"version\": 2");
        assert!(matches!(
            Manifest::from_json(bad.as_bytes()),
            Err(ManifestError::Version(2))
        ));
    }
}
