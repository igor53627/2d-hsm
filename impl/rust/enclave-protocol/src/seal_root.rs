//! Shared platform **provisioning root** for sealed state (TASK-5 producer seal + TASK-7.6 Agent
//! Gateway keystore).
//!
//! The provisioning root is the platform-derived secret (vTPM / SNP VMPL / Nitro hook) installed
//! **once** at enclave boot. It is never accepted from the untrusted host over vsock.
//!
//! Both sealed-state consumers derive their AEAD keys from this one root via **distinct,
//! domain-separated KDFs** — the producer `pq-seal-v1` (ChaCha20Poly1305, label `2d-hsm-pq-seal-v1-key`)
//! and the Agent Gateway `pq-agent-keystore-v1` (XChaCha20Poly1305, label `2d-hsm-agent-keystore-v1-key`).
//! Sharing the *root mechanism* therefore does NOT weaken producer↔agent key isolation: the
//! `ml-dsa-65 ⊥ agent-gateway` compile-time ban is about not shipping both *signing backends* in one
//! binary, not about the platform root (which is a single platform-level secret either way).
//!
//! This module is **always compiled** so the producer (`ml-dsa-65`) and the agent (`agent-gateway`)
//! profiles share exactly one root global, setter, and resolver.

use crate::ProtocolError;
use std::sync::Mutex;

/// Runtime provisioning root from platform integration. Set once at enclave boot before installing a
/// sealed signer / keystore (unless the `reference-seal-v1-root` / `cfg(test)` fallback is used).
static PLATFORM_PROVISIONING_ROOT: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// Install the v1 provisioning root once at enclave boot (production path).
///
/// The root must match the secret the offline provisioning tool used to produce the sealed blob. Do
/// **not** accept this value from the untrusted host over vsock. Install-once: a second call errors.
pub fn set_pq_seal_v1_provisioning_root(root: [u8; 32]) -> Result<(), ProtocolError> {
    let mut guard = PLATFORM_PROVISIONING_ROOT
        .lock()
        .map_err(|_| ProtocolError::PqSigningUnavailable("pq seal platform root mutex poisoned"))?;
    if guard.is_some() {
        return Err(ProtocolError::PqSigningUnavailable(
            "PQ seal v1 provisioning root already configured",
        ));
    }
    *guard = Some(root);
    Ok(())
}

// Used by the producer (ml-dsa-65) tests; dead under an agent-gateway-only test build.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_pq_seal_v1_provisioning_root_for_tests() {
    if let Ok(mut guard) = PLATFORM_PROVISIONING_ROOT.lock() {
        *guard = None;
    }
}

/// Whether the platform boot hook installed a provisioning root (not the CI/test fallback).
pub fn is_platform_pq_seal_v1_provisioning_root_set() -> bool {
    PLATFORM_PROVISIONING_ROOT
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|_| ()))
        .is_some()
}

/// Whether unseal can resolve a provisioning root (platform, `reference-seal-v1-root`, or `cfg(test)`).
/// Presence-only — does not materialize the secret root (mirrors [`resolve_provisioning_root`]'s logic).
pub fn is_pq_seal_v1_provisioning_root_configured() -> bool {
    is_platform_pq_seal_v1_provisioning_root_set()
        || cfg!(any(test, feature = "reference-seal-v1-root"))
}

/// Resolve the provisioning root into a `Zeroizing` so every *transient* caller copy is scrubbed on
/// drop. (The process-lifetime copy in [`PLATFORM_PROVISIONING_ROOT`] is NOT scrubbed during
/// operation — that needs mlock / no-core-dump, orthogonal to zeroize.)
// The returns are cfg-conditional (platform / reference-seal / not-configured), so the explicit
// `return`s are needed under some feature combos even where clippy sees the last one as redundant.
#[allow(clippy::needless_return)]
pub(crate) fn resolve_provisioning_root() -> Result<zeroize::Zeroizing<[u8; 32]>, ProtocolError> {
    let guard = PLATFORM_PROVISIONING_ROOT
        .lock()
        .map_err(|_| ProtocolError::PqSigningUnavailable("pq seal platform root mutex poisoned"))?;
    // copy_from_slice into a pre-zeroed Zeroizing buffer so the secret is never materialized as a
    // bare `[u8;32]` Copy temporary on the stack (which has no Drop and would not be scrubbed).
    if let Some(root) = guard.as_ref() {
        let mut out = zeroize::Zeroizing::new([0u8; 32]);
        out.copy_from_slice(root);
        return Ok(out);
    }
    drop(guard);
    #[cfg(any(test, feature = "reference-seal-v1-root"))]
    {
        // The `&[u8; 32]` annotation keeps the fixture-length check at COMPILE time (a malformed
        // fixture fails the build) instead of a runtime panic in copy_from_slice.
        let reference_root: &[u8; 32] =
            include_bytes!("../testvectors/seal_v1_provisioning_root.bin");
        let mut out = zeroize::Zeroizing::new([0u8; 32]);
        out.copy_from_slice(reference_root);
        return Ok(out);
    }
    #[cfg(not(any(test, feature = "reference-seal-v1-root")))]
    {
        Err(ProtocolError::PqSigningUnavailable(
            "PQ seal v1 provisioning root not configured (call set_pq_seal_v1_provisioning_root at enclave boot)",
        ))
    }
}
