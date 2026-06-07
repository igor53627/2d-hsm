# pq-seal-manifest

Shared format + per-host blob selection for **multi-host pq-seal v1** (TASK-1.1).

The pq-seal v1 provisioning root is derived **per chip** (`snp-derive-root`, bound to the launch
measurement), so one image on N hosts yields N different roots. To run a single producer key across an
HA fleet, the same key is sealed **once per host** and the resulting blobs are shipped in a manifest;
each host selects its own at boot.

This crate is the single source of truth for:

- `Manifest` / `Entry` — the JSON schema (`pq-seal-manifest.json`).
- `root_commitment(root) = SHA3-256(domain ‖ root)` — a publishable one-way commitment to a host's
  32-byte provisioning root (domain-separated from `snp-derive-root`'s derivation domain).
- `Manifest::select(root)` — pick the entry whose commitment matches **this host's own derived root**.

## Trust model

Selection is **trustless**: the commitment is recomputed from the caller's own secret root, never from
a host-supplied value. The manifest and blobs themselves need not be trusted — each blob is AEAD-bound
to `(root, measurement)`, so a wrong/tampered/missing entry simply fails to unseal (**fail-closed**).
The `label` field is advisory (operator/diagnostics) and is never used for selection.

## Consumers

- `pq-seal-v1 manifest build` — the offline ceremony: seal the producer key per host root, emit the
  manifest + `blobs/<label>.sealed`. See `backlog/docs/pq-seal-v1-provisioning-runbook.md` §7.2.
- The boot-time selector (next slice) — derives the root, calls `select`, places the chosen blob where
  the enclave already reads it. The enclave (`#![forbid(unsafe_code)]`) is unchanged.
