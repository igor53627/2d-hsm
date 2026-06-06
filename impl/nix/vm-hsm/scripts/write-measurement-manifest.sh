#!/usr/bin/env bash
# Write TASK-4 measurement manifest JSON. Invoked from the Nix measurement-manifest derivation.
set -euo pipefail

OUT="${1:?usage: write-measurement-manifest.sh <out.json> <prod-bin> <staging-bin>}"
PROD="${2:?}"
STAGING="${3:?}"

GIT_REVISION="${GIT_REVISION:-unknown}"
FLAKE_LOCK="${FLAKE_LOCK:-unknown}"
ENCLAVE_DRV="${ENCLAVE_DRV:-unknown}"
ENCLAVE_STAGING_DRV="${ENCLAVE_STAGING_DRV:-unknown}"

PROD_SHA="$(sha256sum "$PROD" | awk '{print $1}')"
STAGING_SHA="$(sha256sum "$STAGING" | awk '{print $1}')"

# Two distinct identities — kept separate on purpose (TASK-5 AC#4):
#
#   1. BUILD identity (this manifest): reproducible artifact sha256 + git + flake_lock.
#      `fork_spec_hash_input` binds it; `protocol_measurement_label` is the *software*
#      label the enclave advertises absent SNP (matches boot_lab_pq_seal::LAB_PROD_MEASUREMENT
#      / the staging reference) — NOT a TEE measurement.
#
#   2. TEE measurement (runtime, `tee_measurement` block below): the SEV-SNP launch
#      measurement returned live by GET_MEASUREMENT. It is NOT a build output and is NOT
#      emitted here — it anchors the OVMF launch firmware + SNP launch config, not the guest
#      image/binary (kernel loads AFTER the measurement). Empirically the NixOS prod guest
#      and the staging guest yield the SAME launch measurement under the same OVMF, which is
#      why it cannot stand in for build identity. The PQ key is bound separately via
#      report_data = SHA3-512("2d-hsm-snp-report-data-v1" || pq_pubkey).
#
# Do NOT whitelist an on-chain producer from this manifest's labels — consume the
# live-attested measurement + report_data + VCEK cert-chain through the verifier policy.
jq -n \
  --arg schema_version "2" \
  --arg git_revision "$GIT_REVISION" \
  --arg flake_lock "$FLAKE_LOCK" \
  --arg protocol_version "vsock-v0.2" \
  --arg enclave_derivation "$ENCLAVE_DRV" \
  --arg enclave_staging_derivation "$ENCLAVE_STAGING_DRV" \
  --arg prod_artifact_sha256 "$PROD_SHA" \
  --arg staging_artifact_sha256 "$STAGING_SHA" \
  --arg prod_protocol_measurement "enclave-measurement-placeholder" \
  --arg staging_protocol_measurement "prod-enclave-v1" \
  '{
    schema_version: $schema_version,
    git_revision: $git_revision,
    flake_lock: $flake_lock,
    protocol_version: $protocol_version,
    enclave_derivation: $enclave_derivation,
    enclave_staging_derivation: $enclave_staging_derivation,
    artifacts: {
      production: {
        path: "bin/enclave-vsock",
        sha256: $prod_artifact_sha256,
        protocol_measurement_label: $prod_protocol_measurement,
        label_kind: "software-protocol-label (NOT a TEE measurement)"
      },
      staging: {
        path: "bin/enclave-vsock-staging",
        sha256: $staging_artifact_sha256,
        protocol_measurement_label: $staging_protocol_measurement,
        label_kind: "software-protocol-label (NOT a TEE measurement)"
      }
    },
    fork_spec_hash_input: {
      enclave_prod_sha256: $prod_artifact_sha256,
      git_revision: $git_revision,
      flake_lock: $flake_lock
    },
    tee_measurement: {
      kind: "sev-snp-launch-measurement",
      length_bytes: 48,
      source: "runtime GET_MEASUREMENT (CBOR key 2) under SEV-SNP; NOT a build output, not emitted in this manifest",
      anchors: "AMD SEV-SNP platform + the launch firmware (OVMF) and SNP launch config (memory, vCPUs, policy)",
      does_not_anchor: "the guest disk image / enclave binary / kernel — they load after the launch measurement; bind those via artifacts.*.sha256 (build identity) + report_data (key binding), not via this measurement",
      key_binding: "report_data (SNP report offset 0x50, 64 bytes) = SHA3-512(\"2d-hsm-snp-report-data-v1\" || pq_pubkey)",
      expected_value: "OVMF-dependent — not derivable from this flake build; see verifier policy / runbook for the captured allowlist value and provenance",
      on_chain_whitelist: "consume the live-attested measurement + report_data + VCEK cert-chain via the verifier policy, NOT protocol_measurement_label"
    }
  }' >"$OUT"