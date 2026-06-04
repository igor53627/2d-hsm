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

jq -n \
  --arg schema_version "1" \
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
        protocol_measurement_label: $prod_protocol_measurement
      },
      staging: {
        path: "bin/enclave-vsock-staging",
        sha256: $staging_artifact_sha256,
        protocol_measurement_label: $staging_protocol_measurement
      }
    },
    fork_spec_hash_input: {
      enclave_prod_sha256: $prod_artifact_sha256,
      git_revision: $git_revision,
      flake_lock: $flake_lock
    }
  }' >"$OUT"