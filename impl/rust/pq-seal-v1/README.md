# pq-seal-v1 — offline ML-DSA-65 seal provisioning

Command-line tool to create and verify **seal v1** blobs for the 2d-hsm TEE signing service. Normative crypto layout: `backlog/docs/vsock-api-wire-format-spec-draft.md` §2.1.

**Operator runbook (staging):** `backlog/docs/pq-seal-v1-provisioning-runbook.md`

## Where to run

| OK | Not OK |
|----|--------|
| Trusted provisioning workstation (air-gapped or HSM room) | Untrusted Nitro / SEV **parent** that launches the enclave |
| CI job with locked secrets for **staging only** | Production deploy artifact with `reference-seal-v1-root` baked in |

The tool handles **long-term Block Producer ML-DSA-65 secret keys**. Treat outputs and key files as **critical secrets**.

## Build

```bash
cd impl/rust/pq-seal-v1
cargo build --release
# binary: target/release/pq-seal-v1
```

## Wire constants

| Item | Size / value |
|------|----------------|
| ML-DSA-65 secret key file | **4032** bytes |
| ML-DSA-65 public key file | **1952** bytes |
| Provisioning root | **32** bytes (`--provisioning-root-file` only) |
| Sealed blob v1 (output) | **6053** bytes (`2DHSMV1\0` magic) |
| Measurement | Non-empty opaque bytes (launch `measurement` / PCR policy — same bytes enclave passes to `install_sealed_pq_signer`) |

Measurement digest in the blob (for logs / attestation checks):

`meas_digest = SHA3-256("2d-hsm-pq-seal-v1-meas" ‖ measurement)` — use subcommand `meas-digest`.

## Subcommands

### `generate-keypair`

Create a fresh ML-DSA-65 keypair on disk (provisioning ceremony step 1).

```bash
pq-seal-v1 generate-keypair \
  --secret-key-out /secure/producer.sk.bin \
  --public-key-out /secure/producer.pk.bin
```

### `seal`

Encrypt `sk‖pk` into a v1 sealed blob bound to `measurement` and `provisioning_root`.

**Required:** exactly one of `--measurement-file` or `--measurement-hex`; `--provisioning-root-file` (32 bytes); `--secret-key-file`; `--public-key-file`; `-o` / `--output`.

```bash
pq-seal-v1 seal \
  --measurement-file ./enclave.measurement \
  --secret-key-file /secure/producer.sk.bin \
  --public-key-file /secure/producer.pk.bin \
  --provisioning-root-file /secure/provisioning_root.bin \
  -o ./producer-key.sealed
```

Measurement may be supplied as `--measurement-hex` (staging convenience). **Provisioning root must be a file** — never on the command line (argv / logs).

On success, prints blob path and `meas_digest=` (hex) to stderr.

### `verify`

Decrypt-check a blob **without printing key material**. Exit 0 + `ok:` on stderr if measurement and root match.

```bash
pq-seal-v1 verify \
  --sealed-blob-file ./producer-key.sealed \
  --measurement-file ./enclave.measurement \
  --provisioning-root-file /secure/provisioning_root.bin
```

Run after `seal` and again after copying the blob to staging storage.

### `meas-digest`

Print `meas_digest` (hex, one line) for a measurement file or hex string. Use to compare against attestation / enclave logs before sealing.

```bash
pq-seal-v1 meas-digest --measurement-file ./enclave.measurement
```

### `manifest build`

**Multi-host ceremony** (TASK-1.1): seal the **same** producer key once per host provisioning root,
emitting `pq-seal-manifest.json` + `blobs/<label>.sealed` for an HA fleet (the root is per-chip, so
each host needs its own blob). See runbook **§7.2**.

**Required:** exactly one of `--measurement-file`/`--measurement-hex`; `--secret-key-file`;
`--public-key-file`; one or more `--host LABEL=ROOTFILE`; `--out-dir`.

```bash
pq-seal-v1 manifest build \
  --measurement-hex <48-byte image measurement> \
  --secret-key-file /secure/producer.sk.bin \
  --public-key-file /secure/producer.pk.bin \
  --host aya=/secure/aya.root --host bravo=/secure/bravo.root \
  --out-dir ./fleet-manifest
```

- Each `ROOTFILE` is the **raw 32-byte** root from `snp-derive-root --out` (not `--print`, which is hex).
- `LABEL` is the blob filename stem: `[A-Za-z0-9._-]`, 1..=64 chars, unique (case-insensitive).
- Each host needs a **distinct** root; a repeated root is rejected.
- `--out-dir` is created fresh (its parent must exist); a failed build writes nothing (retry-safe).
- The manifest records a one-way `root_commitment = SHA3-256(domain ‖ root)` per host (never the root)
  for trustless boot-time selection; blobs are AEAD-bound to `(root, measurement)`, so they need not be
  kept secret. Shared format/selection lib: `pq-seal-manifest`.

## Staging vs production root

| Environment | Provisioning root |
|-------------|-------------------|
| **CI / local staging** | May use `impl/rust/enclave-protocol/testvectors/seal_v1_provisioning_root.bin` **only** in non-production pipelines |
| **Production** | 32-byte secret from platform (vTPM / SNP VMPL / Nitro). Enclave must call `set_pq_seal_v1_provisioning_root` at boot — **same** 32 bytes as passed to this CLI |

**Never** ship the reference root file or `reference-seal-v1-root` feature in production enclave binaries.

## Enclave integration (reminder)

1. `set_pq_seal_v1_provisioning_root(root)` — once at boot, from platform code (not vsock).
2. `install_sealed_pq_signer(blob, measurement)` — once at boot; host supplies blob path only, not the root.
3. Confirm `GET_MEASUREMENT` / `GET_STATUS`: `pq_signing_ready == true`, `pq_pubkey` length 1952.

See runbook for full staging checklist.

## Library API (custom tools)

Same logic lives in `enclave-protocol` (`ml-dsa-65` feature):

- `seal_mldsa65_keypair_v1_with_root`
- `verify_sealed_blob_v1_with_root`
- `pq_seal_v1_measurement_digest`
- `pq_seal_v1_expected_blob_len`

## Help

```bash
pq-seal-v1 --help
pq-seal-v1 seal --help
```