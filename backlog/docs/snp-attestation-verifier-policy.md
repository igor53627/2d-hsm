# SEV-SNP attestation verifier policy (2d-hsm) — draft

How a **relying party** (Block Producer host, or an on-chain `MeasurementRegistry`
consumer) verifies the SEV-SNP attestation a 2d-hsm enclave returns from
`GET_MEASUREMENT`, and what each check does and does **not** prove.

This document defines the **contract**; the verifier itself runs on the relying
party (it is intentionally **not** in the enclave — the enclave only *produces* the
report + chain). TASK-5 Phase 3.

## 1. Inputs (from `GET_MEASUREMENT`, vsock spec §8)

| CBOR key | Field | Meaning |
|----|-------|---------|
| 2 | `measurement` | 48-byte SNP launch measurement (report offset `0x90`) |
| 3 | `attestation` | the raw SNP `ATTESTATION_REPORT` (v5, 1184 bytes), VCEK-signed |
| 4 | `pq_pubkey` | the ML-DSA-65 producer public key the enclave advertises |
| 7 | `cert_chain` | VCEK→ASK→ARK certificate chain (configfs-tsm `auxblob`); MAY be empty |

`measurement` is a convenience copy of report offset `0x90`; a verifier MUST read
it **from the signed report**, never trust key 2 on its own.

## 2. Verification steps (all MUST pass)

1. **Parse the report.** Require `version == 5` and `len >= 1184`. Read: `report_data`
   (`0x50`, 64 B), `measurement` (`0x90`, 48 B), `policy`, `signature` (ECDSA P-384),
   `chip_id`, `reported_tcb`, `signing_key`/`author_key` flags, `vmpl`. (See AMD
   SEV-SNP ABI §7 ATTESTATION_REPORT; `snp_report.rs` for the offsets this enclave uses.)

2. **Verify the report signature → AMD root.**
   - Take VCEK from `cert_chain` (key 7). If empty, fetch the VCEK from the **AMD KDS**
     (`https://kdsintf.amd.com/vcek/...`) by product (Milan/Genoa), `chip_id`, and the
     report's `reported_tcb`.
   - Verify VCEK signs the report (ECDSA-P384 over the report body), VCEK is signed by
     the ASK, and ASK by the **ARK**. Pin the **AMD ARK** root out of band (do NOT trust
     an ARK delivered in `cert_chain`).
   - Verify the VCEK's TCB fields equal the report's `reported_tcb` (no mix-and-match).

3. **Bind the producer key.** Require
   `report_data == SHA3-512("2d-hsm-snp-report-data-v1" || pq_pubkey)`
   for the `pq_pubkey` in key 4 (`snp_report::report_data_for_pubkey`). This is what ties
   the signed measurement to *this* enclave's PQ key; without it a host could replay a
   genuine report from a different key.

4. **Check the launch measurement allowlist.** Require `measurement ∈ {expected}`.
   - Observed reference (AMDSEV OVMF on aya, 2026-06-06):
     `3e39e33ab71f37ec9391fb285620dc5e50b67dd7cb59447726138596f9c502ed971ae0d095ea2ab3f93a8b8f6016b488`
   - **Important (see §3):** this value anchors the **OVMF launch firmware + SNP launch
     config**, not the guest image. The allowlist is maintained per **OVMF build**, and
     MUST be derived from a reproducible OVMF, not copied blindly from one host.

5. **Check policy / guest posture.** Require `policy.DEBUG == 0` (no debuggable guest);
   apply the deployment's requirements for SMT, migration-agent, and `vmpl`.

6. **Anti-rollback.** Require `reported_tcb >= ` the deployment's minimum SEV TCB.

Only if **all** pass may the relying party treat `pq_pubkey` as a genuine 2d-hsm
producer key for whitelisting / arming.

## 3. What the launch measurement does and does NOT bind (critical)

Measured empirically on aya (2026-06-06): the NixOS production guest
(`.#disk-production-lab`) and the Ubuntu staging guest produce the **identical** launch
measurement under the same OVMF. So:

- The SNP launch measurement pins the **OVMF firmware + launch config** (memory, vCPUs,
  policy) — it is taken **before** OVMF loads the kernel/initrd from disk.
- It does **not** pin the guest disk image, kernel, or enclave binary.

Therefore enclave **image identity** is established by a combination, not by the launch
measurement alone:
- **Build identity** — the reproducible artifact `sha256` in the measurement manifest
  (`nix/vm-hsm` README, schema v2).
- **Key binding** — `report_data` (step 3) ties the running enclave's PQ key to the
  attested platform.
- **Image binding (gap / future work)** — to cryptographically bind the *running* image
  to the attestation you need measured boot: either a **direct-boot** kernel hashed into
  the launch measurement (`-kernel` with `KERNEL_HASHES`), or **dm-verity** + a measured
  `/` whose root hash is carried in `report_data`/host-data, or IMA into a runtime
  measurement register. Until one ships, the residual trust is "the pinned OVMF only
  boots the published image"; document it in the deployment's threat model.

## 4. Status in this repo

- **Produced by the enclave:** the report (key 3) + the `report_data` key binding (verified
  at capture in `snp_report::verify_and_extract_measurement`) + VCEK cert chain (key 7)
  **when the provider populates `auxblob`**. Live on aya (2026-06-06): report 1184 B,
  `report_data` bound, but **`auxblob` is EMPTY → key 7 = empty (`cert_chain_len=0`)** on this
  kernel/provider, and the GET_MEASUREMENT response is 3212 bytes. So on the current setup the
  relying party **must** obtain the VCEK from the **AMD KDS** (step 2) — the on-host chain is not
  available; key 7 is reserved for hosts/providers that do populate it.
- **Relying-party verifier (steps 1–6):** specified here; implementation lives in the BP
  / on-chain consumer (out of scope for the enclave crate — it needs ECDSA-P384 + X.509
  + AMD KDS, deliberately kept off the `#![forbid(unsafe_code)]` signing path).
- **Open:** publish the OVMF reproducibility + allowlist provenance; the image-binding
  mechanism (§3); on-chain `MeasurementRegistry` policy encoding (2d-solidity repo).

## References
- `impl/rust/enclave-protocol/src/snp_report.rs` — report/auxblob fetch, offsets, key binding
- `impl/nix/vm-hsm/README.md` — manifest schema v2 (build identity vs TEE measurement)
- `backlog/docs/vsock-api-wire-format-spec-draft.md` §2.3, §8 — attestation vs chain attestation; GET_MEASUREMENT keys
- AMD "SEV-SNP ABI Specification" (ATTESTATION_REPORT, VCEK/VLEK, KDS)
