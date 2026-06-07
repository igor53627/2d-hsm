# snp-attest-verify

Relying-party **reference verifier** for SEV-SNP attestation. Implements
`backlog/docs/snp-attestation-verifier-policy.md` §2 — specifically **step 2**, the cryptographic
chain the cheap structural checker `enclave-protocol::snp_verify::prevalidate_report` deliberately
leaves out: from the `ATTESTATION_REPORT` up to the **pinned AMD root** (TASK-1 DoD #3).

This runs on the **relying party** (Block Producer host / on-chain `MeasurementRegistry` consumer),
**not** in the enclave — it needs ECDSA-P384 + RSA + X.509, which are kept off the
`#![forbid(unsafe_code)]` signing path on purpose.

## What it verifies

1. **Structural prevalidate** (reused from `prevalidate_report`): version/length, optional
   `report_data == SHA3-512("2d-hsm-snp-report-data-v1" ‖ pq_pubkey)` key binding, measurement allowlist.
2. **Cert chain VCEK → ASK → ARK** to the pinned AMD root:
   - ARK is identified as the self-signed cert and **pinned** — its SubjectPublicKeyInfo must equal
     the out-of-band AMD root (never trust the ARK delivered in the chain on its own).
   - **Name-chaining** (RFC 5280 §6.1): the ASK is selected as the cert whose subject == the VCEK's
     issuer DN, and its issuer must equal the ARK's subject — so an extra/duplicate cert in the bundle
     can't be mis-selected.
   - ASK signed by ARK, VCEK signed by ASK. **Production accepts only AMD's algorithm**
     (RSA-4096 RSASSA-PSS / SHA-384); any other cert signature algorithm is rejected (the ECDSA cert
     path exists solely for the `#[cfg(test)]` synthetic chain).
3. **Report signature**: the report is signed by the VCEK with **ECDSA-P384 / SHA-384**. AMD stores
   `r`/`s` **little-endian** in 72-byte fields at offset `0x2A0`; the verifier byte-reverses to the
   big-endian the `p384` crate expects, then verifies SHA-384 over `report[0..0x2A0]`.
4. **VCEK ↔ chip binding**: the VCEK's AMD `HWID` extension (`1.3.6.1.4.1.3704.1.4`) must equal the
   report's `chip_id` — so a genuine VCEK from a *different* chip can't be paired with the report
   (mix-and-match). The parser tolerates both observed HWID encodings (raw 64 bytes / OCTET STRING).
   **Skipped when `chip_id` is all-zero** (`MASK_CHIP_ID`): the chip isn't exposed, so there's nothing
   to bind to — trust then rests on the chain + measurement (enforcing it would falsely reject).

## Usage

```
snp-attest-verify \
  --report report.bin --vcek vcek.der --cert-chain ask_ark.pem \
  --product turin --pq-pubkey pq.bin --measurement 3e39e33ab71f37ec...
```
`--product <genoa|turin>` pins the bundled AMD root for that CPU family (or pass your own
`--pinned-ark-chain <pem>`) — **one is required**, there's no silent default.

`auxblob` is empty on current providers (see policy §4), so fetch the VCEK + chain from the **AMD KDS**.
**Pick the KDS product to match the CPU**: `lscpu` CPU family **25** (0x19) = `Genoa` (Zen 4), family
**26** (0x1A) = `Turin` (Zen 5). Bundled roots: `testvectors/amd_{genoa,turin}_cert_chain.pem`.

```
P=Turin   # or Genoa — must match the chip's family
curl "https://kdsintf.amd.com/vcek/v1/$P/<chip_id_hex>?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=.." -o vcek.der
curl "https://kdsintf.amd.com/vcek/v1/$P/cert_chain" -o ask_ark.pem
```

`--pq-pubkey` is **required** (it binds the report to the producer key via `report_data`) — without a
key binding the attestation is replayable, since the launch measurement is OVMF-level and shared
across guests (policy §3). To verify without it (e.g. measurement-only debugging), pass the explicit
`--allow-unbound`, which warns.

## Tests

- **Real AMD data** — both `testvectors/amd_genoa_cert_chain.pem` and `…_turin_cert_chain.pem`
  (fetched from KDS): each ARK verifies as self-signed (RSA-PSS) and its ASK is signed by the ARK — the
  production RSA-PSS path on two real product roots (Turin is aya's actual product).
- **VCEK ↔ chip binding** — synthetic VCEK with an AMD HWID extension: matching `chip_id` binds,
  mismatched is rejected, a VCEK with no HWID extension is rejected; `parse_amd_hwid` covers both
  encodings (raw 64 bytes / OCTET STRING).
- **Synthetic ECDSA-P384 chain** (built in-test with the pure-Rust `x509-cert` builder): a full
  ARK→ASK→VCEK chain + a report signed by the VCEK exercises the chain-walk, ARK pin, name-chaining,
  and report binding end to end (pass + wrong-pin + missing-ASK + broken-intermediate). It is ECDSA
  because x509-cert 0.2's builder can't emit randomized RSA-PSS; the production RSA-PSS path is covered
  by the real AMD certs above.
- **Report signature**: deterministic P-384 round-trip + tamper/wrong-key/short-report rejection.
- **Golden report** (`testvectors/snp_report_golden_v5.bin`, real, from aya): field extraction.

## Not (yet) covered — follow-ups

- **A real KDS-resolvable end-to-end golden.** aya is **Turin** (Zen 5, CPU family 26) and its
  `chip_id` is an 8-byte engineering/early-sample value (`snphost show identifier` → 8 bytes, not 64),
  so its VCEK is **404 on KDS even on the correct Turin endpoint** — not a config/BIOS toggle. The full
  real RSA+ECDSA chain is therefore covered only on its upper legs (real ARK/ASK, Genoa+Turin) +
  synthetically. Vendoring a known-good public AMD Turin sample would add a real end-to-end golden —
  and would let the **VCEK HWID/TCB binding** be cross-checked against real AMD extension encoding.
- **VCEK TCB (SPL) anti-rollback** (policy §2 last bullet, the version part) — the chip-id half is now
  done (step 4 above); comparing the VCEK's SPL extensions to the report's `reported_tcb` is deferred
  to pair with the min-TCB policy (it needs the firmware-specific TCB byte layout — aya uses the FMC
  layout `[FMC,BL,TEE,SNP,_,_,_,ucode]` — and a real VCEK to validate the SPL extension encoding).
- **Certificate validity dates** (notBefore/notAfter) — a deployment-policy wall-clock check, left to
  the consumer.
- **basicConstraints / keyUsage** on ARK/ASK (cA=true, keyCertSign) and end-entity on the VCEK —
  currently trust rests on the pin + signatures + name-chaining, not the CA flags.
- **Anti-rollback** (policy §2 step 6): a minimum-`reported_tcb` floor; not enforced (no min-TCB
  parameter yet).
