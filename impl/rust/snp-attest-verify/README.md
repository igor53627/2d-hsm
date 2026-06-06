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
   - ASK signed by ARK, VCEK signed by ASK. AMD ARK/ASK use **RSA-4096 RSASSA-PSS / SHA-384**.
3. **Report signature**: the report is signed by the VCEK with **ECDSA-P384 / SHA-384**. AMD stores
   `r`/`s` **little-endian** in 72-byte fields at offset `0x2A0`; the verifier byte-reverses to the
   big-endian the `p384` crate expects, then verifies SHA-384 over `report[0..0x2A0]`.

## Usage

```
snp-attest-verify \
  --report report.bin --vcek vcek.der --cert-chain ask_ark.pem \
  --measurement 3e39e33ab71f37ec... [--pq-pubkey pq.bin] [--pinned-ark-chain amd.pem]
```

`auxblob` is empty on current providers (see policy §4), so fetch the VCEK + chain from the **AMD KDS**:

```
curl 'https://kdsintf.amd.com/vcek/v1/Genoa/<chip_id_hex>?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..' -o vcek.der
curl 'https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain' -o ask_ark.pem
```

`--pinned-ark-chain` defaults to the committed AMD Genoa ARK/ASK (`testvectors/amd_genoa_cert_chain.pem`).

## Tests

- **Real AMD data** (`testvectors/amd_genoa_cert_chain.pem`, fetched from KDS): the ARK verifies as
  self-signed (RSA-PSS), and the ASK is signed by the ARK — the production RSA-PSS path on real certs.
- **Synthetic ECDSA-P384 chain** (built in-test with the pure-Rust `x509-cert` builder): a full
  ARK→ASK→VCEK chain + a report signed by the VCEK exercises the chain-walk, ARK pin, and report
  binding end to end (pass + wrong-pin + broken-intermediate).
- **Report signature**: deterministic P-384 round-trip + tamper/wrong-key/short-report rejection.
- **Golden report** (`testvectors/snp_report_golden_v5.bin`, real, from aya): field extraction.

## Not (yet) covered — follow-ups

- **A real KDS-resolvable end-to-end golden.** aya's `chip_id` is masked, so its VCEK is 404 on KDS;
  the full real RSA+ECDSA chain is covered only on its upper legs (real ARK/ASK) + synthetically.
  Production hardware resolves; vendoring a known-good public AMD sample would add a real golden.
- **VCEK TCB/chip-id extension binding** (policy §2 last bullet) — parsing AMD's custom X.509 OID
  extensions and matching them to the report's `reported_tcb`/`chip_id`. `report_chip_id` /
  `report_reported_tcb` expose the report side; the cert-side parse + compare is a follow-up.
- **Certificate validity dates** (notBefore/notAfter) — a deployment-policy wall-clock check, left to
  the consumer.
