# Smoke pass criteria (aya / CI)

Explicit expectations for PR #5 / TASK-4 Phase B verification. Scripts live in this directory.

## Nix path (preferred)

| Script | Flake VM | Pass signals |
|--------|----------|--------------|
| `run-nix-enclave-staging.sh` | none (host loopback) | `host-loopback-smoke: OK`; response contains `prod-enclave-v1`; ~2013 bytes |
| `run-nix-vm-guest-smoke.sh` | `.#vm` | `host-guest-vsock-smoke: OK cid=42 port=5000`; marker `prod-enclave-v1`; ~2013 bytes |
| `run-nix-vm-guest-smoke-prod.sh` | `.#vm-production` | OK cid=42; marker `enclave-measurement-placeholder`; ~80 bytes; **no** `pq_signing_ready` required |
| `run-nix-vm-guest-smoke-prod-lab.sh` | `.#vm-production-lab` | OK cid=42; marker `enclave-measurement-placeholder`; ~2030 bytes; CBOR key 6 = true (`pq_signing_ready`) |

Common: host `GUEST_CID=42` matches QEMU `guest-cid=42`. NixOS guest binds `TWOD_HSM_VSOCK_CID=4294967295` (`VMADDR_CID_ANY`); Ubuntu SNP guest may use `VMADDR_CID_ANY` via `guest-start-hsm.sh`.

`vsock_smoke_client.py` decodes the GET_MEASUREMENT CBOR map (requires `cbor2`: `apt install python3-cbor2`).

## Ubuntu / SNP guest path

| Script | Pass |
|--------|------|
| `host-loopback-smoke.sh` | `host-loopback-smoke: OK` on CID 1; ~2013 bytes; `prod-enclave-v1` |
| `run-snp-smoke.sh` | Full E2E: SNP QEMU + `guest-start-hsm.sh` + vsock; OK cid=42; ~2013 bytes; `pq_signing_ready=true` |
| `host-guest-vsock-smoke.sh` | OK on CID 42 after manual `guest-start-hsm.sh` |

## NixOS under SNP — real measurement (TASK-5 AC#5)

| Script | Flake disk | Pass signals |
|--------|------------|--------------|
| `run-nix-snp-guest-smoke.sh` | `.#disk-production-lab` | `[PASS] ... real_measurement=1, pq_ready=1`; CID 42; CBOR key 2 = **48 raw bytes** (not `enclave-measurement-placeholder` / `prod-enclave-v1`); key 3 = real SNP report (≥1184 B, not `attestation-placeholder`); key 6 = true; key 7 = cert_chain (`cert_chain_len=0` on aya — provider doesn't populate `auxblob`). Response ≈ **3212 B** (48 + 1184 + 1952 pubkey + CBOR + empty key 7) |
| `SEV_MODE=none run-nix-snp-guest-smoke.sh` | `.#disk-production-lab` | KVM fallback boots; gate auto-relaxes to `require_real=0`, matches placeholder label; `pq_ready=1` (lab signer present even off-SNP) |
| `DISK_ATTR=disk-production run-nix-snp-guest-smoke.sh` | `.#disk-production` | boot-only (transport); auto `require_real=0 require_pq=0` (no operational signer ⇒ placeholder) |

Gates auto-adjust to disk + mode (lab+SNP ⇒ real measurement + pq; transport or
off-SNP ⇒ placeholder), so no manual `VSOCK_SMOKE_*` env is needed. The
real-measurement gate (`VSOCK_SMOKE_REQUIRE_REAL_MEASUREMENT=1`,
`assert_measurement_fields`) asserts a 48-byte launch measurement distinct from the
dev/staging labels plus a real (≥1184 B) VCEK-signed report — a structural smoke
check, not a cryptographic verifier (VCEK-chain validation is deferred). It is the
live counterpart to AC#4 (enclave-side capture) and needs an SNP host (aya EPYC); CI
only evals the disk-image derivation.

Requires `./warm-smoke-cache.sh` once (golden disk + cargo binary). Guest bind: `TWOD_HSM_VSOCK_BIND_CID=4294967295`; host: `GUEST_CID=42`.

## In-guest quote smoke (TASK-7.7 5b-2b-ii (d-ii)/4c)

| Script | Flake disk | Pass signals |
|--------|------------|--------------|
| `run-nix-snp-quote-smoke.sh` | `.#disk-production-lab-quote-smoke` | ALL THREE host greps in the serial log: `twod-hsm-quote-smoke: RESULT PASS` (the bin's verdict, `phases=7`), the raw child breadcrumb line on ttyS0 (console tee of the staged ERR(1) child's stderr), and `twod-hsm-quote-smoke: journald-breadcrumb PASS` (the unit's ExecStartPost journald-ARRIVAL assert). Phase expectations: `vsock-lapse` `elapsed_ms` ∈ [`deadline - 25ms slop`, 1500) (the lapse fired at ~399ms — poll(2) whole-ms truncation + single-tick early wake; see `LAPSE_ELAPSED_FLOOR_SLOP`); `quote-1`/`quote-2` `report_len` ≥ **1184** + report_data echo ok + a 96-hex launch measurement (NO cert-chain claim on aya — the provider doesn't populate `auxblob`); `gc-clean` zero `twod-hsm-q-*` residue. ~80s warm boot. |
| `SEV_MODE=none` + `run-guest-vm.sh` (KVM dry-run, fresh overlay of the same image) | `.#disk-production-lab-quote-smoke` | `PHASE vsock-lapse PASS` + `PHASE breadcrumb PASS`; the configfs phases FAIL by design (no configfs-tsm off SNP) ⇒ `RESULT FAIL`. NB ExecStartPost (the journald assert) is SKIPPED on ExecStart failure — not exercised in the dry-run. |

Status: **PASSED on aya 2026-06-11 — 4 SNP runs total, `RESULT PASS phases=7`, all three witnesses,
~80s warm boot.** Run 1 surfaced a real test-assertion bug (the lapse fires at 399ms by timer
granularity, 1ms under the exact 400ms floor) → fixed with `LAPSE_ELAPSED_FLOOR_SLOP`; runs 2–4 (the
post-floor-slop run, a confirming idempotence run, and a post-hardening run on the final launcher)
all PASS.

## Agent-gateway live smoke (TASK-7.7 5b-2c-iii)

| Script | Flake disk | Pass signals |
|--------|------------|--------------|
| `run-nix-snp-agent-smoke.sh` | `.#disk-production-lab-agent-gateway` | R1–R4 all hold (see the script header): anchor stub + relay up BEFORE qemu; serial-log boot evidence (raw + validated budget events, `[info] boot handshake outcome:` BEFORE the serve marker — the install-AFTER-Ready order observable; relay `pump ok` + anchor `signed response`); the host client's **`RESULT PASS phases=5`** (count-anchored); witnesses: in-guest `journald-serve PASS`, the calm `[info] ... closed connection (` non-0x40 close, the POSITIVE `[info] ... connection closed cleanly` idle close, and NO `connection fault`. |
| `run-kvm-agent-refusal.sh` (SEV_MODE=none, NO relay/anchor) | same image | **EXPECTED REFUSAL — a first-class run, never a skip**: `[warn] boot handshake outcome:` + `[err] agent-gateway boot failed:` + ≥2 `boot budget config (raw, pre-validate)` lines (restart evidence — supervision restarts, NO in-process retry) + NO `serving on vsock`. |

### 5b-2c-iii acceptance checklist (explicit; check off with run evidence)

- [ ] **Core:** a real 0x40 PUBLIC_IDENTITY round-trip over vsock from the host against the DEBUG
  `twod-hsm-agent-gateway` bin on a real SEV-SNP launch (client phase `public-identity`, byte-exact
  against the minted smoke fixture).
- [ ] **The real 300 s wall-clock idle expiry** (the doc-pinned item deviceless tests cannot drive):
  client phase `idle-expiry` PASS with `elapsed_ms` ∈ **[298 000, 332 000)** — floor = 300 s − 2 s
  slop (NEVER an exact floor — the (d-ii) 399 ms lesson), ceiling = 300 s + the 30 s `SO_RCVTIMEO`
  read-arm tick + 2 s slop (the close lands at the first read-wake ≥ the deadline). At least one
  FULL-WINDOW `RESULT PASS phases=5` run; `PASS-DEV phases=4` (skip-idle) never satisfies this.
- [ ] **Expected-error + close taxonomy live:** `identity-unknown-keyref` (exact 0x42),
  `non-agent-close` (zero reply bytes + the calm `[info]` close), `post-expiry-liveness` (the
  SERIAL loop serves the next client).
- [ ] **Bin logging acceptance split BY PATH:** (i) the happy boot above; (ii) validation-refusal +
  (iii) outcome-refusal — both pinned deviceless in `tests/twod_hsm_agent_gateway_bin.rs` (CI) AND
  (iii) E2E via `run-kvm-agent-refusal.sh` with restart evidence.
- [ ] **Canonical boot order observable in logs:** root → unseal → budget (raw, validated) → relay
  channel → handshake (`decide_serve` inside) → install-AFTER-Ready → serve.
- [ ] **aya `#[ignore]` composition test green on aya:** `relay_real_vsock_loopback_with_lab_anchor`
  (real CID_ANY bind + shipped relay pump + the REAL lab anchor stub; discharges the bind-CID-ANY
  reality item, seeds TASK-21).

### Residuals recorded, NOT discharged by this smoke

- **Release-bin spawn shape** — this smoke is DEBUG by mechanical necessity
  (`lab-agent-keystore-from-file` is release-banned); the release-built agent bin's spawn shape
  stays the explicit 5b-2c residual (owned by the production keystore-source slice).
- **Placeholder measurement** — the smoke keystore is sealed under
  `AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT`; the attested 48-byte SNP launch measurement is the
  deferred production keystore-source slice (binding itself is deviceless-pinned at unseal).
- **Anchor-side AMD cert-chain verification** — the lab stub is match-only on the embedded
  `report_data` (guest security never depends on anchor-side policy).
- **Single-client serial serving** — deliberate; the serve-port peer is the untrusted SNP host
  (availability-vs-host is a NON-GOAL). Concurrent-capped + `MAX_SESSION_LIFETIME` + a starvation
  test remain the BLOCKING PRECONDITION for any multi-tenant-multiplexed serving. The smoke must
  NOT be turned into a multi-client test.

### aya run-book note (bites every time)

Validate from a **detached worktree** (`git fetch origin <branch>` — the aya clone has a restricted
refspec, `origin/main` is not a local ref — then `git worktree add --detach <dir> <sha>`). If you
apply local patches instead, **`git add -A` before any flake build**: the git-flake eval ignores
untracked files and silently builds stale sources. First SNP run after a fixture/source change:
force a clean image build (delete the out-link — the smoke-cache stale-stamp adoption hazard,
`smoke-cache-lib.sh` `twod_hsm_nix_outlink_hit`/stamp adoption path).

## Review record (PR #5)

- **Reduced matrix:** roborev 6890–6892
- **Full matrix (2×3):** roborev 6893–6898 via `pse-review-2x3.sh --dirty`
- **Compact:** roborev 6900 — findings addressed in docs (lab trust naming, review gate, TASK-5 phases)
- **Operator sign-off:** aya 5/5 smokes on `d0ccd39` (2026-06-05), with `TWOD_HSM_CACHE`