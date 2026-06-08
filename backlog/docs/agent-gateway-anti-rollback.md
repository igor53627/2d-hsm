# Agent Gateway anti-rollback mechanism (TASK-7.7)

The production anti-rollback mechanism for Agent Gateway sealed **replay counters** and **faucet
spend caps**. `pq-seal-v1` / `pq-agent-keystore-v1` give confidentiality + integrity +
measurement-binding but **not freshness** — a compromised host can roll the sealed blob backward
(snapshot/file-swap/disk downgrade) and the AEAD still verifies (root + measurement unchanged),
replaying spent capability counters and resetting faucet `cumulative_spend`. This doc selects the
mechanism that proves the sealed blob is the **latest**, and the production-funding **block** that
fails closed until that mechanism is deployed.

Design/contract only (implementation is TASK-7.6). 7.7 **adds** the freshness-binding mechanism +
the AC#5 gate + restore high-water seeding source + the active-active rule, **plus a bounded
`pq-agent-keystore-v1` format extension** — a `freshness_epoch` field and a pinned `anchor_root`
identity/CA in the keystore plaintext config — which is a `format_version` bump with a reviewed,
vector-backed forward-migration **per TASK-7.2 AC#16** (not a silent change). It **consumes**
(unchanged): in-enclave validation + the restore-seeding contract (TASK-7.2 AC#8/#11/#12/#17/#18),
seal-before-emit durability + the atomic serialized single-writer commit (TASK-7.4 §3), the counter
tuple + contiguity + strict recovery counter (TASK-7.1/7.5, vsock §10.6), the
`pq-seal-v1`/`pq-agent-keystore-v1` AEAD/measurement-binding primitives
(`enclave-protocol/src/pq_signer.rs`), SNP attestation (`snp-attest-verify`), the SNP-derived
provisioning root (provisioning-runbook §7.1).

## Decisions (selected, TASK-7.7)

| Topic | Decision |
|-------|----------|
| Platform finding | **SEV-SNP provides no per-enclave hardware monotonic counter** (SNP `reported_tcb` is platform-wide, not per-enclave; `guest_svn` is not platform-enforced-monotonic; no vTPM NV counter integrated; `snp-derive-root` is a key, not a counter). The freshness anchor **must be external**. |
| Selected mechanism | **Option A — remote monotonic counter + epoch-lease** (operator-run, per-instance), specified in full. **Option B — external append-only ledger** is the mandatory upgrade for any active-active/HA topology (§4). Option C (operator-signed boot-auth) is used only for restore-seeding **in combination with** A (it is replay-vulnerable alone). |
| Per-dispense binding | **`lease=1` (synchronous) by default** — a remote bump per fund-moving signature, zero replay window; admin/recovery/config advances are **always** `lease=1`. A naive `lease=N` is **unbounded** (§3); a safe `lease=N` needs anchor-visible lease IDs + a consumed sub-cursor, low-value faucets only, as an explicitly accepted bounded loss. Default/recommended `lease=1`. |
| AC#5 gate | **Hard block by default + a single loud audited opt-out** that forces the operator to record the verbatim TASK-7.2 AC#10 residual-risk acknowledgment. Never a silent default. |
| Anchor trust | The anchor runs under **separation of duties** from the host runtime and must itself be **anti-rollback-durable** (if the anchor can be rolled back the guarantee collapses); a quorum-signed anchor is preferred for high-value treasuries. |
| Anchor unavailable | **Fail closed** on all fund-custody commands (consistent with 7.4 seal-before-emit); only an unexpired `lease=N` window may continue; read-only / status / attestation stay available. |

## §1 Rollback threat model + protected sealed state (AC#2)

**Trust boundary:** the SEV-SNP enclave is trusted; the host (hypervisor / operator runtime /
disk / snapshots / vsock) is untrusted. `pq-seal-v1` AEAD authenticates *"sealed by this
measurement on this platform"* but not *"this is the latest blob"*. **Attack:** the host
checkpoints a sealed keystore, lets the enclave advance counters/spend, then restarts the enclave
on the same platform/measurement against the **old** blob — the AEAD still verifies. Result:
replay of already-consumed capability counters (re-mint keys / re-run a provisioning cap at a
lower counter) and reset of faucet spend toward an earlier value (over-dispense up to the full cap
again per rollback).

**State that anti-rollback must protect (AC#2):**
1. **Capability counter high-water table** — per `(authority, environment_identifier, scope_class,
   scope_target)` (`command_class` folded into `scope_target`); rolling it back re-opens
   already-spent counter values.
2. **Faucet `cumulative_spend`** — refillable, debited per-dispense, seal-before-emit. The
   **primary fund-loss vector**: rollback resets spend → over-dispense.
3. **Faucet `lifetime_spend`** — from genesis, backs the lifetime breaker; rollback defeats the
   absolute ceiling.
4. **Monotonic treasury `config_version`** — rollback re-applies a superseded looser config.
5. **Strict recovery counter** — forward-only, shared by `RESTORE_BACKUP` + `reset_lifetime_breaker`;
   the mechanism must protect it too or the restore/recovery path becomes replayable.

## §2 Platform finding — no SNP monotonic counter ⇒ external anchor required

Surveyed against `impl`: SNP `ATTESTATION_REPORT.reported_tcb` is a platform-wide firmware TCB
version (a relying-party floor, not a per-enclave rollback counter — an enclave rolled back on the
same host reads the same value); `SNP_GET_DERIVED_KEY` `guest_svn`/`tcb_version` are
operator-supplied binding inputs, not platform-incremented; `snp-derive-root` yields a **stable**
measurement-bound key (stability is its goal), not a counter; no vTPM NV monotonic counter is
integrated (`platform_provisioning_boot.rs` is an explicit placeholder). **Therefore AC#1 cannot
be met by a platform primitive; the freshness anchor is external.** The enclave authenticates to
the anchor with a **fresh SNP attestation** (measurement + VCEK + report nonce) so the anchor only
ever advances state for a genuine current enclave instance.

## §3 Selected mechanism — Option A: remote monotonic counter + epoch-lease (AC#1)

An operator-run, durable, monotonic counter/epoch service, one logical counter per treasury
instance, under separation of duties from the host.

**Freshness binding (mutual authentication).** `freshness_epoch` lives in the
**`pq-agent-keystore-v1` encrypted plaintext body** (alongside the counter/spend state); the
keystore AEAD authenticates the whole body, so the epoch is integrity-bound. The AAD itself stays
the fixed `magic ‖ format_version ‖ meas_digest` identity tuple — **do not put a per-restart value
in the AAD, and do not touch the `pq-seal-v1` producer-blob AAD/layout**. **Both** directions are
authenticated: the enclave proves it is a genuine current instance with a fresh SNP attestation
(agent `report_data` layout below), and the **anchor's response is itself signed** by the
`anchor_root` Ed25519 identity whose public half / CA is **pinned in the keystore plaintext config**
(the format extension above), covering `(treasury_id, epoch/marks, the enclave's fresh
channel-binding nonce)` as **canonical CBOR**. On every (re)start the enclave issues a fresh nonce,
verifies the signed response against the pinned `anchor_root`, and **refuses any sealed blob whose
`freshness_epoch` < the authenticated anchor-current** (stale → fail closed). A host controlling
vsock therefore cannot replay a stale low-epoch response or route the enclave to a spoofed anchor.
**`anchor_root` lifecycle:** installed at provisioning into the sealed config; verified at every
boot; rotation is a reviewed reprovisioning (re-seal under the new root).

**Agent attestation `report_data`.** The producer ML-DSA blob already spends SNP `report_data` on
`SHA3-512("2d-hsm-snp-report-data-v1" ‖ pq_pubkey)` (`snp_report.rs`). The Agent Gateway is a
**separate profile/measurement**, so its enclave uses its **own** domain-separated
`report_data = SHA3-512("2d-hsm-agent-anchor-handshake-v1" ‖ treasury_id ‖ freshness_nonce)` for the
anchor handshake — binding the per-(re)start nonce + secp256k1 treasury identity, **not** the
producer pq_pubkey. The anchor verifies that fresh attestation (agent measurement on the allowlist +
VCEK) before advancing or reporting.

**Per-dispense (seal-before-emit, AC#2).** Within the TASK-7.4 serialized single-writer commit,
each fund-moving operation (faucet dispense; and each administrative counter advance) **bumps the
remote counter to `epoch+1` and seals the new epoch into the keystore body in the same commit BEFORE
the signature/refs are emitted**. Default **`lease=1`**: one synchronous remote bump per signature →
**zero replay window** (a rolled-back blob is strictly behind the anchor and rejected). **All
administrative, recovery, and treasury-config counter advances are ALWAYS synchronous (`lease=1`)** —
never amortized. A **naive `lease=N`** (the blob-wide `freshness_epoch` staying equal to
anchor-current for the whole window) is **NOT bounded**: a host can repeatedly snapshot and replay
the same start-of-lease blob and the anchor cannot distinguish it from valid in-window state. A
**safe `lease=N`** (low-value faucets only, explicit per-treasury) therefore requires the anchor to
**track consumption**: each local spend **reports/acks its consumed sub-counter to the anchor before
emit**, the anchor records the per-`lease_id` high-water and **rejects any sub-counter ≤ the recorded
high-water** (reused cursor), so a replayed start-of-lease blob is caught. The alternative "anchor
pre-commits `N` and the enclave only seals the cursor locally" is **rejected** — the cursor would
live in host-rollbackable sealed state the anchor never sees, making replay unbounded. This per-spend
ack removes most of `lease=N`'s round-trip savings. **Production default and recommendation is `lease=1`.**

**Crash/partition reconciliation.** The remote bump is **idempotent**, keyed by the dispense
`request_id`: if the anchor recorded `epoch+1` but the local seal-then-emit did not complete (a
dropped seal/ack), on restart the enclave re-reads the anchor; when the anchor is exactly one ahead
for a `request_id` whose signature was **never emitted**, it **reconciles forward** (re-seals to the
anchor epoch, discards the un-emitted op) rather than self-wedging. A gap > 1, or an
emitted-but-unsealed signature, fails closed for operator intervention — preserving no-over-dispense
without a permanent self-wedge on a single dropped ack.

**Coverage (AC#2).** The same epoch gate protects **both** the capability counter high-water table
and the faucet spend counters (both live in the one sealed keystore whose epoch the anchor pins);
the strict recovery counter is likewise pinned.

**Boot/restore seeding (AC#3).** Counter high-water marks and faucet spend are seeded at boot/restore
from the anchor's **authenticated current marks** (or from authenticated recovery material whose
target is bound to the strict recovery counter) — **never zero, never from a stale backup**; if the
restored blob's epoch is behind the anchor it is rejected. Option C (operator-signed boot
authorization) may supply the seed values **only** when bound to the anchor's challenge-response,
never as a standalone replayable static authorization.

**Anchor requirements.** Separation of duties from the host; itself anti-rollback-durable (durable,
ordered, not itself rollback-able); HA so a partition is the failure mode — on which fund commands
**fail closed** (read-only/status/attestation remain). A quorum-signed anchor is preferred for
high-value treasuries.

## §4 Active-active prohibition + the append-only-ledger upgrade (AC#4)

A per-instance remote counter (Option A) does **not** permit clones: two live enclaves of one faucet
key would each pin their own per-instance epoch and could double-spend, and **Option A gives the
enclave no way to detect that a sibling clone exists** (measurement/sealing are per-instance). So
under Option A the single-instance rule is an **operator-procedural prohibition** (provision exactly
one anchor counter per faucet key + single-instance deployment), **not** an enclave-enforced guard.
Hard, enclave-/anchor-enforced active-active is provided **only** by **Option B — a global external
append-only ledger** shared by every live clone: each clone appends a signed (attestation-bound)
dispense/counter-advance entry and emits its signature only after the append is durably
acknowledged; the ledger enforces a **global** cumulative cap with per-entry sequence +
compare-and-append conflict resolution, and boot/restore replays the ledger tail to reconstruct
authoritative high-water marks (never zero). Option B is the mandatory mechanism for any
active-active or HA topology; its per-dispense append is effectively the synchronous round-trip of
`lease=1`.

## §5 Production-funding gate (AC#5) — hard block + audited opt-out

Two fail-closed layers mirroring the existing TASK-5 `productionMode` pattern, plus a runbook gate.

**Layer 1 — Nix build/eval gate** (mirrors `nixos-module.nix` / `guest-profile.nix` `assertions =
lib.optionals isProd [...]`, like `!(productionMode && labFixtures)`). Add a guest-profile param
`agentAntiRollbackMode ? "none"` (enum `none | remote-counter | external-ledger`) + its
endpoint/credential override args. **`operator-signed-boot` is NOT a standalone passing mode** (it is
replay-vulnerable alone, §3) — it is permitted only as the boot/restore challenge-response sub-mode of
`remote-counter`, never to satisfy the production assertion by itself. Assertion:
`assertion = !(productionMode && agentAntiRollbackEnabled && agentAntiRollbackMode == "none");`
with a message pointing to this doc, where `agentAntiRollbackEnabled` is true on any profile that
installs an operational faucet/transfer signer. A lab override aimed at a stub endpoint counts as
`none` (usesLab-style comparison) so the gate cannot be defeated by a no-op. This **fails the build**,
exactly like the mainnet trust/seal gate.

**Layer 2 — Rust dispatch gate.** (a) compile-time: in the `release_build` cfg family,
`compile_error!` on any lab/stub anti-rollback feature in release. (b) runtime fail-closed: inside
the AgentGateway (0x40) handler, if the boot-resolved anti-rollback binding is absent/unconfigured,
**reject the rollback-sensitive commands** — those that advance/debit sealed counters or spend:
`AGENT_K1_GENERATE_KEYS`, `AGENT_K1_SIGN_FAUCET_DISPENSE`, `AGENT_K1_CONFIGURE_TREASURY` fund-custody
sub-ops (`set_limits` / `refill_budget` / `raise_lifetime_breaker` / `reset_lifetime_breaker`),
`AGENT_KEYSTORE_EXPORT_BACKUP` (advances the export capability counter), and
`AGENT_KEYSTORE_RESTORE_BACKUP` (advances the strict recovery counter) — with an AgentGateway error
*"anti-rollback mechanism not configured (TASK-7.7)"*; read-only/status/attestation stay allowed.
**`AGENT_K1_SIGN_TRANSFER` is deliberately NOT in this runtime list** — it carries no rollback-
sensitive sealed state (no spend/cap/counter; bounded only by key-purpose + canonical EIP-155 +
sealed chain_id per 7.4/7.5), so gating it on anti-rollback would protect nothing it touches. AC#5's
transfer-wallet fund-custody block is instead enforced at **Layer 1**: a funding profile that
provisions transfer wallets does not build without a mechanism, so transfer custody is blocked at
deployment.

**Opt-out (measured/sealed, audited, not silent).** The opt-out is **not** a runtime/host-settable
input — it is provisioned into the **measured/sealed** configuration (a build-time guest-profile flag
captured in the enclave measurement, recorded in the sealed keystore config), so a host cannot flip it
at runtime; changing it requires explicit **reprovisioning**. It relaxes **only** Layer-1's `none`-mode
assertion and Layer-2's runtime fund-command block (**not** the compile-time lab/stub guard), permits a
funding profile **only** by recording the **verbatim TASK-7.2 AC#10** residual-risk acknowledgment
(operator-signed, audited), and may itself carry a reduced spend ceiling. Default is the hard block.
The acknowledgment is the **verbatim AC#10 text**, operator-signed by the admin/recovery authority
and recorded in the sealed keystore config + the audit ring; the enclave verifies that signature and
that the recorded text matches before honoring the opt-out, so it can never be a host-supplied
runtime string.

**Runbook gate** (provisioning-runbook new §): operator must select + provision the mechanism, vet
the measurement allowlist, and record the anchor endpoint/credentials **before** flipping
`productionMode` for a funding profile; explicit residual-risk sign-off if any non-funding/lab path
is used.

## §6 Restore / failover seeding (AC#3)

Restore and failover seed counter high-water marks + faucet spend from **authenticated material**
(the anchor's current marks, or recovery material bound to the strict recovery counter), and
**never** reset to zero from a stale backup (consumes the TASK-7.2 AC#11/#12 contract). A restored
blob whose `freshness_epoch` is behind the anchor is rejected. Fresh-TEE restore additionally runs
the TASK-7.2 attested-ingress ceremony; the new instance registers with the anchor (fresh SNP
attestation) before it may emit fund-moving signatures.

## §7 Test / failure-scenario requirements (DoD#2) + residuals

- **Stale-blob rejection:** an enclave presented a sealed blob with `freshness_epoch` < anchor-current
  refuses to start the fund path (fail closed) — the core anti-rollback assertion.
- **Per-dispense `lease=1`:** a fund signature is emitted only after the remote bump + seal commit;
  simulated anchor failure ⇒ no signature (0x4x). A rolled-back blob after a dispense is rejected.
- **Crash reconciliation:** a dropped seal/ack leaving anchor=`epoch+1` and blob=`epoch` with no
  emitted signature ⇒ restart reconciles forward (no self-wedge); a gap > 1, or an emitted-unsealed
  signature, fails closed for operator intervention.
- **`lease=N` consumed-cursor:** a naive lease is **unbounded** — test that repeated snapshot/replay
  of a start-of-lease blob within the window is caught only by anchor-visible lease IDs + a consumed
  sub-cursor that rejects a reused cursor; admin/recovery/config advances are always synchronous.
- **Counter + spend coverage:** rollback of the capability counter table AND of `cumulative_spend`/
  `lifetime_spend` are both detected.
- **Restore never-zero:** restore from a stale backup with a behind epoch is rejected; seeding is
  from authenticated marks (AC#3).
- **Active-active:** under Option A the single-instance rule is operator-procedural (the enclave
  cannot detect a clone) — provisioning/runbook must enforce one instance per faucet key; under
  **Option B** the global ledger **enforces** the cumulative cap under concurrent appends (AC#4).
- **AC#5 gate:** a `productionMode` funding profile with `agentAntiRollbackMode == "none"` fails the
  Nix build; the runtime dispatch blocks fund commands when unconfigured; the opt-out requires the
  recorded residual-risk acknowledgment.
- **Roborev matrix/compact evidence recorded before merge (AC#6).**

**Residuals:** the guarantee is only as strong as the anchor — a fully-compromised operator who can
also roll the anchor back defeats it (hence separation of duties + an anti-rollback-durable,
preferably quorum, anchor). A safe `lease=N` accepts a bounded replay loss only via the anchor-visible
consumed-cursor scheme (a naive lease is unbounded, §3). Until the
mechanism is deployed, the AC#5 hard block makes production fund custody impossible (absent the
audited opt-out). **Liveness DoS (accepted availability residual):** because production is `lease=1`
(no offline window) and the untrusted host sits on the enclave↔anchor path, the host can **censor**
that channel to wedge all fund custody. This is **fail-closed** — no fund loss, no rollback, and the
host gains nothing — but it is a deliberate availability denial the host can trigger at will; HA +
monitored anchor connectivity is the operational mitigation.
