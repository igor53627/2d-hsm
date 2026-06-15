# Agent Gateway anti-rollback mechanism (TASK-7.7)

The production anti-rollback mechanism for Agent Gateway sealed **replay counters** and **faucet
spend caps**. `pq-seal-v1` / `pq-agent-keystore-v1` give confidentiality + integrity +
measurement-binding but **not freshness** — a compromised host can roll the sealed blob backward
(snapshot/file-swap/disk downgrade) and the AEAD still verifies (root + measurement unchanged),
replaying spent capability counters and resetting faucet `cumulative_spend`. This doc selects the
mechanism that proves the sealed blob is the **latest**, and the production-funding **block** that
fails closed until that mechanism is deployed.

Design/contract document; the **anti-rollback anchor implementation is TASK-7.7's own** (slices in §8;
TASK-7.6 owns the Agent Gateway secp256k1 signer backend it binds onto). 7.7 **adds** the freshness-binding mechanism +
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
| Anchor unavailable | **Fail closed on ALL fund-custody commands** — every fund-moving op needs a synchronous anchor bump+ack (`lease=1`, and a safe `lease=N` also acks the anchor **per spend**), so **no fund custody proceeds offline** and there is no host-rollbackable offline window. Read-only / status / attestation stay available; the host can deny liveness but never fund custody or rollback. |

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
verifies the signed response against the pinned `anchor_root`, and **never trusts a sealed blob whose
`freshness_epoch` < the authenticated anchor-current as-is**: the stale blob's own marks are
discarded and the anchor's authoritative counter/spend high-water binds (the core anti-rollback
assertion). The enclave then **adopts** those marks when they fully resolve the gap (the bounded
counter/spend crash-reconcile of §3) and **fails closed** when the gap spans a structural key/config
mutation the anchor never held or when the anchor is unavailable. An epoch **ahead** of
the anchor (`freshness_epoch > anchor-current`, beyond that bounded reconcile)
indicates the **anchor itself was rolled back** or is inconsistent and **also fails closed** — the
enclave never silently accepts a blob ahead of the anchor. A host controlling vsock therefore cannot
replay a stale low-epoch response or route the enclave to a spoofed anchor.
**`anchor_root` lifecycle:** installed at provisioning into the sealed config; verified at every
boot; rotation is a reviewed reprovisioning (re-seal under the new root).

**Agent attestation `report_data`.** The producer ML-DSA blob already spends SNP `report_data` on
`SHA3-512("2d-hsm-snp-report-data-v1" ‖ pq_pubkey)` (`snp_report.rs`). The Agent Gateway is a
**separate profile/measurement**, so its enclave uses its **own** domain-separated
`report_data = SHA3-512("2d-hsm-agent-anchor-handshake-v1" ‖ treasury_id ‖ freshness_nonce)` for the
anchor handshake — binding the per-(re)start nonce + the keystore-instance identity, **not** the
producer pq_pubkey. The anchor verifies that fresh attestation (agent measurement on the allowlist +
VCEK) before advancing or reporting. **Concrete `treasury_id`** (impl, `agent_anchor.rs`): the
plaintext-config keystore-instance scope `twod_chain_id (8B BE) ‖ len(environment_identifier) (4B BE)
‖ environment_identifier` — the **same tuple the capability envelope scopes to** (§10.5), present in
sealed config from provisioning so the handshake works on a fresh keystore **before** the first
GENERATE_KEYS mints a secp256k1 treasury key. The secp256k1 treasury pubkey is deliberately **not**
the handshake id (it does not exist pre-keygen). This identifies the keystore **instance by scope** —
it does **not** by itself make clones safe: under Option A the anchor is a single per-scope counter
with **no fencing of concurrent attestations**, so two clones at one `(chain_id, environment_identifier)`
would churn each other's epoch (each sees the other's bump as "anchor ahead") rather than double-spend
silently, but the active-active prohibition of §4 still stands and stays operator-procedural under
Option A. Fencing duplicate live attestations per scope (reject a second concurrent instance) is the
upgrade the Option B append-only ledger provides; an Option-A anchor MAY add such fencing, but the
verify slice does not assume it.

**Per-dispense (seal-before-emit, AC#2).** Within the TASK-7.4 serialized single-writer commit,
each fund-moving operation (faucet dispense; and each administrative counter advance) **bumps the
remote counter to `epoch+1` and seals the new epoch into the keystore body in the same commit BEFORE
the signature/refs are emitted**. Default **`lease=1`**: one synchronous remote bump per signature →
**zero replay window** (a rolled-back blob is strictly behind the anchor, so the anchor's higher mark
binds and the rollback gains nothing — adopt-forward). **All
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

**Crash/partition reconciliation.** The remote bump is **atomic with recording the authoritative
post-operation marks** at the anchor — the new `epoch` **and** the resulting counter/spend
high-water — keyed by `request_id`. On restart the enclave re-reads the anchor's authoritative marks;
if they are **ahead of** the local sealed blob **by a counter/spend advance the recorded marks fully
describe**, it **adopts them** (re-seals to the anchor's epoch + marks). So a dropped seal/ack cannot
lose a spend debit, and a host that received a signature **cannot hide the debit** by rolling the
blob back — the debit lives at the anchor. The enclave never reconciles by *guessing* whether a
signature was emitted; it **adopts the anchor's recorded state**. A divergence the anchor cannot
resolve — the anchor **behind** the blob (`freshness_epoch > anchor-current`, §3), **or a forward gap
spanning a structural key/config mutation whose material the anchor never held** (it records only
epoch + counter/spend marks, so a dropped `GENERATE_KEYS`/`CONFIGURE_TREASURY` seal is not
reconstructable) — fails closed for operator intervention (restore from backup). This preserves
no-over-dispense without a permanent self-wedge on a single dropped ack.

**Anchor commit idempotency/conflict contract (NORMATIVE — the out-of-repo anchor MUST honor this; the enclave only verifies the signed ack, so these rules live at the anchor. Pinned against the lab stub in slice 6-5).** The per-op `0x45` commit durably records the post-op `(epoch, structural_version, marks_digest)` **keyed by the `request_id` ALONE** — the request_id is the *logical-op identity*, and a logical op commits **at most once**. Three rules:
1. **Key by `request_id` alone, NOT `(request_id, epoch)`.** After an `EpochOnly` crash + `AdoptForward`, a re-issue of the same logical op proposes the *next* epoch; keying by `(request_id, epoch)` would wrongly admit it as a fresh record → a double-advance / double-spend. The request_id must dedup **across epochs**.
2. **An idempotent retry RE-SIGNS for the CURRENT (fresh per-op) nonce.** A duplicate commit under an already-recorded `request_id` with **matching** `{epoch, structural, marks}` MUST return an ack **re-signed for the attempt's fresh nonce** (NOT a replay of the original ack) — the enclave's `verify_commit_ack_bytes` echoes the *current* op's nonce, so a replayed original ack fails `NonceMismatch` and wedges the retry. The durable record is NOT advanced again.
3. **Conflict ⇒ reject.** A commit under an already-recorded `request_id` proposing **any different** `{epoch, structural, marks}` MUST be rejected; the enclave then fails closed (no seal/emit).

**Precondition (admin/orchestrator obligation):** distinct logical ops MUST carry distinct request_ids. The TEE-enforced per-op sequencer is the capability **counter** (strict-contiguous); the `request_id` is an opaque admin-chosen value bound into the capability signature but NOT checked for uniqueness by the enclave. Reusing one request_id across two genuinely-distinct ops makes the second reject as a conflict (a fail-closed availability loss, never a custody breach) — so request_id-per-op-uniqueness is an explicit admin prohibition, not a TEE invariant.

**Coverage (AC#2).** The same epoch gate protects **both** the capability counter high-water table
and the faucet spend counters (both live in the one sealed keystore whose epoch the anchor pins);
the strict recovery counter is likewise pinned.

**Boot/restore seeding (AC#3).** Counter high-water marks and faucet spend are seeded at boot/restore
from the anchor's **authenticated current marks** (or from authenticated recovery material whose
target is bound to the strict recovery counter) — **never zero, never from a stale backup**: the
backup's own stale marks are never trusted; counters are seeded from the anchor's authenticated
current marks (adopt-forward), and the operation fails closed only if those authenticated marks are
unavailable or the divergence is unresolvable. Option C (operator-signed boot
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

**Layer 1 — Nix build/eval gate.** *(IMPLEMENTED — TASK-16: `guest-profile.nix` adds the
`agentAntiRollbackMode ? "none"` param + the derived `agentAntiRollbackEnabled` (`= agentTransferFaucetSignerPackage != null`, so a funding profile can't bypass) + `antiRollbackResidualOptOut ? false`; `nixos-module.nix` adds the assertion below to the `lib.optionals isProd` list; `flake.nix` adds `checks.agent-anti-rollback-gate` exercising both polarities + the derivation, wired into CI alongside the mainnet gate. No funding profile ships yet (TASK-15), so the assertion is a dormant tripwire on every output and the flake check is where it is verified. The `agentAntiRollbackMode` is a BUILD-TIME guest-profile param captured in the measured image — NOT a runtime env channel a host can flip — so the §1406 env-channel measured-boot obligation is satisfied by construction for the mode itself; the broader disk-image measurement coverage is the TASK-1.1 chain. The lab-stub-endpoint-counts-as-none `usesLab` downgrade is forward-declared for when a real anti-rollback endpoint + its lab fixture land with TASK-15.)* (mirrors `nixos-module.nix` / `guest-profile.nix` `assertions =
lib.optionals isProd [...]`, like `!(productionMode && labFixtures)`). Add a guest-profile param
`agentAntiRollbackMode ? "none"` (enum `none | remote-counter | external-ledger`) + its
endpoint/credential override args. **`operator-signed-boot` is NOT a standalone passing mode** (it is
replay-vulnerable alone, §3) — it is permitted only as the boot/restore challenge-response sub-mode of
`remote-counter`, never to satisfy the production assertion by itself. Assertion:
`assertion = !(productionMode && agentAntiRollbackEnabled && agentAntiRollbackMode == "none" && !antiRollbackResidualOptOut);`
with a message pointing to this doc. `agentAntiRollbackEnabled` is **derived, not a free-defaulting
param** — it is forced `true` by the same profile logic that installs an operational faucet/transfer
signer, so a new profile cannot silently leave it falsy (Nix optional params default falsy) and
bypass the gate. `antiRollbackResidualOptOut` is the **measured/sealed** opt-out (build-time, captured
in the enclave measurement; §5) and is the **only** way the assertion passes with `mode == "none"`, so
the opt-out is explicit in the formula, never an undocumented escape. A lab override aimed at a stub
endpoint counts as `none` (usesLab-style comparison) so the gate cannot be defeated by a no-op. This
**fails the build**, exactly like the mainnet trust/seal gate.

**Layer 2 — Rust dispatch gate.** *(Layer-2b runtime block IMPLEMENTED — `agent_dispatch` `AgentOpcode::is_rollback_sensitive` + the gate after opcode-decode/before privilege-routing + the `ANTI_ROLLBACK_BINDING` boot-resolved global; fail-closed `NotConfigured`/0x45 when unconfigured. Layer-2a compile guard is forward-looking until a stub anti-rollback feature exists; the measured/sealed AC#10 opt-out is a deferred sub-slice — `sealed_optout_acknowledged` is a `false` stub so the gate hard-blocks meanwhile.)* (a) compile-time: in the `release_build` cfg family,
`compile_error!` on any lab/stub anti-rollback feature in release. (b) runtime fail-closed: inside
the AgentGateway (0x40) handler, if the boot-resolved anti-rollback binding is absent/unconfigured,
**reject the rollback-sensitive commands** — those that advance/debit sealed counters or spend:
`AGENT_K1_GENERATE_KEYS`, `AGENT_K1_SIGN_FAUCET_DISPENSE`, `AGENT_K1_CONFIGURE_TREASURY` fund-custody
sub-ops (`set_limits` / `refill_budget` / `raise_lifetime_breaker` / `reset_lifetime_breaker`),
`AGENT_KEYSTORE_EXPORT_BACKUP` (advances the export capability counter), and
`AGENT_KEYSTORE_RESTORE_BACKUP` (advances the strict recovery counter) — with a fail-closed
AgentGateway error. **Wire form (impl):** the reject reuses the generic `NotConfigured` (`0x45`)
§10.9 band code (no distinct wire string — a distinct code/string would be an anti-oracle and would
break the band/variant-equality contracts); the anti-rollback-specific phrasing *"anti-rollback
mechanism not configured (TASK-7.7)"* lives in the code/diagnostics, not on the wire. AC#5 requires a
fail-closed reject, which `0x45` is. Read-only/status/attestation stay allowed.
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
blob's own stale `freshness_epoch`/marks are never trusted as authoritative — counters are seeded
from the anchor's authenticated current marks (adopt-forward); restore fails closed only when those
marks are unavailable or the divergence is unresolvable. Fresh-TEE restore additionally runs
the TASK-7.2 attested-ingress ceremony; the new instance registers with the anchor (fresh SNP
attestation) before it may emit fund-moving signatures.

## §7 Test / failure-scenario requirements (DoD#2) + residuals

- **Stale-blob rejection:** an enclave presented a sealed blob with `freshness_epoch` < anchor-current
  **never trusts the stale blob's own marks** — the anchor's authoritative counter/spend high-water
  binds (defeating the rollback/replay), the core anti-rollback assertion. It then adopts those marks
  (crash-reconcile, below) or fails closed (anchor unavailable, or a structural-mutation gap).
- **Per-dispense `lease=1`:** a fund signature is emitted only after the remote bump + seal commit;
  simulated anchor failure ⇒ no signature (0x4x). A rolled-back blob after a dispense does not enable
  replay — the anchor's higher spend mark binds (adopt-forward), so the double-spend is refused.
- **Crash reconciliation (adopt-forward, never infer emission):** a dropped seal/ack leaving the
  anchor **ahead** of the blob by a **counter/spend advance the recorded marks fully describe**
  (anchor=`epoch+k`, blob=`epoch`) ⇒ restart **adopts the anchor's authoritative epoch + counter/spend
  marks** and re-seals forward (no self-wedge), *without* inferring whether a signature was emitted —
  the debit already lives at the anchor (§3). **Fail-closed** (operator intervention) is reserved for
  a forward gap spanning a **structural key/config mutation** whose material the anchor never held
  (dropped `GENERATE_KEYS`/`CONFIGURE_TREASURY` seal ⇒ restore from backup), the anchor **behind** the
  blob (`freshness_epoch > anchor-current`), an unavailable anchor, or an unresolvable divergence.
- **`lease=N` consumed-cursor:** a naive lease is **unbounded** — test that repeated snapshot/replay
  of a start-of-lease blob within the window is caught only by anchor-visible lease IDs + a consumed
  sub-cursor that rejects a reused cursor; admin/recovery/config advances are always synchronous.
- **Counter + spend coverage:** rollback of the capability counter table AND of `cumulative_spend`/
  `lifetime_spend` are both detected.
- **Restore never-zero:** restore from a stale backup never seeds counters from the backup's own
  (would-be-zero/stale) marks; they are seeded from the anchor's authenticated marks instead (AC#3).
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

## §8 Implementation — verify-only slice (`agent_anchor.rs`, TASK-7.7)

This anti-rollback anchor module is TASK-7.7's *own* mechanism (the freshness binding 7.7 adds on top
of the TASK-7.6 Agent Gateway signer); it is built under the shared `agent-gateway` feature. The
TASK-7.7 ACs/DoD are the **design** acceptance (complete); the task stays In Progress to track these
implementation slices.

The first implementation slice (feature `agent-gateway`, pure + unit-tested with a mock anchor key)
lands the enclave's **anchor-response verification + boot reconcile** core. It is deliberately
*anchor-agnostic*: the enclave only verifies a signed response against the sealed `anchor_root`. WHO
signs — an operator HSM, a quorum, or a **chain-bridge** that reads 2D-chain state (recorded via
ordinary transactions to a normal contract) and signs the current mark — is a provisioning choice
that does not change this code. This hybrid framing is the session's **"Variant C"**: it is the §3
Option-A verify mechanism *extended with optional chain-block binding* so a chain-backed anchor (or a
later direct merkle-read path) can back it **without a wire change**. It is **not** the Decisions-table
"Option C" (operator-signed boot-auth, restore-seeding only).

**Domains.** Response signing preimage prefix `ANCHOR_DOMAIN = "2d-hsm/agent-anchor/v1\0"` (trailing
NUL part of the label); handshake `report_data` domain `"2d-hsm-agent-anchor-handshake-v1"` (§3).

**Anchor freshness response (canonical-CBOR int-key map).** The overall response wire format stays
**v1-PROVISIONAL** for the not-yet-exercised parts (chain-binding 8/9, the epoch handshake), but the
two signed/compared fields `reconcile` already consumes are now pinned: **`structural_version` (key 5)
is FROZEN v1** (sealed-body `u64`, see below) and **`marks_digest` (key 6) has a FROZEN v1 enclave
encoder** (the byte grammar below) whose **cross-component contract stays PINNED-BEFORE-ANCHOR-CO-SIGN**
until the anchor team commits in writing to the same per-row data model. Nothing is wired to the
response at boot yet, so a future bump of the still-provisional parts carries no compatibility cost.
Keys `1..=7` are **always** signed, plus
optional `8/9` **only when chain-bound** (both-or-neither); key `13` (the signature) is excluded from
the preimage. The signed preimage is `ANCHOR_DOMAIN ‖ canonical-CBOR({signed keys})` built with the
**same** RFC 8949 §4.2.1 shortest-form encoders the capability verifier uses, so a conformant anchor
signer matches byte-for-byte. Signature = Ed25519 (64B), verified `verify_strict` against the sealed
`anchor_root`.

| key | field | type | notes |
|----|-------|------|-------|
| 1 | `version` | uint | must == 1 |
| 2 | `chain_id` | uint | == sealed `twod_chain_id` (scope) |
| 3 | `environment_identifier` | text | == sealed `environment_identifier` (scope) |
| 4 | `epoch` | uint | authoritative freshness epoch |
| 5 | `structural_version` | uint | bumped by key/config mutations the anchor cannot reconstruct (**FROZEN v1 — see below**) |
| 6 | `marks_digest` | bytes(32) | digest of authoritative counter/spend high-water (**enclave encoder FROZEN v1; cross-component PINNED-BEFORE-ANCHOR-CO-SIGN — see below**) |
| 7 | `nonce` | bytes(32) | must echo the enclave's fresh per-(re)start challenge |
| 8 | `chain_height` | uint | **optional**, chain-backed anchor only |
| 9 | `chain_block_hash` | bytes(32) | **optional**, chain-backed anchor only |
| 13 | `signature` | bytes(64) | Ed25519 over the preimage above |

**`marks_digest` (key 6) — FROZEN v1 enclave grammar** (impl `KeystoreBody::encode_marks_payload` /
`compute_local_marks_digest`). Key 6 is a **signed** field the same-epoch `Fresh` compare consumes, so
both sides MUST derive identical bytes or every reboot fails closed (`Inconsistent` — a hard liveness
break). `marks_digest = SHA3-256("2d-hsm/agent-anchor-marks/v1\0" ‖ marks_payload)` where `marks_payload`
is hand-built **canonical CBOR** (RFC 8949 §4.2.1 — shortest-form heads, definite length, **not** the
serde body encoding which renders `[u8;N]` as int-arrays), a 4-key map:
- **key 1** → a CBOR array of counter rows, each row a CBOR **`array(4)`**
  `[authority (32-byte bstr), scope_class (CBOR major-0 uint — NOT a raw byte), scope_target (bstr,
  length-prefixed), highest_accepted_counter (CBOR uint)]`. The whole `marks_payload` is therefore a
  genuinely **decodable** canonical-CBOR document (not just a hash preimage), so the seeding slice can
  reconstruct the rows from it. Rows **sorted ascending** byte-lex on `(authority, scope_class,
  scope_target)`; `environment_identifier` is **folded out** (it equals `config.environment_identifier`
  for every row, `validate()`-enforced; the implementation also appends env as a final sort tiebreaker
  so the order stays total even if that precondition is ever violated). The `(authority, scope_class,
  scope_target)` triple is the unique row key.
- **key 2** → `cumulative_native_spend` as a fixed 32-byte bstr (u256-BE), **never** a CBOR uint.
- **key 3** → `lifetime_spend` as a fixed 32-byte bstr.
- **key 4** → `strict_recovery_counter` as a CBOR uint.

`monotonic_treasury_config_version` is **excluded** from marks (it is anchor-non-reconstructable
structural state → it drives `structural_version`; putting it in marks would let a config rollback
masquerade as an adoptable counter gap). **Genesis golden:** the empty-state `marks_payload` is the
hand-derived `A4 01 80 02 5820 00*32 03 5820 00*32 04 00` (pinned in a unit test before hashing — no
self-certifying capture). **Adopt-forward delivery:** the digest is the signed *commitment*; the actual
`marks_payload` is delivered alongside the response (separate payload — it can be large) and the seeding
slice MUST recompute SHA3-256 and check equality with the signed key 6 **before** adopting (so a
digest-only response already authenticates the later-delivered marks). **Anchor data-model requirement
(to fully FREEZE key 6):** the anchor's authoritative marks model MUST be exactly this row set
(env folded), identical sort + framing + units, at same-epoch granularity. Key 6 is promoted from
PINNED-BEFORE-ANCHOR-CO-SIGN to fully FROZEN only on the anchor team's written data-model commitment;
the enclave encoder is frozen now regardless. **Divergence runbook:** `marks_digest` is *computed*
from the sealed body, **not stored in it**, so if the anchor team's model differs before co-sign,
re-spinning the enclave encoder to match costs **no sealed-format bump** (it is not a v2→v3 migration)
— only a recompute. This is exactly why key 6 can be enclave-frozen now while the cross-component
contract stays pending.

**`structural_version` (key 5) — FROZEN v1.** A `u64` in the `pq-agent-keystore-v1` encrypted body,
init **1** (never 0 — same-epoch Fresh equality vs a forged 0-anchor; anchor baseline 1 is normative),
forward-only/never-reset, bumped by **exactly**: each committed GENERATE_KEYS and each key/config-changing
CONFIGURE_TREASURY sub-op (that handler is deferred; its sub-op classifier MUST be an exhaustive `match`
with no wildcard so a new sub-op can't default into the wrong class). MUST NOT bump on counter/spend
advances, `freshness_epoch`, `authority_epoch`, or a pure-config-version change; MUST NOT be aliased
onto `monotonic_treasury_config_version`. Overflow: `checked_add` → fail closed (never wrap).
**ATOMICITY invariant (LIVE — slice 6-4a):** the GENERATE_KEYS bump advances atomically with
`freshness_epoch` (`advance_commit_epoch`); the frame layer then computes the sealed blob FIRST
(side-effect-free) and commits exactly that `{epoch, structural, marks}` through the anchor BEFORE the
swap/emit (the "seal-before-emit" order is seal→commit→swap→emit, so a deterministic seal failure fails
closed without advancing the anchor); boot `reconcile` reads `structural_version` (structural-ahead →
`StructuralGap`). It remains behind the
off-by-default `agent-keygen-exec-preview` gate until the boot channel install (6-4b) + the request_id
idempotency/crash-reconcile proof (6-5) land and TASK-18 un-gates production keygen.

**`strict_recovery_counter` (marks key 4) — FROZEN v1.** A `u64` in the sealed body, init **0** (genuine
genesis; anchor baseline 0 normative), forward-only, encoded as a CBOR major-0 uint at marks key 4. Its
mutators (RESTORE_BACKUP + `reset_lifetime_breaker`) are **deferred**; the field + encoding are frozen
now so `marks_digest` is complete (this is `agent_capability`'s "independent strict recovery counter").

**Format bump.** Adding `structural_version` + `strict_recovery_counter` to the sealed body is
`KEYSTORE_FORMAT_VERSION 1 → 2`. v1 **never shipped a real blob** (the only seal site is the
`agent-keygen-exec-preview`-gated GENERATE_KEYS path), so v2 is a **hard bump with no v1 reader**: the
pre-decrypt `UnsupportedVersion` rejection (version is AAD-bound) is the entire migration. The frozen
golden vector was regenerated. `KeystoreBody` fields are feature-invariant (never `#[cfg]`-gated) so the
golden is single-valued across feature combos.

Strict decode (else `Malformed`): keys ⊆ `{1..=9, 13}`, no duplicates, all required present, fixed
byte-lengths exact, and keys 8/9 **both-or-neither** (a chain attestation binds to a finalized block).

**`verify_anchor_response(response_map, expected_nonce, config)`** → `AnchorState` or fail-closed:
parse → `version == 1` → Ed25519 `verify_strict` vs `config.anchor_root` → scope (`chain_id` ∧
`environment_identifier` == sealed config) → nonce echo == `expected_nonce`. Because the handshake is a
**boot-time ceremony** (not a per-request, host-probeable surface), the reject reasons are coarse
fail-closed variants — `Malformed` / `SignatureInvalid` / `ScopeMismatch` / `NonceMismatch` — **not**
the §10.9 anti-oracle band.

**`reconcile(local_epoch, local_structural_version, local_marks_digest, anchor)`** → implements §3:
`anchor.epoch < local` ⇒ `FailClosed(AnchorBehind)`; `==` ⇒ `Fresh` iff `structural_version` **and**
`marks_digest` match, else `FailClosed(Inconsistent)`; `>` ⇒ `AdoptForward{epoch}` iff
`structural_version` matches (counter/spend-only gap the anchor's marks fully describe), else
`FailClosed(StructuralGap)` — **any** structural mismatch: the normal case is the anchor ahead (a
dropped GENERATE_KEYS/CONFIGURE_TREASURY ⇒ restore from backup), and the defensive case is the
contradictory "epoch ahead but structural behind" (a forged/inconsistent anchor) which also fails
closed.

**`anchor_handshake_report_data(chain_id, environment_identifier, nonce)`** fixes the 64-byte SNP
`report_data` the enclave's handshake attestation must commit to (the concrete `treasury_id` tuple of
§3, length-prefixed env for unambiguous binding).

**Decode contract (load-bearing) — now satisfied by `agent_cbor::strict_decode_map`.** The signature
checks bind the field *values* (the re-encoded canonical preimage), not the received wire bytes (same
convention as the §10.5 capability verifier), so the decode that produces the map MUST be a strict
canonical CBOR reader or a host could submit a non-canonical encoding of otherwise-valid signed values
and have it verify. That shared reader now exists: `src/agent_cbor.rs` `strict_decode_map` (RFC 8949
§4.2.1 — rejects non-shortest integers, indefinite-length items, duplicate **or out-of-order** keys at
every nesting level, reserved/tag/float items, over-deep/over-large input, and trailing bytes;
booleans are the only `major 7` value accepted, for the capability `is_recovery`). It is **wired into
the dispatch path** (`decode_envelope` now decodes the envelope and its nested cap/payload submaps
through it), closing the residual for the privileged-command path. For the anchor path,
`verify_anchor_response_bytes(bytes, nonce, config)` is the strict-decode entrypoint the boot-wiring
slice calls (dead-code-gated until then). `agent_cbor` also unifies the int-keyed map accessors that
were duplicated across `agent_capability`/`agent_dispatch`/`agent_anchor`.

**Safety carve-out:** the reader is for untrusted host wire maps only — the sealed `pq-agent-keystore-v1`
body is serde-CBOR (a struct map, not a canonical int-keyed map) and must **NOT** be routed through it.

**Host-encoder obligation (for the boot-relay / SDK slice).** Because the enclave now *enforces*
canonical form, the legitimate host/SDK that produces these wire bytes MUST emit RFC 8949 §4.2.1
canonical CBOR: integer map keys **ascending by encoded-key bytes**, shortest-form arguments,
definite-length only. Note a plain Rust encoder (e.g. `ciborium::into_writer`) emits shortest-form +
definite-length but does **not** auto-sort map keys — it preserves insertion/struct order — so the
client must build maps in ascending-key order (for shortest-form unsigned int keys, ascending numeric
== ascending encoded-byte order, so emitting keys in numeric order suffices). A non-canonical encoding
of otherwise-valid signed values is rejected as `Malformed`. This tightening is **pre-launch** — the
agent-gateway path is feature-gated and unwired, so no deployed client needs migration.

**Decoder vs schema.** `strict_decode_map` is a *general* canonical reader (it accepts CBOR arrays and
maps up to the caps); per-message admissibility — the exact allowed key set and field types — is
enforced afterward by `check_strict_keys` + the typed accessors in each module. Invariant: keep the
decoder's `MAX_STR_LEN` ≥ the largest per-field byte cap (today 64 B) so no schema-valid field is
rejected at decode.

**Freshness-challenge (nonce) state machine — slice 2 (`agent_challenge.rs`).** The enclave's half of
the freshness handshake: `issue_challenge(chain_id, env)` draws a fresh CSPRNG nonce and installs it as
the **single outstanding challenge** in a volatile process-global (`Mutex<Option<Challenge>>`, mirrors
`INSTALLED_KEYSTORE`/`PLATFORM_PROVISIONING_ROOT`); `Challenge::report_data()` **computes** the
`report_data` the SNP quote will commit to from that *same* draw (nothing is attested until the
deferred quote fetch). `verify_outstanding_response(response, config)` is the **safe verification
primitive** — it `take()`s the challenge **before** verifying against its nonce, so single-use is
*structural* (the challenge is retired on **every** outcome: success, anchor error, or no-challenge) and
there is **no non-consuming peek** to misuse; `consume_outstanding_challenge() -> Option<Challenge>` is
the explicit retire for the no-response (timeout) path. Decisions: **overwrite-on-reissue** (a
re-issuable per-restart token, not an install-once secret — a failed handshake rotates to a fresh nonce,
never retries the same), **poison-recover** uniformly (a non-secret slot must not brick the agent), and a
structural **volatile-only anti-invariant** — `Challenge` is deliberately **non-`Serialize`/`Deserialize`**
so the nonce can never enter sealed/persisted/cached state (the public nonce *does* transit the host
transiently to reach the anchor, but is never stored, sealed, or reused); a restart MUST lose it and force a fresh draw
(otherwise a host that rolls back sealed state could replay a captured `(nonce, response)`). **Boot-slice
obligations (deferred):** `issue_challenge` runs **after** unseal, once per (re)start; the `(chain_id,
environment_identifier)` passed to `issue_challenge` MUST equal the sealed config the response is later
verified against (verify binds scope to the config, not to the challenge — naming this cross-check as an
explicit boot invariant); the boot caller verifies via `verify_outstanding_response` (which retires
atomically) and a retry re-issues, never re-uses a nonce. **Single-slot is intentionally boot-only:** a
future *per-op* freshness scheme would need a keyed/multi-slot redesign + a concurrency guard, not an
extension of this single-outstanding slot. Per-instance only — no clone fencing (design §3 Option A
residual).

**Boot reconcile orchestration — slice 5a (`agent_boot.rs`).** The pure, platform-free *glue* that
sequences the three primitives above into the one canonical boot ceremony, decomposed out of the
platform-coupled boot wiring (5b) so it is unit-testable now. `boot_reconcile_anti_rollback(response_bytes,
body)` runs: (1) `verify_outstanding_response` (retire-then-verify against the sealed `anchor_root` +
scope + issued nonce), (2) `compute_local_marks_digest` over the sealed counters/spend, (3) `reconcile`
the local `(freshness_epoch, structural_version, marks)` vs the verified `AnchorState` — and collapses the
result into a single `BootAntiRollbackOutcome { Ready(state) | AdoptForwardRequired(state) |
FailClosed(reason) }`. Two wildcard-free mappers flatten the verify-stage (`AnchorError`) and
reconcile-stage (`FailReason`) errors into the boot-time `BootFailReason` enum (a new upstream variant is
a compile error here, not a silent fall-through). **The live Layer-2b binding
(`install_anti_rollback_binding`) is installed ONLY on the `Fresh` arm** — `AdoptForward` returns
`AdoptForwardRequired` *without* installing (5b owns the seed-from-marks + re-seal-forward + retry), and
every fail path installs nothing. Four independent properties enforce never-install-off-`Fresh`:
binding-literal-constructed-in-arm-only, exhaustive wildcard-free `match`, const-init `None` fail-closed
default, and the callee's install-once + reject-inactive. Still **UNWIRED** (dead-code-gated): 5b adds the
only caller. 13 unit tests cover every arm + the no-install sweep, driving the real challenge/binding
process-globals (all crate tests touching either global now serialize on one shared
`AGENT_PROCESS_GLOBAL_TEST_GUARD` since `agent_boot` exercises both).

**Out of this slice (next, platform/host plumbing — slice 5b/6):** the actual SNP-quote fetch (the
enclave half of the *mutual* auth — slice 2 only fixes the value the quote commits to), the vsock host
relay that delivers `response_bytes`, the at-boot call sequencing (`issue_challenge` after unseal → relay
→ `boot_reconcile_anti_rollback` → act on the outcome), the `AdoptForward` seed-from-marks + re-seal
forward, and per-op `epoch` bump + seal-before-emit atomic with the structural bump. The
live-GENERATE_KEYS un-gate (TASK-18) depends on that durable commit.

**Slice 5b contract — load-bearing obligations (pinned here after the 5a Full Matrix review):**
- **AdoptForward marks authentication (security-critical).** The `marks_digest` in the verified
  `AnchorState` is a SHA3 hash — non-invertible — so the *raw* counter/spend marks 5b seeds the body
  from must arrive over a **separate authenticated channel** (a second `anchor_root`-signed query, or
  extra signed fields, bound to the same scope + freshness nonce — to the same rigor as the freshness
  response). Before re-sealing, 5b MUST assert **`hash(adopted_marks) == state.marks_digest`** (NOT only
  the weaker `adopted ≥ local`): without the hash-equality check a malicious host could supply forged
  marks (arbitrarily large but `≥ local`) to inflate spend limits, bypassing the anchor entirely. **Until
  that signed raw-marks channel is specified and implemented, `AdoptForward` MUST be treated as
  fail-closed (operator intervention), not auto-adopted.**
- **Retry re-runs the FULL sequence, bounded.** `verify_outstanding_response` consumes the challenge on
  every outcome, so recovering from `AdoptForwardRequired` (or any transient) is NOT a same-bytes
  re-call: 5b must `issue_challenge` afresh → new SNP quote → new anchor round-trip → new
  `response_bytes` → `boot_reconcile_anti_rollback`. The retry loop MUST be **bounded** (fail closed
  after N attempts) so a continuously-advancing anchor cannot cause an infinite boot loop.
- **Non-`Ready` handling.** On any non-`Ready` outcome 5b MUST NOT begin serving rollback-sensitive
  frames. `FailClosed(BindingInstall)` specifically signals an enclave-internal sequencing defect (the
  ceremony ran twice) — treat it as **fatal/abort**, not operator-recoverable; note that the pre-existing
  (first, valid `Fresh`) binding legitimately stays configured, so the fault is "ran twice", not "gate
  left open by a failure".
- **`active` semantics.** The Fresh-arm binding sets `active: true` to mean "a `Fresh` reconcile
  occurred this boot"; there is no anchor-reported per-instance liveness field in `AnchorState` yet
  (design §3 Option A has no clone fencing), so `active` is not yet a liveness signal — a future Option-B
  upgrade that fences concurrent attestations would supply it.
- **Challenge↔config scope cross-check.** `boot_reconcile_anti_rollback` binds the *response* scope to
  `body.config` and the nonce to the challenge, but the challenge's own `(chain_id, environment_identifier)`
  (which fed the SNP `report_data`) is the boot caller's to match against `body.config` — 5b MUST issue
  the challenge with exactly the sealed config's scope so the quote and the verified response commit to
  the same `(chain_id, env)`.

**Boot-handshake driver — slice 5b-1 (`agent_boot_driver.rs`).** The bounded, retrying loop one layer
above the single-shot `boot_reconcile_anti_rollback`, decomposed out of the platform-coupled 5b so it is
unit-testable now. The **one platform dependency** is the `AnchorBootTransport` trait (single method
`anchor_round_trip(request: &AnchorBootRequest) -> Result<Vec<u8>, AnchorTransportError>`): 5b-2's impl
fetches an SNP quote committing to `request.report_data` (`snp_report::fetch_report`) then relays it +
the public challenge to the anchor over the untrusted host and returns the signed response **bytes**
(UNTRUSTED — handed straight to `boot_reconcile_anti_rollback` to strict-decode + Ed25519-verify). The
seam carries the **public** `AnchorBootRequest { chain_id, environment_identifier, nonce, report_data }`
— NOT `report_data` alone: `report_data` is a non-invertible SHA3-512 commitment, but the anchor must
*echo* the cleartext nonce + scope in its signed response (`verify_anchor_response` checks them), so it
needs them in cleartext (they transit the host to the anchor regardless). It is still *transport, never
trust*: every field is public, the scope is the sealed config's (the anchor binds it via `report_data`,
which the anchor recomputes and checks against the quote), it cannot choose the verify key, and a
tampered response simply fails verification downstream. `run_boot_anti_rollback_handshake(transport,
body, max_attempts)` loops `for _ in 1..=max_attempts`
(structurally bounded — no `loop{}`): issue a fresh challenge (scope from `body.config`) → `anchor_round_trip`
→ `boot_reconcile_anti_rollback` → classify into `BootDriverOutcome { Ready(state) | FailClosed(BootDriverFail) }`.
The driver **installs nothing** (reconcile installs on its `Fresh` arm) and **does not serve**.
- **Retry classification (anti-grind, load-bearing).** ONLY `AnchorTransportError` is retryable
  (transient liveness). **EVERY** `BootFailReason` and `AdoptForward` are TERMINAL — in particular the
  host-reachable verify verdicts (`VerifyMalformed`/`VerifyScopeMismatch`/`VerifyNonceMismatch`/
  `VerifySignatureInvalid`) are NOT retried, denying a malicious/buggy host a grind lever to stall boot
  or fish for a serve decision across the budget. `AnchorBehind`/`StructuralGap`/`Inconsistent`/
  `BindingInstall`/`NoChallenge` are deterministic given this body. `AdoptForward` is returned
  immediately as `AdoptForwardUnsupported(state)` (§8 fail-closed; never looped). Exhausting the bound on
  transport flaps → `RetriesExhausted`; `max_attempts == 0` **or above the defensive module ceiling
  `MAX_BOOT_ATTEMPTS_CEILING` (64)** or a CSPRNG failure → `Unstartable`. (5b-2 *may* reclassify ONLY
  `AdoptForward` — once the signed raw-marks channel lands it becomes execute-then-re-run-to-`Fresh`;
  `AnchorBehind` stays TERMINAL — a rolled-back/inconsistent anchor is an operator condition with no
  authenticated recovery, not a retry/reclassify candidate.) Recommended operating bound:
  `max_attempts = 5`, a bin-side const — never host/env-configurable; the module ceiling (64, a generous
  backstop ≫ the operating 5 so it never interferes, while still capping a pathological `u32::MAX`)
  makes the "infinite-loop impossible / soft-DoS bounded" property self-contained even if a caller passes
  a pathological count. **The transport impl (5b-2) MUST enforce a per-call timeout** — the driver bounds
  attempt COUNT, not wall-clock, so a hung relay would otherwise stall boot.
- **Fused serve decision `decide_serve` (the 5b-2 entry point).** Rather than leave the serve ordering to
  5b-2 prose, 5b-1 exports `decide_serve(outcome: BootDriverOutcome, require_real) -> Result<AnchorState,
  ProtocolError>`: **every `FailClosed` is rejected unconditionally** in all builds (including
  `BindingInstall`, which can leave a *prior* valid binding configured so the gate alone would wrongly
  pass), and ONLY `Ready` proceeds to the second, independent gate. 5b-2 calls `decide_serve(outcome,
  cfg!(release_build))?` — the unsafe "handshake → gate → serve without an outcome branch" wiring is
  **unrepresentable**, and the composition is **tested now** (the codex prior-binding case included). The
  inner `agent_anti_rollback_serve_gate(require_real, anti_rollback_configured)` follows the same
  fail-closed shape as `snp_attestation_boot_gate` but has NO production transport-only allowance
  (anti-rollback is mandatory in release): the ONLY fail-closed cell is `(require_real=true,
  configured=false)`. It reads the **installed-binding flag** (`is_anti_rollback_configured()`), NOT the
  outcome, so even a driver bug returning `Ready` fails closed in production. (The standalone gate stays
  exposed for the *anti-rollback-not-wired* deployment, which has no outcome to branch on.) **Scope:** in
  release `decide_serve` is a **whole-service boot prerequisite** (don't begin serving at all without
  `Ready`); the runtime per-opcode gate (`anti_rollback_satisfied`) is the independent second layer that
  blocks rollback-sensitive opcodes regardless. **Precondition:** the boot ceremony is single-threaded
  over the `OUTSTANDING_CHALLENGE`/`ANTI_ROLLBACK_BINDING` process-globals — 5b-2 MUST NOT run the
  handshake concurrently with any other challenge consumer (the fresh-per-attempt + consume-on-exit
  invariants assume it).
- **`NoChallenge` is structurally unreachable in the driver** (terminal only as defense-in-depth): the
  driver issues a fresh challenge immediately before each reconcile and the transport-error path
  consumes-then-reissues, so on a single-threaded boot the reconcile path never sees an empty slot.
- **§8 obligations now SATISFIED by 5b-1** (pure, 26 unit tests against a mock transport): bounded
  full-sequence retry, fresh challenge per attempt, scope-from-`body.config`, `AdoptForward` fail-closed,
  non-`Ready` no-serve (via `decide_serve`, including the `BindingInstall`-with-prior-binding case),
  serve-gate table.

**Boot-relay wire protocol + transport seam — slice 5b-2a (`agent_boot_relay.rs`).** The pure,
CI-testable half of the platform transport. **Request** = a `MessageType::AgentBootRelay` (`0x41`, in the
reserved `0x40..0x4F` agent band; never serve-dispatchable — `decode_wire_command` fail-closes it) frame
carrying a canonical integer-keyed CBOR map: `{1: relay_request_version=1, 2: chain_id, 3: env, 4: nonce
(32B), 5: report_data (64B), 6: quote_report, 7: cert_chain}`; cert_chain bounded by
`snp_report::MAX_CERT_CHAIN_LEN` (64 KiB, single source) and the frame by `MAX_MESSAGE_SIZE`. **Response**
= the raw anchor-signed bytes **verbatim** behind a single 4-byte BE length prefix (no re-encode — that
would break `agent_anchor`'s "signature binds exact wire bytes" property; the enclave never parses anchor
internals), read by `read_bounded_anchor_response` which checks `MAX_ANCHOR_RESPONSE_LEN` (4096) **before
allocating** (no OOM from a hostile relay). Two seams, **both deadline-aware**: `BootQuoteProducer`
(`fetch(report_data, deadline)`) and `BootRelayChannel` (`round_trip(frame, deadline)`, fresh connection
per call for stale-reply isolation). `RelayAnchorTransport<Q, C>` gives **each leg its own `timeout`
deadline** (a fresh `Instant::now() + timeout` computed just before each) — so a hung quote can't stall
boot AND quote latency can't starve the channel's budget (no false channel timeout). Per-attempt
wall-clock is ≤ 2×timeout for a freshness attempt, ≤ 3×timeout for an adopting one (5b-2e: the
`marks_round_trip` is a third per-leg-bounded leg); the driver's per-attempt COUNT bound caps total boot. It is the concrete
`AnchorBootTransport` composing fetch-quote → encode-request → channel-relay → return raw bytes; every
failure folds to the
coarse always-retryable `AnchorTransportError`. **No nonce-precheck** (a precheck-to-retryable would
downgrade a genuine terminal `VerifyNonceMismatch` into a grind lever); a garbage/wrong-nonce reply is
safe (terminal downstream). 25 unit tests incl. the FULL composition through the 5b-1 driver + 5a verify
(mock channel + fake quote). `decode_anchor_boot_request` (for the untrusted host relay + tests) is
hardened — no-trailing-bytes, integer-key rigor (range + no-dup), exact field lengths, `cert_chain`
bound, and the `report_data == anchor_handshake_report_data(chain,env,nonce)` binding — but is NOT an
enclave trust boundary (the enclave only *encodes* requests and *verifies* responses), and deliberately
uses a **lenient** CBOR decode rather than the 4 KiB-per-string strict decoder, since a legitimate
request carries a multi-KiB cert chain (the request is not signature-bound, so byte-level canonicality is
not load-bearing). The response framing has a single shared writer (`frame_anchor_response`) so the host
relay and the reader can't drift.

**Wire-spec registry (synced in 5b-2a):** `MessageType::AgentBootRelay = 0x41` is now registered in the
source-of-truth `vsock-api-wire-format-spec-draft.md` §10.1 (allocated in the `0x40..0x4F` agent band;
enclave-initiated; NOT serve-dispatchable; unknown-frame coverage moved to `0x42`). **Canonicality
contract:** the enclave encoder MUST emit canonical CBOR (it does, via the `put_*` helpers); the host-relay
*decoder* MAY be lenient after semantic validation (the request is not signature-bound). A canonical
request golden vector is a 5b-2b test-vector item.

**Still 5b-2 platform/host, split into ordered independently-gated slices (aya/SNP):**
- **5b-2b — transport + quote leaf**, split into a CI-testable core (5b-2b-i) and the OS-syscall leaf
  (5b-2b-ii) because **CI has no live vsock env** (the framing/deadline/cleanup logic therefore lives
  OUTSIDE that gate so it is exercised by ordinary `cargo test`). Since 5b-2b-ii PR-A (#55) CI **compiles
  AND RUNS** the gate's deviceless tests (`cargo test --features vsock-transport,agent-gateway` on the
  Linux runner — this executes the `cancellable_boundary` unit tests, incl. the poll-lapse and
  connect-predicate pins the (a') coverage notes lean on) — but the `#[ignore]` vsock-device tests still
  never run in CI (those run on aya):
  - **5b-2b-i DONE — MERGED PR #53** *(HISTORICAL RECORD as merged — the deadline half described below
    is GONE since (4a); see the bolded correction at the end of this bullet before acting on any
    signature/entrypoint named here)* **(CI-tested in the default + `agent-gateway` builds, NOT behind `vsock-transport`):**
    `snp_report` deadline-aware quote fetch via a `TsmFs` fs-seam — `fetch_report_with(fs, report_data,
    deadline: Option<Instant>)` (`Some` ⇒ fast-path past-deadline → no fs + per-step `check_deadline`;
    `None` ⇒ unbounded; **unconditional entry cleanup on every path incl. mid-sequence timeout** so no
    stale `twod-hsm` configfs entry leaks). `fetch_report` is a refactor-only wrapper that stays
    **UNBOUNDED** (`None`) — the producer GET_MEASUREMENT path keeps its historical no-timeout contract,
    so this slice does NOT silently impose a wall-clock bound on the unrelated producer measurement; only
    `fetch_report_deadline` (the agent boot-relay entrypoint) is bounded. `agent_boot_relay` framing core
    `relay_round_trip_over_stream<S: Read+Write>` + host-relay forward core `relay_forward_once<E,A>`
    (reject-malformed-before-anchor-round-trip; shared `frame_anchor_response` writer; **both cores check
    the deadline at every read AND before each `write_all`/`flush` leg** — symmetric, so a lapsed budget
    never initiates a write; the blocking `write_all` already in flight still needs the socket's
    `SO_SNDTIMEO`, a 5b-2b-ii obligation) + `SnpQuoteProducer` (delegates to `fetch_report_deadline`, honoring the deadline
    **cooperatively/between-steps only** — a single wedged in-kernel read is bounded by the deferred
    cancellable-boundary hard-bound, NOT this deadline; see the deadline bullet below). **(Historical
    record — the deadline half is GONE: (4a) deleted `fetch_report_deadline`, `SnpQuoteProducer`, the
    `Option<Instant>` plumbing and its deadline tests; `fetch_report_with(fs, report_data)` is now
    unbounded-only. The 22-test count is as-of PR #53.)** The pure relay/serve
    port resolution lives in the **gate-free `vsock_addr` module** (NOT `vsock_listen`, which is gated
    `vsock-transport` and now holds only the socket-binding leaf + a re-export of `vsock_listen_addr_from_env`
    for the bins): `DEFAULT_ANCHOR_RELAY_PORT=5001` (`VMADDR_CID_HOST=2`) + `anchor_relay_port_from_env()`
    over the shared `serve_vsock_port_from_env` + pure `validate_relay_port` (rejects 0 + same-as-serve-port).
    Splitting it out of `vsock_listen` is what makes the port validation actually CI-tested — it was
    previously trapped behind the never-compiled `vsock-transport` gate. **22 CI tests** (10 relay +
    9 `snp_report` seam + 3 `vsock_addr`; all run under `cargo test --features agent-gateway`; the
    `snp_report` + `vsock_addr` subset of 12 also runs in the bare `cargo test` default build): seam full-sequence cleanup on every error leg
    (create/write/outblob/mid-sequence-timeout) + fast-path + unbounded-None, framing/forward round-trips
    over in-memory duplexes incl. pre-write-deadline guards on both cores, oversize/malformed-pinned
    rejection, cap-before-alloc outblob/auxblob reads, fast-path quote no-hang, `validate_relay_port` +
    `validate_vsock_listen_addr`.
  - **5b-2b-ii (aya leaf)** — independently-reviewable sub-items (split so a single PR doesn't mix vsock
    integration, daemon fault semantics, and acceptance infra; review each obligation on its own). The
    rule's load-bearing intent is **keep (b) daemon fault-semantics out of the vsock-integration PR** —
    preserved: (b) is still open. PR #54 co-landed (0)+(a)+(c) because (0) is a test-only frozen vector and
    (c) is a one-line CI guard for (a) — neither is a separate review surface from the channel; (b) was NOT
    bundled. Status: **(0)+(a)+(c) DONE (PR #54); (a') DONE (PR #56); (d) DONE (in-guest quote smoke
    PASS, `run_boot_handshake_wired` landed); (b) host-relay daemon LANDED (`run_host_anchor_relay` +
    `twod-hsm-host-anchor-relay` bin — see the (b) decision record below). Live serve now gated on
    5b-2c ALONE.**
    - **(0) canonical golden vector — DONE PR #54 (BLOCKS (a)+(b)):** committed
      `testvectors/agent-gateway/boot_relay_anchor_handshake_v1.frame.bin` (+ `.json` manifest with a
      hand-auditable byte breakdown); the agent-gateway CI test asserts byte-exact `encode==golden` AND
      `decode(golden)==inputs` AND canonical layout. **Ordering inversion (intentional,
      annotated):** the decode-leniency-relevant code (`relay_forward_once` + `decode_anchor_boot_request`)
      already landed in 5b-2b-i, asserted against frames from the *canonical encoder*
      (`encode_anchor_boot_request` — the vector's source of truth), so the in-crate production path is
      correct NOW; the frozen-bytes regression anchor for external/separate-service reimplementation is
      added in (0). So: invariant *asserted via the in-crate encoder in 5b-2b-i; frozen-bytes anchor added
      in 5b-2b-ii(0)* — (0) precedes the channel/daemon, not the already-merged 5b-2b-i core.
    - **(a) channel socket wrapper — DONE PR #54** ((c) is a SEPARATE obligation that landed in the same PR,
      tracked below — not "part of" (a)): the concrete
      `VsockBootRelayChannel` (fresh connection per call, RAII-dropped; originally a blocking
      `VsockStream::connect_with_cid_port` — SUPERSEDED by (a')'s `connect_bounded`, which is now the only
      connect path) → a `DeadlineSocket` wrapper that **reapplies `SO_RCVTIMEO`/`SO_SNDTIMEO` = the budget
      remaining to the deadline before EVERY read/write** (tight per-syscall bound — satisfies the
      "Exact-bound caveat" below: no once-set socket timeout, so a late syscall can't overrun the leg) →
      `relay_round_trip_over_stream`; blanket-maps all `ProtocolError`→retryable. Compile- AND runtime-
      validated on aya (real vsock loopback: happy round-trip, prompt connect-failure, stalled-peer
      read-timeout — all `#[ignore]`). **Connect bound: cancellable hard bound (a') — DONE PR #56** (the
      original PR #54 connect used a watchdog-thread soft-bound; that is now SUPERSEDED — historical note
      below). **(a') cancellable hard connect bound — DONE PR #56:** [`connect_bounded`] creates a NON-blocking
      vsock `SOCK_STREAM` fd directly (`nix::sys::socket`) and waits via
      `cancellable_boundary::poll_with_deadline(POLLOUT, deadline)`; on a deadline lapse the `poll` returns and
      the `OwnedFd` drops in-scope (closing the fd, aborting the connect) — **no watchdog thread, no leaked
      fd**, eliminating the earlier `max_attempts`-bounded thread+fd leak. Its OWN item, NOT collapsed into the
      quote (d) bound. **Acceptance criteria (all MET):** (1) NON-blocking vsock `SOCK_STREAM` fd via
      `nix::sys::socket::socket(AddressFamily::Vsock, SockType::Stream, SOCK_NONBLOCK|SOCK_CLOEXEC, None)` —
      NOT vsock 0.5's `VsockSocket` (that is `SOCK_DGRAM`); (2) `connect` (expect `EINPROGRESS`; **`EINTR`
      fails FAST via the catch-all, it is NOT routed to the poll path** — af_vsock's signal path CANCELS an
      interrupted connect (state → `TCP_CLOSE`, transport `cancel_pkt`, `sk_err` left 0) and a cancelled vsock
      socket polls as bare clean `POLLOUT`, so polling after `EINTR` would bless a never-connected socket as
      success; unreachable for an `O_NONBLOCK` connect anyway — the kernel returns before any interruptible
      wait); (3) `poll_with_deadline(&fd, POLLOUT, deadline)`; (4) **connect-success check =
      `connect_poll_succeeded(revents)` AND `getsockopt(SocketError)==0`** (a bare `Ok(_)` is NOT success —
      the predicate's definition/rationale lives in its rustdoc in `cancellable_boundary`, the single source;
      **keep BOTH checks**: on AF_VSOCK a refused/timed-out connect surfaces `POLLERR|POLLOUT` (no `POLLHUP` —
      vsock gates `EPOLLHUP` on *local* shutdown, unlike inet) so the predicate alone already vetoes it, but
      `SO_ERROR` is the *authoritative, portable* connect result (Stevens UNP: a clean `POLLOUT` with
      `SO_ERROR != 0` exists across stacks), so the `SO_ERROR` read is the robust belt-and-suspenders, not
      dead code to "simplify away"). **Which arm runs which check:** `connect_poll_succeeded` gates ONLY the
      polled-completion arm (`EINPROGRESS` → `poll(POLLOUT)` → inspect `revents`); the synchronous
      `connect → Ok(())` arm has no `revents` and is validated by `getsockopt(SO_ERROR) == 0` ALONE. The
      predicate is **deliberately connect-scoped — `POLLOUT` is hardcoded, there is no `want` parameter** (as
      this AC originally specced via `connect_succeeded`): the `POLLHUP` veto is connect-specific correctness,
      and on a pipe READ (the future (d) quote-subprocess fd) `POLLHUP` is a *normal EOF* that can carry final
      data (`POLLIN|POLLHUP`) — (d) must build its own EOF-aware `POLLIN` check, and the scoped signature
      makes reusing this one impossible rather than comment-guarded (`poll_with_deadline` itself stays shared:
      it returns raw `revents`, the caller decides); (5) promote the
      `OwnedFd` to `VsockStream` via `From<OwnedFd>`, then `set_nonblocking(false)` so `DeadlineSocket`'s
      `SO_*TIMEO` take effect; RAII fd drop on every path — no thread, no leak. Needs the nix `socket` feature
      alongside `poll` (both added; plus `fs` — the nix feature gating `fcntl()`/`OFlag` — for the readback test below). aya acceptance (re-run on the
      rewritten `poll(POLLOUT)` `connect_bounded`, not inherited from the deleted watchdog path) — **be
      precise about WHICH failure mode each test proves**: (i) connect-to-a-no-listener-endpoint fails
      **promptly** and folds to a retryable error — kernel reality: the refusal lands as `sk_err=ECONNRESET`
      → an *immediate* error-ready poll wake (`POLLERR|POLLOUT`) → the **`connect_poll_succeeded` veto arm**
      (error string `"anchor relay: vsock connect failed (poll)"`; the synchronous and `SO_ERROR` arms are structurally
      unreachable for a refusal — `vsock_connect` holds the sock lock and the REQUEST tx is workqueued), and
      the test's elapsed bound is BELOW the deadline so it genuinely discriminates prompt-refusal from a
      lapse; (ii) a loopback connect round-trips; (iii) stalled-peer **read** times out within budget
      (behavioral `SO_RCVTIMEO` bound); (iv) **blocking-mode + arming asserted DIRECTLY** (the
      `vsock_connect_restores_blocking_and_arms_so_timeo` test): `F_GETFL` confirms `O_NONBLOCK` is cleared
      after `connect_bounded` (a busy-spin via `WouldBlock`-retry would otherwise pass the behavioral tests
      on wall-clock alone), and `DeadlineSocket::arm_*`'s `SO_RCVTIMEO`/`SO_SNDTIMEO` values are read back
      via SAFE nix getsockopt. The **deadline-lapse on a genuinely-wedged in-flight connect** is the one mode
      a HOST-side real-vsock aya test CANNOT exercise (host→nonexistent CID fails synchronously
      `ENODEV` in `vhost_transport_send_pkt` — no `EINPROGRESS`, no black hole) — the lapse test MUST
      be IN-GUEST and
      MUST use a deadline **shorter than the kernel's ~2s `VSOCK_DEFAULT_CONNECT_TIMEOUT`** (or raise
      `SO_VM_SOCKETS_CONNECT_TIMEOUT`), because the kernel's own connect timer otherwise fails the socket
      with `ETIMEDOUT` (→ the veto arm, NOT the lapse arm) first; it IS covered structurally by the
      `cancellable_boundary::poll_times_out_when_not_ready`
      unit test (poll returns at the deadline, no hang; CI-run, deviceless) + RAII drop. **Status:
      implementation + prompt-refusal/round-trip/read-timeout/blocking-readback VERIFIED on aya; the
      in-flight-connect black-hole lapse test is now IMPLEMENTED as `quote_smoke` phase `vsock-lapse`
      ((4c): in-guest guest→nonexistent-CID probe through the quadruple-gated `connect_bounded_for_smoke`
      shim, 400ms deadline, lapse-arm const asserted exactly) — **PASSED on aya 2026-06-11 (2 SNP runs,
      RESULT PASS phases=7; the lapse fired at ~399ms — our deadline, not the ~2s kernel timer — after a
      floor-slop fix absorbing poll(2)'s whole-ms truncation)**; the
      checked-residual box below tracks it.** **HARD PRECONDITION for a live 5b-2c serve
      (mirroring (d)) — SATISFIED:** (a') is landed, so 5b-2c no longer needs the risk-acceptance fallback for
      the connect leg. *(Historical: the PR #54 watchdog soft-bound was bounded by the deadline via
      `recv_timeout` but leaked one thread+fd per truly-wedged connect, bounded by `max_attempts`; that path is
      now removed.)*
    - **(b) host relay daemon:** a feature-gated **`pub fn run_host_anchor_relay(...)` wrapper in the
      LIBRARY** whose serial loop, per pump, READS + DECODES the enclave request FIRST (so a malformed
      frame never burns a TCP connect — the canonical read-decode-before-dial order; see the (b) record),
      THEN dials the anchor, THEN forwards verbatim by composing the SHARED `pub(crate)` cores
      (`read_framed_message_with_idle_deadline` + `decode_anchor_boot_request` +
      `relay_round_trip_over_stream` + `frame_anchor_response` + `deadline_guarded_write`) — NOT by calling
      `relay_forward_once` (which dials-first / reads internally, the wrong order here). The
      `host_anchor_relay` bin is a thin caller of the wrapper because a Cargo `[[bin]]` target is a separate
      crate and CANNOT call those `pub(crate)` cores directly (it would otherwise duplicate the
      framing/decoder and risk codec drift). The wrapper owns the Err→close mapping + operator-triage
      logging (oversize/malformed/timeout) + a **serial accept loop** (one deadline-bounded pump at a time;
      revisit only if concurrent enclave boots need it) — see the host-relay daemon requirement below.
      **Anchor-facing CONNECT timeout (required, symmetric with (a)):** the daemon's upstream-anchor socket
      MUST set a connect timeout in addition to `SO_RCVTIMEO`/`SO_SNDTIMEO` — `connect()` is bounded by
      NEITHER `SO_*TIMEO` nor `relay_forward_once`'s in-fn deadline (which operates on already-connected
      streams), so with the serial loop a black-holing anchor that stalls on connect would wedge the ENTIRE
      daemon (head-of-line-blocking every queued enclave boot). **DECISION ITEM (ordered BEFORE (b)'s
      connect-bound work): pin the anchor transport.** The connect-bound SHAPE is transport-determined, so
      (b) cannot be scoped or reviewed until "TCP or UDS" is decided — record the choice here when (b)
      starts. **HOW to bound it is transport-conditional —
      do NOT hand-copy `connect_bounded`'s sequence:** the anchor leg is TCP-or-UDS (the anchor is a separate
      service; the vsock leg is enclave-facing only). If **TCP**: use `std::net::TcpStream::connect_timeout`
      (it performs the whole nonblocking→poll→`SO_ERROR`→restore-blocking dance internally — no hand-rolling).
      If **UDS**: std has NO `UnixStream` connect-timeout, and a non-blocking AF_UNIX connect that would block
      returns **`EAGAIN`, not `EINPROGRESS`** (connect(2)) — so `connect_bounded`'s `EINPROGRESS`→`poll(POLLOUT)`
      finish sequence is the WRONG shape there; treat `EAGAIN` as a retryable fail-fast (UDS connects are
      local and either succeed immediately or the listener backlog is full — and the daemon's pump loop must
      treat that retryable as "this pump failed, serve the next queued boot", i.e. backlog pressure surfaces
      as a per-pump retry, not an ambiguous daemon-level failure). Only a vsock anchor leg (not a
      realistic deployment) would reuse `connect_bounded`'s sequence — extract it from (a') then, never
      hand-roll (the `getsockopt(SO_ERROR)` check and the `set_nonblocking(false)` restore are both mandatory
      and are exactly the steps a copy drops). **Blast-radius note (explicit non-goal):**
      under the serial loop a slow/wedged pump delays every queued boot by ≤ (per-pump deadline + socket +
      connect timeouts); those bounds are what keep it tolerable — concurrency (and accept-backlog limits)
      is the named follow-up trigger if many enclaves boot at once.
      - **(b) LANDED — decision record (TASK-7.7 5b-2b-ii(b)):** shipped `pub fn run_host_anchor_relay()
        -> Result<Infallible, Box<dyn Error>>` (lib, triple-gated `linux ∩ vsock-transport ∩
        agent-gateway`) + the thin `twod-hsm-host-anchor-relay` bin (`required-features =
        ["agent-gateway","vsock-transport"]` — NOT `lab-quote-smoke`, NOT
        `production-vsock`/`staging-vsock`: those pull `ml-dsa-65` → the role-isolation `compile_error!`).
        The daemon binds AF_VSOCK `VMADDR_CID_ANY` on the relay port, accepts SERIALLY, and per pump
        reads+decodes the enclave request FIRST, then dials the anchor, then forwards verbatim via the
        `pub(crate)` cores — close-on-any-fault, NEVER synthesizes bytes, NEVER dies.
        - **Anchor transport = TCP** via `std::net::TcpStream::connect_timeout` (the whole
          nonblock→poll→`SO_ERROR`→restore-blocking dance is internal — no `nix`, no `unsafe`, clean under
          `#![forbid(unsafe_code)]`; NOT `connect_bounded`'s vsock poll-sequence). Isolated behind a
          one-method `AnchorDial` trait. **UDS deferred** behind that trait, with the
          **`EAGAIN`-not-`EINPROGRESS`** hazard recorded ON THE TRAIT DOC: a future UDS impl must treat a
          would-block `EAGAIN` as a retryable per-pump fail-fast, must NOT copy `connect_bounded`'s
          `EINPROGRESS`→`poll(POLLOUT)` finish sequence, and must keep the `getsockopt(SO_ERROR)` +
          `set_nonblocking(false)` restore a naive copy drops. UDS is documented, NOT built (one TCP impl
          ships — the seam advertises forward-compat the code does not exercise; stated plainly, no
          structural over-claim).
        - **Env knob** `TWOD_HSM_ANCHOR_ENDPOINT` (+ legacy `2D_HSM_ANCHOR_ENDPOINT`) = a `host:port`
          string, **NO default** — a missing/empty value is a fail-closed boot error naming the var (never
          a silent localhost guess; §8 profile-uniformity). Resolved ONCE at startup via `to_socket_addrs`
          (DNS names work) into a `Vec<SocketAddr>` (the dialer tries each); per-pump dials never re-do
          DNS. The resolver `anchor_endpoint_from_env()` lives gate-free in `vsock_addr.rs` so its
          fail-closed/resolve logic is CI-tested in the default/agent-gateway build (no vsock dep).
        - **Budget — single source, NO new operator knob.** `PUMP_BUDGET` (10 s) is a **HEAD-OF-LINE
          bound** (prevents a wedged pump blocking the serial loop), NOT the boot bound — the enclave owns
          `max_attempts·(3·timeout+ε)` (quote + freshness + marks legs, 5b-2e); the daemon carries NO ε, NO producer, NO budget arithmetic. The
          connect timeout + `SO_RCVTIMEO`/`SO_SNDTIMEO` are DERIVED from `PUMP_BUDGET` (a floored fraction),
          never separate knobs. HONEST coordination caveat: "same source" means matching consts sized to
          the same boot-handshake envelope, NOT a shared runtime value (different process — the daemon does
          not receive the enclave's per-leg timeout over the wire).
        - **`relay ⊇ anchor` leniency = a cross-component sync OBLIGATION, not a claimed fact.** With a
          SEPARATE external anchor, the relay-side `decode_anchor_boot_request` must stay at least as
          lenient as the anchor's acceptance — else a request the anchor WOULD honor becomes a relay
          Err→retryable close that silently burns the enclave's attempt budget toward a FALSE terminal. The
          5b-2b-ii(0) golden vector freezes only the CANONICAL request (production path safe); the broader
          superset is defense-in-depth NOT regression-protected. Differential/property tests vs the real
          anchor tracked SEPARATELY.
        - **Never-synth is BEHAVIORAL, not structural:** enforced by RAII close + the absence of any
          error-path write (the response write-back is the ONLY enclave write, reached only on full
          success). Deviceless tests assert ZERO anchor-looking bytes reach the enclave on every fault
          class. **Never-die:** every per-connection fault = log (`let _ = writeln!`, NEVER `eprintln!`,
          which panics on broken stderr and would kill the serial daemon) + close + serve next; the only
          `run_host_anchor_relay` exits are the STARTUP config/bind faults. Deviceless tests 1-11 + the bin
          acceptance test pass (Linux CI under `agent-gateway,vsock-transport`); the real-vsock-loopback
          aya test (bind-CID `CID_ANY` reality) stays `#[ignore]`, landing with 5b-2c bring-up.
        - **Status:** (b) landed; **live serve now gated on 5b-2c ALONE** (the other live gate).
          Concurrency + accept-backlog DEPTH limits = the named §8 follow-up.
        - **xhigh-review hardening (pre-merge, PR #64 — 6 real findings, all fixed):** the review caught
          four runtime/robustness gaps in the as-first-written (b) code, now fixed:
          1. **Connect leg was N×budget, not one budget.** `TcpAnchorDial::dial` applied the FULL
             `connect_budget()` to EACH resolved address, so a multi-A / dual-stack black-holing anchor
             multiplied the head-of-line bound to `N·2.5s` (and past `PUMP_BUDGET` for N≥5). FIX: `dial`
             now takes an ABSOLUTE `connect_deadline = min(now + connect_budget(), pump_deadline)` and
             tries each addr against the REMAINING budget — cumulative connect across ALL addrs is one
             `connect_budget()` AND never overruns the pump deadline. (This is what the "wedged-bounded
             HERE, never on the loop" claim always intended.)
          2. **Accept-loop tight-spin under fd exhaustion.** A persistent immediate `accept(2)` error
             (EMFILE/ENFILE — accept fails without draining the backlog) made the bare log+continue peg a
             core + flood stderr. FIX: an `ACCEPT_ERROR_BACKOFF` (50 ms) sleep caps the retry rate;
             NEVER-DIE still holds. The accept-error arm + pump path are now ONE shared `handle_accepted`
             body (the prod `Infallible` loop and the `#[cfg(test)]` finite twin can't drift the guard).
          3. **Unbounded blocking DNS at startup.** `anchor_endpoint_from_env` called `to_socket_addrs`
             (blocking `getaddrinfo`) with no cap BEFORE the bind/`Listening` log — a wedged resolver hung
             the daemon INVISIBLY (defeating fail-closed startup). FIX: a bounded resolver thread
             (`ANCHOR_RESOLVE_BUDGET` = 8 s) → a clean named error → exit 1 instead of a silent hang.
          4. **Write-back not deadline-guarded like the core.** The final enclave write used bare
             `write_all`/`flush` instead of the reused `relay_forward_once`'s `deadline_guarded_write`, so
             a write begun past a lapsed deadline was bounded only by `SO_SNDTIMEO` (10 s). FIX: the
             write-back now goes through the SAME `deadline_guarded_write` (now `pub(crate)`) — core-
             symmetric; the per-pump bound holds on the last leg too.
          Plus two test-quality fixes: the misnamed `deadline_lapsed_pump` (it tested an EMPTY-response
          EOF, NOT a lapse) is split into `empty_anchor_response_closes_never_synth` + a GENUINE
          `lapsed_deadline_pump_never_synth` (deadline injected via a new `relay_one_pump_until` seam);
          and the duplicated golden-frame literals are single-sourced at the `agent_boot_relay` module
          root (shared by both test modules — no silent drift between the freeze and the sibling
          forwarder). The relay-can-tamper "finding" was REFUTED (by design — the enclave Ed25519-verifies).
        - **Full-Matrix reconciliation (PR #64, 8 cells codex/claude-code/gemini/grok × security/design —
          ZERO new code bugs; both prior fixes confirmed landed):** the only actionable items were doc
          reconciliations, applied here:
          - **Canonical pump order = read-decode-BEFORE-dial.** The implementation reads+decodes the
            enclave request FIRST, then dials (so a malformed frame never burns a TCP connect; deviceless
            test 2 pins dial-never-called). This is the AUTHORITATIVE order — it OVERRIDES any "dial-first"
            §-numbered prose in the pre-merge scratch design (which the code's `DEVIATION FROM DESIGN §3c`
            comment records as internally inconsistent). 5b-2c (and any UDS dialer) MUST follow read-decode-
            before-dial, not dial-first.
          - **`PUMP_BUDGET` deadline is minted at PUMP ENTRY (before the enclave read), NOT "after
            connect".** The stale const docstring ("minted AFTER connect") flagged by codex+claude is fixed
            in code; the absolute deadline spans enclave-read + connect + forward + write-back, with connect
            additionally clamped to `min(connect_budget(), remaining-deadline)`.
          - **`anchor_endpoint_from_env` is DAEMON-STARTUP-ONLY.** The bounded-resolve "fail-closed → exit
            1" guarantee relies on the BIN exiting the process on the returned Err; the library fn itself
            only returns the error (and the abandoned `getaddrinfo` worker thread dies with the process). A
            long-lived in-process caller that swallows the Err + retries against a wedged resolver would
            leak a thread per attempt — out of scope (the bin is the only caller, one-shot at startup).
          - **Head-of-line worst case is ~2×PUMP_BUDGET, not PUMP_BUDGET.** A write-back that begins at
            `deadline − ε` is bounded only by `SO_SNDTIMEO` (= PUMP_BUDGET = 10 s) — Risk #3's additive
            socket-timeout tail. The concurrency/accept-backlog follow-up trigger must be sized against
            ~2×PUMP_BUDGET per wedged pump, not the nominal 10 s.
          - **`relay ⊇ anchor` differential test now OWNED by TASK-21** (was "tracked SEPARATELY" with no
            id) — lands with 5b-2c when a concrete anchor endpoint exists to model.
          - **Orchestration-drift seam (Low, accepted):** `relay_one_pump_until` re-implements
            `relay_forward_once`'s sequencing (it must, to insert the dial + distinct `AnchorConnect`
            classification between decode and forward) but reuses the SAME guard/codec cores
            (`deadline_guarded_write`, `relay_round_trip_over_stream`, `frame_anchor_response`). OBLIGATION:
            a future per-leg-guard hardening of `relay_forward_once` must be mirrored into the pump (the two
            share guarantees, not the function body).
    - **(c) feature-build CI — DONE PR #54 (upgraded in PR #55):** originally `cargo test --no-run
      --features vsock-transport,agent-gateway` on the ubuntu (Linux) `rust-test` job; since PR #55 the
      `--no-run` is dropped — CI now compiles the channel + the `#[ignore]` aya tests AND **runs the
      deviceless tests** under those features (the `#[ignore]` device tests still skip); the only place
      `vsock-transport` compilation is validated in CI. NOT `staging-vsock,agent-gateway`, which fails the
      `ml-dsa-65 ⊕ agent-gateway` role-isolation `compile_error!` since `staging-vsock` pulls
      `staging-host`→`ml-dsa-65`.
    - **(d) aya/live-platform tests:** `#[ignore]` acceptance tests (real quote fetch against live
      configfs via the killable-subprocess path — `HardBoundedQuoteProducer`, the (4c) smoke; the
      originally named `fetch_report_deadline` target was deleted in (4a) — incl. no-stale-entry-after-kill
      via the child-side prefix GC; connect to CID 2) verifying socket-timeout
      enforcement **BEHAVIORALLY** (stalled-peer read times out within budget; prompt connect-failure) AND
      via direct `SO_*TIMEO` getsockopt readback — **the safe readback path EXISTS since the nix `socket`
      feature landed** (`sockopt::ReceiveTimeout`/`SendTimeout`, no `unsafe`/`libc` needed; the
      `vsock_connect_restores_blocking_and_arms_so_timeo` aya test already does it for the channel), so the
      old "readback would need unsafe" exemption is EXPIRED — (d) SHOULD assert its socket-timeout values the
      same way.
      Plus the hard wall-clock bound for a wedged in-kernel read (a CANCELLABLE boundary — killable
      subprocess — the only sanctioned boundary per the REVISED (d) pin below (the old menu is closed:
  "kernel timeout" was ELIMINATED — configfs-tsm offers no read-timeout mechanism — and unique
  per-attempt entries are the subprocess design's COMPANION, not an alternative), NOT a plain worker
  thread; see the deadline
      requirement below). **(d) is the critical-path blocker for a live 5b-2c serve** (a/b/c are
      necessary-but-insufficient) — do NOT deprioritize it as "last". (Note: the channel half of these
      behavioral tests already landed in 5b-2b-ii(a) — `vsock_channel_*` aya tests — leaving (d) the configfs
      + hard-bound items.)
- **5b-2c — agent-gateway bin + boot sequencing**: set platform root → unseal the agent keystore →
  `RelayAnchorTransport::new(...)` → `run_boot_anti_rollback_handshake(&body)` →
  `decide_serve(outcome, cfg!(release_build))?` → **`install_agent_keystore(body, measurement)`** → serve.
  **CANONICAL ORDERING (reconciled — anti-rollback timing contract):** install the keystore **only AFTER**
  the handshake returns `Ready` (the move-vs-borrow order in the 5b-2d record: the handshake BORROWS
  `&body`, install MOVES it LAST). So a stale-but-structurally-valid keystore is **never** written to the
  process-global `INSTALLED_KEYSTORE` — non-`Ready` fails closed BEFORE install, and stale state never
  becomes visible to any dispatch path (vs an install-before-handshake order, which would rely on
  "no-serve-before-the-gate" to keep already-installed stale state from being used). `install_agent_keystore`
  returns `bool`; **`false` (overwrite / empty-measurement / poison) is a FATAL boot abort.** Like the
  daemon (b), 5b-2c needs a **`pub`
  library boot-sequencing entrypoint** (e.g. `run_agent_gateway_boot(...)`) — the `RelayAnchorTransport` /
  `BootQuoteProducer` / `BootRelayChannel` types it names are `pub(crate)`, unreachable from a separate-crate
  `[[bin]]`. **Manifest obligation (pinned — previously unpinned anywhere):** the 5b-2c bin is a NEW `[[bin]]`
  target in `enclave-protocol` (e.g. `agent-gateway-vsock`, `src/bin/agent_gateway_vsock.rs`) with
  `required-features = ["agent-gateway", "vsock-transport"]` — exactly the feature pair the crate-root
  `agent_quote_child_dispatch` export is cfg-gated on (plus `target_os = "linux"`, so the bin is Linux-only
  like the export). It MUST NOT reuse or extend `production-vsock`/`staging-vsock` (nor share the
  `enclave-vsock`/`enclave-vsock-staging` bins): both pull `ml-dsa-65` (`staging-vsock` via `staging-host`),
  which trips the `ml-dsa-65 ⊕ agent-gateway` role-isolation `compile_error!` (vsock §10.2) — the same wall
  the (c) CI note records for the test combo. Caveat: `required-features` only gates whether the bin BUILDS;
  it cannot enforce the dispatch-first rule (the quote child re-execs `current_exe()`, so a main that skips
  the dispatch call silently boots a second full gateway instead of a quote child). So EITHER give the
  library a run-main wrapper (e.g. `pub fn agent_gateway_main()` whose first statement is
  `agent_quote_child_dispatch()`, the `[[bin]]` a thin one-line caller — the same thin-bin rule as (b)'s
  daemon) OR make "main's first statement is `agent_quote_child_dispatch()`" an explicit, checked 5b-2c
  acceptance item (see the byte-exact-stdout pin in the (d-ii) note below, which enforces it by test).
  **Two further 5b-2c preconditions recorded from the (d-ii)/2 review:** (1) DEPLOYMENT — the agent bin
  must be self-contained w.r.t. the loader (RPATH/static): the production quote child re-execs it under
  `clear_env`, which strips `LD_LIBRARY_PATH`-style vars (fine for the Nix-built guest binary; a
  dynamically-linked build for another target would silently break child exec — the (4c) smoke is the
  checked validation); (2) NO in-process whole-handshake retry loop — the producer's process-ledger
  claim is permanent, so the entrypoint runs ONE handshake and on failure EXITS for supervisor restart
  (an in-process outer retry would fail closed on its second iteration by construction); relatedly the
  `production()` constructor error is FATAL wiring-time config (must be `?`-propagated; funneling any
  construction error through the fetch-path retryable fold would spin the attempt budget on a permanent
  refusal — construction-fatal and fetch-retryable deliberately share `ProtocolError`, position is the
  discriminator: a sub-slice (3) hazard to keep visible); (3) CONFIG LOGGING — content + severity
  are LIBRARY-DISCHARGED at (4b) (`AgentBootEvent` Display + `level()`: (a) the RAW config triplet
  emitted BEFORE validation — the getters exist only on success, and the static error strings carry
  no numbers (house anti-oracle pattern), so a failed validate() still leaves the operator the
  numbers; (b) on success the getter line incl. `nominal_boot_cost` AND the slack
  (`overall_boot_budget − nominal_boot_cost`) — a zero-slack config validates (`≤` passes) but is
  mis-sized by definition and `level()` says Warn, library logic, test-pinned); the REMAINING 5b-2c
  obligations are: forwarding the Display lines to stderr→journald (mapping `level()` to priority),
  AND rendering the returned `ProtocolError` to stderr at err priority (a CHECKED item, not a smoke
  nicety) — the fatal paths emit no DEDICATED ERROR event (events emitted BEFORE the failure still
  flow: context, not cause — the per-class event matrix lives in the module doc), so a bin that
  swallows the Err and only exits non-zero recreates the numberless-refusal anti-pattern. The bin
  acceptance is split BY PATH (one happy smoke is NOT enough): (i) successful boot — events
  forwarded at the right priorities; (ii) validation refusal — RawBudgetConfig line + the err-render
  both appear; (iii) outcome refusal — the ready:false Warn line + the err-render both appear. NB
  the bin must NOT parse the `HandshakeOutcome` line (the `{outcome:?}` Debug payload is explicitly
  NOT a stable contract — the stable surface is `ready` + `level()`; a curated Display mapping is a
  5b-2c option if tooling needs structure). SINK CONTRACT (compact 8473): the sink is
  infallible-synchronous by design (no error channel for logging — classification stays CLOSED);
  the bin's closure MUST be non-panicking bounded best-effort (`let _ = writeln!`, never
  `eprintln!`) — a sink panic after the claim burns the process claim (fail-closed, restart heals),
  and blocking affects only the pre/post-handshake edges (the sink is never threaded into the
  deadline-bounded fetch). `production_transport` is `#[cfg(test)]` since this fix round — the
  standalone door's test-only status is structural, not prose. Promotion notes: `AgentBootEvent`
  AND `BootLogLevel` both get `#[non_exhaustive]` AT PROMOTION TIME (the enums promote together;
  decide then whether `ready: false` deserves an `Error` level distinct from Warn). Known
  event-invisible corner (by design today): the Ready-but-gate-refused defense-in-depth arm of
  `decide_serve` — reachable only via a driver bug — leaves the event stream ending at Info
  "Ready(...)" while the process refuses; 5b-2c MAY add a serve-decision event as hardening (the
  refusal Err string is distinct, so the bin's err-priority render above covers triage); (4)
  DRIVER-COUNT BINDING — a named,
  TEST-BACKED acceptance item: the count passed to `run_boot_anti_rollback_handshake` MUST be
  `budget.max_attempts()` from THE SAME witness instance fed to the transport mint (the witness
  alone does not bind the count). DISCHARGED at (4b) — by construction (no SEPARATE driver-count
  input exists on the wired surface: the ONE `max_attempts` input is the value `validate()` blesses
  and the driver receives — `run_boot_handshake_wired` derives it in-body from the same witness that
  minted the transport, so a second, divergent count is unrepresentable) + the named test
  `wired_driver_count_is_the_same_witness_max_attempts`;
  residual 5b-2c review check: the bin calls `run_boot_handshake_wired` (the core is
  module-private — structurally unreachable from the bin).
  **(4b) re-scope additions to this bullet:** (a) the 5b-2c `pub` wrapper (`run_agent_gateway_boot`)
  hardcodes `require_real = cfg!(release_build)` — no operator override flag is representable in the
  bin (matches the `decide_serve(outcome, cfg!(release_build))?` sketch above; `require_real` stays
  parametric only on the pub(crate) wired entry, for both-polarity tests). NB `release_build` is THE
  CRATE's build.rs-defined custom cfg (PROFILE=release or `TWOD_HSM_STRICT_RELEASE_GUARDS`,
  registered via `rustc-check-cfg`) — NOT a std flag; the `[[bin]]` shares the crate build.rs so it
  applies as-is, but a literal copy into a DIFFERENT crate would silently evaluate FALSE (fail-open)
  without its own build.rs — never move the bin out-of-crate without carrying the cfg. Staging consequence,
  recorded: release-profile builds have NO escape hatch — dev/lab runs use debug builds. (b) When
  `AgentBootEvent` is promoted `pub` for the separate-crate bin, add `#[non_exhaustive]` AT
  PROMOTION TIME and give the bin's match a catch-all arm (a future reap-status variant must not
  break the bin build; no effect in-crate today). (c) The remaining bin obligations are unchanged:
  manifest + `required-features`, dispatch-first + the byte-exact-stdout integration test,
  RPATH/static deployment, no in-process whole-handshake retry, unseal sequencing supplying `body`.
  **Dependency order:** *construction/compilation* is unblocked once 5b-2b-ii(a)/(b) land (the
  concrete `VsockBootRelayChannel`); a **live anti-rollback serve path is blocked on 5b-2b-ii(d) AND the
  boot-budget gate** — TWO gates, both now ENFORCEABLE artifacts that LANDED ((d-ii)/2 + (d-ii)/3, not
  checklist lines); what remains on each is the 5b-2c WIRING/SMOKE work itemized in the state note
  below, and live serve stays closed until that work completes.
  (a') = the cancellable hard CONNECT bound is now **DONE (PR #56)**, so the connect leg
  no longer gates the live serve. **The TWO hard preconditions for a live 5b-2c serve (state:
  gate #1's artifact landed (d-ii)/2, gate #2's artifact landed (d-ii)/3, the (4b) wiring landed
  ((d-ii)/4b), the (4c) smoke PASSED on aya (2 SNP runs 2026-06-11, RESULT PASS phases=7) — so
  **gate #1 (d) is now FULLY CLOSED** (the spawn shape ran live; the smoke is a DEBUG build — the
  release-built agent bin's spawn shape is an explicit 5b-2c residual, recorded below) and live serve now waits on 5b-2c
  (the `pub` wrapper `run_agent_gateway_boot`, witness-construction-from-operator-config / bin-side
  env-flag parsing, the agent bin, the byte-exact-stdout test RE-TARGETED to the agent bin, the
  serve loop, the 5b-2c boot-budget validation) AND the (b) host-relay daemon for a real anchor:**
  1. **(d) quote bound** — DISCHARGED STRUCTURALLY in two halves: the structural gate landed ((d-ii)/2
     `HardBoundedQuoteProducer`, required by signature — a build lacking (d) cannot construct the
     serving path), and (4a) DELETED `SnpQuoteProducer`/`fetch_report_deadline` outright, so the
     original "MUST NOT wire the cooperative producer" precondition is now VACUOUS — there is nothing
     cooperative left to mis-wire (kept as the historical record of why the by-signature gate exists).
     NB the discharge is CONDITIONAL on the never-generic-Q rule (the (d-ii)/2 LANDED note below):
     the serve-path signature must name the CONCRETE `HardBoundedQuoteProducer` — a generic
     `<Q: BootQuoteProducer>` wrapper re-opens the class this deletion closed (the trait stays open;
     a 5-line in-crate shim over pub `fetch_report` would compile). Enforce BOTH at 5b-2c review.
     The (4b) wiring LANDED ((d-ii)/4b, never-generic-Q held: the wired entry is concrete, the
     generic core module-private); the (4c) smoke PASSED on aya (2 SNP runs 2026-06-11, RESULT PASS
     phases=7) — **this gate (d) is FULLY CLOSED** (debug-smoke spawn shape closed; the release
     agent-bin spawn shape stays a 5b-2c residual); live serve waits on 5b-2c + the (b) host-relay daemon.
  2. **Boot-budget validation** — the structural fail-closed config check of the boot-budget invariant
     (`max_attempts · (3·timeout + ε) ≤ overall_boot_budget` — quote + freshness + marks legs, 5b-2e; or the
     generalized leg-sum form if distinct timeouts ship),
     ordered BEFORE any live-serve wrapper — full spec in the "Per-leg sizing floor" section below. Listed
     HERE too so this summary cannot be read as "(d) is the only gate" (a prior wording said "the ONE hard
     precondition", contradicting the budget MUST below — both gates are required). **The enforceable
     artifact EXISTS ((d-ii)/3): `quote_subprocess::ValidatedBootBudget`** — checked-arithmetic
     fail-closed constructor, taken by the producer's constructors as an ordering witness
     (validation-before-claim by signature); the REMAINING gate-#2 obligation is 5b-2c constructing it
     from operator config (bin-side env/flag parsing — the TWO-PHASE logging half is
     LIBRARY-DISCHARGED at (4b), see precondition (3) above; the bin only forwards the lines).
     Both gates stay required; the (4c) smoke PASSED (aya, 2026-06-11) so live serve now opens only
     at 5b-2c + the (b) host-relay daemon.

  *Satisfied precondition (no longer gating, listed for audit):* **(a') connect bound — DONE (PR #56).**
  [`connect_bounded`] is a non-blocking connect + `poll_with_deadline(POLLOUT)` cancellable hard bound:
  deadline lapse drops the `OwnedFd`, no thread/fd leak. The earlier requirement (land (a') OR record an
  operational risk-acceptance of the watchdog leak) is met by landing (a'); the leak-bound risk-acceptance
  fallback is no longer needed.
  *(Historical leak-bound scope — moot now (a') is landed: the PR #54 watchdog thread/fd leak was **per
  wedged connect ATTEMPT**, worst case `max_attempts` simultaneous leaked thread+fd per boot (driver
  `max_attempts`, ceiling 64) until kernel-reaped, × restart count across boots. (a') removes the leak
  entirely, so no boot-attempt backoff/cap is needed on the connect leg for fd-table safety.)*

  **5b-2c-i LANDED (boot wrapper + budget config + bin skeleton; serve STUBBED fail-closed).** The
  WALL-crossing + boot sequencing, split off so the serve-loop design doesn't block it:
  - NEW `pub fn run_agent_gateway_boot() -> Result<Infallible, ProtocolError>` IN `agent_gateway_boot.rs`
    (the SOLE `pub` bridge — every wired type stays `pub(crate)`; triple-gated, `pub use` in lib.rs):
    `boot_configure_agent_seal_root()?` → `unseal_agent_keystore_at_boot()?` (5b-2d) → parse budget →
    `VsockBootRelayChannel::new(VMADDR_CID_HOST, anchor_relay_port_from_env()?)` →
    `run_boot_handshake_wired(.., &body, cfg!(release_build), &mut emit)?` (decide_serve INSIDE; `&body`
    BORROWED; require_real HARDCODED) → `install_agent_keystore(body, &measurement)` LAST (false=FATAL,
    install-AFTER-`Ready`) → `run_agent_serve_loop()` (5b-2c-i STUB = fail-closed Err; 5b-2c-ii replaces).
    The emit sink is WRAPPER-INTERNAL (decision: keeps `AgentBootEvent` `pub(crate)` — no promotion);
    `let _ = writeln!` NEVER `eprintln!`; the returned `ProtocolError` is rendered at err (the event seam
    emits no dedicated error event). ONE handshake/process — no in-process retry.
  - NEW gate-free `env_config::boot_budget_config_from_env() -> (u32, Duration, Duration)` in
    `validate()` PARAM ORDER (positional, no config struct). Three env knobs `TWOD_HSM_BOOT_MAX_ATTEMPTS`
    / `_PER_LEG_TIMEOUT_MS` / `_OVERALL_BUDGET_MS` (+ legacy); overall is DERIVE-BY-DEFAULT
    (`max_attempts·(3·per_leg + 1000ms margin) + 2000ms` — 3 legs since 5b-2e, saturating, ≫ the real ε so
    it always clears `validate()`'s nominal≤overall) but an operator may widen it. Parse+default ONLY — `validate()` is the
    sole band judge. CI-tested on darwin (gate-free, 6 unit tests incl. a non-UTF-8 fail-closed case). A
    gated TRIPWIRE test (`boot_derive_margin_covers_quote_attempt_overhead`) pins the 1000ms margin ≥ the
    real ε so a future ε growth can't silently push the DEFAULT-config boot below `validate()`'s floor.
  - NEW `[[bin]] twod-hsm-agent-gateway` (`required-features=[agent-gateway,vsock-transport]` — NOT
    production-vsock/staging-vsock [ml-dsa-65 role-isolation] NOT lab-quote-smoke [release-banned]): the
    2-statement dispatch-first main (`agent_quote_child_dispatch()` FIRST, then `run_agent_gateway_boot`),
    non-linux stub exit 2, `Ok(Infallible)` unreachable → exit 1 on the FATAL Err (lib already rendered).
  - NEW `tests/twod_hsm_agent_gateway_bin.rs` DISCHARGES the §8 byte-exact-stdout acceptance item
    (re-targeted to the agent bin): marker-set/report_data-absent → stdout == `[0xA2,0x01]` byte-exact +
    exit 1 (dispatch-first proven — any stdout write before dispatch fails it) + a fail-closed-startup arm
    (no marker → `boot_configure_agent_seal_root` stub → exit 1 naming the root, stdout empty).
  - Validation: aya `agent-gateway,vsock-transport` 429 lib + 2 bin-integration PASS (incl. the dispatch-
    first byte-exact); darwin agent-gateway (gated module out, budget parser in); no new warnings.
  - **Full-Matrix reconciliation (PR #66, 6 cells codex/claude-code/grok × security+design; gemini
    infra-down NOTED):** ZERO fail-open / ordering / dispatch defects (the install-AFTER-`Ready`,
    borrow-then-move, require_real hardcode, and dispatch-first byte-exact all passed). Applied: (1) xhigh
    + matrix — the budget env-helpers swallowed `Err(NotUnicode)` → now fail closed naming the var
    (matching var_twod's contract); (2) claude design Medium — the anchor-relay-port `map_err` now surfaces
    its SPECIFIC reason (a relay==serve PORT COLLISION names the conflicting serve var) before the static
    error, same as the budget path; (3) claude design Low — the ε tripwire test above. The codex design
    "High" (irreversible handshake/claim before the always-failing serve stub) is DOCUMENTED, not a code
    change: the 5b handshake is VERIFY-ONLY (no anchor-side mutation — the bump+ack is slice 6), and the
    producer claim + binding + installed keystore are process-VOLATILE, so a post-`Ready` serve-stub exit is
    a CLEAN supervisor restart (no persistent half-boot). In CI/lab WITHOUT a real anchor the wrapper
    fail-closes at root/unseal long before `Ready`; a working-anchor DEPLOY of the skeleton would crash-loop,
    which is why the serve loop lands in 5b-2c-ii BEFORE any live-anchor deploy (the skeleton is not for one).
    NB the serve port (`vsock_listen_addr_from_env`) is already load-bearing at boot via the relay≠serve
    collision check, even though the serve loop is a stub this slice. The positional budget tuple (no config
    struct) is the DELIBERATE §8 transposition-fails-closed discipline (run_boot_handshake_wired doc), kept.
    **5b-2c-ii = the agent 0x40 serve loop** (replaces the stub); **5b-2c-iii = aya SNP live smoke**
    (DEBUG-build first — production live-serve still needs the attested host-vsock keystore-source slice).

  **5b-2c-ii LANDED (the agent 0x40 serve loop — replaces the fail-closed stub).** Decision (Design WF,
  all 3 judges): **SERIAL** accept loop (mirror the SNP-validated (b) host-relay), NOT thread-per-connection —
  every keystore mutation already serializes on the `INSTALLED_KEYSTORE` Mutex inside
  `handle_agent_gateway_frame` (lock held across `seal_body`), so concurrency buys NOTHING; serial is strictly
  safer (NO shared `EnclaveState` mutex → the producer's `process::exit(1)`-on-poison hazard is structurally
  ABSENT, NOT swallowed; no panic=abort dependency). Concurrent-capped = a NAMED follow-up (trigger: the
  upstream gateway multiplexing many independent slow clients).
  - NEW `pub fn serve_framed_pump<S, H>(stream, handle_frame, idle_timeout)` in `enclave_serve.rs` — the
    generic per-connection frame-pump KERNEL extracted from `serve_framed_connection`'s body (break taxonomy
    EOF/timeout/oversize→close + idle-reset-on-NON-error via `is_wire_error_payload`) MINUS the EnclaveState
    lock / attestation / `process::exit`. ONE caller (the agent) this slice; the producer
    `serve_framed_connection` stays BYTE-IDENTICAL (convergence onto the kernel = a NAMED §8 follow-up — do
    NOT perturb the SNP-validated producer). CRITICAL: the idle-reset predicate is `is_wire_error_payload`
    (wire.rs, pub) NOT `decode_agent_error_code` (which is `#[cfg(test)]`-gated → would not compile in prod).
  - In `agent_gateway_boot.rs`: `agent_serve_one_frame` (decode → REQUIRE `MessageType::AgentGateway` → a
    NON-0x40 frame returns Err → CLOSE-SILENTLY [human decision: strictly fail-closed, zero bytes back, never
    synthesizes an agent body for a misrouted type] → `handle_agent_gateway_frame(&payload)` →
    `encode_message(AgentGateway, body)`); `handle_agent_accepted` (the shared accepted-item body +
    `ACCEPT_ERROR_BACKOFF=50ms` + `let _=writeln!` never eprintln!); `serve_agent_loop<I,S> → Infallible`
    (serial, mirrors `serve_anchor_relay_loop`); `run_agent_serve_loop` REPLACES the stub —
    `vsock_listen_addr_from_env` (DISTINCT serve port; relay≠serve already validated boot-step-D) → `bind_vsock_listener`
    → arm SO_*TIMEO per stream → `serve_agent_loop`. Bind faults FATAL (fail-closed); bind branch
    aya/SNP-pinned (UnixStream pairs have no CID).
  - Reused VERBATIM: `handle_agent_gateway_frame` (the whole per-frame 0x40 compute — holds the keystore
    Mutex, poison-recovers, ALWAYS returns a 0x40..=0x46-band body), the framing primitives
    (`read_framed_message_with_idle_deadline` = oversize MessageTooLarge-before-alloc + slowloris bound;
    `write_framed_message`; `decode_message`/`encode_message`; `MessageType::AgentGateway`),
    `bind_vsock_listener`/`configure_vsock_session_timeouts`, `SESSION_IDLE_TIMEOUT` (300s), the (b)
    never-die/Infallible-divergence/finite-cfg(test)-twin discipline.
  - Validation: aya `agent-gateway,vsock-transport` 438 lib (+8 deviceless serve tests: 0x40 round-trip→0x40
    reply no-panic, wrong-type closes-silently zero-bytes, oversize/EOF clean close, multi-frame, close-and-
    continue, accept-backoff, agent-error idle-reset classification) + 2 bin-integration; darwin default +
    agent-gateway (the gate-free kernel) 339; no new warnings. The success-body COMPUTE is covered by
    agent_dispatch's own PUBLIC_IDENTITY tests; the serve loop's job is transport+reframe. **NEXT 5b-2c-iii =
    aya SNP live smoke** (DEBUG build; a real 0x40 round-trip over vsock from the host) — production live-serve
    still needs the attested host-vsock keystore-source slice. NAMED follow-ups: producer-convergence onto
    `serve_framed_pump`; concurrent-capped (if multi-client).
  - **xhigh review-max applied (22 raw→19 survived→+3 sweep→15 findings; ZERO runtime correctness bugs — all
    hardening / log-taxonomy / test-adequacy / cleanup / efficiency).** Fixes landed: (1) the idle-reset rule
    is EXTRACTED to `pub(crate) fn reply_resets_idle(reply)` in `enclave_serve.rs` (the SUCCESS-extends + the
    ERROR-does-not directions are now both DETERMINISTICALLY unit-testable without a wall-clock expiry — the
    error-only classifier test left the positive half unguarded, so a flipped/dropped `!` re-opening the
    slowloris hole would have passed every test); the pump calls it; the producer keeps its byte-identical
    inline copy (convergence = the named follow-up). (2) `ACCEPT_ERROR_BACKOFF` PROMOTED to a single
    `pub const` in `enclave_serve.rs` — was duplicated verbatim in `agent_gateway_boot` + `host_anchor_relay`
    (a silent-drift surface). BOTH loops now `use` the shared const: the agent loop in cbbd918, the (b)
    host-anchor relay in the matrix-fix commit (the cbbd918 doc OVERCLAIMED "single source" while the relay
    still carried its own copy — caught by the roborev claude-code DESIGN cell as a spec↔code contradiction;
    now the claim is REAL). (3) a wrong-type / bad-version pump Err is now logged CALMLY at `[info]` via
    `is_peer_protocol_reject` (the CLOSE-SILENTLY policy an UNAUTHENTICATED peer trips pre-auth was a `[warn]`
    flood lever; genuine IO faults stay `[warn]`). (4) the per-stream SO_*TIMEO arming moved to a
    `prepare`-seam threaded through `handle_agent_accepted`/`serve_agent_loop`/the finite twin (mirrors the
    producer's `run_incoming_accept_loop` `prepare_connection`) — an arm failure is now labeled "stream setup
    failed" (NOT mislabeled "accept error"), skipped WITHOUT backoff (not fd pressure), AND deviceless-testable.
    NEW deviceless tests: `reply_extends_idle_on_success_not_on_error`, `serve_pump_respects_expired_idle_deadline`
    (ZERO idle budget → break-before-read), `serve_loop_stream_setup_failure_skips_and_continues`.
    Re-validation: aya `agent-gateway,vsock-transport` **441 lib (438+3) + 2 bin-integration, 0 failed, clippy
    clean**; darwin gate-free 92 lib green. DEFERRED to the producer-convergence follow-up (do NOT perturb the
    SNP-validated producer this slice): the redundant per-frame `decode_message(&reply)` re-parse + the owning
    payload-Vec alloc (efficiency) — fix it for BOTH the pump AND the producer together via a handler that
    returns `(frame, is_error)`. The real wall-clock 300s idle expiry stays an aya 5b-2c-iii smoke obligation
    (deviceless can't drive a true timer). NAMED follow-up (gemini PR #67 medium, greptile P2 both REPLIED +
    RESOLVED; greptile's "idle dead path / 300s teardown" REFUTED — success bodies are key1=Bytes/Array, NOT
    `{1:Integer,2:Text}`, so they DO reset idle, pinned by the new `reply_extends_idle_on_success_not_on_error`
    test): **uniform serve-loop accept-error CLASSIFICATION** — `handle_agent_accepted`'s genuine-`accept(2)`
    `Err` arm currently backs off `ACCEPT_ERROR_BACKOFF` UNCONDITIONALLY; only EMFILE/ENFILE (os 23/24) actually
    busy-spin (accept fails without draining the backlog), so ECONNABORTED/EINTR need no backoff. Defer rather
    than narrow ONLY the agent loop, because the (b) host-anchor relay accept loop uses the IDENTICAL
    unconditional backoff — fix BOTH together so they never drift (cbbd918 already consolidated the const).
  - **Full Matrix (8 cells) outcome.** codex/claude-code/grok × {security,design} ran; the 2 **gemini cells
    FAILED (infra-down — consistent, NOTED not silently dropped)**. grok security = "No issues"; grok design =
    Pass. Two recurring Medium themes, both addressed:
    - **(spec↔code contradiction — FIXED in code)** the `ACCEPT_ERROR_BACKOFF` "single source" claim — the
      relay was converted to the shared const (item (2) above); the matrix-fix commit makes the doc true.
    - **(serial single-client monopolization — TRUST BOUNDARY recorded, control deferred)** codex + claude-code
      (both lenses) flag that `reply_resets_idle` extends the 300s idle budget on EVERY *successful* reply, so
      one client issuing cheap successful `0x40` frames at any interval < `SESSION_IDLE_TIMEOUT` holds the sole
      SERIAL slot forever and starves all other clients — the cbbd918 hardening closes the *erroring*-frame
      slowloris but NOT the *success*-frame monopolization. **TRUST BOUNDARY (now explicit, was the reviewers'
      ask):** the agent serve vsock port is reached by the (untrusted) SNP HOST; availability *against the host*
      is a NON-GOAL because the host already controls VM scheduling/CPU/teardown — it can DoS the enclave
      trivially regardless of any in-enclave cap (claude-code-security rates this Medium-not-High for exactly
      this reason). The EXPLOITABLE case is a future deployment where the host gateway MULTIPLEXES many
      INDEPENDENT untrusted clients onto one shared serve loop. **Therefore the named `concurrent-capped`
      follow-up is a BLOCKING PRECONDITION before any multi-tenant-multiplexed serving** (not "if multi-client"
      hand-wave): its acceptance = a per-connection bound that survives the success-reset (absolute
      `MAX_SESSION_LIFETIME` from `accepted_at`, independent of idle reset) + a max-frames-per-connection cap +
      an adversarial "a steady stream of successful frames cannot monopolize / starve a second client" test.
      The interim single-client (host-only) deployment is safe under the trust boundary above.
    - **(low — FIXED) incomplete calm-close classification** (surfaced by `roborev compact` re-verify): the
      original `is_peer_protocol_reject` caught only `WireProtocol`+`InvalidVersion`, so other peer-controlled
      pre-auth decode rejects (`UnknownMessageType`, a sub-header `Io(UnexpectedEof)` short frame) still hit the
      `[warn]` arm — the same flood-lever class as fix (3), left half-done. Extended to ALL peer decode/route
      rejects (the only `UnexpectedEof` reaching the arm is a peer's short frame; mid-frame read EOF breaks to
      `Ok`; write faults are `BrokenPipe`/`ConnectionReset`), pinned by the new
      `peer_protocol_rejects_are_calm_genuine_faults_are_not` unit test.
    - **(low) live-timer obligation** → add the real 300s wall-clock idle-expiry round-trip as an EXPLICIT
      checklisted acceptance item for the 5b-2c-iii aya/SNP smoke (deviceless can't drive a true timer), not
      just prose. compact consolidated the matrix (job 8558); the const contradiction VERIFIED-fixed; CI green.
- **5b-2d — sealed-blob source + unseal sequencing — LANDED (lab file source).** NEW agent-gateway-gated
  `src/boot_agent_keystore.rs` (the agent twin of `boot_lab_pq_seal`), TWO public fns:
  - `unseal_agent_keystore_at_boot() -> Result<(KeystoreBody, Vec<u8> /*measurement*/), ProtocolError>` —
    a PURE source→unseal→return seam. It reads the sealed blob + the enclave measurement, resolves the
    provisioning root, and calls the SHARED `agent_keystore::unseal_body` VERBATIM (length → magic
    `2DAGTKS\0` → `format_version==2` BEFORE decrypt → measurement-binding → strict whole-buffer CBOR →
    `validate()` incl. `structural_version!=0`). It does **NOT** install (the 5b-2c bin owns
    `install_agent_keystore` + the move-vs-borrow order: the handshake BORROWS `&body`, install MOVES it +
    retains the measurement for re-seal; `install_agent_keystore` returns `bool` and **false** —
    overwrite/empty-meas/poison — is FATAL for 5b-2c) and does **NOT** set the root.
  - `boot_configure_agent_seal_root() -> Result<(), ProtocolError>` — the thin agent root-step (the
    `ml-dsa-65`-only `platform_provisioning_boot::boot_configure_pq_seal_v1_platform_root` is unavailable to
    the agent build), calling the SHARED `seal_root::set_pq_seal_v1_provisioning_root` so `resolve` succeeds
    standalone. Sharing the root mechanism does NOT weaken isolation (distinct domain-separated KDFs).
  - **SECURITY boundary:** the seam enforces ONLY the structural/seal invariant; it MUST NOT judge
    freshness/anti-rollback — a rolled-back-but-valid blob UNSEALS fine; the handshake `reconcile` (NOT this
    module), which runs on `&body` BEFORE install (canonical install-after-`Ready` order above), then catches
    it and fails closed, so a stale keystore is NEVER installed. Structurally enforced: the module use-list imports NO
    `agent_anchor`/`agent_boot`/`reconcile`/`marks`/`AdoptForward`/`AnchorState` symbol (grep-checkable);
    AdoptForward + re-seal-forward stay strictly 5b-2e. Honors `MAX_KEYSTORE_BLOB_SIZE` (re-installable).
  - **NEW SURFACE (house rule):** feature `lab-agent-keystore-from-file = ["agent-gateway"]` (base
    `agent-gateway`, NOT `ml-dsa-65` — the role-isolation-exclusive producer feature; a NEW
    `compile_error!` in `lib.rs` mirrors the `lab-pq-seal-from-file` release-ban). NEW env var
    `TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE` (+ `2D_HSM_*` alias, read **RAW** — a sealed binary blob is never
    newline-trimmed). The lab root REUSES `TWOD_HSM_PQ_SEAL_V1_ROOT_FILE` (one shared platform-root
    mechanism); the lab measurement REUSES `TWOD_HSM_ENCLAVE_MEASUREMENT_FILE` (text override) with a
    DISTINCT agent placeholder const `AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT` fallback (cross-role
    hygiene vs the producer placeholder). The production (non-lab) arms are documented fail-closed stubs.
  - **ERROR TYPE:** returns `ProtocolError::PqSigningUnavailable` (NO new variant — `protocol_error_to_wire_body`
    is the only exhaustive `ProtocolError` match; a new variant is a wire-facing public-enum widening with
    zero caller benefit). Observability via DISTINCT `agent keystore:`-prefixed coarse labels (wire code 2,
    reason-distinguishable from a producer-signer); the `KeystoreError`→label mapper is WILDCARD-FREE (one
    arm per the 17 variants → a future 18th variant is a COMPILE error, not a silent fail-open).
  - **GENESIS GOLDEN:** committed `testvectors/agent-gateway/agent_keystore_genesis_v2.{sealed.bin,json}`
    (deterministic-nonce `seal_keystore_with_nonce` over the committed reference root + the agent
    placeholder; `structural_version=1`, `strict_recovery_counter=0`, no entries/counters; both required,
    no serde default; `format_version=2` hard, no v1 reader; blob 3998 B ≤ `MAX_KEYSTORE_BLOB_SIZE`). An
    in-source byte-exact freeze + a from-disk integration test (`tests/agent_keystore_boot_loader.rs`) both
    consume the same bytes — any encoder/layout drift flips BOTH; regen via `#[ignore]
    regen_agent_genesis_golden_vector` (re-mint the `.json` in the same commit on a `format_version` bump).
  - **TESTING TRAP (pinned):** `resolve_provisioning_root` has a `cfg(test)`/`reference-seal-v1-root`
    reference-root fallback (`seal_root.rs`) that MASKS a naive root-not-set Err under `cargo test` — the
    negative ordering case is pinned via the production-stub path (a non-lab build where blob/measurement
    sourcing Errs first), NOT a naive unset-root assertion. An agent-side test guard resets the seal-root
    global + the keystore slot + the env under one process-globals Mutex.
  - **Validation:** darwin agent-gateway WITH `lab-agent-keystore-from-file` (16 module tests + the from-disk
    integration test) AND WITHOUT (6 feature-independent + the production fail-closed stub test) green;
    clippy clean; release-build + the lab feature fails to compile (release-ban).
  - **DEFERS:** the production host-vsock install/restore wire envelope (its own slice; the framing is still
    PROVISIONAL); the real attested 48-byte SNP launch measurement (production derives it from the SNP
    report, not the placeholder); the 5b-2c bin wiring (install-after-Ready ordering, false-is-fatal, a real
    production root hook); AdoptForward/re-seal (5b-2e). A per-role agent root env var was rejected as a
    wider diff (the shared `TWOD_HSM_PQ_SEAL_V1_ROOT_FILE` is correct — distinct KDF domains; flagged for
    reviewer sign-off). The production root provider, the production sealed-blob source, and the real
    measurement source are explicit ORDERED 5b-2c/later obligations, each replacing one of this slice's
    documented fail-closed stubs.
  - **NO PRODUCTION CALLER until 5b-2c:** in a non-lab (production) agent build the seam + root-step are
    fail-closed STUBS (no env read), so `unseal_agent_keystore_at_boot` is intentionally UNREACHABLE/inert
    until the 5b-2c bin wires a real root + source; the from-disk integration test is what keeps the
    otherwise-dead loader CI-exercised. **Producer ⊕ agent is a BUILD-LEVEL `compile_error!`** (lib.rs
    `all(ml-dsa-65, agent-gateway)`), so NO single binary runs both role root-steps — the shared install-once
    provisioning-root slot is configured by exactly one role; the distinct agent placeholder measurement is
    belt-and-suspenders cross-role hygiene, not a dual-role-in-one-binary scenario (which can't be built).
  - **Full-Matrix reconciliation (PR #65, 6 cells — gemini infra-down both runs, NOTED not silently
    dropped; codex/claude/grok × security+design):** ZERO core-logic defects. Applied: (1) codex security
    Low — the lab file readers now use a CAPPED reader (`boot_input::read_boot_file_capped`, reads ≤ max+1)
    so `/dev/zero` / an oversize file fails closed instead of OOMing the boot path (pinned by
    `seam_neverending_file_capped_not_oom`); (2) codex design Medium — the loader's tests now serialize on
    the CRATE-WIDE `agent_dispatch::lock_and_reset_agent_process_globals()` (+ a seal-root/env reset) instead
    of a private lock, so they can't race other agent tests on `INSTALLED_KEYSTORE`; (3) claude design Low —
    the sidecar coupling test now also pins `nonce_hex`/`enclave_measurement_hex`/`provisioning_root_hex` to
    the source-of-truth constants (not just sha256/len). The codex design "High" (boot-ordering doc
    contradiction) is the §8 5b-2c CANONICAL ORDERING reconciliation above (install-after-Ready).
- **5b-2e — `AdoptForward`** (last + separate, because it changes fail-closed behavior — flips
  `AdoptForwardUnsupported` from terminal to executable): the `anchor_root`-signed raw-marks channel +
  `hash(adopted)==marks_digest` seed + re-seal/persistence.

**Enclave-initiated outbound vsock is feasible** (the `vsock` crate's `VsockStream::connect` to CID 2,
separate from the serve-loop listener — spike confirmed via `vsock_listen.rs`), but the live exchange +
timeouts are validated on aya. Still **UNWIRED**
(dead-code) until 5b-2b adds the bin caller; **5b-2 MUST land before any release build claims anti-rollback
support** (else 5a/5b-1/5b-2a ship dead). 5b-2a is the LAST pure layer — its tests already drive the full
verify+driver+transport composition end-to-end (including the response wire framing via
`driver_ready_through_real_response_framing`), so the accumulation bottoms out here. **In the window where
5b-2b-i is merged but 5b-2b-ii is not, NO production boot path can hang on a wedged quote fetch — because
there is no current caller**: the quote producer + relay transport are `#[cfg_attr(not(test),
allow(dead_code))]` and the only intended caller is the 5b-2c bin (not yet built). That window CLOSED at
(4a): `fetch_report_deadline` is DELETED (with `SnpQuoteProducer`), so the former "coarser pub(crate)
guarantee vs. checklist obligation" distinction is moot for the DELETED TYPE — "wire `SnpQuoteProducer`"
is unrepresentable. SCOPE HONESTLY: the CLASS (an in-crate unbounded `BootQuoteProducer` impl wired into
`RelayAnchorTransport::new`, e.g. a 5-line shim over the pub `fetch_report`) remains representable —
the trait is open and `new` stays reachable for fakes; the surviving checklist guards are the
never-generic-Q rule ((d-ii)/2 note: the serve path names the CONCRETE `HardBoundedQuoteProducer`) +
the (4b) acceptance review (`RelayAnchorTransport::new`'s own "same residual class" rustdoc). (The
unbounded producer `fetch_report` stays `pub` — it has no wall-clock contract to violate.)

**5b-2b implementation requirements (pinned after the 5b-2a design matrix — these are the contract 5b-2b
MUST satisfy; none is a 5b-2a code defect, they are forward obligations on the platform leaves):**
- **Deadline-aware quote fetch (load-bearing).** `BootQuoteProducer::fetch(report_data, deadline)`'s
  contract requires honoring `deadline`. **Cooperative/between-steps bound — DONE in 5b-2b-i and
  DELETED in (d-ii)(4a) [user sign-off 2026-06-10]:** that cooperative machinery — `SnpQuoteProducer`,
  `fetch_report_deadline`, the `Option<Instant>` plumbing and its deadline tests (incl. its pin
  `fetch_cleans_up_on_mid_sequence_deadline_timeout`) — is GONE; "wire the cooperative producer anyway"
  is now structurally impossible (unrepresentable), not a prose caveat. The unconditional stale-entry
  cleanup SURVIVES on the unbounded path (fixed `twod-hsm`; cleanup is the last statement) — pinned by
  the surviving `fetch_cleans_up_on_*` error-leg tests. **Hard wall-clock bound — (d-i) harness
  LANDED (this PR); (d) remains OPEN until (d-ii):** a single in-kernel blocking `read(outblob)` cannot be
  interrupted under `#![forbid(unsafe_code)]`, so any cooperative deadline WAS best-effort, NOT a
  guaranteed ceiling against a wedged kernel/configfs provider — which is exactly why (4a) deleted the
  cooperative path outright (no such deadline exists anymore; the surviving bound is the parent's
  pipe-poll + SIGKILL). A true hard bound needs a **cancellable
  boundary**, and 5b-2b-ii MUST use a **killable-subprocess** one — **REVISED PIN (was: "(i)/(ii) keep the
  fixed-name clear valid and are preferred"; that claim is FALSE under the exact failure (d) exists for):**
  SIGKILL only *pends* against a child wedged in an uninterruptible (D-state) configfs read — the child
  does not exit and its open fds are NOT released, so it still HOLDS the fixed `twod-hsm` entry; the next
  attempt's best-effort `remove_entry` fails SILENTLY (`RealTsmFs` ignores the error) and `create_entry`
  fails `EEXIST` behind the misleading "needs kernel >= 6.7 / TSM provider" message — ONE wedged child
  poisons every remaining attempt in the boot budget with a wrong-cause error. **Shipped design = (i) +
  (iii)'s naming companion:** the quote fetch runs in a killable subprocess whose PIPE is the cancellable
  boundary (`poll_with_deadline(POLLIN)`; EOF-aware `classify_pipe_revents` — on a pipe `POLLIN|POLLHUP`
  is the NORMAL final-data shape, `read()==0` the only authoritative EOF); the subprocess path uses unique
  **child-self-named** entries `twod-hsm-q-<child_pid>` (live-pid uniqueness forbids collision; a recycled
  pid's child clears its own stale name); orphan entries are reclaimed by best-effort prefix GC run
  **inside the next killable child** — the parent performs **NO configfs I/O of any kind** (parent-side
  readdir/rmdir against a wedged provider could itself block uninterruptibly — a permanent boot hang,
  strictly worse than fail-closed; in the child, a wedged GC is just another killable attempt). The prefix
  `twod-hsm-q-` is strictly longer than the bare `twod-hsm`, so GC can never match the producer entry.
  Abandoned (killed-but-unreaped) children are bounded by `ABANDONED_CHILD_BUDGET =
  MAX_BOOT_ATTEMPTS_CEILING (= 64)` (derived AND assert-pinned); the fetch refuses to spawn past it
  (retryable → fail-closed `RetriesExhausted`) — the option-(iii) "refuse boot past a threshold" policy,
  implemented. NO blocking `wait()` exists in the (d) path BY TYPE (`ChildHandle` = `kill_best_effort` +
  WNOHANG `try_reap` only; bounded ≤10ms reap grace, so ε ≈ ≤12ms/attempt of spawn+kill+reap overhead —
  see the budget invariant below for the explicit `max_attempts · ε` term [user decision 2026-06-10]).
  Production child stderr → **journald (`inherit`)** for kill-storm triage [user decision 2026-06-10].
  The fixed `twod-hsm` entry is now EXCLUSIVELY the unbounded producer/GET_MEASUREMENT path's — (4a)
  deleted the cooperative boot fetch, so the exclusivity is a present structural fact (the former "do
  not build interim code on the exclusivity" caveat is RETIRED; code MAY rely on it). The
  "unconditional cleanup on every path" invariant is rescoped: it holds for the in-process producer
  path (error legs — the in-process timeout leg no longer exists, (4a) deleted the deadline plumbing)
  and for a SURVIVING child; a killed child structurally cannot clean — next-child/next-boot GC owns
  that case (configfs is RAM-backed; nothing survives reboot). *(d-i) landed: deviceless killable-subprocess harness
  (`quote_subprocess.rs` — EOF-aware pipe predicate [co-located with the connect predicate in
  `cancellable_boundary`], capped incremental frame codec [the PARSER owns trailing-byte rejection;
  per-drain-window best-effort by design], deadline-bounded
  drain, kill/WNOHANG-reap/abandon ledger, budget = 64, real-subprocess CI smokes; honest limit stated in
  the test docs: a true D-state child cannot be staged on demand ANYWHERE — the unreapable arm's only
  deterministic coverage is the Fake-handle ledger tests) + the entry-path `fetch_report_with_at` refactor;
  (d-ii) adds the configfs child mode (`agent_quote_child_main`, child-side GC) + `HardBoundedQuoteProducer`
  (the structural serve-gate type — deliberately NO skeleton in (d-i): it would satisfy the by-signature
  gate while the hang remains) + the in-SNP-guest aya validation (absorbed into sub-slice (4c) of the
  slicing below — not a separate co-equal artifact). **(d-ii) slicing note (review-load):** (d-ii) lands as
  ordered sub-slices, each gated — (1) child dispatch entrypoint + child core (unique-entry fetch +
  child-side GC) — **LANDED (this PR); bin wiring is 5b-2c.** The bin-facing surface is the
  crate-root **`agent_quote_child_dispatch()`** export (self-dispatching: returns in a parent, never
  returns in a child; the marker env stays crate-private so the dispatch condition cannot be re-keyed
  one-sided) — the 5b-2c bin calls it unconditionally as main's first statement. **Threat-model pin
  (matrix HIGH "env-injected report_data", refuted 3-0 — oracle equivalence):** child mode is NOT an
  authentication/trust boundary and deliberately carries no parent-vs-external-launch check — the SNP
  signing oracle is configfs-tsm + firmware, natively available to ANY equally-privileged in-guest
  process (the firmware signs any 64-byte report_data for any guest code; the report carries no
  requesting-process identity), so an env-token/ppid/parent-capability check would be unfalsifiable
  theater, and deriving report_data from key material inside the child would move secrets INTO the
  SIGKILL-able child (which deliberately holds zero) for no oracle reduction. report_data binding is
  enforced by the RELYING PARTY's derive-and-compare rule + the measured-boot chain, NOT by which
  process requested the report. Two standing preconditions of this argument: the binary is never
  installed setuid / wrapped by a privileged env-forwarding service, and no relying path ascribes extra
  weight to "this binary produced the quote". **Named TASK-16 obligation (new):** the AC#5 Layer-1
  measured-boot chain MUST cover the kernel cmdline and any host-to-init env channel
  (`systemd.setenv=`-style) — env-dispatched modes (this marker, and any future env-sensitive behavior)
  assume guest-internal env integrity; direct-boot `KERNEL_HASHES=on` measurement satisfies this.
  Mechanics, the child
  exit-code table, and the never-panic/PROTOCOL-ONLY-stdout rules live in the dispatch/entrypoint
  rustdoc (single source); the outblob post-check messages are snp_report-owned pub(crate) consts
  consumed by both the emitters and the child's code refinement (no transcribed copies); the
  `fetch_report_with_at` promotion obligation is DISCHARGED (entry-path-honored test included); e2e
  real-subprocess tests drive the REAL child core + PRODUCTION env parser through the REAL parent
  orchestration (full pipeline minus configfs). **Parent-side reap-status logging — named obligation
  RE-SCOPED to 5b-2c with HARD constraints from the (d-ii)/3 xhigh review** (an in-fetch emission was
  implemented and REVERTED there): the emission MUST NOT live inside the deadline-bounded fetch path
  — `StdChildHandle::try_reap` / `dispose_child` / the ledger sweep are OFF-LIMITS, because a
  blocking `write(2)` to inherited stderr (journald backpressured + pipe full) inside try_reap is an
  UNBOUNDED block in the UNKILLABLE parent — the exact wedge class (d) exists to kill, reintroduced
  one level up (the child-side synchronous-breadcrumb acceptance does NOT transfer: the child is
  killable, the parent is not; and O_NONBLOCK on fd 2 flips the SHARED open file description).
  Emission must live OUTSIDE the fetch (e.g. bin/driver level between attempts) or behind a
  genuinely non-blocking channel — and the carrier itself is an EXPLICIT 5b-2c design task (e.g. a
  bounded in-memory status buffer the fetch appends to non-blockingly and the bin drains between
  attempts), followed by bin-level emission + smoke verification: without a named carrier design,
  implementers either reintroduce the forbidden in-fetch write or skip parent-side logging entirely.
  Emission SURFACE decided at (4b): the carrier rides the `AgentBootEvent` sink (a future variant +
  a between-attempts drain call site — additive; `run_boot_handshake_wired` is pub(crate), so
  signature growth is a contained in-crate diff; the sink's rustdoc PROSE-PINS emission points away
  from the in-fetch role — the structural fact TODAY is code-positional (the sink is never threaded
  into driver/producer/transport) and MUST be re-established by construction when the carrier lands);
  the carrier DESIGN itself remains this explicit 5b-2c task
  and the hard constraints above stand (no in-fetch emission). ALSO record for that implementation: an `ExitStatus` cannot
  distinguish own-SIGKILL from an EXTERNAL SIGKILL (the Linux OOM-killer delivers exactly SIGKILL),
  so any filter silencing the uniform-disposition kill also silences OOM kills — an accepted blind
  spot to document, not paper over ("crashes must not be swallowed" cannot be promised for the
  SIGKILL class); and an abandoned-then-exited child reaps as SIGNAL 9 (the pending kill), so a
  later sweep carries an exit CODE only in the kill-failed corner. The in-band ERR frame + the lapse
  strings remain the reliable cause-carriers meanwhile. Child-side, every nonzero exit emits a
  BEST-EFFORT breadcrumb (`twod-hsm quote child: exit <code>`; races the parent's SIGKILL-on-frame;
  a never-exiting D-state child logs nothing — nothing to reap), verification folded into the (4c)
  aya smoke — (2) producer wrapper + single-ledger
  ownership — **LANDED ((d-ii)/2)**: `HardBoundedQuoteProducer` (in `quote_subprocess`, triple-gated) =
  the structural serve-gate type; its `BootQuoteProducer::fetch` delegates to the killable-subprocess
  orchestration (the (d-i) NO-skeleton rule SATISFIED, not waived — the delegate IS the bound). Pin (1)
  below DISCHARGED structurally, four stacked levers: (i) a process-claim flag
  (`compare_exchange` in `new()`, NEVER released incl. Drop — drop+reconstruct hands the next producer
  a fresh ledger and IS the voided-cap hole; reset only via the crate test-reset site
  `lock_and_reset_agent_process_globals`, per that helper's adds-its-reset-HERE pin), which also closes
  the cross-handshake accumulation hole on `ABANDONED_CHILD_BUDGET` — consequence recorded: ONE boot
  handshake per process; a second producer construction refuses fail-closed at boot wiring (a
  supervisor restart is a new process and claims fresh; if a future design legitimately needs producer
  reuse across transports, the fix is `into_parts`-style reuse of the ONE producer, NOT claim release);
  (ii) the orchestration (`fetch_quote_via_child`) + `AbandonedLedger` demoted module-PRIVATE — outside
  the module the producer is the only quote-fetch door; (iii) private `ledger` field, no
  Clone/Default (a clone = a forked budget; any later derive is a pin violation); (iv)
  `BootQuoteProducer::fetch` migrated to **`&mut self`** — the single-mutator rule as a borrow-checker
  fact, uniform with the sibling seams (Mutex REJECTED: a lock held across a multi-second pipe poll
  blocks a second caller UNBOUNDED, violating the seam's own deadline contract, and poison makes budget
  accounting unprovable; RefCell trades the compile-time proof for a latent runtime borrow panic).
  `ExecChildSpawn::production()` = the `/proc/self/exe` LITERAL (infallible — no error arm; the magic
  link resolves at EXEC time to the running parent's inode, so a mid-boot on-disk upgrade cannot drift
  the parent/child frame halves across versions, which a `current_exe()` PATH would race; matches the
  (d-i) seam pin verbatim); `HardBoundedQuoteProducer::production(&ValidatedBootBudget) -> Result`
  ((d-ii)/3 witness signature) errs only on the claim refusal; the one-call (4b)/5b-2c entry is now
  `agent_gateway_boot::run_boot_handshake_wired`; its mint is the ONE shared body
  `ValidatedBootBudget::transport_with_spawn`, which `production_transport` instantiates with the
  production spawn shape (pins unchanged). **NEW 5b-2c obligation:** the serve-path signature must name the
  CONCRETE `HardBoundedQuoteProducer` (default `S = ExecChildSpawn`), NEVER a generic
  `<Q: BootQuoteProducer>` — a generic wrapper re-opens the hole (4a) DELETED (any substituted
  `BootQuoteProducer` impl — the deletion's unrepresentability holds only while the serve path names
  the concrete type).
  Landing (2) does NOT open live serve (the TWO-artifact gate below is unchanged) and does NOT
  discharge pin (2) below (production-shape runtime stays ZERO-CI; the construction-shape CI test is
  not the discharge — (4c) is). — (3)
  budget-gate integration — **LANDED ((d-ii)/3)**: `ValidatedBootBudget` (in `quote_subprocess`,
  triple-gated — never wider than the three consumed consts' cfg intersection) = gate #2 of the
  TWO-artifact live-serve gate; sole constructor `validate(max_attempts, per_leg_timeout,
  overall_boot_budget)` runs the order-pinned fail-closed chain (zero/over-ceiling attempts → floor
  → **MAX_PER_LEG_TIMEOUT sanity ceiling** (keeps every blessed value panic-free for the transport's
  `Instant::now() + timeout` mints — std's Add panics on overflow; xhigh finding) → CHECKED overflow
  (defense-in-depth, unreachable while the ceiling holds; checked NOT saturating) → ε-bearing
  exceeds; the `3·` (quote + freshness + marks) exists only as a call-site fact — the formula is the generalized leg-sum). The
  producer's constructors take it as an ORDERING WITNESS (`new(&budget, spawn)` /
  `production(&budget)`): validation-before-claim is a compile fact — SCOPE HONESTY: the witness
  proves SOME budget validated, not that THE SAME instance feeds the wiring; the timeout binding is
  structural via `production_transport(channel)` (composes both gate ARTIFACTS in one call, mints
  the transport from `per_leg_timeout()`; droppable to getter-sourcing if contested — recorded
  fallback), and **the driver-count binding is a named, TEST-BACKED (4b) acceptance item: the count
  passed to `run_boot_anti_rollback_handshake` MUST be `budget.max_attempts()` from THE SAME witness
  instance, and the (4b) test must refuse the drift** (the driver keeps its raw-u32 signature for
  cfg-lattice reasons) — DISCHARGED at (4b), by construction + the named test (see the (4b) LANDED
  entry below). The parent-side reap
  obligation is RE-SCOPED to 5b-2c with hard constraints (see above — the in-fetch emission was
  reverted); the TWO-PHASE config logging is LIBRARY-DISCHARGED at (4b) (the bin only FORWARDS the
  `AgentBootEvent` lines — see the (4b) LANDED entry), and the witness
  construction from operator config remains 5b-2c work. Landing (3) does NOT open live serve. (4a)
  cooperative-path deletion — **LANDED (this PR)**: removed `SnpQuoteProducer`,
  `fetch_report_deadline`, the `Option<Instant>` plumbing and its deadline tests — INCLUDING the
  `fetch_report_with_at` signature rework: the cooperative `deadline: Option<Instant>` parameter is
  GONE from the whole `snp_report` fetch chain (`fetch_report_with`/`_at`/inner); the (d-ii) child is
  the only caller at a SELF-NAMED entry path, while `_at` remains the SHARED orchestration core under
  the producer wrapper `fetch_report_with` (stale-clear → sequence → unconditional cleanup serves BOTH
  paths — a child-specific edit to `_at` changes the producer path too), and the whole chain is now
  unbounded BY SIGNATURE — the rustdoc-pinned "makes the
  narrowing structural: `_at` loses the parameter entirely" obligation is DISCHARGED. The
  fixed-`twod-hsm` exclusivity claim flips TRUE (see the rescoped sentence above), (4b) live
  wiring of `HardBoundedQuoteProducer` into the boot path — **LANDED ((d-ii)/4b)**: new triple-gated
  module `agent_gateway_boot` (cfg = the dependency intersection, never wider) with the pub(crate)
  CONCRETE wired entry `run_boot_handshake_wired` over a module-PRIVATE generic core
  (`run_boot_handshake_core`), the typed boot-event seam `AgentBootEvent`/`BootLogLevel`
  (library-owned `level()`), and the `ValidatedBootBudget` additions `transport_with_spawn` (the ONE
  shared producer+transport mint; `production_transport` = its production-spawn instantiation, pins
  unchanged) + `slack()` (log-only saturating_sub — the "checked NOT saturating" rule targets budget
  PRODUCTS, not a log difference of validated fields). Sequence: raw-triplet event →
  `validate` (`?`) → validated event (incl. slack) → mint (`?`) → driver with
  `budget.max_attempts()` INLINE → `HandshakeOutcome` event → `decide_serve`. Named-item
  discharges, each test-backed: DRIVER-COUNT BINDING discharged BY CONSTRUCTION (no count parameter
  exists anywhere on the new surface; the count is derived in-body from the SAME witness local that
  minted the transport) + the named test `wired_driver_count_is_the_same_witness_max_attempts`
  (spawns == round_trips == config N through BOTH legs; honesty note: its refusal power is
  VALUE-level, not instance-level — a second validate() with identical numbers is observationally
  identical and harmless; the §8 drift class (different numbers) is what the signature eliminates
  and the test refuses); TWO-PHASE LOGGING content+severity LIBRARY-discharged (`AgentBootEvent`
  Display + `level()`; zero-slack Warn is library logic) — tests
  `boot_events_raw_triplet_before_validate_on_refusal` (phase (a): the raw event is the operator's
  only numbers copy in a fail-closed boot),
  `wired_wrapper_emits_validated_getters_and_slack_before_the_claim` (phase (b), emitted BEFORE the
  claim; doubles as proof the wrapper constructs the CONCRETE process-claiming producer — a
  generic-Q shim claims nothing), `boot_events_zero_slack_is_warn_and_still_boots` (zero slack
  validates AND warns); ONE-handshake-per-process pinned AT THE WIRING by
  `wired_second_call_refuses_via_permanent_claim_before_any_attempt` (claim refusal is FATAL
  position — post-validate, pre-driver, no attempt spent); the full composition + install-on-Fresh
  provenance by `wired_boot_ready_installs_binding_and_serves_with_real_gate` (require_real=true).
  Never-generic-Q HELD: the wired path names the concrete producer via the single mint; the generic
  core is module-private; generic-`S` is INSIDE the (4a)-closed class, not a reopening ((d-ii)/2's
  own "default `S = ExecChildSpawn`" wording: every `S` runs under the same pipe-poll → SIGKILL →
  ledger orchestration; `<Q: BootQuoteProducer>` substitutes the BOUND ITSELF, `S` cannot — its only
  non-test impl is `ExecChildSpawn`). Serve NOT opened: nothing `pub`, no bin, no listener,
  dead-code-allowed until 5b-2c; the TWO-artifact gate stands. The `HandshakeOutcome` event is the
  ONE scope-add beyond the named items — the boot-log carrier of the `BootDriverFail` cause that
  `decide_serve` deliberately folds to its uniform refusal string (without it (4b) would wire the
  exact numberless-refusal anti-pattern the two-phase item exists to prevent; drops cleanly if
  contested). The Display lines become a de-facto operator interface — journald tooling is tracked
  at the 5b-2c smoke. The production wrapper's one-line spawn VALUE
  (`ExecChildSpawn::production()`) stays (4c)'s checked item: production spawn-shape runtime remains
  ZERO-CI by pin — the (4c) in-guest run is the coverage. The TWO-artifact live-serve gate stands:
  wiring here does NOT open live serve until (4c) PASSes, (4c) the in-guest aya smoke (SNP spike
  2026-06-10: `.#disk-production-lab` boot+configfs PASS in ~80s warm — the guest path is alive; test
  delivery = lab profile + test-binary oneshot printing to ttyS0) — **PASSED on aya 2026-06-11
  (2 SNP runs, RESULT PASS phases=7, all three witnesses; ~80s warm):**
  the lab-only `twod-hsm-quote-smoke` `[[bin]]` (feature `lab-quote-smoke`, release-banned;
  dispatch-first main = the 5b-2c main SHAPE) + `quote_smoke::run_quote_smoke()` driving seven
  ordered phases (vsock-lapse → gc-seed → budget-claim → quote-1 → gc-clean → quote-2 → breadcrumb;
  order LOAD-BEARING — the claim is permanent) inside `.#disk-production-lab-quote-smoke` (oneshot
  under the production sandbox knobs, journal+console, ExecStartPost journald-arrival assert), host
  gate `run-nix-snp-quote-smoke.sh` (three independent witnesses: `RESULT PASS` + the raw ttyS0
  breadcrumb + the unit's journald-arrival marker). **PASSED on aya 2026-06-11 (2 SNP runs, RESULT
  PASS phases=7, all three witnesses; ~80s warm boot).** Discharges NAMED, each naming exactly what RUNS:
  **pin (2)** — the production spawn shape (`PipeSource::Stdout`
  + `clear_env` + stderr→journald) runs live via `ExecChildSpawn::production()` through
  `HardBoundedQuoteProducer::fetch` at `twod-hsm-q-<pid>`, breadcrumb observed IN journald AND on
  ttyS0; **dispatch-first realism** — a real `/proc/self/exe` re-exec, both polarities (healthy
  frame + the staged ERR(1)); dispatch stays zero-CI by pin (the smoke + the bin-contract test
  `tests/twod_hsm_quote_smoke_bin.rs` are the coverage); **loader/RPATH validation** (5b-2c
  precondition (1) above) — the `clear_env` re-exec of the Nix-built DEBUG binary fetches a real
  quote (the RELEASE-built agent bin remains 5b-2c coverage); **the (d) in-guest items** (the (d)
  bullet above) incl. no-stale-entry GC via the child-side prefix GC — HONESTY: the smoke seeds a
  synthetic orphan-shaped entry (`twod-hsm-q-stale-4c`, non-numeric suffix: unallocatable as a pid,
  proves prefix-MATCH not pid-parse) and asserts the post-state; the kill→orphan TRANSITION is not
  staged (ms-fast healthy provider; kill mechanics are (d-i)-pinned by
  `killed_wedged_child_shows_sigkill`); **claim permanence + single-claim two-fetch reuse** observed
  live in a shipped binary (CI only sees the claim under cfg(test) resets). Acceptance EXPLICITLY
  includes exercising the production spawn shape (`PipeSource::Stdout` + `clear_env` +
  stderr→journald), restating pin (2) below as this sub-slice's checked item (the stderr-piped test
  shape does NOT discharge it) — rather than one subprocess+configfs+wiring mega-review (the
  bundling an unsplit (4) would have recreated).
  **(4c) NEW-SURFACE record (house rule; live serve stays CLOSED):** feature `lab-quote-smoke`
  (bare marker, no deps, release-banned by `compile_error!` in lib.rs); `pub use
  quote_smoke::run_quote_smoke` (QUADRUPLE-gated: the consumed items' triple gate ∩ the marker —
  never wider); the `twod-hsm-quote-smoke` `[[bin]]` (`required-features = agent-gateway +
  vsock-transport + lab-quote-smoke` — a SUPERSET of the 5b-2c manifest pin; never
  production-vsock/staging-vsock, which would trip role isolation); the pub(crate)
  `connect_bounded_for_smoke` shim (`connect_bounded` itself stays module-private); the
  `TSM_REPORT_DIR` pub(crate) promotion; the single-sourced connect-arm string consts
  `VSOCK_CONNECT_LAPSE_MSG`/`VSOCK_CONNECT_VETO_MSG` (+ literal pin tests);
  `quote_subprocess::smoke_breadcrumb_arm` (quadruple-gated; never callable from cargo-test code —
  rustdoc TEST RULE); `tests/twod_hsm_quote_smoke_bin.rs` (CI-enforces the SMOKE bin's
  dispatch-first + PROTOCOL-ONLY stdout; SEEDS but does NOT discharge the 5b-2c byte-exact item —
  that test must re-target `CARGO_BIN_EXE_<agent-bin>`; the env names stay crate-private per the
  pin above — the test transcribes the literals, fail-loud by construction). Explicit: live serve
  stays CLOSED — `run_boot_handshake_wired` remains unexported; the smoke does no handshake and no
  serve; parent-side configfs I/O in the smoke (gc-seed mkdir + the read_dir asserts) is a recorded
  SMOKE-ONLY allowance (the no-parent-configfs-I/O rule binds the production boot path). CI: the
  pinned (c) leaf step is byte-identical; a NEW additive step runs the bin-contract test + the
  `quote_smoke` deadline-window unit under `vsock-transport,agent-gateway,lab-quote-smoke`.
  **Named (d-ii) obligations** *(the `fetch_report_with_at` promotion + entry-path test: DISCHARGED in
  sub-slice 1)*: the production child's STDOUT is PROTOCOL-ONLY (no
  logging, no panic text — the std panic handler writes to stderr, which production inherits to
  journald; nothing else may write to the pipe); child error classification is CLOSED by design — ALL
  child-reported failures (ERR frames) and ALL parent-side fetch errors fold to the retryable
  transport class at the seam (no terminal smuggling; a host/child cannot manufacture a terminal boot
  verdict). **Three (d-ii)/5b-2c pins from the (d-i)
  review:** (1) `HardBoundedQuoteProducer` owns THE one `AbandonedLedger` for the process — the budget
  binds only if exactly one ledger outlives all fetches (a fresh ledger per attempt resets `is_full()`
  and voids the cap; the ledger's own doc carries the same pin) — **DISCHARGED structurally in
  (d-ii)/2, see the LANDED note above (process claim + privacy demotions + no-Clone + `&mut self`)**;
  (2) the production spawn shape
  (`PipeSource::Stdout` + `clear_env` + stderr→journald) has ZERO (d-i) coverage — the (d-ii) aya smoke
  of the shipped producer MUST exercise exactly that shape (checked item, not assumed from the
  stderr-piped test shape); (3) **5b-2c acceptance item — bin-contract enforcement:** the
  `agent_quote_child_dispatch()`-as-main's-FIRST-statement + PROTOCOL-ONLY-stdout contract is documented
  (dispatch rustdoc + this section) but structurally unenforceable until the bin exists — 5b-2c MUST ship
  a real-subprocess test that spawns the ACTUAL agent bin (`env!("CARGO_BIN_EXE_<agent-bin>")`; production
  spawn shape: marker env set, `clear_env`, stdout piped) and asserts the child's stdout, read to EOF, is
  BYTE-EXACTLY the expected frame and nothing else — full-buffer equality, NOT the frame parser (the
  parser's per-drain-window tolerance must not mask banner/log bytes before or after the frame) — plus the
  matching exit code. Deterministic deviceless arms (no configfs needed, plain CI): (a) marker env set,
  report_data env missing ⇒ stdout == `encode_err_frame(1)` exactly, exit 1; (b) valid report_data env on
  a configfs-less host ⇒ stdout == `encode_err_frame(2)` exactly (create fails), exit 2. Place the test as
  an INTEGRATION test (`tests/`): Cargo's documented contract sets `CARGO_BIN_EXE_<name>` only when
  building integration tests/benches, NOT lib unit tests — and the pub(crate) frame encoders are
  unreachable from an integration test anyway, so pin the expected frames as GOLDEN BYTES (the 2-byte ERR
  frames are stable wire constants; the in-crate golden-byte test already pins the same encoding). A
  dispatch moved below any stdout-writing statement — or any stdout logging anywhere in the bin — fails
  this test by construction.* Acceptance criteria — split by what each environment can actually stage (per the honest
  limit above, a true D-state wedge cannot be staged on demand ANYWHERE, so NO acceptance item requires a
  live wedged provider): (1) **D-state/unreapable arm — fake-handle, deterministic (landed in (d-i)):**
  **"no stuck process accumulation across repeated timeouts"** and **"a subsequent attempt is well-defined
  (no entry collision) after a timeout"**, proven by the Fake-handle ledger tests (kill-pends →
  abandon-ledger → budget refusal); promptness needs no live wedge — the parent never waits BY TYPE, so
  the attempt fails at the deadline regardless of child state; (2) **S-state timeout — real subprocess
  (CI, repeated on aya):** a stalled-but-killable child stand-in (sleeping, NOT a real provider wedge) is
  killed at the deadline and the attempt fails promptly with a retryable error rather than hanging boot;
  (3) **healthy-path in-SNP-guest aya smoke:** the shipped producer in its production spawn shape
  (`PipeSource::Stdout` + `clear_env` + stderr→journald — pin (2) above) fetches a real quote through
  configfs-tsm. No acceptance item stages a real D-state provider wedge — that arm's only deterministic
  coverage is (1), by design. **This is the live-serve blocker:** 5b-2b-ii(a)/(b) only unblock 5b-2c
  *construction/compilation* (the concrete channel exists); a **live anti-rollback serve path requires (d)**.
  There is no "wire it live but best-effort" window — (4a) DELETED the cooperative path (nothing
  best-effort remains to wire); a live serving 5b-2c MUST wait for (d) — (4b) wiring + the (4c) smoke
  (the wedged-read hang is otherwise reachable).
- **⚠️ 5b-2e UPDATE — the budget is now THREE legs.** Everything in this bullet below describes the
  historical 5b-2b TWO-leg model (quote + freshness). 5b-2e's `AdoptForward` path runs a THIRD per-leg-
  bounded round-trip (`marks_round_trip`) within an attempt, and a continuously-advancing anchor can make
  every one of `max_attempts` attempts take it, so the **enforced invariant and the derived default are
  now `max_attempts · (3·timeout + ε)`** (quote + freshness + marks; the marks leg adds one channel
  deadline, NOT a second ε). `per_attempt_nominal_cost` sums all three legs and the env-config derive uses
  `3·per_leg`. Read every `2·timeout`/`2·per_leg` below as `3·` for the CURRENT enforced ceiling — the
  generalized leg-sum shape is unchanged; only the leg COUNT grew.
- **Timeout semantics + total bound.** The single-`timeout`-per-leg model from 5b-2a is the **baseline and
  is final for 5b-2b** (quote and channel each get `timeout`; one attempt ≤ `2·timeout` + the subprocess overhead ε
  ([`QUOTE_ATTEMPT_OVERHEAD`], as of (d)); total boot ≤ `max_attempts · (2·timeout + ε)` **for the 5b-2b two-leg model — 5b-2e raises this to `3·timeout` per the ⚠️ banner above**) — `RelayAnchorTransport` threads one `Duration` and gives each leg its own
  `Instant::now()+timeout`. **Decision (was an unassigned SHOULD):** exposing *distinct*
  `quote_timeout`/`relay_timeout` is **deferred to 5b-2c** (the bin that constructs the transport and owns
  operator config) — NOT 5b-2b-i/ii, which keep the single-budget model. 5b-2c, if it splits them, MUST
  restate the resulting total-boot bound as a success criterion so "timeout" is never ambiguous between
  total-attempt and per-leg. **Exact-bound caveat — SATISFIED in 5b-2b-ii(a):** the per-leg bound (`≤ 2·timeout`
  for a freshness attempt, `≤ 3·timeout` for an adopting one — see the ⚠️ 5b-2e banner) only
  holds if the socket `SO_*TIMEO` are derived from the *remaining* per-leg budget, NOT set equal to the full
  leg `timeout` — otherwise a single blocked in-flight syscall could overrun a leg by up to one socket
  timeout. (The derived-from-remaining premise applies to every channel leg, freshness and marks alike.) `VsockBootRelayChannel` achieves this via `DeadlineSocket`, which reapplies the timeout =
  remaining-budget before EVERY read/write (not once), so the channel-I/O leg is tightly bounded by the
  deadline. (Connect is the cancellable hard bound (a') — DONE PR #56: non-blocking connect + `poll(POLLOUT)`
  to the deadline; see above.) **Per-leg sizing floor (5b-2c):** the
  per-leg `timeout` is shared SEQUENTIALLY by connect + I/O, so 5b-2c MUST pick a value with headroom for
  both (NB per the kernel-timer note below, a connect can only consume "nearly the whole leg" when the per-leg `timeout` is ≲ the ~2s kernel connect timer — for longer legs a wedged connect is kernel-capped at ~2s and the I/O budget keeps the rest), AND MUST
  satisfy the boot-budget invariant **`max_attempts · (3·timeout + ε) ≤ overall_boot_budget`** (3 legs
  since 5b-2e — quote + freshness + marks; ε = the
  quote-subprocess overhead const `QUOTE_ATTEMPT_OVERHEAD`, see the ε term below) so the bounded
  retry loop can't blow the operator's total boot deadline. **The checked-arithmetic validation
  artifact EXISTS ((d-ii)/3): `quote_subprocess::ValidatedBootBudget`** — the invariant is validated
  fail-closed at construction for any caller holding the witness, and the producer's constructors
  REQUIRE it by signature. WORDING DISCIPLINE: the ceiling stays NOMINAL sizing arithmetic (ε is not
  a runtime guarantee — the runtime hard bounds remain the per-leg deadlines), and live serve is
  STILL gated on (d) incl. the (4c) smoke + (4b) wiring — the artifact landing does NOT open live
  serve; the surviving gate-#2 obligation is 5b-2c constructing the witness from operator config. **Invariant (wiring-enforced in 5b-2b — a single
  local variable, NOT a structural gate; re-verify on any refactor of `round_trip_inner`):** `connect_bounded`'s
  `deadline` arg is the **per-leg channel deadline** —
  `round_trip_inner` passes the *same* `deadline` local to `connect_bounded` and to the channel-I/O
  `DeadlineSocket`, so connect + I/O share ONE channel-leg `timeout` — and this holds INDEPENDENTLY for
  EACH channel leg the boot runs (the freshness `anchor_round_trip` and, on an adopt, the 5b-2e
  `marks_round_trip` — both go through the same `round_trip_inner` wiring). The leg COUNT in the invariant
  counts the *quote* leg + the *freshness-channel* leg + the *marks-channel* leg (`3·`), NOT connect-vs-I/O
  within a single channel leg. Nothing prevents a refactor from passing two different
  deadlines (no newtype/constructor coupling — by the standard this doc applies to (d), that would be a prose
  check, which is why this line says *wiring*-enforced), so any future change to `round_trip_inner` MUST
  re-verify it (for BOTH channel legs); the named break mode is handing `connect_bounded` the *overall* boot deadline, which would
  void the per-leg accounting. 5b-2c does NOT thread this deadline (it only constructs the channel and
  supplies `max_attempts`/`timeout`), so the surviving 5b-2c obligation is purely the budget sizing
  (`max_attempts · (3·timeout + ε) ≤ overall_boot_budget` — 3 legs since 5b-2e). **Post-(a') threat model (kernel-timer-aware):** with
  the fd/thread leak gone, a black-holing host no longer exhausts the guest fd table. For the remaining TIME
  cost, note the kernel's own per-socket connect timer: a non-blocking AF_VSOCK connect arms
  `vsk->connect_timeout` (**default `VSOCK_DEFAULT_CONNECT_TIMEOUT` ≈ 2s**; `connect_bounded` does not set
  `SO_VM_SOCKETS_CONNECT_TIMEOUT`), and on expiry the kernel fails the socket (`sk_err = ETIMEDOUT`) and
  wakes the poller with `POLLERR|POLLOUT` → the `connect_poll_succeeded` veto → a retryable error. So a
  sustained black-hole costs **`~min(timeout, ~2s)` per wedged connect leg** — the caller's
  `poll_with_deadline` lapse is the binding bound only for per-leg timeouts SHORTER than the kernel timer;
  worst-case connect-only cost is `max_attempts · min(timeout, ~2s)` (the no-listener/reset case is prompt,
  milliseconds). Budget-consumption was never a *new* exposure from (a') (the old watchdog also blocked the
  caller up to the budget; (a') removed the *leak*, not the time cost), and the
  enforced CEILING is the ε-bearing form `max_attempts · (3·timeout + ε) ≤ overall_boot_budget` (5b-2e: 3 legs) — the
  TIMEOUT portion is conservative (the kernel connect timer can only make real attempts cheaper, never
  costlier; the I/O leg, which has no kernel cap, can still consume its full per-leg share), but ε is
  ADDITIVE overhead the kernel timer cannot absorb (it lands between the legs), which is exactly why the
  ε-less product is NOT a valid ceiling and every statement of this invariant carries the ε term. **5b-2c MUST enforce it as a structural artifact (NOT
  a prose checklist line) — same MUST/enforceable standard the doc applies to (d), and gate #2 in the
  dependency-order list above:** because this invariant is
  now load-bearing as the sole availability bound, 5b-2c MUST validate **whichever invariant form it ships**
  (the `3·timeout + ε` form, or the generalized `quote_timeout + freshness_timeout + marks_timeout + ε`
  form below if distinct timeouts ship — BOTH carry ε; do NOT hardcode the `3·` special case in the check) where the
  transport/driver is
  constructed — a constructor/config check that **returns an error** (fail-closed, not merely a
  `debug_assert`, since the bound must hold in release) when the shipped form exceeds `overall_boot_budget`.
  The check MUST run AFTER `max_attempts` range validation (below), use **CHECKED arithmetic ONLY —
  saturating arithmetic is FORBIDDEN for budget products** (`u32 · Duration` products can overflow; a
  wrapped product passing the check is the exact failure the gate exists to stop, and a SATURATED
  `Duration::MAX` product would PASS `≤ Duration::MAX` — saturation re-opens the same hole; this rule
  carries unchanged into the generalized distinct-timeout form if it ever ships), and reject zero /
  sub-`MIN_BOUNDARY_BUDGET` timeouts at config-parse time (a 0ms leg is
  meaningless and `set_read_timeout(ZERO)` is an Err on vsock). *Hardening note (one of TWO
  prose-enforced premises this gate rests on — the other is the same-instance driver-count binding,
  the named test-backed (4b) item above):* the per-leg accounting assumes connect+I/O share ONE deadline — and
  this premise applies INDEPENDENTLY to each channel leg (freshness AND, on adopt, marks; the `3·` counts
  quote + freshness-channel + marks-channel) — which is only
  wiring-enforced in `round_trip_inner` (see above) — when 5b-2c builds the budget check, prefer computing it
  where both deadlines ORIGINATE (e.g. a constructor that derives connect and I/O deadlines from one
  channel-leg value), so the structural gate cannot outlive the wiring assumption it depends on.
  This is a checked 5b-2c task item, ordered BEFORE any live-serve wrapper. **STATUS ((d-ii)/3 —
  LANDED): the artifact is `quote_subprocess::ValidatedBootBudget`** (triple-gated; home chosen for
  cohabitation with ε's definition + no second triple-gate mod declaration — a same-gated sibling
  consuming the consts by path would be equally transcription-free, the HARD rule is only that the
  artifact's gate is never WIDER than the three consts' cfg intersection). Sole constructor
  `validate(max_attempts, per_leg_timeout, overall_boot_budget)`: fail-closed `Err` in release;
  order-pinned chain (range → floor → MAX_PER_LEG_TIMEOUT sanity ceiling [keeps every blessed value
  panic-free for the downstream `Instant::now() + timeout` mints — std's Add panics on overflow] →
  CHECKED overflow [defense-in-depth, unreachable while the ceiling holds; checked NOT saturating —
  a saturated `Duration::MAX` product would PASS `≤ Duration::MAX`, the exact wrapped-product
  failure named above] → exceeds); the check arithmetic is written in the GENERALIZED leg-sum form
  (no multiplier literal in the VALIDATION formula — `per_attempt_nominal_cost` sums quote + freshness +
  marks + ε as named legs, so a future distinct-timeout split changes its constructor INPUTS, never the
  formula. The gate-free env-config DERIVE is separate and DOES carry a `3·per_leg` literal —
  `derive_overall_budget_ms`'s `saturating_mul(3)` + the `3 * attempts` test assertion — which a
  distinct-timeout split would also have to update; it is sized ≫ ε by design, not a re-derivation of the
  formula). The BEFORE-claim ordering pin is now STRUCTURAL:
  `HardBoundedQuoteProducer::{new, production}` take `&ValidatedBootBudget` as an ordering witness
  (scope honesty: SOME budget — same-instance binding is `production_transport` for the timeout +
  the recorded (4b) count obligation). Deadline ORIGINATION is
  structural too: `ValidatedBootBudget::production_transport(channel)` claims the producer AND
  constructs `RelayAnchorTransport` from `per_leg_timeout()` in one call — the value the invariant
  was checked against IS the value both leg deadlines are minted from (the transport cannot take the
  type BY SIGNATURE — cfg-lattice: `agent_boot_relay` compiles in agent-gateway-without-vsock builds
  where the type does not exist — so its Duration seam is the deliberate coupling shape). The
  surviving wiring-enforced residual (connect+I/O sharing ONE channel-leg deadline in
  `round_trip_inner`) is UNCHANGED — its re-verify pin stands. **ε term — EXPLICIT in the
  operator-facing check [user decision 2026-06-10]:** as of (d), each attempt additionally costs the
  quote-subprocess overhead ε — **the code const `quote_subprocess::QUOTE_ATTEMPT_OVERHEAD`** (derived
  from its dominant term `REAP_GRACE` + a spawn/kill/fd-close margin; assert-pinned so a `REAP_GRACE`
  retune moves ε with it — 5b-2c consumes the CONST, never a transcribed number; currently 12ms, all
  non-blocking by construction — no `wait()` exists behind the `ChildHandle` seam), landing BETWEEN
  the legs. **ε's nature, stated honestly: NOMINAL accounting, not a hard wall-clock ceiling** — only
  the reap grace is code-bounded; `Command::spawn`, SIGKILL delivery and the ~1ms sleeps can stretch
  under scheduler load. The config-time check is therefore SIZING ARITHMETIC enforced fail-closed at
  construction (it stops mis-sized configs, the failure class that is actually configurable), NOT a
  runtime guarantee — the runtime hard bounds remain the per-leg deadlines themselves, and operators
  MUST size `overall_boot_budget` with slack above the nominal product (a budget set exactly equal to
  it is mis-sized by definition). The enforced check is therefore
  **`max_attempts · (3·timeout + ε) ≤ overall_boot_budget`** (3 legs since 5b-2e — quote + freshness + marks)
  (nominal worst case `max_attempts·ε ≈ ≤0.8s` at the 64-ceiling) — an explicit term, not silent slack. **Generalized form (the
  `3·` assumes connect+I/O share one per-leg `timeout` on BOTH channel legs AND the quote leg uses the same `timeout`):** if
  5b-2c exposes *distinct* per-leg timeouts (deferred decision, see above), the invariant generalizes to
  **`max_attempts · (quote_timeout + freshness_timeout + marks_timeout + ε) ≤ overall_boot_budget`** — 5b-2c MUST restate
  and enforce whichever form it ships.
  - [x] **Deferred verification artifact (CHECKED residual — do not lose behind "DONE PR #56") —
    DISCHARGED in (4c), PASSED on aya 2026-06-11 (2 SNP runs; lapse fired at ~399ms, our deadline,
    after a floor-slop fix for poll(2)'s whole-ms truncation):** the
    real-vsock in-flight-connect black-hole *deadline lapse* test (previously unit-level-only via
    `poll_times_out_when_not_ready`) is `quote_smoke` phase `vsock-lapse`: IN-GUEST
    guest→nonexistent CID (999_999_983) through the quadruple-gated `connect_bounded_for_smoke`
    shim, 400ms deadline, the lapse-arm const `VSOCK_CONNECT_LAPSE_MSG` asserted EXACTLY (the veto
    string = the staging assumption broke = a loud FAIL printing the observed string), elapsed ∈
    `[400ms − 25ms floor-slop, 1500)` (the slop absorbs poll(2)'s whole-ms truncation — the real lapse
    fired at ~399ms on aya). RECORDED FACTS so nobody re-derives them: HOST-side staging is IMPOSSIBLE —
    host→nonexistent CID fails synchronously `ENODEV` in `vhost_transport_send_pkt` (no
    `EINPROGRESS`, no black hole); a listening-never-accepting peer completes the handshake at
    `listen()` time; unbound ports RST promptly (= the already-aya-verified veto arm). Mechanism:
    the guest virtio transport queues the connect REQUEST unconditionally; host vhost_vsock
    silently FREES `dst_cid != 2` packets — no RST, no RESPONSE. Pre-designed fallback stagings if
    a future kernel RSTs unknown-CID: SIGSTOP a second booted guest and connect to ITS CID (frozen
    virtqueue = a true black hole; host orchestration cost), or raise
    `SO_VM_SOCKETS_CONNECT_TIMEOUT` and keep the deadline under the timer. Constraint (kernel-timer
    note above) UNCHANGED: the deadline MUST be **< ~2s** or the test silently exercises the
    kernel-`ETIMEDOUT` veto arm instead of the lapse arm — now CI-pinned by the deviceless unit
    `lapse_probe_deadline_is_inside_binding_window`.

  **Term definitions (single source — 5b-2c wires
  both into one check):** `max_attempts` = the value 5b-2c passes to
  `run_boot_anti_rollback_handshake(..., max_attempts)` — valid range **`1..=MAX_BOOT_ATTEMPTS_CEILING
  (= 64)`**; the driver **REJECTS** out-of-range values as `Unstartable` (0 and `> 64` are config errors —
  it does NOT silently clamp; see `agent_boot_driver.rs`: "reject, don't clamp" — so 5b-2c must validate the
  range at config parse, not assume clamping);
  `timeout` = the per-leg `Duration` 5b-2c gives `RelayAnchorTransport::new`; `overall_boot_budget` = a NEW
  5b-2c operator config (the total wall-clock the platform allows for boot before fail-closed). 5b-2c MUST
  pick `max_attempts`/`timeout` so the product respects its own `overall_boot_budget`.
- **Socket-timeout precondition — DONE in (a) for read/write; connect via (a') DONE PR #56.** `read_bounded_anchor_response`'s
  deadline is only enforceable if the stream has `SO_RCVTIMEO`/non-blocking set. `VsockBootRelayChannel`
  sets `SO_RCVTIMEO` + `SO_SNDTIMEO` (per-syscall via `DeadlineSocket`); the **connect** bound is the
  cancellable hard bound **(a') — DONE PR #56** (non-blocking connect + `poll(POLLOUT)` to the deadline via
  [`connect_bounded`], `set_nonblocking(false)` afterwards so `SO_*TIMEO` apply to I/O). **What the aya tests
  actually verify:** behaviorally — `SO_RCVTIMEO` via a stalled-peer read that times out within budget; the
  connect bound via a prompt connect-failure (which lands via the `connect_poll_succeeded` veto arm, error
  string `"anchor relay: vsock connect failed (poll)"` — see the (a') AC for the kernel arm-attribution detail). Directly —
  the `vsock_connect_restores_blocking_and_arms_so_timeo` test asserts `O_NONBLOCK` is cleared post-connect
  (`F_GETFL`) and reads BOTH armed `SO_RCVTIMEO`/`SO_SNDTIMEO` values back via SAFE nix getsockopt
  (`sockopt::ReceiveTimeout`/`SendTimeout` — the former "readback needs `unsafe`/`libc`" limitation is gone
  since the nix `socket` feature; `SO_SNDTIMEO` thus IS now asserted by value even though a small request
  frame never makes `write_all` block behaviorally). (The daemon (b) anchor-facing socket has the same
  obligations — bounded transport-conditionally, see the (b) bullet.)
  The connect/socket timeout **budget is derived from the per-leg `Duration`** (a fraction of it), NOT a
  separate operator knob, so channel (a) and daemon (b) coordinate on the same source and the total-boot
  bound stays verifiable.
- **Serialization premise (write it down).** Quote fetches are **strictly serial within a guest** —
  unchanged, but as of 5b-2b-ii(d) the protected invariant changed: the fixed-`twod-hsm` start-of-attempt
  `remove`+`create` premise now applies ONLY to the unbounded producer path; the subprocess quote path uses
  unique `twod-hsm-q-<pid>` entries. Serial execution is now load-bearing for a NEW reason: the
  **child-side prefix GC** may only run when no sibling quote child is mid-fetch (a concurrent attempt's
  entry could be swept between its `create` and its blob I/O). Serial driver attempts + the
  one-handshake-per-process rule guarantee **≤ 1 ACTIVE (non-abandoned) quote child** — NB up to
  `ABANDONED_CHILD_BUDGET` (64) killed-but-unreapable D-state children can simultaneously remain LIVE,
  each still holding its `twod-hsm-q-<pid>` entry; the child-side GC MUST treat held entries as
  EXPECTED, never impossible: best-effort `remove_dir` per prefixed name, EVERY failure (EBUSY on a
  still-wedged sibling's entry, absent dir) skipped silently, never blocking or gating the attempt, and
  GC is never required to prove all orphans were removed before proceeding. Any future parallel-attempt OR
  split-timeout idea (the distinct `quote_timeout` decision deferred to 5b-2c is the named candidate)
  MUST first (a) scope GC per attempt owner, AND (b) re-derive BOTH naming premises — the subprocess
  path's per-pid uniqueness assumes ≤1 live quote child, and the PRODUCER path still uses the fixed
  `twod-hsm` remove+create, which silently corrupts if two producer fetches (or a producer fetch and a
  pre-(d-ii) cooperative boot fetch) ever overlap.
- **Host-relay daemon (its own 5b-2b sub-checklist).** Define: daemon location + feature gate; the
  upstream enclave→anchor request/response schema; the **error→framing mapping** — a relay/anchor error
  (unavailable, timeout, upstream 5xx) MUST be surfaced to the enclave as a *retryable transport close*
  (so the driver retries), NEVER as malformed bytes (which the driver would turn into a TERMINAL
  `VerifyMalformed`, burning the attempt budget on a transient); retry/concurrency model; and tests for
  anchor-unavailable, timeout, malformed-anchor-response, and oversized-response cases. **Concretely:** on
  ANY `Err` from `relay_forward_once` (malformed enclave request, anchor connect/timeout, oversize/garbled
  anchor reply, write failure to either side) the daemon MUST **drop/close the enclave connection** and
  loop to the next one — it MUST NOT write partial or synthesized anchor-looking bytes back, and MUST NOT
  hold the connection open after a fault (a half-written response would desync the next frame). The error
  is logged out-of-band (operator-facing, not over the wire). This keeps every relay fault a *retryable
  close* the enclave's per-attempt deadline + `max_attempts` already handle. **Decode-gate leniency
  invariant:** `relay_forward_once` rejects a malformed request via `decode_anchor_boot_request` *before*
  an anchor round-trip — this relay-side gate MUST stay **at least as lenient as the anchor's own
  acceptance**, else a request the anchor would have honored becomes a relay `Err` → retryable close that
  silently burns the enclave's attempt budget toward a false terminal. If the anchor is the SAME process
  reusing `decode_anchor_boot_request`, `relay ⊇ anchor` holds trivially. If the anchor is a **separate
  service** (the likely deployment), this is a **cross-component sync obligation, not a present fact**.
  **Sufficiency for the production path:** the enclave *encoder* (`encode_anchor_boot_request`) is canonical,
  so the only request that ever actually transits the wire is the canonical one — the 5b-2b-ii(0) golden
  vector freezes exactly that, so freezing it guarantees the production request the anchor must accept.
  **NOT pinned by that vector:** the broader `relay ⊇ anchor` *superset* (the relay decoder is lenient and
  accepts non-canonical inputs the canonical vector contains none of) is **defense-in-depth, not regression-
  protected by a single canonical vector**; if a separate anchor must provably honor the full leniency set,
  that requires differential/property tests of non-canonical inputs against the anchor, tracked separately.
- **Canonical request golden vector** — add an `AgentBootRelay` canonical-request test vector to
  `testvectors/agent-gateway/` **before** any host-daemon/channel implementation, so external/later relay
  work implements against bytes, not prose (the encoder is canonical; the decoder is lenient).
- **Observability** — the boot log MUST distinguish quote-timeout / relay-timeout / anchor-unavailable /
  oversized-response / malformed-response / verify-failure for operator triage, WITHOUT leaking
  oracle-grade detail over the serve APIs (boot-time, operator-facing only).
- **Profile uniformity** — the relay CID/port (`DEFAULT_ANCHOR_RELAY_PORT=5001` / `TWOD_HSM_ANCHOR_RELAY_PORT`)
  applies uniformly across lab/staging/production; a misconfiguration surfaces as a clear fail-closed boot
  error, never a silent wrong-endpoint connect. **Authoritative relay-vs-serve port policy (code + doc now
  agree):** there is **no CID-level bind collision, ever** — the relay endpoint is
  `(VMADDR_CID_HOST=2, relay_port)` while the serve listener binds the *guest* CID, so the two are already
  distinct endpoints even at the same port *number*. Nonetheless `validate_relay_port` (called by
  `anchor_relay_port_from_env`) **does fail-closed-reject `relay_port == serve_port`** as a deliberate
  operator-ergonomics guard against confusing the two numbers. So the policy is: **distinct port numbers
  ARE enforced (fail-closed) at the env-config layer** — code downstream of `anchor_relay_port_from_env`
  may rely on `relay_port != serve_port` because the resolver guaranteed it — but this enforcement is an
  ergonomics CHOICE, not a CID-collision safety necessity (equal numbers would be harmless; we forbid the
  confusing config anyway). The `+1` default keeps the common case clear of the guard entirely.
