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

**Layer 1 — Nix build/eval gate** (mirrors `nixos-module.nix` / `guest-profile.nix` `assertions =
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
**ATOMICITY/INERT invariant:** the GENERATE_KEYS bump is **LOCAL-ONLY and currently INERT** — it MUST
advance atomically with `freshness_epoch` + the anchor ack in the deferred seal-before-emit co-slice;
`reconcile` is unwired at boot, so nothing reads `structural_version` yet (an inert write cannot trigger
`Inconsistent`).

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
wall-clock is ≤ 2×timeout; the driver's per-attempt COUNT bound caps total boot. It is the concrete
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
  (5b-2b-ii) because **CI never compiles `vsock-transport`** — so all framing/deadline/cleanup logic lives
  OUTSIDE that gate to stay tested:
  - **5b-2b-i IN REVIEW — PR #53 (this slice; CI-tested in the default + `agent-gateway` builds, NOT behind `vsock-transport`):**
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
    worker-thread hard-bound, NOT this deadline; see the deadline bullet below). The pure relay/serve
    port resolution lives in the **gate-free `vsock_addr` module** (NOT `vsock_listen`, which is gated
    `vsock-transport` and now holds only the socket-binding leaf + a re-export of `vsock_listen_addr_from_env`
    for the bins): `DEFAULT_ANCHOR_RELAY_PORT=5001` (`VMADDR_CID_HOST=2`) + `anchor_relay_port_from_env()`
    over the shared `serve_vsock_port_from_env` + pure `validate_relay_port` (rejects 0 + same-as-serve-port).
    Splitting it out of `vsock_listen` is what makes the port validation actually CI-tested — it was
    previously trapped behind the never-compiled `vsock-transport` gate. **21 CI tests** (all run under
    `cargo test --features agent-gateway`; the `snp_report` + `vsock_addr` subset of 12 also runs in the
    bare `cargo test` default build): seam full-sequence cleanup on every error leg
    (create/write/outblob/mid-sequence-timeout) + fast-path + unbounded-None, framing/forward round-trips
    over in-memory duplexes incl. pre-write-deadline guards on both cores, oversize/malformed-pinned
    rejection, cap-before-alloc outblob/auxblob reads, fast-path quote no-hang, `validate_relay_port` +
    `validate_vsock_listen_addr`.
  - **5b-2b-ii (aya leaf, deferred)** — independently-reviewable sub-items (split so a single PR doesn't
    mix vsock integration, daemon fault semantics, and acceptance infra; review each obligation on its own):
    - **(0) canonical golden vector (BLOCKS (a)+(b)):** commit the `AgentBootRelay` canonical-request byte
      vector to `testvectors/agent-gateway/` FIRST, so the channel + daemon (and any external relay
      reimplementation) are built against frozen bytes, not prose. NOTE: 5b-2b-i's `relay_forward_once`
      tests assert against frames built by the *canonical encoder* (`encode_anchor_boot_request`) — which
      IS the vector's source of truth, so the core is correct — but the frozen vector is what an external
      relay/anchor must reimplement against, and it is the byte-level regression anchor for the
      `relay ⊇ anchor` decode-leniency invariant; it was an implicit precondition not met by 5b-2b-i.
    - **(a) channel socket wrapper:** the concrete `VsockBootRelayChannel` (`VsockStream::connect` to
      `VMADDR_CID_HOST`, fresh-per-call, `SO_RCVTIMEO`/`SO_SNDTIMEO`+connect-timeout, delegates to the
      CI-proven `relay_round_trip_over_stream`).
    - **(b) host relay daemon:** a feature-gated **`pub fn run_host_anchor_relay(...)` wrapper in the
      LIBRARY** that loops `relay_forward_once`, with the `host_anchor_relay` bin a thin caller of it —
      because a Cargo `[[bin]]` target is a separate crate and CANNOT call the `pub(crate)`
      `relay_forward_once`/`frame_anchor_response` cores directly (it would otherwise duplicate the
      framing/decoder and risk codec drift). The wrapper owns the Err→close mapping + operator-triage
      logging (oversize/malformed/timeout) + a **serial accept loop** (one deadline-bounded pump at a time;
      revisit only if concurrent enclave boots need it) — see the host-relay daemon requirement below.
    - **(c) feature-build CI:** a new `cargo build --features vsock-transport,agent-gateway` step (so the
      `vsock-transport` leaf can't bit-rot — NOTE: NOT `staging-vsock,agent-gateway`, which fails the
      `ml-dsa-65 ⊕ agent-gateway` role-isolation `compile_error!` since `staging-vsock` pulls
      `staging-host`→`ml-dsa-65`).
    - **(d) aya/live-platform tests:** `#[ignore]` acceptance tests (real `fetch_report_deadline` against
      live configfs incl. no-stale-entry-after-timeout; `SO_*TIMEO` getsockopt readback; connect to CID 2)
      + the hard wall-clock bound for a wedged in-kernel read (worker-thread/process timeout; see the
      deadline requirement below).
- **5b-2c — agent-gateway bin + boot sequencing**: set platform root → unseal the agent keystore →
  `install_agent_keystore` → `RelayAnchorTransport::new(...)` → `run_boot_anti_rollback_handshake` →
  `decide_serve(outcome, cfg!(release_build))?` → serve. **Blocked on 5b-2b-ii**, not merely 5b-2b-i:
  `RelayAnchorTransport::new` needs a concrete `BootRelayChannel` (= `VsockBootRelayChannel`), which
  5b-2b-ii supplies — so 5b-2c cannot be wired even though 5b-2b-i is done.
- **5b-2d — sealed-blob source + unseal sequencing** (where the agent sealed keystore comes from at boot).
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
allow(dead_code))]` and the only intended caller is the 5b-2c bin (not yet built). NOTE this is a
call-graph guarantee, not a type-enforced one — `fetch_report_deadline` is `pub fn` (crate-public), so the
obligation is explicit: **`fetch_report_deadline` MUST NOT be wired into any serve-gate / live boot path
before 5b-2b-ii's hard wall-clock bound lands.** A future in-repo or out-of-tree caller that ignores this
would silently reintroduce the hang risk.

**5b-2b implementation requirements (pinned after the 5b-2a design matrix — these are the contract 5b-2b
MUST satisfy; none is a 5b-2a code defect, they are forward obligations on the platform leaves):**
- **Deadline-aware quote fetch (load-bearing).** `BootQuoteProducer::fetch(report_data, deadline)`'s
  contract requires honoring `deadline`. **Cooperative/between-steps bound — DONE in 5b-2b-i:**
  `fetch_report_deadline` (via the `TsmFs` seam) checks `deadline` around each configfs op and runs
  **unconditional stale-entry cleanup on every path incl. mid-sequence timeout** (the entry dir is fixed
  `twod-hsm`; cleanup runs as the last statement so the next attempt's `remove_dir`+`create_dir` still
  works — pinned by `fetch_cleans_up_on_mid_sequence_deadline_timeout`). **Hard wall-clock bound — STILL
  DEFERRED (tracked here):** a single in-kernel blocking `read(outblob)` cannot be interrupted under
  `#![forbid(unsafe_code)]`, so the cooperative deadline is **best-effort, NOT a guaranteed ceiling against
  a wedged kernel/configfs provider.** A true hard bound needs a **cancellable boundary** — and a plain
  worker thread is NOT sufficient: it cannot cancel a wedged `read(outblob)`, it can only *abandon* a stuck
  thread, which leaks the thread AND leaves the fixed `twod-hsm` configfs entry in use (so the next
  attempt's `create_dir` collides). 5b-2b-ii MUST therefore use one of: (i) a **killable subprocess**
  helper (SIGKILL on timeout), (ii) a kernel-supported read timeout if one exists, or (iii) **unique
  per-attempt configfs entry names** + an explicit abort/leak policy (bounded stuck-reader budget; refuse
  boot past a threshold). Acceptance criteria: **"no stuck worker/process accumulation across repeated
  timeouts"** and **"a subsequent attempt is well-defined (no entry collision) after a timeout"**, plus the
  aya test that a wedged provider fails the attempt promptly rather than hanging boot. Until it lands, the
  boot serve-gate (5b-2c) MUST treat the quote-fetch deadline as best-effort.
- **Timeout semantics + total bound.** The single-`timeout`-per-leg model from 5b-2a is the **baseline and
  is final for 5b-2b** (quote and channel each get `timeout`; one attempt ≤ `2·timeout`; total boot ≤
  `max_attempts · 2 · timeout`) — `RelayAnchorTransport` threads one `Duration` and gives each leg its own
  `Instant::now()+timeout`. **Decision (was an unassigned SHOULD):** exposing *distinct*
  `quote_timeout`/`relay_timeout` is **deferred to 5b-2c** (the bin that constructs the transport and owns
  operator config) — NOT 5b-2b-i/ii, which keep the single-budget model. 5b-2c, if it splits them, MUST
  restate the resulting total-boot bound as a success criterion so "timeout" is never ambiguous between
  total-attempt and per-leg.
- **Socket-timeout precondition.** `read_bounded_anchor_response`'s deadline is only enforceable if the
  stream has `SO_RCVTIMEO`/non-blocking set. 5b-2b's `VsockBootRelayChannel` MUST set `SO_RCVTIMEO` +
  `SO_SNDTIMEO` + a **connect** timeout (so connect can't hang either); the aya test verifies all three.
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
  service** (the likely deployment), this is a **cross-component sync obligation, not a present fact**: the
  5b-2b-ii(0) canonical golden vector is the contract that pins it — the anchor MUST accept every request
  the relay's decoder accepts, regression-tested against that vector.
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
