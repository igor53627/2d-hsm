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

**Out of this slice (next, platform/host plumbing):** the actual SNP-quote fetch (the enclave half of
the *mutual* auth — this slice only fixes the value the quote commits to), the host relay, wiring
verify+reconcile (via `verify_anchor_response_bytes`) into boot/install, per-op `epoch` bump +
seal-before-emit, and seeding the body's counter/spend from the anchor's authoritative marks (asserting
adopted marks ≥ local). The live-GENERATE_KEYS un-gate (TASK-18) depends on that durable commit.
