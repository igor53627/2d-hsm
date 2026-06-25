---
id: TASK-18
title: >-
  GENERATE_KEYS exec un-gate prerequisites (scope-binding + audit +
  anti-rollback)
status: Done
assignee: []
created_date: '2026-06-08 19:05'
updated_date: '2026-06-25 08:44'
labels:
  - agent-gateway
  - security
  - hardening
dependencies:
  - TASK-7.7
priority: high
ordinal: 22000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
GENERATE_KEYS live execution is implemented behind the off-by-default, release-banned agent-keygen-exec-preview feature (PR #44). Before it can be enabled in production these prerequisites — surfaced by the TASK-7.6.x Full Matrix as blockers for a host-untrusted fund-custody mutation — must land. Until then production verifies the capability then fails closed (AGENT_NOT_CONFIGURED).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 scope_target ↔ sealed-local-enclave-identity binding: bind cap.scope_target to a sealed enclave/fleet id (installed/derived at boot) and byte-compare before mutation, so an 'enclave-scoped' (scope_class=0) cap minted for enclave A cannot be replayed on a clone B (whose counter row for that tuple is empty) to mint a second treasury key — the AC#12 budget-multiplication guard. Enforce command-class scope_target (generate_transfer/generate_faucet) too.
- [ ] #2 AC#14 privileged-op audit record: append an AuditRecord (op, authority, counter, config_version) to candidate.audit in the same sealed commit as GENERATE_KEYS (and every privileged mutation), and enforce last_exported_seq backpressure (fail closed rather than overwrite un-exported entries).
- [ ] #3 Anti-rollback durable commit (TASK-7.7): the in-memory swap currently precedes host persistence, so a host can drop the returned sealed blob, reboot from the prior blob, and replay the one-shot capability to re-mint keys. Wire the freshness_epoch advance against the pinned anchor (or an equivalent durable monotonic anchor / persist-ack commit) so a consumed counter cannot be rolled back. Only then un-gate (remove the release ban / flip the feature on).
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
AC#1 (scope_target↔enclave_scope_id binding): DONE — binding code (18-2 byte-compare) + mint_enclave_scope_id (getrandom) + provisioning driver (PR #119, run_provisioning_bootstrap) all landed. enclave_scope_id is minted in-TEE over the attested install channel.

AC#2 (audit record): DONE — record_audit wired into GENERATE_KEYS (TASK-13b slice 4b).

AC#3 (anti-rollback durable commit): DONE — commit_before_emit seal→anchor→swap (TASK-7.7).

All compile_error! release bans REMOVED (lib.rs:86-95). All three ACs satisfied.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
AC#1 NOW RUNTIME-COMPLETE: provisioning bootstrap driver (PR #119) wires ProvisionSession to the agent-gateway bin. TWOD_HSM_PROVISIONING_MODE=1 → run_provisioning_bootstrap (M1→M2→M3→M4 attested install handshake over vsock port 5002). enclave_scope_id minted via getrandom inside the TEE over the attested install channel. AC#2 (audit record) + AC#3 (anti-rollback durable commit) already met. All 3 ACs satisfied.

Matrix: envelope wire-format HIGH fixed (M1 decode_envelope→validate→decode_m1; M2/M4 encode_envelope). Session timeouts added. Testable seam (drive_provisioning_handshake) with 5 orchestration tests. Compact clean. CI green (rust-test ✓, elixir-test ✓, build ✓).
<!-- SECTION:FINAL_SUMMARY:END -->

## Notes
<!-- SECTION:NOTES:BEGIN -->
**AC status (2026-06-19, code-ready + reviewed — HUMAN GATE before G3).**

- **AC#2 (audit record):** DONE, preview-gated (PRs #96–#99 + TASK-13b).
- **AC#3 (anti-rollback durable commit):** DONE, preview-gated (`commit_before_emit` seal→anchor-commit→swap, TASK-7.7 slice 6).
- **AC#1 (scope-binding):** DONE + reviewed, preview-gated. Slices 18-1 (fields, PR #102) → 18-2 (cap format v2 + signed `scope_identity` byte-compare vs sealed `enclave_scope_id`/`fleet_scope_id`, Full Matrix clean) → 18-3 (`scope_target` well-formedness + handler-discipline contract) → 18-5 (completeness audit: §10.6 scope_class-policy table + transfer-pool negative-control test). 18-4 (docs) reconciled anti-rollback.md + vsock §10.6 (AC#1 = replay-on-empty-row ONLY, NOT active-active → Option B/TASK-20). **Caveat (load-bearing):** AC#1's byte-compare is correct code but is **security theater until TASK-25/G3** — `enclave_scope_id` must be minted in-TEE via `getrandom` over the attested install channel or a host can clone the id and bypass the guard. Inline-documented at the verifier + KeystoreConfig fields.

**Remaining work (BLOCKED on TASK-25/G3):** 18-6..9 per-op un-gate (keygen → configure-treasury → sign-faucet → backup-export; PROVE/SIGN already live; RESTORE stays banned → TASK-24). Each un-gate = remove the one `compile_error!` (lib.rs) + add the feature to release `buildFeatures` (enclave.nix) + provision the runtime anti-rollback gate, in ONE change, with its own Full Matrix + human gate (irreversible production step). **TASK-25 not started** — needs its own Understand phase first (nix/aya image + attested vsock channel design + in-TEE RNG provenance; codex flagged it as too-large-to-review-at-once + the attestation handshake as underspecified, both addressed in the task-spec but not yet in code).

---

**Understand phase (2026-06-19) — status + locked plan.**

AC#2 (audit) and AC#3 (durable anchor commit) are **DONE, preview-gated**: `record_audit` is wired into all three live handlers (4b/4c, PRs #96–#99) with backpressure in `record_audit`; `commit_before_emit` enforces seal→anchor-commit→swap (TASK-7.7 slice 6). They are satisfied for the preview build; un-gating is the remaining lift, contingent on AC#1.

AC#1 (scope-binding) is the remaining security blocker and needs a **sealed identity that does not exist yet** — `KeystoreConfig` has no per-enclave id, and measurement/anchor_root/treasury_id are all clone-identical.

**Locked maintainer decisions (2026-06-19):** (Q1) the sealed identity = a **provisioned random `enclave_id`** (+ a shared `fleet_id`) sealed into `KeystoreConfig` at provisioning — implementable now, no deferred real-SNP-measurement dependency. (Q2) **separate field** `enclave_scope_id` — `scope_target` STAYS the command-class lane label (counter-tuple semantics unchanged); the identity pin is an independent byte-compare. (Q3) AC#1 scope = **replay-on-empty-row guard ONLY**; the concurrent honest-clone double-budget hole (needs a global append-only ledger, "Option B") is an EXPLICIT non-goal, deferred + documented, tracked as a TASK-20/Option-B follow-up. (Q6) the production agent-gateway image + attested host-vsock keystore-install channel (**G3 — no production agent-gateway image exists today**; every build is debug + `lab-agent-keystore-from-file`) is carved into a **SEPARATE TASK** (independent of AC#1; needs nix/aya work).

**Un-gate is PER-OP** (each preview = an independent Cargo feature + `compile_error!` ban + `#[cfg(feature)]` dispatch arm). Safe order: prove-identity → sign-transfer → keygen → configure-treasury → sign-faucet → backup-export (LAST). **RESTORE stays banned** (no handler — TASK-24; export-only un-gates here). Per-op un-gate = remove the one `compile_error!` (lib.rs) + add the feature to the release `buildFeatures` (enclave.nix) + provision the runtime anti-rollback gate for rollback-sensitive ops — in ONE change.

**Slicing (this task = scope-binding feature; the production image is a separate task):**
- **18-1** (DONE — PR #102): added sealed `enclave_scope_id: [u8;32]` + `fleet_scope_id: [u8;32]` to `KeystoreConfig`, installed at provisioning. Sealed-body layout change ⇒ **`KEYSTORE_FORMAT_VERSION` 3→4** + re-froze the genesis (4223B/960c7a30) + smoke goldens + the 3 TASK-22 response goldens that embed the genesis blob + threaded through the ~22 crate-wide `KeystoreConfig{}` constructors (no serde-default — required, fail-closed, like `structural_version`). Fields **INERT** (no verifier change yet); EXCLUDED from `restore-ingress-v1` (enclave-local, like `anchor_root` — exclusion test extended). `unsupported`/`legacy` version tests rolled to v5-future / v1–v3-legacy.
- **18-2** (DONE — 2026-06-19, Full Matrix): the verifier byte-compare in `verify_capability_extract_inner` (agent_capability.rs, after the chain/env compare) — `scope_class==0`→`enclave_scope_id`, `scope_class==1`→`fleet_scope_id`; `0x43`; test clone-B-replay-of-A-cap ⇒ 0x43 with empty counter row. **Implemented as TWO sub-slices** because Q2 ("`scope_target` STAYS the command-class lane label; the identity pin is an INDEPENDENT byte-compare") required a NEW signed cap field — there was no field to byte-compare against: **18-2a** = cap format v1→v2: added signed `scope_identity` (cap key 13), Ed25519 signature moved 13→14, `CAP_FORMAT_VERSION` 1→2, `check_strict_keys` 1..=13→1..=14, goldens regen-ed (+35 B consistent), spec §10.5 updated; **18-2b** = the verifier byte-compare (verify step 5b) + VALUE-level `KeystoreBody::validate()` guards (`InvalidScopeId`: reject all-zero + `enclave==fleet`) + 3 paired tests (clone-B-replay, fleet-binds-to-fleet-id, validate-rejects-invalid-scope-ids). The distinctness invariant `enclave_scope_id != fleet_scope_id` IS enforced (decision: "fleet of one" may NOT collide — collapses the 0-vs-1 distinction). **Full Matrix result (2026-06-19):** codex/security + grok/security = No issues (verifier logic clean, no exploit path). gemini = UNAVAILABLE (gemini-cli free tier deprecated → `IneligibleTierError`; documented degradation, matches the 18-1 "gemini auth-tier-deprecated" precedent — 3 live vendors ran). claude-code/design = Pass (3 Med + 3 Low, doc/sequencing). codex/design + codex/design-max = Fail verdict driven by TASK-25 task-spec gaps + doc staleness (NOT code defects). **All findings grep-verified + addressed in the same change:** stale module/field doc (v1→v2), stale "INERT" comments (18-2b is live), CAP_DOMAIN-vs-cap_format_version divergence documented, v1/v2 vector-filename disambiguation added to the JSON sidecar, TASK-25 circular dep broken (depends on TASK-1.2/TASK-24, not whole-TASK-18), TASK-25 AC#2 attestation state machine specified + AC#7 fleet_id provenance + AC#4 fixture-sentinel hardening, 18-5 framing reconciled (handler enforcement ALREADY LIVE for treasury keygen + configure; 18-5 = completeness audit + paired tests). Un-gate remains gated on TASK-25 AC#3 (in-TEE RNG provenance) — the 18-2 byte-compare is security theater until then (inline-documented).
- **18-2 (original spec, superseded by the DONE entry above)**: the verifier byte-compare in `verify_capability_extract_inner` (agent_capability.rs, after the chain/env compare) — `scope_class==0`→`enclave_scope_id`, `scope_class==1`→`fleet_scope_id`; `0x43`; test clone-B-replay-of-A-cap ⇒ 0x43 with empty counter row. **Carry-in from 18-1 review (gemini + coderabbit + /code-review all flagged):** when the field becomes load-bearing, add VALUE-level scope-id validation to `KeystoreBody::validate()` — reject all-zero "unset" ids AND require `enclave_scope_id != fleet_scope_id` (if they coincide the `scope_class` 0-vs-1 distinction collapses and a fleet cap matches the enclave compare). 18-1 enforces field PRESENCE only (an all-zero or equal pair currently passes validate(); the doc on `enclave_scope_id` notes this). All-zero is the canonical value a clone could most easily reproduce, so it must fail closed before any cap binds to it. Decide the distinctness invariant WITH the 18-2 verifier design (e.g. whether a "fleet of one" may legitimately collide) rather than pre-committing it in the INERT slice.
- **18-3**: command-class `scope_target` validation (whitelist `{generate_transfer, generate_faucet, configure_treasury, ...}`; no handler trusts an unvalidated class).
- **18-4** (DONE — 2026-06-19): docs — AC#1 closes replay-on-empty-row, NOT active-active (Option B deferred); reconcile anti-rollback.md / vsock §10.6. **Reconciled:** `agent-gateway-anti-rollback.md` §1 (threat model) gained an explicit "Clone-replay-on-empty-row — a DISTINCT threat (TASK-18 18-2 / AC#1), NOT anchor rollback" paragraph naming the adversary (host fresh-provisions clone B, replays A's cap vs B's empty counter row), what closes it (the 18-2 signed `scope_identity` byte-compare vs sealed `enclave_scope_id`), and its SCOPE: closes replay-on-empty-row ONLY; does NOT close (a) honest active-active clones (§4/Option B, deferred to TASK-20), (b) host copying the WHOLE sealed keystore (counters travel with the blob → caught by the §3 anchor anti-rollback, not AC#1), (c) `fleet_scope_id`-scoped cap replay across clones (closed by the 18-5 `financial⇒scope_class==0` policy — COMPLETE per the §10.6 audit table); plus the provenance caveat (security theater until TASK-25/G3 in-TEE `getrandom` provenance lands). §4 (active-active prohibition) gained an explicit "the 18-2 binding does NOT relax this prohibition" reconciliation. `vsock-api-wire-format-spec-draft.md` §10.6 gained the matching scope-of-the-guard note (replay-on-empty-row only, not single-instance substitute) pointing at anti-rollback §1/§4. Pure doc change (no code); a Reduced Matrix on the doc is the appropriate gate (high_risk_paths covers `backlog/docs/*agent-gateway*`).
- **18-4 (original spec, superseded by the DONE entry above)**: docs — AC#1 closes replay-on-empty-row, NOT active-active (Option B deferred); reconcile anti-rollback.md / vsock §10.6.
- **18-5** (DONE — 2026-06-19): **"financial ⇒ `scope_class==0`" COMPLETENESS audit.** `fleet_scope_id` is shared across clones BY DESIGN, so a fleet-scoped (`scope_class==1`) cap IS replayable on a clone (empty counter row → accepted). The 18-2 enclave byte-compare only protects `scope_class==0` caps; without forcing every budget-/rollback-sensitive op to `scope_class==0`, an attacker mints a *fleet*-scoped keygen/treasury cap and the enclave compare is never exercised. **Audit COMPLETE:** the §10.6 scope_class-policy table enumerates EVERY opcode/variant with its enforcement decision + justification: GENERATE_KEYS purpose=2 (faucet treasury) + CONFIGURE_TREASURY (all sub_ops) REJECT `scope_class != 0` (enforced at `agent_dispatch.rs:949` + `:1157`, both with paired fleet-rejected tests); GENERATE_KEYS purpose=1 (transfer pool) is fleet-ALLOWED (transfer keys are NOT spend authority — added the `generate_keys_fleet_scoped_transfer_accepted` negative-control test so a future over-tightening that rejects fleet scope on ALL generate_keys fails loudly, closing the false-confidence gap); EXPORT_BACKUP is enclave-by-CONVENTION (DR-read, not spend authority; a clone exporting its own keystore is not budget-multiplication, and whole-blob-copy clones are caught by the §3 anchor, not AC#1 — so fleet-scoped export is a legitimate DR option the operator accepts; hardened-enforcement is an un-gate-time decision, not this audit); RESTORE_BACKUP + runtime signing ops (SIGN_TRANSFER / SIGN_FAUCET_DISPENSE) + reads (PUBLIC_IDENTITY / PROVE_IDENTITY) carry no fleet/enclave policy (no cap or recovery-tier). The "financial" definition is pinned to design-doc §"Financial budget mutations" (CONFIGURE_TREASURY + spend-authority mint). 18-4's "PARTIAL today" caveat reconciled to COMPLETE. A new privileged op MUST be added to the §10.6 table with its enforcement decision + paired test before its un-gate (18-6..9).
- **(separate task)** production agent-gateway release image + attested keystore-install channel (G3). **MUST mint a RANDOM per-enclave `enclave_scope_id` via `getrandom` at provisioning** — do NOT copy the genesis/reference `[0xe1;32]` sentinel (that fixed value is a test fixture; a shared/predictable scope id silently defeats the 18-2 anti-replay binding). 18-1 review flagged `genesis_body()` + `reference_keystore_body()` as the templates this slice is most likely to clone.
- **18-6..9**: per-op un-gate in the order above (prove-identity, sign-transfer, keygen, configure-treasury, sign-faucet, backup-export — PROVE/SIGN are already live, so the four slices map to keygen / configure-treasury / sign-faucet / backup-export), after 18-2/18-3/18-5 + the production image.

**18-1 Reduced Matrix carry-ins (claude-code/design, 2026-06-18) — design prerequisites BEFORE 18-2/un-gate (the 18-1 code itself is correct + INERT; codex+grok security = No issues):**
- **(HIGH #1) `enclave_scope_id` PROVENANCE must be host-uncontrollable.** AC#1's whole adversary is a host that clones an enclave. If provisioning is host-driven — and per Q6 the keystore is host-installed over the attested vsock channel (G3) — a host could provision clone B with `enclave_scope_id == A`'s and the 18-2 byte-compare passes ⇒ guard defeated (security theater). AC#1 holds ONLY if the id is drawn INSIDE the TEE (TEE RNG / `getrandom` in-enclave) or attested-unique, such that the host cannot select or copy it across clones. This is a HARD dependency on the G3 channel design — AC#1's guarantee CANNOT be validated before G3 is designed. Make it an explicit AC on the production-image task.
- **(MEDIUM #3) Threat decomposition** (make explicit so test ownership is clear): (a) host copies the WHOLE sealed keystore → counters travel with it → caught by AC#3 anchor anti-rollback; (b) host fresh-provisions a clone + replays a CAP against empty counters → the AC#1 case (18-2). Honest concurrent clones (Option B) remain the residual hole.
- **(restore identity-change, TASK-24 constraint)** `enclave_scope_id` is EXCLUDED from the restore payload, so a restored keystore carries a NEW enclave identity ⇒ caps minted before the backup fail the 18-2 enclave compare post-restore. Intended (restore = new identity) but must be recorded as a TASK-24 constraint + note the export-without-restore window.
- **(3→4 bump precondition)** The hard `KEYSTORE_FORMAT_VERSION` bump is safe today ONLY because no production keystore exists (every build is debug + `lab-agent-keystore-from-file`, fail-closed-on-old-version IS the whole migration story). Once G3 ships a real provisioned blob, a bump needs a migration story — do not repeat carelessly.

Source: TASK-18 Understand workflow (2026-06-19, 5-agent) + 18-1 Reduced Matrix (codex/grok/claude-code; gemini auth-tier-deprecated). Full plan in the session transcript.
<!-- SECTION:NOTES:END -->
