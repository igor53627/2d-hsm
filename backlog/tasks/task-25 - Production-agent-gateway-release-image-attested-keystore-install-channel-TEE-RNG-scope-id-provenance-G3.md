---
id: TASK-25
title: >-
  Production agent-gateway release image + attested keystore-install channel + TEE-RNG
  enclave_scope_id provenance (G3 — un-gate precondition for TASK-18)
status: To Do
assignee: []
created_date: '2026-06-19'
labels:
  - agent-gateway
  - security
  - hardening
  - provisioning
  - nix
dependencies:
  - TASK-1.2
  - TASK-24
priority: high
ordinal: 22500
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Carves the **G3 gap** out of TASK-18 (per the 2026-06-19 locked maintainer decision Q6): today
**no production agent-gateway image exists** — every build is a debug build that loads a keystore
via the `lab-agent-keystore-from-file` feature from a host file. Before any per-op un-gate
(TASK-18 slices 18-6..9) can flip a preview feature on in a release build, three things that do
not exist yet must land: (1) a production release image of the agent gateway (release build, no
debug/lab features), (2) an attested AF_VSOCK + SNP channel that installs the sealed keystore into
the enclave, and (3) a `getrandom`-minted random `enclave_scope_id` at provisioning so the 18-2
scope-binding byte-compare is not security theater.

**Dependency direction (explicit, acyclic):** TASK-25 does NOT depend on all of TASK-18. It depends
only on the already-landed verifier/design slices (18-1 fields + 18-2 verifier byte-compare are in;
18-3/18-5 are prerequisite completeness work tracked under TASK-18). The reverse edge is the real
one: **TASK-18 un-gate slices 18-6..9 MUST NOT proceed until TASK-25 AC#3 (in-TEE RNG provenance)
lands** — that is the gate, recorded in TASK-18's own un-gate criteria. The frontmatter deps below
(TASK-1.2 attestation chain, TASK-24 restore identity-change) are the concrete blockers this task's
ACs reference. This task is **provisionally one ticket**; at implementation time it MUST be sliced
(see Notes) — it is too large to review as one change.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 **Production agent-gateway release image.** A Nix-built release image of
  `twod-hsm-agent-gateway` (the AF_VSOCK + SNP bin — NOT the `agent-contract-server` deviceless
  UDS test server, which stays release-banned). Release build, no `lab-agent-*` features, no
  `agent-*-preview` features enabled until each is un-gated by its own slice. Reproducible
  (nix/aya). The `enclave.nix` `buildFeatures` surface this task owns does not yet exist.
- [ ] #2 **Attested keystore-install channel (explicit SNP state machine).** The provisioning flow is:
  (a) the enclave mints a fresh `enclave_scope_id` via in-TEE `getrandom` AND an ephemeral install
  handshake key (AC#3); (b) the enclave emits a signed SNP attestation report binding its
  measurement + the ephemeral install key + a fresh nonce; (c) the **provisioner** (NOT the host
  being trusted blindly) verifies VCEK/ASK/ARK chain + TCB/revocation (TASK-1.2) + a measurement
  allowlist + the nonce freshness, thereby authenticating THAT enclave; (d) only then does the
  provisioner send the authenticated `fleet_scope_id` (AC#7) + any config the enclave cannot derive,
  which the enclave seals itself. The direction is: **attestation proves the enclave to the
  provisioner** (standard SNP); a host that cannot present a report the provisioner accepts cannot
  install a keystore. Acceptance test MUST include the NEGATIVE case (a non-attesting / wrong-
  measurement / stale-nonce host ⇒ install refused).
- [ ] #3 (HIGH carry-in #1, HARD BLOCKER) **`enclave_scope_id` provenance is host-uncontrollable.**
  AC#1's whole adversary is a host that clones an enclave. The `enclave_scope_id` MUST be drawn
  INSIDE the TEE — minted via `getrandom` in-enclave at provisioning (or attested-unique by
  construction) — never host-selected and never copied across clones. A host that provisions clone B
  with `enclave_scope_id == A`'s defeats the 18-2 byte-compare (guard passes ⇒ security theater).
  Document the in-TEE RNG path and the attested-channel binding that prevents the host from selecting
  or replaying the id.
  > **Implementation reconciliation (25-2b-iv, compact 9113):** the frozen `provision_wire_version=1`
  > wire format (25-2a) simplified AC#2's "ephemeral install handshake key" + "mint before M2" design
  > concepts — the frozen M3 transcript binds only `(config_map, N_p, N_e, report_hash)` and carries NO
  > `enclave_scope_id`. The id is minted at **seal time** (inside `on_m3`, after the §6 verify passes),
  > and its host-uncontrollability is **structural** (§5.1 wire map has no field for it — I2; the host
  > never supplies it), NOT a per-field attestation in M2/M3. AC#2's "attestation proves the enclave to
  > the provisioner" still holds (the M2 SNP report); AC#3's "binding that prevents the host from
  > selecting/replaying the id" = the structural absence + the one-shot session (a replayed M3 is
  > caught by the transcript N_e compare, TranscriptMismatch). The "ephemeral install handshake key"
  > was NOT carried into the frozen format (the provisioner's Ed25519 cert key serves the role); if a
  > future revision wants a per-enclave attested install key, it is a `provision_wire_version=2` change.
- [ ] #4 (provenance hygiene) **Mint a RANDOM per-enclave `enclave_scope_id` via `getrandom`.** Do
  NOT copy the genesis/reference `[0xe1;32]` sentinel — that fixed value is a TEST FIXTURE
  (`genesis_body()` + `reference_keystore_body()` in `agent_keystore.rs`, both feature-gated to
  `test`/`lab` only — confirm at implementation that NO release-build code path can source them).
  A shared/predictable scope id silently defeats the 18-2 anti-replay binding. Acceptance test: a
  release/provisioning-path test that proves production code mints a fresh random id AND rejects a
  host-supplied `enclave_scope_id` (the id is enclave-derived, never host-supplied).
- [ ] #5 (3→4 bump precondition, forward note) Once G3 ships a real provisioned blob, a future
  `KEYSTORE_FORMAT_VERSION` bump needs a migration story (today's hard bump 3→4 — landed in TASK-18
  18-1, commit `e4eb016` — was safe ONLY because no production keystore exists, so
  fail-closed-on-old-version IS the whole migration story; the 18-2b `InvalidScopeId` invariant is
  likewise safe today only because every existing body already carries distinct non-zero sentinels).
  Record the migration obligation so a future bump is not repeated carelessly.
- [ ] #6 (restore identity-change constraint, BLOCKER: TASK-24) `enclave_scope_id` is EXCLUDED
  from the restore payload (enclave-local, like `anchor_root`), so a restored keystore carries a NEW
  enclave identity ⇒ caps minted before the backup fail the 18-2 enclave compare post-restore.
  Intended (restore = new identity). TASK-24 (now an explicit dependency) MUST: preserve the
  `enclave_scope_id` exclusion, mint a fresh in-TEE id on restore, and surface an operator-visible
  audit/status note so post-restore `0x43` on old caps is diagnosable (not a generic reject).
  Acceptance test: restore ⇒ pre-backup enclave-scoped caps FAIL the 18-2 compare; freshly-minted
  caps PASS. Export-without-restore window noted in operator docs.
- [ ] #7 (fleet_scope_id provenance + lifecycle) Define who is authorized to assign the
  `fleet_scope_id` (the provisioner, post-attestation — AC#2 step d), its allowed source (NOT a
  fixture, NOT host free-form at runtime — delivered via the authenticated install channel), its
  uniqueness domain (one value shared across one fleet's clones), and its rotation behavior (a
  rotation is a reviewed reprovision, not a runtime mutation; retired fleet ids' caps fail the
  verifier compare). Without this, `fleet_scope_id` could be host-selected / static / copied from a
  fixture, which would let a fleet-scoped cap replay across unrelated clones.
<!-- AC:END -->

## Notes
<!-- SECTION:NOTES:BEGIN -->
**Slicing status (2026-06-20).**

- **25-1 (DONE)** — design doc `agent-gateway-provisioning-channel.md`, Q1-Q8 locked + 3-round
  design Full Matrix clean (job 8844). 3 HIGH from the first matrix (offline-N_e impossible,
  deleted-blob indistinguishable, whole-blob clone) all resolved; MVP signature realization picked
  (online provisioner key certified by offline operator CA); honest residuals (whole-blob clone +
  deleted-blob re-provision closed by the TASK-7.7 anchor, NOT G3) recorded.
- **25-2a (DONE — frozen)** — wire-format spec `agent-gateway-provisioning-wire-format.md`,
  `provision_wire_version = 1`. Four-message two-round-trip handshake (M1-M4), `Sig_PROV` over the
  live transcript `(config_map, N_p, N_e, report_hash)`, single-level DER X.509 provisioner cert.
  Independently reviewable of code (the point of the split); golden vectors in §10 (domains/magics
  literal, config_map/M3 byte-exact regenerated by the 25-2b regen test). Full Matrix next.
- **25-2b (in progress)** — Rust impl of 25-2a, **pre-declared sub-slices for incremental review**
  (25-2a-rev2 Low): (i) pure codec + DoS caps + §9 structural negatives; (ii) provisioner-cert
  chain validation + role-constraint check; (iii) verify-order integration (transcript + Sig_PROV);
  (iv) mint+seal wiring; (v) golden-vector regen test. **Per-slice review gate (clarified
  2026-06-20, compact 9048 + 9109):** slices i + ii are PURE functions (codec / cert-verify — no
  state, no concurrency) → **Reduced Matrix** suffices; slices iii (verify-order) AND iv
  (`ProvisionSession` stateful: AwaitingM1→AwaitingM3→Done/Failed) are the state-machine / ordering-
  sensitive surfaces → **Full Matrix** incl. the 2×3 concurrency floor (`pse-review-2x3.sh`).
  (The original "each sub-slice is Full Matrix" was written for 25-2b-as-a-whole; the per-slice split
  lets the pure slices land on Reduced, the state-machine slices on Full.)
  **⚠ Full Matrix PARTIAL for iii + iv (compact 9113):** the gemini 2×3 cells (agy) failed on
  non-interactive re-auth (AGENTS.md known scenario; cannot re-auth without an interactive terminal).
  So iii + iv are reviewed under a PARTIAL Full Matrix: codex×3 (security/design/design-max) +
  claude-code/design + gemini/security(Reduced) all completed; the gemini design + design-max 2×3
  views are the OPEN gap. The design lens is multi-covered (claude-code + codex×2), so this is a
  documented degradation, NOT a clean Full Matrix — re-run `pse-review-2x3.sh` interactively (after
  `agy` re-login) to close it before the runtime driver wires.
  - **25-2b-i (DONE — reviewed)** — `agent_provision.rs` (agent-gateway-gated): pure codec for the
    frozen `provision_wire_version=1` — envelope (magic/version/msg_type), per-state direction
    validation (`HandshakeStep`/`validate_inbound`), M1-M4 encode/decode, `ProvisionConfig` + §5.1
    config_map (strict keys {1..=7}, key-8 enclave_scope_id injection ⇒ Malformed), §2 DoS caps
    (TooLarge distinguished from Malformed), full §9 `ProvisionError` model (crypto arms defined,
    constructed by ii/iii). Supporting `agent_cbor::strict_decode_map_capped` parameterizes the bstr
    cap so an over-cap field surfaces as TooLarge. Reduced Matrix (codex/gemini/grok clean,
    claude-code/design 1 Med + 4 Low) → 3 compact rounds settled clean (job 9028). 29 tests; 521
    total pass. Commits `1b99523` + fixes `08e31fb`/`871cdf9`. One doc rev (25-2a-rev6: §5.2
    `text(5)`→`text(6)` typo).
  - **25-2b-ii (DONE — reviewed)** — `verify_provisioner_cert`: single-level X.509 leaf verify
    via `x509-cert` 0.2.5 (optional dep, gated under `agent-gateway`). Five checks: DER parse → v3 +
    Ed25519 SPKI (RFC 8410) → BOTH signature AlgorithmIdentifiers == Ed25519 (inner==outer; alg
    agility intentionally absent) → `verify_strict` over the ORIGINAL TBS bytes (exact byte-range
    slice, not a re-encode) against the pinned operator CA root → role EKU (`2.25.209175620`).
    `operator_ca_root` passed as a param (pure/testable; production pin wired by slice iv). No
    wall-clock check. Reduced Matrix (codex/gemini/grok clean, claude-code/design 1 Med — untested
    Malformed branches — + 5 Lows) → compact 9048; all 6 findings addressed in the fix commit (sig-
    alg checks, raw-TBS-bytes, x509-cert optional gating, malformed-branch tests, EKU-narrative
    reword, this per-slice-gate clarification). 10 cert tests; 531 total pass.
  - **25-2b-iii (DONE — reviewed)** — §6 verify-order integration: `compute_report_data`
    (SHA3-512 REPORT_DATA commitment) / `compute_report_hash` (SHA3-256), `transcript_canonical` +
    `sig_prov_signed_bytes` (PROVISION_DOMAIN ‖ canonical-CBOR), `verify_m3_transcript_and_sig`
    (steps 3+4: transcript byte-compare → TranscriptMismatch; Sig_PROV verify_strict → BadSignature),
    and `verify_m3_in_order` (full §6 order 1→5: envelope+decode → cert → transcript+sig → config,
    returns ProvisionConfig + provisioner pubkey for slice iv). **Full Matrix** (first state-machine
    slice): Reduced (codex/gemini/grok clean, claude-code/design Lows) + 2×3 (codex security/design
    clean, design-max Fail → fixed). Findings (config-sub test gap, stale module docs, §6 step-
    numbering, wrong-msg_type + isolated-field replay tests, precise identity-binding note) addressed
    in `4cf2e88` + `6d0081e`; 3 compact rounds → clean (job 9088). **DEGRADATION (noted):** 2 of 3
    gemini 2×3 cells failed agy re-auth (non-interactive session; AGENTS.md known scenario); gemini
    coverage held via Reduced security + one design-max cell, and the design lens is multi-covered
    (claude-code + codex×2) — the missing gemini-design-2×3 view is the documented gap. 53 tests;
    544 total pass.
  - **25-2b-iv (DONE — reviewed)** — mint+seal + `ProvisionSession`: `mint_enclave_scope_id`
    (getrandom, AC#3/#4; `validate_minted_scope_id` rejects zero + [0xe1]/[0xf1] sentinels),
    `build_provisioned_keystore_body` (basket A/B/C mapping, genesis-zero faucet), `seal_provisioned_keystore`
    (→ M4 blob), `ProvisionSession` (pure transport-free: on_m1 mints N_e + report_data; on_m3 runs
    verify_m3_in_order → mint scope_id → seal). **One-shot failure semantics (Full Matrix HIGH fix):**
    on_m3 CONSUMES the session on ANY error (→ Failed terminal) so the host cannot retry forged M3s
    against a fixed N_e (static-target / fault-injection / oracle defense — must restart from M1).
    **Full Matrix** (Reduced + 2×3): gemini + codex×2 convergent HIGH (session-not-consumed) + Mediums
    (fleet_scope_id=0 → Malformed at decode; sentinel rejection; scope_id attestation-timing
    reconciliation with AC#2; genesis-version divergence note) addressed in `82aac6e`. 62 tests; 554
    total pass. **Same gemini 2×3 agy degradation** as iii (noted).
  - **Driver contract (slice iv → the `twod-hsm-agent-gateway` bootstrap bin, deferred):** (1) the
    `seal_root` + `measurement` passed to `ProvisionSession::new` MUST be the SAME measurement proven
    in the M2 SNP report (derive both from one source — never seal under a measurement the provisioner
    did not attest); (2) one-shot failure — a Failed session ⇒ tear down the bootstrap listener (the
    host must re-connect + re-M1 for any retry; Q5 already makes the listener one-connection); (3) wrap
    `on_m3`'s sealed blob in `encode_m4` + the envelope before emitting; (4) the operator-CA-root pin
    + measurement allowlist are compiled into the bin (25-1 Q7).
- **25-3..25-6** — per 25-1 §7 (enclave_scope_id in-TEE mint; production nix profile; restore identity
  hard gate on TASK-24; operator runbook).

The TASK-18 un-gate (18-6..9) is hard-blocked on 25-3 + 25-4 + TASK-7.7 anchor readiness.

---

**Why this is a separate task (2026-06-19).** TASK-18's Understand phase (5-agent) + the 18-1
Reduced Matrix established that AC#1's guarantee **CANNOT be validated before G3 is designed**
— specifically before the keystore-install channel's attestation gating + the in-TEE scope-id
provenance are specified. The 18-2 verifier byte-compare is correct code and lands now (preview),
but its security claim is conditional on this task. Per maintainer decision Q6, the production
image work (needs nix/aya expertise) is carved out so it does not block the in-`enclave-protocol`
verifier hardening track (18-2 → 18-3 → 18-5 → 18-4).

**Threat decomposition (18-1 carry-in MEDIUM #3, made explicit):**
- (a) Host copies the WHOLE sealed keystore → counters travel with it → caught by AC#3 anchor
  anti-rollback (TASK-7.7, DONE preview-gated).
- (b) Host fresh-provisions a clone + replays a CAP against empty counters → the AC#1 case
  (closed by 18-2 + this task's provenance AC#3).
- (c) Honest concurrent clones of one treasury key (active-active) without a global append-only
  ledger → residual hole, EXPLICIT non-goal (Option B, deferred to TASK-20).

**Source.** TASK-18 Understand workflow (2026-06-19) + 18-1 Reduced Matrix (codex/grok/claude-code;
claude-code/design HIGH #1 + MEDIUM #3 are the carry-ins that define this task's AC#3/#4).
<!-- SECTION:NOTES:END -->
