---
id: TASK-20
title: >-
  roborev residual findings from TASK-7.7 (d-ii) slices — doc-wording +
  test/code hardening
status: To Do
assignee: []
created_date: '2026-06-11 19:38'
labels: []
dependencies: []
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Captured from the roborev backlog drain (2026-06-11) so the 47 stale open consolidated-review rows on now-deleted squash-merged TASK-7.7 branches could be closed (audit-before-close per CLAUDE.md hygiene; compact cannot reach deleted-branch jobs). All 8 terminal-residual findings below are Low/Medium, non-blocking, from FULLY-merged+gated slices. NB the §8 doc has been rewritten many times since these fired (#56-#63) — verify each doc finding against CURRENT agent-gateway-anti-rollback.md before acting; some may already be resolved.

DOC-WORDING (§8 / task-docs — verify-against-current first):
- [8022 strict-cbor] §8 describes strict_decode_map as accepting "CBOR arrays and maps up to the caps", but it rejects any non-map TOP-LEVEL item (arrays only nested). Reword: requires a top-level definite-length map; nested arrays/maps allowed subject to caps.
- [8324 quote-hard-bound] §8 ε caveat: "the runtime hard bounds remain the per-leg deadlines themselves" is too strong for the QUOTE leg (spawn/setup + dispose/reap happen OUTSIDE the pipe deadline). Reword: only the cancellable pipe/channel WAITS are deadline-enforced at runtime; the ε product is nominal sizing arithmetic. (Likely partly addressed by the #60 "ε is NOMINAL, not a runtime ceiling" edits — verify.)
- [8325 boot-relay-quote-leaf] §8 ~829/871 contradiction: "two enforceable artifacts, not checklist lines" vs a later paragraph calling the (d) wrapper precondition "only a checklist obligation, not a compile error". (Likely STALE — the never-generic-Q + (d)-FULLY-CLOSED rewrites since #61-#63 reconciled this; verify it still exists.)
- [8024 ac5-funding-gate] The deferred owner-mapping assigns the AC#10 measured/sealed opt-out + Layer-2a release compile_error! to TASK-18, but TASK-18's ACs only track scope-binding/audit/durable-commit. Add explicit TASK-18 ACs (or notes) for those AC#5 deliverables so closing TASK-18 from its own ACs can't miss them.

CODE / TEST HARDENING:
- [8327 boot-handshake-driver, Medium] agent_anti_rollback_serve_gate is pub(crate) + raw booleans → in-crate wiring could bypass decide_serve and serve after FailClosed(BindingInstall) when a prior binding stays installed. Make the raw gate private to agent_boot_driver.rs; expose only decide_serve for handshake-backed boot (or a deliberately-named unwired wrapper). NB: (4b) run_boot_handshake_wired is the canonical entry now — confirm the raw gate has no remaining legit caller.
- [8310 boot-relay-protocol, Medium] No regression test for per-leg deadline freshness: MockChannel ignores the supplied channel deadline, so a future change reusing the quote deadline for the channel leg would pass while silently shrinking the relay budget. Add a fake quote/channel seam test that records both deadlines + injects quote latency + asserts the channel gets a freshly-computed deadline. (The §8 "wiring-enforced in round_trip_inner, re-verify on refactor" pin is the prose guard this would harden.)
- [8025 format-v2-structural-marks, Low] structural_version_zero_fails_validation only exercises validate() directly — wouldn't catch seal_body()/unseal_body() dropping the check at the sealed-blob boundary. Extend: assert seal_body() rejects structural_version=0, and that unseal_body() of an invalid-but-sealed body returns KeystoreError::InvalidStructuralVersion.
- [8494 quote-smoke, Low] The lab-only quoteSmokePackage Nix guard (quoteSmokePackage==null || !productionMode) has no FAIL-side regression check — a negative tryEval test (productionMode=true + quoteSmokePackage set ⇒ expect assertion failure) would make the guard self-testing. (Currently eval-enforced for the lab image + documented; declined inline at #63 as disproportionate, parked here.)

Source: roborev jobs 8022/8024/8025/8310/8324/8325/8327/8494 (terminal consolidations of the respective deleted branches). All other open rows on those branches were superseded-clean intermediate compacts.

---

### 5b-2e AdoptForward residuals (from the PR #69 `/code-review max` pass, 2026-06-13)

The max-effort review (27 candidates → 13 verified) found **0 critical/high and 0 security defects** — the adversarial gate-security angle found NO wrong-accept path. The one Medium (orphaned `verify_outstanding_response` dead-code + lying docs) was FIXED in-PR via reroute, and the host-relay unknown-type triage bucket was completed in-PR. The remaining Low items are parked here (all non-blocking; several are documented-intentional):

- **[test-DRY, Low]** The canonical marks-payload test builder is triplicated: `agent_boot::marks_payload`, `agent_cbor::marks_bytes`, `agent_anchor::marks_payload_bytes` (all byte-identical grammar). The agent_boot/agent_cbor copies fail LOUDLY on drift (digest/decoder-guarded), but `agent_anchor::marks_payload_bytes` is decoder-independent (round-trip-verbatim assert) and could silently encode a stale grammar. Consolidate into ONE `#[cfg(test)] pub(crate)` builder (mirror `test_signed_marks_response_bytes`'s single-sourcing).
- **[provenance, Low]** 13 `#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit N/8` markers across agent_anchor/agent_cbor/agent_keystore/agent_boot_relay/agent_boot remain on items that now have real production callers (verified: a clean build emits no dead-code warning for any). The "staged commit N/8" provenance is stale post-squash. Drop the now-redundant attrs/comments (several files also carry a module-level blanket allow, making the per-item ones doubly redundant).
- **[perf, Low]** `marks_dominate_local` (agent_boot.rs:296) is O(N×M) nested `.find()` over two counter tables; `decoded.rows` is already strictly ascending by `(authority,scope_class,scope_target)`, so a `binary_search_by` → O(N·log M). Once-per-boot path, table "should never approach" MAX_COUNTER_ENTRIES, so low priority.
- **[perf, Low]** The hash gate's `candidate.compute_local_marks_digest()` (agent_boot.rs:267) re-sorts+re-encodes the candidate marks even though the already-authenticated canonical `marks_payload` bytes are in hand (equal by the strict-decode↔encode inverse). `SHA3(MARKS_DOMAIN ‖ marks_payload)` would skip the re-encode — BUT the candidate re-encode is INTENTIONAL belt-and-suspenders behind the decoder; only act if that belt is judged redundant.
- **[consistency, Low]** `decode_anchor_marks_request` env field uses lenient ciborium decode + an uncapped `s.clone()` (frame-bounded by MAX_MESSAGE_SIZE, out of the enclave trust boundary; matches the existing 0x41 decoder's deliberate lenient design). A strict-decode + a 64-byte env cap would tighten both relay decoders consistently. Benign — the enclave verifies only the signed RESPONSE.
- **[liveness coupling, Low — documented]** `marks_dominate_local` belt fail-closes a hash-gate-PASSING adopt if the (not-yet-frozen) anchor data model ever legitimately prunes/lowers a local counter row. Never a wrong-accept (the hash gate authenticated first); availability-only. Revisit when the anchor data model freezes (already noted in the belt's doc-comment).

Source: PR #69 code-review-max workflow wf_36523dbd (40 agents). The Medium + the host-relay bucket were fixed in-PR; these Lows are the parked residual.

---

### 6-4b residual (from the PR #74 compact, 2026-06-14)

The 6-4b branch compact (roborev job 7314) re-surfaced one **High-labelled** finding: the `0x45` anchor-commit REQUEST carries only `{scope, proposed state, nonce, request_id}` with **no enclave-authenticated MAC/signature or boot-attested session binding**, so a compromised host/relay can forge/substitute well-formed commit requests and make the anchor durably advance/sign attacker-chosen state.

**Adversarially verified DoS-only (2 independent agents) — NOT a wrong-accept / rollback, NOT a 6-4b regression, accepted residual:**
- **No wrong-accept:** the enclave seals/swaps/emits ONLY after `verify_commit_ack_bytes` passes — Ed25519 `verify_strict` against the **sealed** `anchor_root` + echo of the enclave's OWN fresh per-op CSPRNG nonce (`draw_commit_nonce`) + `{epoch, structural, marks, request_id}`. A host holds only the public `anchor_root` (verify-only) so it cannot mint any valid ACK; a replayed genuine ACK fails the fresh-nonce echo. The enclave never adopts host-proposed state.
- **No rollback / never wrong-accept on reconcile:** the anchor is forward-only (`advance_commit_epoch` checked, monotone); a forged commit can only ADVANCE it. On next-boot `reconcile` (per the codex-7323 correction): a **structural** advance — the GENERATE_KEYS case, which is exactly 6-4b's path — routes to `StructuralGap` → `FailClosed` (recoverable). An **epoch-only** advance with matching `structural_version` routes to `AdoptForward`, which is itself GATED by the constant-time marks hash-equality vs the anchor's recorded marks: forged marks ≠ local ⇒ the gate fails closed (no adopt); marks == local ⇒ a benign freshness-epoch fast-forward (no key/spend change — the marks/keys are unchanged). `AnchorBehind` (a LOWER anchor) is NOT reachable by a forward-only host. So no reconcile path yields a wrong-accept; LOWERING the anchor is an anchor-side capability, not the host's — the documented residual is "a compromised operator who can ALSO roll the anchor back" (`agent-gateway-anti-rollback.md §3/§7`).
- **DoS-only + already conceded:** the host already relays all enclave↔anchor traffic + controls VM scheduling, so it can already wedge custody by dropping commits — the explicitly **accepted** "liveness-DoS availability residual" (§7: "fail-closed — no fund loss, no rollback, and the host gains nothing"). Forging adds no new power.
- **Design property, not new:** "the request is not signature-bound" is a deliberate decision (§5, same model as the `0x41` boot request); the `0x45` request format was FROZEN in slice 6-1 (PR #70). 6-4b only makes the path REACHABLE — under the OFF-BY-DEFAULT, release-banned `agent-keygen-exec-preview` gate (non-production).

**Parked OPTIONAL hardening (defense-in-depth vs the host-DoS variant; NOT required for safety):** bind `0x45` commit requests to the boot-attested enclave session — e.g. an enclave-held ephemeral MAC/signing key derived during the attested boot handshake, which the anchor verifies before any durable commit/ACK. This is a `0x45` wire + **anchor-side** protocol change (6-1-level, and it requires the anchor implementation to enforce it), so it belongs with a future anchor-protocol hardening pass, not the preview-gated boot wiring. User decision (2026-06-14): accept the documented DoS-only residual, merge 6-4b, park this hardening here.

Source: PR #74 compact job 7314 + the 2-agent adversarial verification (DoS-only, no wrong-accept/rollback).
<!-- SECTION:DESCRIPTION:END -->
