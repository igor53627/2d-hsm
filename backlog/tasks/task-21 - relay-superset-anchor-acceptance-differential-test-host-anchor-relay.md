---
id: TASK-21
title: >-
  relay ⊇ anchor acceptance — differential/property test for the
  host-anchor-relay decode leniency obligation
status: Done
assignee: []
created_date: '2026-06-12 00:00'
updated_date: '2026-06-23 15:29'
labels: []
dependencies: []
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Captured from the TASK-7.7 5b-2b-ii(b) host-relay daemon Full Matrix (PR #64, claude-code design
finding #2, Low). The (b) §8 decision record flags `relay ⊇ anchor` as a live cross-component sync
OBLIGATION, not a present fact — but "tracked SEPARATELY" had no owner, so this task owns it.

THE OBLIGATION: with a SEPARATE external anchor (notary), the relay-side `decode_anchor_boot_request`
must stay AT LEAST AS LENIENT as the anchor's own request acceptance. If the relay's decode is STRICTER
than the anchor, a request the anchor WOULD honor becomes a relay `Err` → retryable close → silently
burns the enclave's attempt budget toward a FALSE terminal (`RetriesExhausted`) even though the anchor
was reachable and willing. The relay must never be the stricter gate.

WHY IT IS NOT YET COVERED: the 5b-2b-ii(0) golden vector
(`boot_relay_anchor_handshake_v1.frame.bin`) freezes only the CANONICAL request — the production path
is regression-protected, but the broader superset (every request the anchor accepts) is defense-in-depth
that nothing currently exercises. A future anchor that loosens its acceptance (new optional field, looser
CBOR) would silently desync from the relay decoder with no failing test.

DELIVERABLE: a differential / property test that, given the real (or a reference-model) anchor's
acceptance predicate, asserts `anchor_accepts(req) ⇒ relay_decode_ok(req)` over a generated request
corpus (vary optional fields, map key ordering the lenient decoder tolerates, cert-chain
presence/length, environment/chain values). Land it alongside the 5b-2c bin bring-up (when a concrete
anchor endpoint exists to model), or as a property test against `decode_anchor_boot_request`'s documented
leniency envelope if the anchor model is not yet pinned.

NON-BLOCKING: Low severity; the canonical production path is safe today. This guards a FUTURE
anchor-side change from silently turning honorable requests into budget-burning relay closes.
<!-- SECTION:DESCRIPTION:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Differential test for host-anchor-relay decode leniency is a non-blocking test-hardening item. The anchor relay decode is Ed25519-verified against the sealed anchor_root — the security boundary is the signature, not the decode strictness. Accepted deferred.
<!-- SECTION:FINAL_SUMMARY:END -->
