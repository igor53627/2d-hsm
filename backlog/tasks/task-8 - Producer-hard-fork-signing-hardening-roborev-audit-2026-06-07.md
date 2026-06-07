---
id: TASK-8
title: Producer/hard-fork signing hardening (roborev audit 2026-06-07)
status: To Do
assignee: []
created_date: '2026-06-07 18:02'
labels:
  - security
  - audit
dependencies: []
ordinal: 12000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Pre-existing findings surfaced by the 2026-06-07 roborev audit of open consolidations on main (jobs 6589, 6509, 6624, 6656). Triage each; some may be known/accepted.

- Hard-fork signing does not enforce that ticket.pq_pubkey matches the enclave's actual armed ML-DSA key (lib.rs); armed key is used regardless of ticket pubkey.
- Recovery signing accepts an arbitrary pq_pubkey and validates it against the active signer only after the fact, not before signing.
- decode_sign_authorization_ticket_response accepts any signature byte length; per the vsock spec (~line 840), wire-decode must REJECT 64-byte mock PQ signatures in production and accept only the configured algorithm's production length (ML-DSA-65 = 3309 bytes). (Corrected: the earlier wording here said "reject non-64-byte", which was inverted.)
- pq-seal v1 secrets are not zeroized on all runtime paths.
- reference_test_attestation_signing_key / reference_test_attestation_trust re-exported in default builds; default build embeds mldsa65_reference_sk.bin and returns pq_signing_ready/pq_signing true with a placeholder key.
- compute_canonical_ticket_hash is public and performs no validation (callers can hash malformed tickets).
- new_header_version inconsistency: rust requires non-zero for hard-fork tickets; vsock spec wording differs.

Source roborev jobs: 6589, 6509, 6624, 6656 (2d-hsm).
<!-- SECTION:DESCRIPTION:END -->
