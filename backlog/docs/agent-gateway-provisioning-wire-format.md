# Agent Gateway provisioning channel — wire-format spec (25-2a, byte-exact frozen)

The byte-exact wire format for the G3 provisioning ceremony defined in
`agent-gateway-provisioning-channel.md` (25-1 design, Q1-Q8). This spec is **frozen**
(25-2a): it is reviewable independently of any implementation, and the Rust impl (25-2b)
is a consumer of this format, not a source of truth for it. A remote signer / provisioner
that byte-matches the golden vectors in §10 is conformant; anything else is not.

**Status: frozen at `provision_wire_version = 1`.** A future bump is a new wire format, not
a compatible extension — the enclave fails closed (`PROV_UNSUPPORTED_VERSION`, §9) on any
version other than `1`, exactly as the keystore seal fails closed on an unknown
`KEYSTORE_FORMAT_VERSION`.

**Canonical encoding.** All CBOR is RFC 8949 §4.2.1 core deterministic encoding (ascending
shortest-form integer keys, definite-length, no duplicate keys), matching the existing
capability / anchor / marks surfaces. Encoders MUST emit canonical bytes; decoders MUST
reject non-canonical bytes (§9). Non-canonical ⇒ `PROV_MALFORMED`.

**The MVP realization (Q1, locked 25-1-rev2).** An **online provisioner key** (its X.509
cert signed by the offline operator CA) signs the live transcript. The enclave verifies the
cert chain to the pinned operator CA root, then the transcript signature. The
offline-operator-with-round-trip variant from 25-1 is documented in §11 as an alternative
but is NOT this frozen format.

## §1 The four messages (two-round-trip handshake)

```
PROVISIONER (online key, cert ⊂ offline operator CA)          ENCLAVE (no keystore on disk)
═════════════════════════════════════════════════════════════════════════════════════════════
                                                               bootstrap listener open (Q5)
  ── M1 PROV_CHALLENGE (N_p) ──────────────────────────────►
                                                               mint N_e; emit SNP report whose
                                                               report_data = SHA3-512(handshake_dom ‖ N_p ‖ N_e)
  ◄────────────────────────────── M2 PROV_ATTEST (N_e, report) ──
  verify VCEK/ASK/ARK (TASK-1.2); measurement ∈ allowlist;
  TCB not revoked; N_p echoed in report_data
  ── M3 PROV_CONFIG (config, Sig_PROV, provisioner_cert) ──►
                                                               verify provisioner_cert → operator CA root;
                                                               re-derive (N_p, N_e, report_hash) from session;
                                                               verify Sig_PROV over PROVISION_DOMAIN ‖ canonical-CBOR(transcript);
                                                               mint enclave_scope_id via getrandom;
                                                               construct KeystoreBody; seal_body()
  ◄────────────────────────────── M4 PROV_SEALED (sealed_blob) ──
                                                               shut down bootstrap listener; start runtime serve loop
  host persists sealed_blob to keystore path
```

All four messages share the envelope framing of §2. The transcript signed in M3 covers the
config map (§5) + the live nonces + the report hash, so a host cannot substitute config in
transit (HIGH#1) and the signature is unforgeable for any other session (different `N_e`).

## §2 Envelope framing (every message)

```
magic[8] ‖ version[1] ‖ msg_type[1] ‖ deterministic-CBOR(payload)
```

| Field | Bytes | Value |
|---|---|---|
| `magic` | 8 | `b"2DAGPRV\0"` (`0x32 44 41 47 50 52 56 00`) — the G3 provision family; follows the existing 8-byte `2DAGxxx\0` convention (`2DAGTBK\0` backup, `2DRIGV1\0` restore-ingress, `2DAGTKS\0` keystore). |
| `version` | 1 | `0x01` (`provision_wire_version = 1`). Any other value ⇒ `PROV_UNSUPPORTED_VERSION` (§9). |
| `msg_type` | 1 | `0x01` M1, `0x02` M2, `0x03` M3, `0x04` M4. Direction-ambiguous framing: `msg_type` disambiguates (this is a handshake, not RPC request/response). |
| payload | var | `deterministic-CBOR(msg_type-specific-payload)`, defined per-message in §3-§6. |

**Per-state direction validation (25-2a-rev1 Low fix).** A known `msg_type` received in the wrong
role/state is `PROV_MALFORMED`: the **enclave** bootstrap listener accepts only M1 (initial state)
→ then M3 (after emitting M2); the **provisioner** accepts only M2 (after sending M1) → then M4
(after sending M3). Any other msg_type in either role ⇒ `PROV_MALFORMED` (a §9 negative test pins
this).

Decoders fail closed on: wrong magic (`PROV_BAD_MAGIC`), unsupported version
(`PROV_UNSUPPORTED_VERSION`), unknown msg_type (`PROV_MALFORMED`), payload that does not
round-trip canonical-CBOR (`PROV_MALFORMED`).

**DoS caps (25-2a-rev1 Med fix).** All variable-length fields from the untrusted side are
bounded; a decoder MUST fail closed `PROV_TOO_LARGE` (dedicated code, distinguishable from
`PROV_MALFORMED`) on:

| field | cap | rationale |
|---|---|---|
| overall M1/M3 payload | `MAX_PROV_PAYLOAD_LEN = 8192` | the largest legitimate M3 is ~1.8 KB (config ~1.7 KB + sig 64 + cert ~300 + framing); 8 KB is a 4× headroom. |
| `config_map` (M3 key 1, bytes) | `MAX_CONFIG_MAP_LEN = 4096` | 7 fields, the 1568-byte ML-KEM pubkey dominates; 4 KB is 2× headroom. |
| `provisioner_cert` (M3 key 6, bytes) | `MAX_PROV_CERT_LEN = 2048` | a single-level DER X.509 Ed25519 leaf is ~300-500 B; 2 KB rejects pathological / multi-cert bundles. |
| `report` (M2 key 2, bytes) | `SNP_REPORT_LEN = 1184` (fixed) | the SNP attestation report is a fixed-size structure; pin the exact length, reject any other. |

These mirror the existing `read_boot_file_capped` discipline (`boot_input.rs`) for the keystore
unseal path — untrusted variable-length inputs are capped before the (more expensive) DER / CBOR
parse. §9 includes a `PROV_TOO_LARGE` negative per field.

## §3 Message M1 — PROV_CHALLENGE (provisioner → enclave)

```
payload = canonical-CBOR({1: N_p})
```

| key | type | value |
|---|---|---|
| 1 | bytes[32] | `N_p` — the provisioner's fresh challenge nonce, `getrandom(32)` on the provisioner side. |

Fixed-width 32B nonce, matching the `DIGEST_LEN` convention used by the anchor handshake
(`agent_anchor.rs`). The enclave echoes `N_p` inside its `report_data` (§4) so the
provisioner's challenge-response check is hardware-bound.

## §4 Message M2 — PROV_ATTEST (enclave → provisioner)

```
payload = canonical-CBOR({
    1: N_e,           # bytes[32], the enclave's fresh session nonce
    2: report,        # bytes[var], the raw SNP attestation report bytes (the VCEK-signed structure)
})
```

| key | type | value |
|---|---|---|
| 1 | bytes[32] | `N_e` — enclave session nonce, `getrandom(32)` in-TEE. |
| 2 | bytes[var] | `report` — the canonical SNP attestation report bytes as emitted by the platform (the exact byte sequence the VCEK signed). The provisioner verifies it via TASK-1.2 `snp_verify.rs`. |

**`report_data` layout (what the enclave commits to inside the report's 64-byte
`REPORT_DATA` field):**

```
report_data = SHA3-512("2d-hsm-agent-provision-handshake-v1" ‖ N_p[32] ‖ N_e[32])
```

- 64-byte SHA3-512 output fits the SNP `REPORT_DATA` field exactly (no truncation).
- The domain string `b"2d-hsm-agent-provision-handshake-v1"` (no NUL — matches the anchor
  handshake domain `b"2d-hsm-agent-anchor-handshake-v1"` style).
- `N_p` (32) ‖ `N_e` (32) are fixed-width ⇒ the binding is unambiguous (no length-prefix
  needed; mirrors the anchor handshake's fixed-width layout).
- `measurement` and `TCB` are NOT in `report_data` — they are VCEK-bound in the report
  structure itself (25-1-rev2 Med fix: avoids a dummy-report round-trip to discover them).
- The provisioner verifies: `SHA3-512(domain ‖ N_p ‖ N_e) == report.report_data`. Mismatch ⇒
  `PROV_ATTEST_MISMATCH` (the report is not for this challenge).

`report_hash` (used in M3, §5) is defined as:

```
report_hash = SHA3-256(report)   # hash of the exact report bytes from M2 key 2
```

SHA3-256 over the full report binds the whole VCEK-signed structure (measurement, TCB,
`report_data`, all auth fields) into the signed transcript — strictly stronger than hashing
only `report_data` (WF5 decision).

## §5 Message M3 — PROV_CONFIG (provisioner → enclave)

```
payload = canonical-CBOR({
    1: config_map,         # bytes[var] = pre-encoded canonical-CBOR of the §5.1 config map (see §5.2)
    2: N_p,                # bytes[32], the SAME N_p from M1 (echoed for transcript completeness)
    3: N_e,                # bytes[32], the SAME N_e from M2
    4: report_hash,        # bytes[32], SHA3-256(report) from §4
    5: Sig_PROV,           # bytes[64], Ed25519 signature over PROVISION_DOMAIN ‖ canonical-CBOR(transcript) (§6)
    6: provisioner_cert,   # bytes[var], DER X.509 leaf cert chaining to the pinned operator CA (§7)
})
```

The **transcript** that `Sig_PROV` covers is:

```
transcript_canonical = canonical-CBOR({1: config_map, 2: N_p, 3: N_e, 4: report_hash})
signed_bytes = PROVISION_DOMAIN ‖ transcript_canonical
Sig_PROV = Ed25519(provisioner_sk, signed_bytes)
```

where `PROVISION_DOMAIN = b"2d-hsm/agent-provision/v1\0"` (NUL-terminated, matches
`b"2d-hsm/agent-cap/v1\0"` / `b"2d-hsm/agent-anchor/v1\0"`).

**Encoding choice for `config_map` (key 1): a pre-encoded `bytes` value, NOT a nested map.**
This mirrors the existing `payload_binding` precedent (agent_capability.rs:
`keccak256(opcode ‖ [sub_op] ‖ request_id ‖ canonical_params)` where `canonical_params` is
pre-encoded bytes). It keeps the transcript a flat 4-key canonical map (no first nested-map
in the codebase) and makes the config bytes independently freezable / hashable. The enclave
re-decodes the inner bytes as the §5.1 config map after verifying `Sig_PROV`.

### §5.1 The config map (basket B, 7 fields — no `enclave_scope_id`)

```
config_map = canonical-CBOR({
    1: twod_chain_id,                    # uint
    2: environment_identifier,           # text (UTF-8, 1..=64 bytes, [a-z0-9-] no leading/trailing/double hyphen — same rule as the sealed config)
    3: admin_authority_pk,               # bytes[32], Ed25519 public key (raw)
    4: recovery_authority_pk,            # bytes[32], Ed25519 public key (raw)
    5: backup_recovery_wrapping_pubkey,  # bytes[1568], ML-KEM-1024 encapsulation key (raw)
    6: anchor_root,                      # bytes[32], Ed25519 public key (raw) — the TASK-7.7 anchor identity
    7: fleet_scope_id,                   # bytes[32], the shared fleet scope id
})
```

**Structural enforcement of I2 (`enclave_scope_id` host-uncontrollable).** There is NO key
`8` (or any key) for `enclave_scope_id` in this map. A host cannot supply the id because
the protocol does not carry it. The enclave mints it in-TEE (§6.3 of 25-1 design). A
decoder that sees an unknown key (e.g., a host trying to inject `8: <id>`) fails closed
`PROV_MALFORMED` (strict canonical-CBOR: keys exactly `{1..=7}`).

**Basket-C fields are NOT in the wire map.** `monotonic_treasury_config_version` (=1) and
`authority_epoch` (=0) are enclave-init deterministic (25-1-rev2 Q4 clarification); the
enclave hard-codes them at genesis, they are never on the wire.

### §5.2 Canonical-CBOR byte shapes (for the golden vectors in §10)

The canonical bytes of a config_map for a representative config (`chain_id=11565`,
`env="prod-0"`, `admin=[0xa1;32]`, `recovery=[0xa2;32]`, `backup=[0xb0;1568]`,
`anchor=[0xa3;32]`, `fleet=[0xf1;32]`) are constructed as:

```
A7                              # map(7) — major 5, additional 7
   01                             # key 1
   19 2D 2D                      # uint 11565 (0x2D2D) — major 0, additional 26 (4-byte BE)
   02                             # key 2
   65 "prod-0"                   # text(5) "prod-0"
   03                             # key 3
   58 20  <32 bytes admin>       # bytes(32)
   04                             # key 4
   58 20  <32 bytes recovery>    # bytes(32)
   05                             # key 5
   59 06 20  <1568 bytes backup> # bytes(1568) — 0x0620
   06                             # key 6
   58 20  <32 bytes anchor>      # bytes(32)
   07                             # key 7
   58 20  <32 bytes fleet>       # bytes(32)
```

(The full byte-exact golden vector — with concrete sentinel bytes — is frozen in §10 and
in the regen test of 25-2b; the shape above is the encoder reference.)

## §6 The `Sig_PROV` signature + enclave verify order

```
Sig_PROV = Ed25519(provisioner_sk, signed_bytes)
signed_bytes = PROVISION_DOMAIN ‖ canonical-CBOR({1: config_map_bytes, 2: N_p, 3: N_e, 4: report_hash})
```

The enclave verifies, in this exact order (fail-closed at each step):

1. **Envelope** (§2): magic, version=1, msg_type=3, canonical-CBOR payload. Else
   `PROV_MALFORMED` / `PROV_UNSUPPORTED_VERSION`.
2. **Provisioner cert chain** (§7): the DER cert parses, its public key is Ed25519, its
   signature verifies against the **pinned operator CA root pubkey** (compiled into the
   enclave binary at build, see 25-1 Q7 measurement-allowlist parallel). Else
   `PROV_UNAUTHORIZED_PROVISIONER`.
3. **Transcript reconstruction**: re-derive `(N_p, N_e, report_hash)` from this session's
   own state (the `N_p` it received in M1, the `N_e` it minted in M2, the SHA3-256 of the
   report it emitted). Compare byte-exact to keys 2/3/4 of the M3 payload. Mismatch ⇒
   `PROV_TRANSCRIPT_MISMATCH` (replay or MITM).
4. **Sig_PROV**: re-compute `signed_bytes` from the M3 payload's key 1 (`config_map_bytes`)
   + keys 2/3/4 + `PROVISION_DOMAIN`, verify against the provisioner cert's public key.
   Else `PROV_BAD_SIGNATURE`.
5. **Config re-decode**: decode `config_map_bytes` (key 1) as the §5.1 config map; strict
   canonical-CBOR, keys exactly `{1..=7}`, field-type + length validation. Else
   `PROV_MALFORMED`.

Only after all five pass does the enclave proceed to mint + seal (§6.3 of 25-1). **Ordering
rationale (25-2a-rev1 Low fix):** only step 1 (envelope) is a pre-crypto cheap check; the
cryptographic heavy lifts (2 = cert-chain verify, 4 = `Sig_PROV` verify) intentionally precede
step 5 (config re-decode), because step 5 operates on signature-VERIFIED bytes (the config was
bound by `Sig_PROV`, so decoding it after the sig passes guarantees the bytes the host sent are
the bytes the provisioner signed — a pre-sig decode could be mutated between decode and verify).
DoS ordering is handled by the §2 DoS caps (a malformed oversized payload is rejected at step 1
before any crypto).

## §7 provisioner_cert — DER X.509 leaf (single-level chain, MVP)

```
provisioner_cert = DER-encoded X.509 leaf certificate
```

- **Public key**: Ed25519 (raw 32-byte SPKI, same family as the sealed authority keys).
- **Issuer**: the **operator CA** — its root public key is pinned in the enclave binary at
  build (the same binary-pinning discipline as the Q7 measurement allowlist). MVP quorum = 1
  (one operator CA key); threshold > 1 is post-MVP.
- **Chain depth**: **single-level** (leaf signed directly by the pinned root; NO
  intermediate CA). This keeps the enclave-side verification to one Ed25519 verify of the
  cert signature + one SPKI extraction, avoiding a full PKI path-validation stack in-TEE.
  Intermediate CAs are a documented post-MVP extension (§11).
- **Role constraint (25-2a-rev1 Med fix).** The cert MUST carry a provisioning-specific role
  marker — a dedicated EKU OID (e.g. `2.25.x`-style private OID, frozen in 25-2b) OR a pinned
  Subject string — so a leaf cert the operator CA issued for a DIFFERENT purpose (TLS client,
  code-signing, log-signing) cannot be repurposed as a provisioner (confused-deputy defense).
  The enclave rejects any cert lacking the role marker ⇒ `PROV_UNAUTHORIZED_PROVISIONER`.
  Without this, any leaf under the operator CA is a valid provisioner — the operator CA's blast
  radius is its whole issued-cert set.
- **Validity / revocation (NO enclave wall-clock check — 25-2a-rev1 HIGH fix).** SNP reports
  carry a TCB *version* (firmware/hardware SVNs), NOT a trusted wall-clock timestamp, and the SNP
  TEE has no secure RTC — so the enclave **cannot** evaluate X.509 `not_before`/`not_after` against
  a trusted time, and MUST NOT fall back to host time (the host is the adversary during provisioning).
  Revocation + validity is therefore enforced by **mechanisms the enclave CAN verify**:
  (i) **TCB-version gating** — the operator's pinned measurement-allowlist entry (Q7) is paired with
  a minimum TCB-version; the enclave rejects reports whose TCB is below the floor or above a
  revoked ceiling; (ii) **operator-CA rotation** — a compromised provisioner cert is retired by
  re-building the enclave binary with a new operator CA root (the old cert's chain no longer pins);
  (iii) **cert serial denylist** (optional 25-2b) — a small compile-time list of revoked provisioner
  cert serials, checked in-TEE without a clock. The X.509 `not_before`/`not_after` fields are parsed
  for audit logging only, NOT enforced (documented as residual: short-term compromise of an
  operator CA before rotation is the window — accepted, MVP quorum = 1).

**Why X.509 DER (not a custom min-format).** Operator tooling signs/provisions using
standard libraries (openssl / cloud KMS); DER X.509 is universally interoperable and
auditable. The cost is a DER parser in-TEE (accepted residual, 25-1-rev2 §5: "the online-
provisioner-key MVP adds X.509-style chain validation to the enclave — larger verification
surface than a single pinned-key Ed25519 verify"). 25-2b is Full Matrix partly because of
this verification surface.

## §8 Message M4 — PROV_SEALED (enclave → provisioner)

```
payload = canonical-CBOR({
    1: sealed_blob,   # bytes[var], the pq-agent-keystore-v1 sealed blob (magic 2DAGTKS\0)
})
```

The enclave returns the freshly-minted + sealed keystore blob (the output of `seal_body()`
over the freshly-constructed `KeystoreBody`). The host persists it to the keystore path on
disk; subsequent boots unseal via the existing `unseal_agent_keystore_at_boot` path.

**Atomicity (25-1 §2 step 6; 25-2a-rev1 Med fix — no M5 ack message).** The seal is committed
in volatile enclave session memory before M4 is emitted; the enclave **tears down the bootstrap
listener and starts the runtime serve loop immediately after sending M4** (§1 — fire-and-forget;
there is NO M5 persistence-ack in this format). The host-side persist is observed host-side; the
enclave cannot confirm it (it is gone before persistence). A vsock send failure of M4 leaves the
blob un-emitted and volatile (no TEE NVRAM); on reboot the enclave re-runs the ceremony with a
FRESH `enclave_scope_id` (harmless — counters zero, anchor has seen nothing). A ceremony is
**successful iff the host persisted M4's blob** (host-observable); the one-shot listener slot is
consumed on M4 send (the only in-enclave signal available). This is the volatile fire-and-forget
model; if a future revision needs in-enclave persistence confirmation it MUST add an explicit M5
message and bump `provision_wire_version`.

## §9 Negative test requirements (decoder strictness)

The 25-2b impl MUST include negative tests proving the decoder fails closed on each of:

- Wrong magic (`b"2DAGxxx\0"` ≠ `b"2DAGPRV\0"`) → `PROV_BAD_MAGIC`.
- `version ≠ 1` (incl. `0`, `2`, `0xFF`) → `PROV_UNSUPPORTED_VERSION`.
- `msg_type ∉ {1,2,3,4}` → `PROV_MALFORMED`.
- Non-canonical CBOR (descending keys, duplicate keys, indefinite-length, non-shortest
  int encoding, map header count ≠ actual pairs) → `PROV_MALFORMED`.
- `config_map` with a key `8` (a host attempting to inject `enclave_scope_id`) →
  `PROV_MALFORMED` (keys must be exactly `{1..=7}` — the structural I2 enforcement).
- `config_map` field-type/length violation (e.g., `admin_authority_pk` ≠ 32 bytes,
  `backup_recovery_wrapping_pubkey` ≠ 1568, `environment_identifier` failing the sealed-
  config charset rule) → `PROV_MALFORMED`.
- `report_data` mismatch (`SHA3-512(domain ‖ N_p ‖ N_e) ≠ report.report_data`) →
  `PROV_ATTEST_MISMATCH` (the report is not for this challenge).
- `transcript` mismatch (M3 keys 2/3/4 not byte-equal to the session's `N_p`/`N_e`/
  `report_hash`) → `PROV_TRANSCRIPT_MISMATCH` (replay on a different session).
- `provisioner_cert` not chaining to the pinned operator CA root →
  `PROV_UNAUTHORIZED_PROVISIONER`.
- `Sig_PROV` not verifying under the provisioner cert's key → `PROV_BAD_SIGNATURE`.
- **Channel-binding regression**: a captured M3 replayed against a DIFFERENT enclave
  session (different `N_e`) → `PROV_TRANSCRIPT_MISMATCH` (the load-bearing HIGH#1 test).

## §10 Frozen golden vectors (byte-exact)

The following are **frozen bytes** — a conformant encoder produces these for the named
inputs, and a conformant decoder accepts exactly these. Regenerated mechanically in 25-2b's
regen test; the values here are the spec authority.

### 10.1 Domains + magic

```
magic              = 0x32 44 41 47 50 52 56 00              # "2DAGPRV\0" (8 bytes)
PROVISION_DOMAIN   = 0x32 64 2D 68 73 6D 2F 61 67 65 6E 74 2D 70 72 6F 76 69 73 69 6F 6E 2F 76 31 00
                     # "2d-hsm/agent-provision/v1\0" (26 bytes incl. NUL)
handshake_domain   = 0x32 64 2D 68 73 6D 2D 61 67 65 6E 74 2D 70 72 6F 76 69 73 69 6F 6E 2D 68 61 6E 64 73 68 61 6B 65 2D 76 31
                     # "2d-hsm-agent-provision-handshake-v1" (35 bytes, NO NUL)
```

### 10.2 M1 PROV_CHALLENGE golden

Inputs: `N_p = [0x11; 32]`.

```
envelope:  0x32 44 41 47 50 52 56 00  01  01           # magic ‖ version=1 ‖ msg_type=1 (M1)
payload:   0xA1 01 58 20  <32 × 0x11>                 # canonical-CBOR({1: N_p}) = map(1) {1: bytes(32)}
```

Full M1 = `envelope ‖ payload` = `8 + 1 + 1 + 2 + 32` = 44 bytes. The payload head is `0xA1`
(map(1)), `0x01` (key 1), `0x58 0x20` (bytes(32)), then 32 payload bytes — a single-key map
wrapping the nonce, NOT a bare bytes value (25-2a-rev1 fix: the prior `0x58 20 …` form omitted
the required `{1: N_p}` CBOR map wrapper).

### 10.3 config_map golden (basket B)

Inputs: `twod_chain_id=11565`, `environment_identifier="prod-0"`,
`admin_authority_pk=[0xa1;32]`, `recovery_authority_pk=[0xa2;32]`,
`backup_recovery_wrapping_pubkey=[0xb0;1568]`, `anchor_root=[0xa3;32]`,
`fleet_scope_id=[0xf1;32]`.

The canonical-CBOR is constructed per §5.2; the byte-exact hex is regenerated by the 25-2b
regen test (the shape in §5.2 is the encoder reference, the regen test freezes the literal).
SHA3-256 of this exact byte string is the `config_map_hash` cross-check the decoder may use
to detect transport corruption before the full Ed25519 verify.

### 10.4 M3 PROV_CONFIG transcript golden

Inputs (in addition to §10.3): `N_p=[0x11;32]`, `N_e=[0x22;32]`, `report_hash=[0x33;32]`,
provisioner key = the operator-CA-certified test key.

```
transcript_canonical = canonical-CBOR({1: config_map_bytes, 2: N_p, 3: N_e, 4: report_hash})
signed_bytes        = PROVISION_DOMAIN ‖ transcript_canonical
Sig_PROV            = Ed25519(provisioner_test_sk, signed_bytes)
```

`Sig_PROV` and the full `provisioner_cert` are frozen by the 25-2b regen test (they depend
on a test provisioner keypair + operator CA keypair that 25-2b mints and commits alongside
the existing test-key fixtures). The 25-2b regen test asserts the decoder ACCEPTS the
golden M3 and that the verifier reaches the mint+seal step; the 25-2b negatives assert each
§9 failure mode on a perturbation of the golden.

## §11 Out-of-scope / post-MVP (documented alternatives, NOT this format)

- **Offline-operator-with-round-trip variant.** The 25-1 design documents an alternative
  where the provisioner forwards `(N_p, N_e, report_hash, config)` to an offline operator
  who signs and returns; the enclave then verifies a single operator-CA signature (no
  provisioner cert on the wire). This is a DIFFERENT wire format (no `provisioner_cert`
  field; different `Sig` semantics) and is NOT `provision_wire_version = 1`. If ever
  adopted, it is `version = 2`.
- **Intermediate CA chain.** MVP is single-level (leaf ← pinned root). A multi-level chain
  (leaf ← intermediate ← root) is a future format extension requiring an in-TEE
  path-validation step + a wire field for the intermediate bundle.
- **Threshold / quorum > 1 operator CA.** MVP = 1 key. A threshold scheme changes the cert
  / signature fields (multiple certs + a threshold signature) — a future format extension.

## Cross-references

- **`agent-gateway-provisioning-channel.md`** (25-1 design) — the locked decisions Q1-Q8,
  the threat model, the ceremony narrative, and the provenance contract this format
  instantiates.
- **`vsock-api-wire-format-spec-draft.md` §10.5** — the capability canonical-CBOR precedent
  (`CAP_DOMAIN ‖ canonical-CBOR({signed keys})`, ascending int keys, shortest-form).
- **`agent_anchor.rs`** — the anchor handshake `report_data` layout this format mirrors
  (`SHA3-512(domain ‖ fixed-width)`); the anchor signed-transcript precedent.
- **`agent_keystore.rs`** — the `KeystoreConfig` field types this format's basket B
  encodes; `KEYSTORE_MAGIC = b"2DAGTKS\0"` (the M4 sealed blob's own magic).
- **TASK-1.2** — the VCEK/ASK/ARK chain verification the provisioner runs on the M2 report.
- **TASK-18** — the 18-2 `scope_identity` byte-compare this whole mechanism makes
  production-enforceable; the I2 structural-absence of `enclave_scope_id` in §5.1.

## Revision log

- 2026-06-20 — 25-2a frozen. Wire format `provision_wire_version = 1`, MVP realization =
  online provisioner key certified by offline operator CA (Q1 25-1-rev2). Four-message
  two-round-trip handshake (M1-M4), `Sig_PROV` over the live transcript
  `(config_map, N_p, N_e, report_hash)`, single-level DER X.509 cert. Golden vectors in
  §10 (domains/magics frozen literally; config_map + M3 byte-exact values regenerated by
  the 25-2b regen test, shape in §5.2). Input to the Full Matrix on the wire format before
  25-2b (impl skeleton).
- 2026-06-20 — 25-2a-rev1 after the first Full Matrix (compact job, 2 HIGH + 3 Med + 2 Low).
  HIGH#1 fix: golden-shape chain_id encoding was `19 2D 0D` (11533), corrected to `19 2D 2D`
  (11565) — a byte-exact spec contradicting its own named input; the M1 golden also regained
  its `0xA1 01` map wrapper. HIGH#2 fix (claude-code + gemini independently): the §7
  enclave-side X.509 `not_before/not_after` check assumed a trusted time, but SNP reports carry
  a TCB version, NOT a wall-clock; removed the enclave wall-clock check, replaced with TCB-
  version gating + operator-CA rotation + optional cert-serial denylist (the only mechanisms the
  enclave can verify without a clock). Med fixes: cert role constraint (EKU/pinned Subject —
  confused-deputy defense); DoS caps on all untrusted variable-length fields
  (MAX_PROV_PAYLOAD_LEN / MAX_CONFIG_MAP_LEN / MAX_PROV_CERT_LEN / fixed SNP_REPORT_LEN); §8
  atomicity clarified to volatile fire-and-forget (NO M5 ack — the prior "send + ack" referenced
  a non-existent message; if persistence confirmation is ever needed it's version 2). Low fixes:
  handshake_domain 34→35 bytes; per-state msg_type direction validation; verify-order rationale
  corrected (only step 1 is pre-crypto; step 5 is post-sig by design). grok clean.
