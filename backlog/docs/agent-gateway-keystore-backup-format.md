# Agent Gateway sealed keystore + encrypted backup/DR format (TASK-7.2)

Concrete on-disk format design for the Agent Gateway secp256k1 signer: the **sealed
multi-key keystore** (`pq-agent-keystore-v1`) and the **disaster-recovery backup blob**
(`pq-agent-backup-v1`). This is the storage layer under the TASK-7.1 protocol — it holds
the agent keys and all the sealed state the protocol references. Implementation is TASK-7.6;
this document is the reviewed contract that TASK-7.3/7.4/7.6/7.7 build on.

Design context: `agent-gateway-secp256k1-signer-design.md` (§"Keystore and backup model"),
protocol: `vsock-api-wire-format-spec-draft.md` §10. Producer sealing baseline reused as
primitives: `impl/rust/enclave-protocol/src/pq_signer.rs` (`pq-seal-v1`).

## Scope and non-goals

- TASK-7.2 owns the sealed **multi-key** agent keystore and the encrypted **DR backup**
  format, **separate** from the producer ML-DSA sealed blob (AC#1, AC#2) — producer keys /
  AuthorizationTicket state are never stored here.
- **Non-goal (first slice):** no production restore *automation*. Fresh-TEE restore is a
  documented operator **ceremony**, not shipped automation. The MVP 2D gate is
  `identity_verified`; `restore_verified` is a later operator drill (the design doc §Keystore and backup model).
- Implementation (Rust, secp256k1, ML-KEM) is TASK-7.6. This doc + its test-vector
  requirements are the spec.

## Decisions (locked, TASK-7.2)

| Topic | Decision |
|-------|----------|
| Reuse | Reuse `pq-seal-v1` **primitives/conventions**; new blob **layouts** (`pq-agent-keystore-v1`, `pq-agent-backup-v1`). `pq-seal-manifest` is **not** a basis (only its version + fail-closed pattern). |
| DR wrapping | Asymmetric escrow to a **single** operator-held recovery **public** key (MVP); `recovery_key_id`/quorum-descriptor field reserved so M-of-N drops in later without changing version semantics. |
| KEM primitive | **ML-KEM-1024** (pure PQ, Cat-5; e.g. RustCrypto `ml-kem`) for the backup KEM-DEM envelope. *Residual:* no classical hybrid layer (see Residuals); `recovery_key_id` reserved for a later `X25519+ML-KEM` hybrid. |
| Fresh-TEE restore | Restore only onto an **operator-approved measurement allowlist**, verified at the recovery ceremony. |
| Serialization | **Deterministic CBOR** (`deny-unknown-fields`): serde struct-field order, all collections are `Vec` (no maps), so a given body always encodes identically — but **not** RFC 8949 *canonical* CBOR, and byte fields encode as integer-arrays, not byte strings. Any change (byte-string encoding, strict canonical ordering) is a `format_version` bump + golden-vector update, never a silent edit. |
| Authority rotation | **Deferred** to full re-provisioning in MVP; sealed `authority_epoch` field reserved so a later rotation task needs no format bump (the design doc §Keystore and backup model). |
| Audit | Bounded in-enclave **ring buffer + `last_exported_seq` backpressure** (fail privileged ops closed rather than discard un-exported entries). |

## Reuse decision and primitive inventory

Reuse from `pq-seal-v1` (`pq_signer.rs:230-359`): the AEAD *conventions* — `SHA3-256(domain ‖
provisioning_root ‖ meas_digest)` key derivation; `magic ‖ version ‖ meas_digest ‖ nonce`
header with **AAD = header-minus-nonce**; `Zeroizing` buffers (TASK-6); boot-time
install-before-use sequencing; the SEV-SNP-derived provisioning root (TASK-5).

**AEAD choice — XChaCha20Poly1305 (24-byte nonce), NOT the producer's ChaCha20Poly1305.** The
producer blob is sealed *once* at provisioning (one nonce per key), so a 96-bit random nonce is
safe. The keystore is **re-sealed on every privileged mutation** under a *fixed* per-enclave key,
so a 96-bit random nonce would accrue a birthday-bound collision risk (NIST caps random-96-bit
nonces at ~2^32 messages/key); the 192-bit XChaCha nonce removes it regardless of re-seal count.

Do **not** reuse the `pq-seal-v1` blob *layout*: it is structurally single-key and
fixed-size (`PLAINTEXT_LEN = ML_DSA65_SK + ML_DSA65_PK`, `pq_signer.rs:243`) with no entry
list, counters, or metadata. `pq-seal-manifest` solves a different problem (trustless
selection of one blob among N per-host variants via `root_commitment`); mirror only its
versioned + `deny_unknown_fields` + fail-closed-unknown-version pattern.

## `pq-agent-keystore-v1` — sealed keystore (same-enclave restart material)

Wrapped to the per-enclave seal root + measurement; unseals only on the same chip/image.

**Header** (plaintext on disk, AAD-authenticated; all multi-byte integers **big-endian**):
- `magic` = `b"2DAGTKS\0"` (8 bytes) — distinct from producer `b"2DHSMV1\0"`, so a producer
  blob can never be mis-parsed as a keystore (and vice-versa) — format-level AC#2 separation.
- `format_version` = `u16` (=1). **Fail-closed on unknown version BEFORE any decrypt**
  (mirror `pq_signer.rs:327-330`): no silent downgrade, no best-effort parse.
- `meas_digest` = `SHA3-256(b"2d-hsm-agent-keystore-v1-meas" ‖ enclave_measurement)` (32 B).
- `nonce` = 24 random bytes (XChaCha20Poly1305 extended nonce).
- `AAD = magic ‖ format_version ‖ meas_digest`. Body = XChaCha20Poly1305 ciphertext + 16-byte tag.

**KDF:** keystore AEAD key = `SHA3-256(b"2d-hsm-agent-keystore-v1-key" ‖ provisioning_root ‖
meas_digest)`. Same shape as `pq_signer.rs:291-299`, **distinct label** (AC#19) so it cannot
collide with the producer `2d-hsm-pq-seal-v1-key` material derived from the same SNP root.

**Plaintext** (deterministic CBOR, `deny-unknown-fields`):
1. **Config / identity** (AC#8): `twod_chain_id`; `environment_identifier` (UTF-8, `1..=64`,
   `[a-z0-9-]`, no leading/trailing/double hyphen — TASK-7.1 §10.6); `admin_authority_pk`
   (Ed25519 32 B); `recovery_authority_pk` / threshold root (Ed25519 32 B / quorum
   descriptor); `backup_recovery_wrapping_pubkey` (the operator recovery **public** key for
   DR — ML-KEM-1024 encapsulation key, 1568 B; public, sealed here so the enclave can wrap to
   it; private side never in TEE); `monotonic_treasury_config_version` (u64 — bumped by EVERY committed
   `CONFIGURE_TREASURY` sub-op (slice 15-4) via a checked add SEPARATE from the anti-rollback
   epoch/structural bump; **not** a marks surface and **never** aliased onto `structural_version`; overflow
   fails closed); `authority_epoch`
   (u64, reserved for future rotation); `anchor_root` (Ed25519 32 B — the pinned TASK-7.7
   anti-rollback anchor identity the enclave verifies freshness responses against; 7.2 stores it,
   7.7 owns the mechanism).
1b. **Anti-rollback freshness** (TASK-7.7): `freshness_epoch` (u64) lives in the body alongside
   the counter/spend state, so the keystore AEAD integrity-binds it; 7.2 seals/stores it, 7.7
   advances it against `anchor_root` and rejects any unsealed blob whose epoch is stale.
2. **Entry list** (AC#1): length-prefixed `KeyEntry { key_ref, purpose
   (agent_faucet_treasury_k1 | agent_transfer_k1), algorithm (secp256k1), public_identity
   (uncompressed 65-byte SEC1, TASK-7.1), creation_metadata (config-version + counter
   snapshot, batch_id), backup_export_metadata }`. Private scalars held as `Zeroizing<…>` in
   memory. Singleton treasury vs batch transfer keys distinguished by `purpose`. Capacity
   (AC#5): `max_batch_size` + `total_capacity` enforced before seal; fail-closed on overflow
   or persist-write failure.
3. **Counter high-water table** (AC#8/#11): `(authority, environment_identifier,
   scope_class, scope_target) -> highest_accepted_counter`. Acceptance (TASK-7.1):
   `incoming == highest+1`; reject lower (replay) and gaps.
4. **Faucet state** (AC#8/#17): per-dispense max amount, max gas limit, max effective gas
   fee rate, `cumulative_native_spend` (refillable) + a lifetime-spend counter always
   maintained from genesis with an **optional** circuit-breaker threshold (see TASK-7.4 §2).
   Spend counters keyed **independently of the treasury `key_ref`** so they survive
   treasury-key rotation (AC#17 — never reset on key replacement).
5. **Audit** (AC#8/#14): bounded ring buffer of privileged-op records (op, authority,
   counter, config_version, monotonic seq) + `last_exported_seq` so rollover cannot silently
   drop un-exported entries.

**Forward-migration** (AC#16): the enclave reads a bounded window of prior versions during a
migration window and re-seals to current on the next privileged mutation; any version
outside the known set ⇒ fail-closed (no zero-init, no truncation tolerance). A version bump
requires a reviewed, vector-backed change.

**Atomic key generation** (AC#18): `AGENT_K1_GENERATE_KEYS` seals the counter advance **and**
the new key metadata in one commit before returning refs; a partial/persist failure returns
**no usable refs** and a reconcilable signal (no silent orphan refs).

## `pq-agent-backup-v1` — DR backup blob (the crux, AC#3/#6/#12/#13)

The DR backup must be confidentiality-rooted in operator/recovery material **independent of
the source enclave seal root** (AC#13, the design doc §Keystore and backup model) — a blob wrapped only to the SNP seal
root is same-enclave restart material (that is the sealed keystore above), not DR.

**Mechanism:** asymmetric escrow via a standard **KEM-DEM** construction (HPKE-style), using
**ML-KEM-1024** to an operator-held recovery public key. ML-KEM is a KEM, so it does **not**
encrypt a caller-chosen key — encapsulation derives a *fresh* shared secret:

1. `(kem_ct, ss) = ML-KEM-1024.Encaps(backup_recovery_wrapping_pubkey)` — `ss` is a fresh
   32-byte shared secret the producer cannot choose; `kem_ct` is the encapsulation.
2. `payload_key = SHA3-256(b"2d-hsm-agent-backup-v1-key" ‖ ss)` — domain-separated KDF (this
   is where the `2d-hsm-agent-backup-v1` domain lives; there is **no** separately-chosen DEK).
3. The exported payload is encrypted with `ChaCha20Poly1305(payload_key, payload_nonce, payload, AAD)`.

`ss`/`payload_key` exist only transiently and are held in `Zeroizing`. The enclave seals only
the recovery **public** key (keystore config); the ML-KEM decapsulation **private** key lives
**offline** in operator custody and never enters a runtime/production TEE. Consequence: a
fully compromised runtime that exfiltrates all sealed + in-memory enclave material **still
cannot decrypt** past or future DR backups (AC#13/#6 — no recovery secret in the enclave).

**Layout** (frozen v1; all multi-byte integers **big-endian**; variable fields are length-prefixed —
`lp16` = `u16`-length-prefix, `lp32` = `u32`-length-prefix; an over-width field is REFUSED, never
silently truncated). On-disk byte order:
`magic(8) ‖ backup_format_version(u16) ‖ lp16(recovery_key_id) ‖ chain_id(u64) ‖ lp16(environment_identifier)
 ‖ kem_ct(1568) ‖ lp32(key_refs_manifest) ‖ payload_nonce(12) ‖ lp32(dem_ciphertext)`.
- `magic` = `b"2DAGTBK\0"`; `backup_format_version` = `u16` (=1, versioned **independently** of the keystore
  version). Fail-closed on unknown version / wrong magic BEFORE any decapsulation.
- `recovery_key_id` / quorum descriptor (which operator recovery material this is wrapped to; single-key
  MVP, descriptor reserved for M-of-N and a later `X25519+ML-KEM` hybrid).
- `chain_id` (u64) + `environment_identifier` (UTF-8) — so a `testnet` blob cannot be restored into a
  `mainnet` enclave (cross-environment restore must fail).
- `kem_ct` = the ML-KEM-1024 encapsulation (KEM ciphertext, FIXED 1568 bytes ⇒ no length prefix).
- authenticated `key_refs` manifest (which keys are included).
- `payload_nonce` (12 bytes). `payload_key` is unique per backup (fresh `ss` per `Encaps`), so a fixed-zero
  nonce is cryptographically safe; the field is explicit so the layout is unambiguous, and an implementation
  MAY use a random nonce instead.
- `dem_ciphertext` = ChaCha20Poly1305 over the exported payload + 16-byte tag.
- **`AAD` = the EXACT serialized header bytes** — everything from `magic` through `payload_nonce`
  INCLUSIVE (`magic ‖ version ‖ lp16(recovery_key_id) ‖ chain_id ‖ lp16(environment_identifier) ‖ kem_ct ‖
  lp32(key_refs_manifest) ‖ payload_nonce`), INCLUDING the length prefixes and the nonce. This is an
  UNAMBIGUOUS encoding (CWE-347): because the length prefixes are authenticated, a host cannot re-partition
  the same authenticated byte string into a different `chain_id`/`environment_identifier` by mutating only
  the (otherwise plaintext) on-disk length prefixes — the recompute-from-disk AAD would differ and the AEAD
  tag fails. Seal and offline-open use the IDENTICAL header bytes as AAD, so they cannot diverge.
  (Implementation: `agent_backup.rs` `build_header`/`strict_parse`.) **NB this supersedes an earlier draft
  AAD `magic ‖ version ‖ recovery_key_id ‖ chain_id ‖ env ‖ kem_ct ‖ canonical(manifest)` that bound only
  the field VALUES — that was CWE-347-ambiguous (the unauthenticated length prefixes permitted re-partition);
  the length-prefixed header-as-AAD is the frozen v1.**

**Freeze contract (v1).** The frozen golden vector (`testvectors/agent-gateway/agent_backup_v1.bin`,
TASK-13b slice 3) pins the ENVELOPE (header + framing + AAD + KEM-DEM) — NOT the payload semantics. The
payload there is an opaque slice-1 stand-in; its restorable contents are defined in slice 4. **Slice 4 may
only define/ADD to the opaque payload; ANY change to a header / AAD / framing field (magic, version,
field order, length-prefix widths, the AAD construction) is a `backup_format_version` 2 bump + a new
golden vector**, never a silent edit to v1.

Any randomness (a non-zero `payload_nonce`) comes from the TEE platform CSPRNG, never
host-influenced (cf. the RFC 6979 deterministic-signing note for secp256k1).

**Export self-check** (AC#3, the design doc §Keystore and backup model): before returning success, parse the
header/manifest, verify the authenticated key-ref list equals the requested refs, and reject
truncated/malformed blobs. The payload contains only agent private scalars + public
metadata; it **excludes** producer ML-DSA/AuthorizationTicket material (AC#2), any runtime
signing credential, and the seal root itself.

## Restore scope + counter seeding (AC#4/#11/#12/#13)

Three keying assumptions, stated separately:
1. **Same-enclave restart** — the sealed keystore unseals on the same chip/image. Default
   path, no ceremony.
2. **Same-fleet** (same image, different chips) — per-chip SNP root differs, so a sealed
   keystore does **not** move between hosts; provisioning the same agent keys cross-host is a
   DR operation via the backup blob, not by copying the keystore.
3. **Fresh / newly-provisioned TEE** — allowed **only** via the recovery ceremony, with a
   defined **confidential ingress** so plaintext agent scalars never touch the untrusted host:
   (i) the destination TEE generates an **attested ephemeral ML-KEM keypair** and publishes
   the public key with its attestation; (ii) the operator verifies that attestation's
   measurement against the **operator-approved allowlist**; (iii) in the **offline recovery
   environment** (operator HSM/enclave holding the recovery private key) the backup is
   decapsulated to recover the payload, which is then re-encrypted to the destination TEE's
   attested ephemeral public key as an **import envelope** — the *same* KEM-DEM construction
   as the backup blob, but to the ephemeral key:
   - `(ingress_kem_ct, ss') = ML-KEM-1024.Encaps(dest_ephemeral_pubkey)`
   - `ingress_key = SHA3-256(b"2d-hsm-agent-restore-ingress-v1" ‖ ss')`
   - `ChaCha20Poly1305(ingress_key, ingress_nonce, payload, AAD')`, with
     `AAD' = dest_attestation/measurement ‖ chain_id ‖ environment_identifier ‖
     key-ref-manifest-hash ‖ original-backup-digest ‖ ingress_kem_ct`.

   (iv) the destination TEE decapsulates with its ephemeral private key and, **before
   importing**, verifies that the attestation/measurement in `AAD'` is its own, that
   `chain_id` / `environment_identifier` equal its sealed config (cross-environment restore
   fails closed), and that the manifest hash + original-backup digest match, then imports the
   plaintext scalars **only inside itself**. Plaintext therefore exists only in the trusted
   offline recovery environment and inside the attested destination TEE — never in a
   runtime/production TEE on an untrusted host, and the recovery private key never enters any
   production TEE. A routine image upgrade adds the new measurement to the allowlist;
   arbitrary measurements are refused.

**Counter / spend high-water seeding** (AC#11/#12 — never zero, never stale): on fresh-TEE
restore the enclave **must not** initialise capability counters or faucet cumulative-spend
from zero, and **must not** trust the high-water values inside a possibly-stale backup alone.
It seeds them from one of: (a) authenticated recovery material stating expected high-water
marks (signed by recovery authority/quorum); (b) a remote monotonic ledger; (c) an
operator-signed boot authorization stating the marks. Any override is accepted only if
`target > enclave's highest known`, or is bound to an independent strict recovery counter
(AC#11). Faucet consistency (the design doc §Keystore and backup model): restore the treasury key **and** its eligible
transfer-key allowlist as one consistent set, or fail faucet signing closed until the
allowlist is reconstructed and verified. Active-active clones of one treasury key without a
global spend/capability ledger remain prohibited.

## Anti-rollback boundary (7.2 vs 7.7) + residual risk (AC#10)

**7.2 owns:** the **storage + validation** of sealed counters/caps — sealing the high-water
table, faucet caps, spend counters, lifetime breaker, and monotonic config version inside
the keystore; the in-enclave acceptance rules (contiguous counter, spend ≤ cap, config
monotonic); atomic keygen seal (AC#18); the restore-time seeding **contract** that forbids
zero/stale init (AC#11/#12); and the explicit statement that plain sealing gives
confidentiality + integrity but **not** host-rollback resistance.

**7.7 owns:** the anti-rollback / freshness-binding **mechanism** itself (external
append-only ledger, remote monotonic counter, or operator-signed boot authorization bound to
a platform/hardware monotonic counter or remote challenge-response). 7.2 only **consumes** it.

**Residual-risk wording (AC#10):** *Standard sealed storage of agent-gateway counters and
treasury caps provides confidentiality and integrity but not host-rollback resistance. A
compromised host that rolls the enclave's persistent sealed state backward can replay
capability counters and reset cumulative faucet spend toward earlier values; the TEE cannot
independently enforce absolute cumulative limits or replay protection against such a host.
These counters are host-rollback-sensitive until the deployment supplies the TASK-7.7
mechanism. Production fund custody REQUIRES that mechanism; a deployment that cannot provide
it must explicitly accept that treasury caps and replay counters are rollback-sensitive and
therefore unsuitable for production fund custody (the design doc §Success criteria).*

## Privilege model (AC#6)

Four distinct, TEE-verified Ed25519 admin/recovery capabilities (TASK-7.1 §10.5): (a)
key-generation/provisioning — cannot export; (b) backup-export — produces the opaque blob,
cannot decrypt/restore; (c) restore — recovery-tier, fresh-TEE only; (d) treasury config —
separate. **Runtime signing credentials** (`AGENT_K1_SIGN_TRANSFER` /
`AGENT_K1_SIGN_FAUCET_DISPENSE`) can do **none** of generate/export/restore/access-recovery.

## secp256k1 zeroization (AC#15)

Stored private scalars in `Zeroizing<Vec<u8>>` (TASK-6 pattern, `pq_signer.rs:189-193`);
per-signature transient key material wiped after use; RFC 6979 deterministic nonce + low-S
(TASK-7.1). State the residual: process-abort paths skip `Drop`, so abort does not guarantee
wipe — same residual TASK-6 records for ML-DSA (the design doc §Keystore and backup model).

## Audit metadata retention (AC#14)

Bounded ring buffer + `last_exported_seq`; an authenticated pull-export (or attested
log-streaming as a production upgrade) must drain entries before rollover. If un-exported
entries would be overwritten, privileged operations **fail closed** (backpressure) rather
than silently discard reviewable history.

## Provisioning runbook amendments (AC#9)

`pq-seal-v1-provisioning-runbook.md` gains subsections for: choosing/installing `chain_id`,
`environment_identifier`, `admin_authority_pk`, recovery/quorum root, **backup-recovery
wrapping public key** (with offline custody of the matching ML-KEM private key); initialising
replay/cap/spend state + treasury config version; wedged-scope counter recovery; the
fresh-TEE restore ceremony outline + operator-approved measurement allowlist custody.

## Golden-vector + test requirements (AC#7, AC#20, DoD)

Consumed by TASK-7.6 (these are requirements; the live sealed/backup blobs are produced once
the format is implemented):
- **Keystore round-trip:** seal N keys + full sealed-state → unseal → byte-exact recovery;
  frozen golden keystore blob committed with its provisioning-root + measurement fixture
  (mirror `seal_v1_provisioning_root.bin`, `pq_signer.rs:267-275`).
- **Unknown-version fail-closed:** keystore/backup blob with an unsupported version is
  rejected **before** any decrypt (parallel `pq_signer.rs:327-330`).
- **Wrong-magic rejection:** a producer `2DHSMV1\0` blob fed to the keystore parser fails on
  magic, and vice-versa (format-level AC#2 separation).
- **KDF domain non-collision:** keystore key (`…agent-keystore-v1-key`) ≠ producer key
  (`…pq-seal-v1-key`) for identical root+meas; cross-decrypt fails both ways.
- **Measurement binding:** keystore sealed under measurement A fails to unseal under B.
- **Backup export self-check:** truncated blob / corrupted tag / mutated key-refs manifest
  → failure, never success (AC#3).
- **No plaintext-key leakage** (AC#7): the backup blob and on-disk keystore contain no
  plaintext private scalar (known test secret bytes must not appear); blob is opaque.
- **DR wrapping independence** (AC#13): a blob wrapped to recovery key R1 cannot be decrypted
  with the source seal root; it decrypts only with R1's offline ML-KEM private key.
- **KEM-DEM round-trip:** `Encaps`→KDF→AEAD then `Decaps`→KDF→AEAD recovers the payload
  byte-exactly; because `kem_ct` is in the AAD, mutating it fails decryption.
- **Restore ingress envelope:** ingress KEM-DEM round-trip to the destination ephemeral key
  recovers the payload; mutating any `AAD'` field (dest attestation/measurement, `chain_id`,
  `environment_identifier`, manifest hash, original-backup digest, `ingress_kem_ct`) fails
  decapsulation/import. (Ceremony path; full vectors land with TASK-7.6.)
- **Cross-environment restore fails:** a backup carrying `environment_identifier=testnet`
  (and/or a different `chain_id`) is rejected by a `mainnet` enclave (AAD mismatch).
- **Recovery-auth vs wrapping-key separation** (AC#13): a restore authorized by the Ed25519
  recovery authority but whose backup is wrapped to a *different* ML-KEM key than the sealed
  `backup_recovery_wrapping_pubkey` fails — the authorize role and the decrypt role are distinct.
- **Restore counter seeding** (AC#11/#12): (a) restore that would lower a high-water is
  rejected; (b) fresh-TEE restore with no authenticated high-water source is rejected (no
  zero-init); (c) restore seeded at `target > highest` succeeds with the seeded marks.
- **Atomic keygen** (AC#18): simulated mid-generation persist failure ⇒ no usable refs +
  reconcilable signal.
- **Capacity fail-closed** (AC#5): exceeding `max_batch_size`/`total_capacity` or a
  persist-write failure both fail closed without partial state.
- **Faucet spend carry-over on rotation** (AC#17): generating a replacement treasury key
  does not reset cumulative spend / lifetime breaker.
- **Forward-migration** (AC#16): a prior-version blob within the window is read and re-sealed;
  outside the window ⇒ fail-closed.

## Residuals to record

- **ML-KEM without a classical hybrid layer** (per locked decision): no X25519 hedge against
  an ML-KEM implementation defect for long-lived DR-backup confidentiality. The
  `recovery_key_id` / wrapping descriptor is designed so a hybrid `X25519+ML-KEM` envelope
  can be added later without changing version semantics. Flagged for security review.
- **Single recovery-key custody** (MVP): one compromise/loss point for the offline recovery
  key; quorum descriptor reserved for an M-of-N upgrade.
- **Authority rotation deferred:** authority compromise ⇒ full re-provisioning in MVP
  (the design doc §Keystore and backup model); sealed `authority_epoch` reserved.
