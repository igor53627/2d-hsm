# Agent Gateway secp256k1 keygen + public identity (TASK-7.3)

Design for secp256k1 **key generation** and **public identity / proof-of-possession** in the
Agent Gateway signer. Design-only: the secp256k1 implementation (k256, RFC 6979 signing) is
TASK-7.6, and `AGENT_K1_SIGN_*` signing is TASK-7.4. This doc **consumes** the contracts
already pinned by TASK-7.1 (protocol §10, golden vectors) and TASK-7.2 (sealed keystore
format) and only adds the keygen + identity + non-collision specifics.

Refs: protocol `vsock-api-wire-format-spec-draft.md` §10; keystore
`agent-gateway-keystore-backup-format.md`; design `agent-gateway-secp256k1-signer-design.md`
§Key purposes / §Public identity; golden vectors
`impl/rust/enclave-protocol/testvectors/agent-gateway/`; 2D address derivation
`../2d/lib/chain/crypto/address.ex`, `../2d/lib/chain/tron/address.ex`.

## Decisions (locked, TASK-7.3)

| Topic | Decision |
|-------|----------|
| `key_ref` | **Random 32-byte** value from the TEE CSPRNG, assigned **inside** the enclave; the host never supplies or overwrites a ref. (Atomic seal — 7.2 AC#18 — is all-or-nothing, so reproducible derivation is unnecessary; random avoids any derivation-input-collision surface.) |
| Pubkey encoding | **Uncompressed 65-byte SEC1** (`0x04 ‖ X ‖ Y`). TASK-7.1 AC#14 **locked** this (did not delegate); compressed (`0x02/0x03`) is rejected, matching 2D `address.ex`. 7.3 records the confirmation. |
| Public identity | `AGENT_K1_PUBLIC_IDENTITY` returns **both** eth `0x…` and TRON `T…` addresses (unified-account model). Low-privilege read (7.1 AC#16) — no admin capability. |
| Live PoP sample | The live, *signed* `PROVE_IDENTITY` sample is **deferred to TASK-7.6** (needs the k256 signer). 7.3 consumes the 7.1-pinned `identity_proof_v1.*` layout/non-collision witness. |
| Error codes | Reference the TASK-7.1 §10.9 agent error band `0x40–0x46`; 7.3 states only which distinctions are safe to expose (anti-oracle), not new codes. |
| Treasury singleton | Detect an active treasury key by **scanning the sealed entry list** for `purpose=agent_faucet_treasury_k1` (no new keystore field; 7.2 entry schema is authoritative). |
| 2D `0x19` reservation | **Does not block 7.3 merge.** Cited as a tracked cross-repo blocking dependency (2D PR #144 / TASK-132.5 family); the non-collision vector asserts the pinned 2D encoding has not assigned `0x19`. Final binding gates production fund custody (which TASK-7.7 gates anyway). |

## Canonical pubkey encoding + address derivation (AC#3, AC#4) — consumed

- **Pubkey:** uncompressed 65-byte SEC1, `0x04 ‖ X(32) ‖ Y(32)`.
- **eth (2D) address:** `keccak256(X ‖ Y)[12:32]` → 20 bytes (authoritative source
  `address.ex:115-118`; the enclave drops the `0x04` prefix and hashes the 64-byte `X‖Y`).
- **TRON address:** `Base58Check(0x41 ‖ body20)` with `SHA256(SHA256(0x41‖body20))[0:4]`
  checksum (`tron/address.ex`), over the **same** 20-byte body — unified-account model.
- **Pinned witnesses (consume, do not re-pin):** `keys.json` carries both keys with
  `pubkey_uncompressed_sec1`, `eth_address`, `tron_address` — e.g. transfer
  `0xf39fd6e5…92266` / `TYBNgWfhGuNzdLtjKtxXTfskAhTbMcqbaG`, treasury
  `0x70997970…79c8` / `TLEaY8XoqpBmndLsjcfThgdKLN1ssNuUcF`. The AC#6 address-derivation test
  re-derives both from the pinned pubkeys and asserts byte-exact equality.

## Key generation (`AGENT_K1_GENERATE_KEYS`) (AC#1, AC#2)

Privileged command (TASK-7.1 §10.5 — requires the signed Ed25519 admin capability at
envelope key 5). One opcode serves both purposes, distinguished by `purpose`:

- **`agent_transfer_k1` (batch):** `count ≥ 1`; each key gets a fresh **random 32-byte
  `key_ref`** from the TEE CSPRNG; fleet scope allowed; **transfer-refill** admin tier.
- **`agent_faucet_treasury_k1` (singleton):** `count` must be `1`; **enclave-scoped**
  contiguous counter; **treasury-provisioning** admin tier — strictly **stronger** than
  transfer-refill (a transfer-refill capability cannot mint a treasury key; the capability
  binds command + key purpose + scope, §10.5).

**Opacity (AC#1):** `key_ref` is generated inside the enclave and is never accepted from the
host; the host cannot choose or overwrite a ref. Entry-list append is a privileged sealed
mutation.

**Private scalar:** generated inside the enclave from the TEE CSPRNG (`getrandom`; cf.
`pq_signer.rs:400-403`), never host-influenced; held in `Zeroizing` (7.2 AC#15).

**Atomic seal (AC#18, via 7.2 keystore):** the admin capability-counter advance **and** the
new `KeyEntry` (`key_ref`, `purpose`, `algorithm=secp256k1`, `public_identity` = uncompressed
65-byte SEC1, `creation_metadata`) are sealed in **one** `pq-agent-keystore-v1` commit before
any ref is returned. Partial/persist failure ⇒ no usable refs + a reconcilable signal (no
silent orphans). Capacity (`max_batch_size`, `total_capacity`, 7.2 AC#5) is checked **before**
seal; fail-closed on overflow or persist failure.

**Treasury singleton (AC#2):** before generating a treasury key, the enclave scans the sealed
entry list for an active `agent_faucet_treasury_k1`; if present, a second treasury keygen
**fails closed** unless a later reviewed rotation protocol is active (design §Protocol
version). Spend counters are keyed independently of the treasury `key_ref` (7.2), so rotation
never resets spend. 7.3 owns duplicate-treasury rejection; 7.2/7.4 own rotation counter
semantics.

## Public identity (`AGENT_K1_PUBLIC_IDENTITY`) (AC#4)

Low-privilege read (no admin capability; 7.1 AC#16) — still validates command domain, key
purpose, and chain/environment binding. Response:

```
{ pubkey: uncompressed 65-byte SEC1 (0x04‖X‖Y),
  eth_address:  20 bytes  (keccak256(X‖Y)[12:32]),
  tron_address: Base58Check(0x41‖body20),
  key_ref:      32 bytes (opaque),
  key_purpose:  agent_transfer_k1 | agent_faucet_treasury_k1,
  backend:      agent_version(=1) + build/protocol version }
```

## Identity proof (`AGENT_K1_PROVE_IDENTITY`) + non-collision (AC#5)

Low-privilege read; EIP-191 `0x19` non-transaction domain. **Layout (pinned by 7.1 AC#15,
`identity_proof_v1.*`):** `0x19 ‖ len(label) ‖ label ‖ chain_id(8B BE) ‖ len(env_id) ‖
env_id ‖ key_ref(32B) ‖ pubkey(65B) ‖ address(20B) ‖ verifier_nonce(32B)`,
`label="2d-hsm/agent-identity-proof/v1"`, keccak256, signed low-S + recovery id. Signs only
structured fields (no caller-controlled arbitrary bytes); the **verifier** owns nonce
freshness; the enclave binds the 32-byte verifier nonce so proofs are live and non-replayable.

**Non-collision argument (what 7.3 adds)** — the identity-proof preimage is disjoint from all
three 2D transaction surfaces, with the frozen vectors as witnesses
(`domain_separation.json`):

1. **vs eth EIP-155 RLP — structural.** Identity first byte `0x19`; an RLP-list head is
   always `≥ 0xc0` (`ordinary_tx_v1` first byte `0xed`). `0x19 < 0xc0`, so an identity
   preimage can never be a valid RLP-list head. Both use keccak256.
2. **vs TRON protobuf — two independent separations.** Leading byte `0x19` vs protobuf
   field-tag `0x0a` (`tron_transfer_v1` first byte `0x0a`), **and** hash separation (TRON
   `sha256` vs identity `keccak256`).
3. **vs EIP-2718 typed tx — policy, not structural.** `0x19` (= 25) is a legal EIP-2718
   `TransactionType` (`0x00..0x7f`), so disjointness here holds **only** as the pinned policy
   that 2D permanently reserves and never assigns type `0x19`. The enclave cannot enforce a
   2D type assignment — this is the **cross-repo blocking dependency (2D PR #144 /
   TASK-132.5)**; the non-collision vector asserts the pinned 2D encoding has not assigned
   `0x19` (`domain_separation.json` `note_eip2718`).

## secp256k1 implementation contract (design-only; impl in TASK-7.6/7.4)

- **Crate:** RustCrypto **k256** (+ `ecdsa` with `recovery`) — consistent with the existing
  RustCrypto stack (`sha3`; `ml-kem` in 7.2). No secp256k1 dependency exists yet (deferred).
- **Signing:** **RFC 6979** deterministic nonce (raw RNG-only `k` is **not** acceptable) +
  **low-S** normalization + recovery id (design §Keystore and backup model). 7.3 records the
  requirement; the k256 keygen module + RFC6979/low-S enforcement are implemented in
  TASK-7.6, and `SIGN_TRANSFER`/`SIGN_FAUCET_DISPENSE` in TASK-7.4.
- **Zeroization:** scalars in `Zeroizing`; transient per-signature `k` wiped; residual:
  process-abort skips `Drop` (same residual TASK-6 records for ML-DSA).

## Golden-vector + test requirements (AC#6, AC#7)

Consumed by TASK-7.6 (live signed/sealed artifacts land with the implementation):
- **Address derivation:** re-derive eth + TRON addresses from both `keys.json` pubkeys; assert
  byte-exact match to the pinned values above.
- **Keygen vector (new, AC#3):** `agent_keygen_v1` sealed `KeyEntry` { random 32B `key_ref`,
  purpose, `algorithm=secp256k1`, uncompressed 65B SEC1 `public_identity`, derived eth+TRON
  addresses, `creation_metadata` } round-trips byte-exact through `pq-agent-keystore-v1`
  seal/unseal (live blob produced in 7.6).
- **Opaque-ref:** the host cannot supply or overwrite a `key_ref`; two batches never collide
  (random 32B).
- **Treasury singleton:** a second active `agent_faucet_treasury_k1` keygen fails closed.
- **Key-purpose mismatch:** `SIGN_TRANSFER` with a treasury key, `SIGN_FAUCET_DISPENSE` with a
  transfer key, and any producer/AuthorizationTicket command with an agent key purpose each
  fail closed.
- **Treasury-vs-transfer permissions:** transfer-refill cap generates ≥1 `agent_transfer_k1`;
  treasury-provisioning cap generates exactly one `agent_faucet_treasury_k1`; a transfer-refill
  cap cannot mint a treasury key; no capability ⇒ fail closed.
- **Identity-proof layout byte-exactness:** the built preimage equals
  `identity_proof_v1.preimage.bin` and the signing hash equals
  `identity_proof_v1.signing_hash.bin`; a low-S signature with recovery id recovers the bound
  address.
- **Non-collision (AC#5):** identity first byte `0x19` ≠ `ordinary_tx_v1` `0xed` (and `<0xc0`)
  and ≠ `tron_transfer_v1` `0x0a`; keccak256 vs TRON sha256; assert the pinned 2D encoding has
  not assigned EIP-2718 type `0x19` (reference 2D PR #144).
- **Atomic keygen / capacity fail-closed** (carry from 7.2 AC#18/#5).
- **Roborev matrix/compact evidence recorded before merge (AC#7).**

## Cross-repo dependency

2D PR #144 (TASK-132.5 family) permanently reserves EIP-2718 transaction-type `0x19`. It is a
tracked blocking dependency for the AC#5 non-collision guarantee but does **not** block this
design task; production fund custody (gated by TASK-7.7) must not proceed until the 2D-side
reservation is merged.
