# Agent Gateway golden vectors (TASK-7.1)

Frozen, in-repo test vectors that pin the **2D ordinary-transaction preimage**,
the **TRON-protobuf preimage** (reserved surface), and the **EIP-191 identity-proof
preimage** for the Agent Gateway secp256k1 signer. Consumed by TASK-7.3 (identity /
non-collision proof) and TASK-7.4 (transfer/faucet signing), and referenced by the
Agent Gateway section of `backlog/docs/vsock-api-wire-format-spec-draft.md`.

## Provenance (authoritative)

`gen_agent_vectors.exs` generates these from **2D's own crypto** (`Chain.Crypto`,
`Chain.Crypto.Envelope`-equivalent RLP, `Chain.Tron.Protobuf`, `Chain.Tron.Address`,
`ExSecp256k1`), so the eth and TRON vectors match exactly what the live 2D verifier
accepts. Each signing vector is **self-checked by signature recovery** at generation
time (eth via `ExSecp256k1.recover`, TRON via `Chain.Crypto.recover_tron_sender`),
and every signature is asserted **low-S** (`s <= n/2`).

Regenerate (from the sibling `../2d` checkout, deps already compiled). These vectors were
generated against 2D commit `93183ca` ("Harden agent signer custody grants"); regenerate
against that revision for byte-identical output:

```sh
cd ../2d && mix run --no-start \
  /path/to/2d-hsm/impl/rust/enclave-protocol/testvectors/agent-gateway/gen_agent_vectors.exs
```

> **TEST KEYS ONLY.** `keys.json` uses well-known Anvil dev keys (acct0 / acct1).
> Never production. They exist only to make the preimages and addresses reproducible.

## Files

| File | What it pins |
|------|--------------|
| `ordinary_tx_v1.{json,preimage.bin,signing_hash.bin,signed.bin}` | eth EIP-155 ordinary transfer, `chain_id=11565`: unsigned RLP preimage, `keccak256` signing hash, low-S secp256k1 signature (`v=chain_id*2+35+rid`), signed RLP, recovered `from`. **This is the AC#13 frozen artifact for `AGENT_K1_SIGN_TRANSFER`.** |
| `tron_transfer_v1.{json,raw_data.bin,txid.bin}` | **RESERVED** TRON-surface vector: protobuf `TransferContract` `raw_data`, `sha256` txid, 65-byte `r‖s‖v`. For the AC#15 3-way domain-separation proof and a future TRON-signing opcode (eth-MVP + reserve-TRON decision). |
| `identity_proof_v1.{json,preimage.bin,signing_hash.bin}` | EIP-191-style identity-proof preimage layout (`0x19 ‖ len(label) ‖ label ‖ chain_id ‖ len(env_id) ‖ env_id ‖ key_ref ‖ pubkey ‖ address ‖ verifier_nonce`; variable-length fields are 1-byte length-prefixed) and its `keccak256` hash. Layout owned by TASK-7.1 AC#15; final non-collision proof owned by TASK-7.3. |
| `keys.json` | TEST-ONLY keypairs showing one unified secp256k1 account in **both** address encodings (eth `0x…` and TRON `T…`). |
| `domain_separation.json` | The 3-way disjointness witnesses (below). |
| `agent_keystore_genesis_v2.{sealed.bin,json}` | **TASK-7.7 5b-2d** frozen genesis `pq-agent-keystore-v1` blob (**now keystore_format_version 3** — TASK-15 15-2b added `FaucetState.cumulative_signing_budget`; the `_v2` in the filename is the historical fixture name, kept to avoid churning `include_bytes!` paths): a deterministic-nonce seal (`seal_keystore_with_nonce`) of a minimal valid genesis body (`structural_version=1`, `strict_recovery_counter=0`, no entries/counters) over the committed reference provisioning root + the agent placeholder measurement. Consumed by the `boot_agent_keystore` deterministic from-disk loader test (`tests/agent_keystore_boot_loader.rs`) + the in-source byte-exact freeze. Re-installable (`blob_len <= MAX_KEYSTORE_BLOB_SIZE`). **TEST KEYS ONLY.** Regen: `cargo test --features agent-gateway,lab-agent-keystore-from-file regen_agent_genesis_golden_vector -- --ignored --nocapture` (re-mint the `.json` sidecar in the same commit on any `format_version`/body-layout change). |
| `agent_keystore_smoke_v1.{sealed.bin,json}` | **TASK-7.7 5b-2c-iii** minted SMOKE keystore for the aya SNP live smoke (`lab_agent_smoke.rs`): like the genesis blob but `anchor_root` is derived from the public in-repo Ed25519 seed `[0x42; 32]` (`LAB_ANCHOR_TEST_SEED` — so the lab anchor stub can sign freshness responses the guest accepts and boot reaches `Ready`) and it carries ONE secp256k1 key entry (`key_ref=[0x11;32]`, public scalar `[0x77;32]` — so PUBLIC_IDENTITY returns a SUCCESS body; the zero-entry genesis stays the negative control). **TEST KEYS ONLY — both the anchor seed and the secp scalar are public constants in `lab_agent_smoke.rs`; no secrecy claim; the `lab-agent-smoke` feature is release-banned.** Regen (mints BOTH files): `cargo test --features agent-gateway,lab-agent-smoke regen_agent_smoke_golden_vector -- --ignored --nocapture`. |

## 0x40 wire vectors (TASK-22)

Byte-exact golden vectors for the **Agent Gateway `0x40` request/response wire format**, so the
downstream **2d** Elixir codec (`Chain.AgentGateway.SignerProtocol`, TASK-132.5.2) can validate its
CBOR encoder/decoder against the enclave — the authoritative producer of the canonical CBOR shape,
the §10.5 capability preimage, and the sealed response bodies. These catch Elixir↔Rust drift
(map ordering, integer minimal-encoding, `bstr`-vs-`uint`) at CI time instead of when a live
capability is rejected `0x40`/`0x43` *after* the host has already burned a monotonic counter slot.

Unlike the signing vectors above (minted from 2D's own crypto by `gen_agent_vectors.exs`), the `0x40`
vectors are minted **from the enclave's own canonical encoders** (the inverse direction), via `#[ignore]`
regen tests next to each producer, and frozen here. Each is byte-exact vs its committed `.bin` AND
re-validated against the live decoder/encoder, so a drift breaks CI.

### AC#1 — request envelopes (`req_*_v1.bin` + `request_envelopes_v1.json`)

Canonical int-keyed CBOR request envelope (keys 1..=7: `agent_version`, `opcode`, `command_domain`,
`request_id`, `capability`, `key_ref`, `payload`) for each **non-privileged** opcode. Each `.bin` is
proven to be ACCEPTED by the strict-canonical `decode_envelope` and decode to the documented fields;
the `request_envelopes_v1.json` index couples each blob's `sha256`/`len` + decoded fields + `blob_hex`.
**TEST VALUES ONLY** (addresses mirror `ordinary_tx_v1.json`; `key_ref` = `[0x11;32]`).

| File | Opcode | Keys present |
|------|--------|--------------|
| `req_public_identity_v1.bin` | 2 PUBLIC_IDENTITY | {1,2,3,4,6} (no cap, no payload) |
| `req_prove_identity_v1.bin` | 3 PROVE_IDENTITY | {1,2,3,4,6,7} (payload `{1: nonce32}`) |
| `req_sign_transfer_v1.bin` | 4 SIGN_TRANSFER | {1,2,3,4,6,7} (8-field EIP-155 payload) |
| `req_sign_faucet_dispense_v1.bin` | 5 SIGN_FAUCET_DISPENSE | {1,2,3,4,6,7} (8-field EIP-155 payload) |

These are **wire-shape (decode) vectors**: each is proven to be accepted by the strict-canonical
envelope decoder and to carry the documented field shape (incl. the 8-field EIP-155 payload, whose
key layout matches the live `handle_sign_transfer` / `handle_sign_faucet_dispense` decoders). They are
**not end-to-end dispatch-success fixtures** — a successful dispatch additionally needs the matching
keystore state (a stored key for `key_ref`, the sealed `chain_id`, the faucet allowlist/config) and the
relevant preview feature; absent those, a live enclave returns the appropriate §10.9 error rather than a
signed body (e.g. `0x42` KeyPurposeMismatch for an unknown/wrong-purpose key, or `0x45` NotConfigured for
a preview-gated op). (NB `key_ref` here is the lab-smoke fixture's `[0x11;32]`, so it is *not* a universal
"no such key" — what a given enclave returns depends on the installed keystore.) End-to-end response-body
vectors land in the later TASK-22 response slices.

The **cap-bearing** envelopes (`req_generate_keys_v1.bin`, `req_configure_set_limits_v1.bin` +
`cap_envelopes_v1.json`) carry a §10.5 capability at key 5 and NO key_ref. Each is byte-exact +
accepted by `decode_envelope`, and its embedded cap (key 5), re-encoded, **equals** the
corresponding `cap_full_*_v1.bin` (AC#2) — which is itself accepted by the live `verify_capability`,
so the envelope provably carries a valid capability. **TEST KEYS ONLY** (admin Ed25519 `[7;32]`;
env `env-prod-0`, chain 11565).

Regen (per group): `cargo test --features agent-gateway <mod>::regen_<...> -- --ignored --nocapture`
where `<mod>` is `golden_request_envelopes` / `golden_cap_envelopes` / `golden_response_bodies` /
`golden_negative_vectors` (in `agent_dispatch`) and `golden_capability_vectors` (in `agent_capability`);
commit the `.bin`s + the re-minted `*_v1.json` in the same commit.

### AC#2 — §10.5 capability (`cap_*_v1.bin` + `payload_binding_*_v1.bin` + `capability_vectors_v1.json`)

The Ed25519-signed **preimage** (`CAP_DOMAIN ‖ canonical-CBOR(keys 1..12)`) and the **full capability
map** (keys 1..13, incl. the signature), for GENERATE_KEYS (11-entry preimage, header `0xAB`) and
CONFIGURE_TREASURY `set_limits`(sub_op 0)/`reset`(sub_op 3) (12-entry, header `0xAC`) — pinning the
11-vs-12 header asymmetry. Plus the **`payload_binding`** derivation
(`keccak256(opcode ‖ [sub_op] ‖ request_id ‖ canonical-CBOR(params))`) for op 1 (no sub_op byte) and
op 6 sub_op 0 (sub_op byte) — pinning the sub_op-in-binding. **Each full map is ACCEPTED by the live
`verify_capability`** (admin `[7;32]` / recovery `[9;32]`), so a signer/encoder/authority-tier drift
breaks CI. The per-sub-op **authority tier** matters: sub-ops 0..=2 are admin-signed; sub-op 3
(`reset_lifetime_breaker`) is recovery-signed on the recovery authority's lane (see §10.7).

### AC#3 — response bodies (`resp_*_v1.bin` + `response_bodies_v1.json`)

PUBLIC_IDENTITY (6-key), SIGN_TRANSFER (7-key), SIGN_FAUCET_DISPENSE (8-key incl. sealed blob at key 8),
GENERATE_KEYS (`{1:[key maps], 2:blob}`), CONFIGURE_TREASURY (`{1:blob}`), and the §10.9 **AgentError**
body `{1:code, 2:reason}` for all 7 codes. Minted from the real encoders over fixed inputs (signed-tx
fields from `ordinary_tx_v1`, identity from `keys.json` via the real derivation); the sealed blob is the
already-frozen `agent_keystore_genesis_v2.sealed.bin` (opaque AEAD — a representative blob pins the
response SHAPE). Each success body's key 1 is NOT a bare int code, so it is distinguishable from an
error body.

### AC#4 — negatives (`neg_*_v1.bin` + `negative_vectors_v1.json`)

`{request bytes → expected §10.9 code}` pairs, each asserted via the real `dispatch_agent`: `0x40`
(unknown envelope key; runtime opcode carrying a capability), `0x41` (agent opcode on the producer
profile), `0x42` (key_ref not found), `0x43` (capability bad signature; non-contiguous counter), `0x45`
(GENERATE_KEYS with the anti-rollback binding absent). `0x44` (CapExceeded) / `0x46` (SealFailed) are
handler/preview-level and deferred. NB CONFIGURE_TREASURY currently **accepts + ignores** a stray
envelope key 6 (`key_ref`) — §10.7 specifies no key_ref, but the capability binding carries integrity
(TASK-20 residual; document-the-ignore until a strict-shape tightening makes it a `0x40` negative).

## 3-way domain separation (AC#15)

A single agent key must never be coerced across the three preimage domains. They are
disjoint **by construction**:

| Domain | First preimage byte | Hash |
|--------|---------------------|------|
| eth EIP-155 tx | `0xed` (RLP list, always `>= 0xc0`) | keccak256 |
| TRON tx | `0x0a` (protobuf field-1 tag) | sha256 |
| Identity proof | `0x19` (EIP-191 prefix) | keccak256 |

The three leading bytes are mutually distinct, **and** the TRON surface additionally
uses a different hash (`sha256` vs `keccak256`). The enclave always constructs each
preimage itself from semantic fields and never signs a caller-supplied digest, so a
request for one domain cannot yield a signature valid in another.

**Caveat (EIP-2718):** `0x19` is a legal EIP-2718 `TransactionType` (`0x00..0x7f`).
Structural disjointness from typed transactions therefore depends on the pinned
policy that **2D permanently reserves and never assigns transaction type `0x19`** —
tracked by a 2D-side acceptance criterion in the TASK-132.5 family, since the enclave
cannot enforce a 2D type assignment.
