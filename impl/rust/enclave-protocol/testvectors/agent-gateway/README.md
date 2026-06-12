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
| `agent_keystore_genesis_v2.{sealed.bin,json}` | **TASK-7.7 5b-2d** frozen v2 genesis `pq-agent-keystore-v1` blob: a deterministic-nonce seal (`seal_keystore_with_nonce`) of a minimal valid genesis body (`structural_version=1`, `strict_recovery_counter=0`, no entries/counters) over the committed reference provisioning root + the agent placeholder measurement. Consumed by the `boot_agent_keystore` deterministic from-disk loader test (`tests/agent_keystore_boot_loader.rs`) + the in-source byte-exact freeze. Re-installable (`blob_len <= MAX_KEYSTORE_BLOB_SIZE`). **TEST KEYS ONLY.** Regen: `cargo test --features agent-gateway,lab-agent-keystore-from-file regen_agent_genesis_golden_vector -- --ignored --nocapture` (re-mint the `.json` sidecar in the same commit on any `format_version`/body-layout change). |

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
