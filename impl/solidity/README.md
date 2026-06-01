# Canonical Hash Verification (Solidity side)

This folder contains the **source of truth** for the canonical `AuthorizationTicket` preimage used in 2D.

The goal is that `compute_canonical_ticket_hash` in Rust produces **bit-identical** results to:

```solidity
keccak256(abi.encode(ticketType, nonce, contextHash, activationHeight, newMeasurement, pqPubkey, forkSpecHash, newHeaderVersion))
```

## One-time setup (required for automated tests)

```bash
cd impl/solidity
forge install foundry-rs/forge-std --no-commit
```

After running this once, the Rust tests will be able to automatically call Forge and verify that the Rust implementation matches the on-chain encoding.

## How automated verification works

- Rust tests write a temporary `input.json` with the ticket fields.
- They run `forge script CanonicalTicketHash.s.sol` (from this directory) with `INPUT_JSON` and `OUTPUT_JSON` environment variables.
- The script reads the input, computes the hash using the real `abi.encode` + `keccak256`, and writes the result to `output.json`.
- Rust reads the result and asserts equality with its own computation.

If Forge or the dependencies are not set up, the cross-check tests gracefully skip with a helpful message.

## Manual verification

You can also compute hashes manually:

```bash
forge script CanonicalTicketHash.s.sol --sig "hardForkHash(uint8,uint64,bytes32,uint64,bytes,bytes,bytes32,uint32)" \
  1 1234 0x... 10000000 0x... 0x... 0x... 2
```

This makes the on-chain encoding the single source of truth and prevents divergence between the enclave and the precompile.