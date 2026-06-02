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

Use the JSON-driven `run()` entrypoint (same as automated tests):

```bash
cd impl/solidity
cat > /tmp/ticket-input.json <<'EOF'
{
  "ticketType": 1,
  "nonce": 1234,
  "contextHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
  "activationHeight": 10000000,
  "newMeasurement": "0x",
  "pqPubkey": "0x",
  "forkSpecHash": "0x00000000000000000000000000000000000000000000000000000000000000ab",
  "newHeaderVersion": 2
}
EOF
INPUT_JSON=/tmp/ticket-input.json OUTPUT_JSON=/tmp/ticket-output.json \
  forge script CanonicalTicketHash.s.sol -vv
cat /tmp/ticket-output.json
```

This makes the on-chain encoding the single source of truth and prevents divergence between the enclave and the precompile.