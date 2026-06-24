# Authorization Tickets Precompile — Detailed Draft Spec (v0.1)

**Status**: Draft for discussion (2026-06-05)  
**Scope**: 2D chain only (for now)  
**Location**: Temporarily maintained inside `2d-hsm` repo under `backlog/docs/`.  
**Goal**: Define a unified, extensible, permissionless on-chain mechanism for:
- BlockProducer recovery / key rotation
- Hard fork activation / code measurement transitions

Later decision: keep as 2d-hsm spec, move to main 2d repo, or extract into a separate "2d-authorization" repo.

## 1. Motivation & Design Principles

The mechanism must satisfy the following (directly from requirements):

1. **Permissionless activation** — anyone who can run a correctly measured TEE with the right image can submit a ticket.
2. **Strong TEE binding** — submission proves that the private key lives inside a genuine TEE running a specific measurement.
3. **Client-enforced safety** — readers, verifiers, light clients, and external consumers must be able to reject invalid transitions (including forged state or unauthorized producers).
4. **Network as second factor** — the TEE service itself can require on-chain evidence of the ticket before arming the key for production.
5. **Unified primitive** — the same ticket format and precompile should serve both producer recovery and hard fork activation (and future actions).
6. **Minimal blast radius** — submission is cheap/permissionless; heavy verification and policy enforcement lives on the reader/client side.
7. **ABI first** — interface is defined with a proper Solidity-compatible ABI for clarity, tooling, and future cross-chain or governance integration.

## 2. High-Level Architecture

- **Submission**: Special transaction type **or** direct call to a fixed precompile address.
- **Precompile address** (proposed): `0x2D000000000000000000000000000000000000A0`
- **On-chain effect**: Records authorized state transitions (producer key + optional code measurement + fork version).
- **Enforcement**: Off-precompile (reader nodes, verifiers, light clients, explorers, bridges). The precompile only validates the ticket cryptographically and records it.
- **TEE service role** (2d-hsm): Generates the ticket payload, produces the attestation + signature, and (for network-as-second-factor) can verify recent on-chain state before signing blocks.

## 3. Ticket Types (v1 behavior)

```solidity
enum TicketType {
    PRODUCER_RECOVERY      = 0,
    HARD_FORK_ACTIVATION   = 1
}
```

**Important v1 distinction** (per latest requirements):

- `PRODUCER_RECOVERY`: Relatively permissionless. Can be submitted by a hot standby after catastrophic downtime (with proper TEE proof). Does **not** require being the current producer.
- `HARD_FORK_ACTIVATION` (v1): **Not permissionless**. In the first version there is no governance. A hard fork is signaled by the **current active Block Producer** sending a message/ticket. Only the current authorized `pqPubkey` can successfully submit a `HARD_FORK_ACTIVATION` ticket. This is the on-chain equivalent of "the block producers are announcing the upcoming fork".

## 4. Unified AuthorizationTicket Structure

```solidity
struct AuthorizationTicket {
    // === Header ===
    uint8    ticketType;           // TicketType enum
    uint64   nonce;                // Per-submitter or global sequence (anti-replay)

    // === Context (interpretation depends on ticketType) ===
    bytes32  contextHash;          // For RECOVERY: last_good_tip_hash
                                   // For HARD_FORK: keccak256(forkSpecHash || previousMeasurement ||
                                   //                 activationHeight || producerEpochBinding)
                                   // where producerEpochBinding = keccak256(pqPubkey || currentProducerActivatedAtHeight)
                                   // — binds the ticket to the SPECIFIC producer epoch that authorized it,
                                   // preventing withheld-ticket replay across a rotation A → B → A (TASK-31).

    uint64   activationHeight;     // For PRODUCER_RECOVERY: height from which the new producer is authorized
                                   // For HARD_FORK_ACTIVATION: **must** be a specific future block number (like in Ethereum).
                                   // The fork rules + newMeasurement become mandatory starting from this exact block.
                                   // 0 is invalid for hard forks in v1.

    // === Identity & Proof ===
    bytes    newMeasurement;       // 32-64 bytes: SEV-SNP measurement or Nitro PCR composite
                                   // For recovery: measurement of the signing service that holds the key
                                   // For hard fork: measurement of the *new* relevant producer code

    bytes    pqPubkey;             // ML-DSA-65 public key (1952 bytes) — hot path / 2d-hsm TEE (see vsock spec §2.1)

    bytes    attestation;          // Full remote attestation document binding newMeasurement + pqPubkey

    bytes    signature;            // ML-DSA-65 signature (3309 bytes) over canonical ticketHash by pqPrivkey

    // === Metadata ===
    bytes32  forkSpecHash;         // For HARD_FORK only: hash of the fork specification document / EIPs / changes.
                                   // For RECOVERY: set to 0x00...
    uint32   newHeaderVersion;     // Header version that must be used starting at activationHeight for HARD_FORK.
                                   // For RECOVERY: set to 0.
    uint256  bond;                 // Reserved for future anti-spam. Must be 0 in v1.
}
```

**Canonical Signed Payload (normative – single source of truth)**

The value that the enclave signs (`ticketHash`) **must** be computed as:

```solidity
bytes32 ticketHash = keccak256(
    abi.encode(
        ticketType,
        nonce,
        contextHash,
        activationHeight,
        newMeasurement,
        pqPubkey,
        forkSpecHash,
        newHeaderVersion
    )
);
```

This is the **definitive** canonical preimage for all `AuthorizationTicket` signatures (both Recovery and Hard-Fork).

- Use `abi.encode` (typed, non-malleable). Never use `abi.encodePacked` for this hash.
- `governanceRef` and `bond` are **not** part of the signed preimage.
- For RECOVERY tickets (`ticketType == 0`): `forkSpecHash` and `newHeaderVersion` are set to 0.
- For HARD_FORK_ACTIVATION (`ticketType == 1`): both fields must be populated and are part of the signed preimage.

The on-chain precompile **must** re-compute the hash using exactly this `abi.encode` expression. The enclave **must** use the identical preimage construction. Any divergence between the enclave and the precompile is a HIGH severity bug.

This definition supersedes all previous "recommended" wording and is now the binding contract for implementation.

## 5. Precompile Interface (Solidity ABI)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAuthorizationTickets {
    /// @notice Submit a new AuthorizationTicket. Permissionless.
    /// @dev Reverts with specific errors on validation failure.
    ///      Emits `TicketSubmitted` on success.
    function submitTicket(AuthorizationTicket calldata ticket) external;

    /// @notice Returns the currently active producer authorization.
    function getCurrentProducer() external view
        returns (bytes memory pqPubkey, bytes memory measurement, uint64 activatedAtHeight);

    /// @notice Returns the active hard fork (if any) at or after the given height.
    function getActiveForkAt(uint64 height) external view
        returns (
            bytes32 forkSpecHash,
            bytes memory codeMeasurement,
            uint64 activationHeight,
            uint32 newHeaderVersion
        );

    /// @notice Check if a specific ticket hash has been accepted.
    function isTicketAccepted(bytes32 ticketHash) external view returns (bool);

    // Events
    event TicketSubmitted(
        bytes32 indexed ticketHash,
        uint8 ticketType,
        bytes indexed pqPubkey,
        bytes newMeasurement,
        uint64 activationHeight,
        uint32 newHeaderVersion
    );

    event ProducerAuthorized(
        bytes indexed pqPubkey,
        bytes measurement,
        uint64 activatedAtHeight,
        bytes32 ticketHash
    );

    event HardForkActivated(
        bytes32 indexed forkSpecHash,
        bytes codeMeasurement,
        uint64 activationHeight,
        uint32 newHeaderVersion,
        bytes32 ticketHash
    );
}
```

**Indexer / verifier note:** `newHeaderVersion` is part of the signed `ticketHash` and **must** be observable on-chain. `TicketSubmitted` and `HardForkActivated` emit it for hard-fork tickets; `getActiveForkAt` returns it so light clients and header builders do not rely on off-chain metadata alone.

### Proposed Precompile Address

`0x2D000000000000000000000000000000000000A0`

(This follows the existing `0x2D00...` pattern used for BridgeHalt etc.)

### Error Selectors (proposed)

```solidity
error InvalidTicketType();
error NonceAlreadyUsed(uint64 nonce);
error DowntimeThresholdNotMet(uint64 observed, uint64 required);
error AttestationVerificationFailed();
error SignatureVerificationFailed();
error MeasurementNotWhitelisted(bytes measurement); // future
error ActivationHeightInPast(uint64 height);
error BondInsufficient(uint256 provided, uint256 required);
```

## 6. Submission Methods (for 2D chain)

### Option A — Special Transaction Type (recommended for v1)

Introduce a new transaction kind (e.g. `kind = "authorization_ticket"` or a new tx type byte).

Payload (RLP or custom encoding):
- `AuthorizationTicket` fields (without the outer struct overhead)
- Signature is already inside the struct.

Advantages:
- Clean separation from normal user transactions.
- Easier for mempool / throttle logic.
- Can have its own gas schedule (very cheap — mostly signature + attestation checks).

### Option B — Direct Precompile Call

If 2D ever exposes a more contract-like calling convention, the same ABI above can be used directly.

For now we treat Option A as primary, with the precompile acting as the canonical validator + state writer.

## 7. On-Chain Storage Layout (Elixir side sketch)

```elixir
# state.authorization_tickets
%{
  current_producer: %{
    pq_pubkey: binary(),
    measurement: binary(),
    activated_at_height: integer(),
    activated_by_ticket: binary()  # ticket hash
  },

  active_forks: %{
    # height => {fork_spec_hash, code_measurement, activation_height, ticket_hash}
  },

  accepted_tickets: MapSet of ticket hashes (or a more efficient structure)
}
```

The precompile logic (in Elixir) must be **deterministic** and replayable by verifiers.

## 8. Verification Rules (Reader Nodes, Verifiers, Clients) — v1

### Core Rule for Hard Fork tickets (v1)

In the first version, a `HARD_FORK_ACTIVATION` ticket is only accepted by the precompile if:

- The `signature` recovers to the `pqPubkey` that is **currently** recorded as the active producer (i.e. the ticket must be signed by the current Block Producer).
- `activationHeight` is strictly greater than the current block height (future block scheduling, Ethereum style).
- `forkSpecHash` is non-zero.
- `newMeasurement` is different from the current one.
- `contextHash` MUST bind to the current producer epoch via `producerEpochBinding`
  (see §4 field definition). The on-chain precompile/contract MUST recompute the
  expected contextHash from the CURRENT producer's `(pqPubkey, activatedAtHeight)`
  and reject any ticket whose contextHash does not match. This is the **PRIMARY
  enforcement** against withheld-ticket replay across a rotation A→B→A: a ticket
  signed when A was active at height H1 carries `producerEpochBinding =
  keccak256(A_pqPubkey, H1)`; after rotation A→B→A the current producer is A at
  height H3, so the recomputed binding is `keccak256(A_pqPubkey, H3)` which differs
  from H1's → mismatch → rejected. Without this recompute, the replay is NOT
  prevented: the Solidity `_producerEpochId` storage scoping (line 439) keys off
  the SUBMISSION-TIME producer epoch (not the signing-time epoch), so a withheld
  epoch-1 ticket submitted fresh in epoch-3 passes the producer-key check (same
  pqPubkey) and is stored + activated under epoch-3.
  **⚠ NOT YET IMPLEMENTED:** the landed `RecoveryTicket.sol` (PR #18) treats
  contextHash as opaque bytes32 (only checks non-zero at line 281). The contextHash
  recomputation MUST be added to `_submitHardForkActivation` in 2d-solidity
  (tracked in 2d-solidity TASK-10). TASK-31 AC#4 (replay scenario A→B→A covered)
  is NOT met until this lands.

This means hard forks in v1 are **producer-driven scheduled announcements**, not fully permissionless events.

### General Verification Rules

1. **Producer Key Check**
   - Blocks must be signed by the active `pqPubkey` according to the latest applicable `PRODUCER_RECOVERY` or `HARD_FORK_ACTIVATION` ticket.

2. **Hard Fork Enforcement (scheduled block + header versioning)**
   - The `HARD_FORK_ACTIVATION` ticket (signed by the current producer) declares the exact `activationHeight`, `newMeasurement`, and `forkSpecHash`.
   - **Recommended mechanism**: Introduce a small integer `version` field in the 2D block header + DB (e.g. `u32` or `smallint`).

   Current block identity (from `finalize_block`):
   ```elixir
   hash = keccak256( <<number::64>> <> parent_hash <> <<timestamp::64>> <> tx_root <> state_root )
   ```

   Proposed change for hard forks:
   - Add `version: integer` to the block record and include it in the hash calculation.
   - Genesis / current: `version = 1`
   - In `HARD_FORK_ACTIVATION` ticket the producer declares the `new_header_version` (e.g. 2).
   - From `activationHeight` onward, every block **must** have `header.version == new_header_version` and be produced under the declared `newMeasurement`.

   This makes the fork extremely visible at the wire/protocol level. Non-upgraded nodes will immediately see blocks with version 2 (or whatever) and can reject them early, before even trying to execute state transitions. This matches exactly what you described: they "просто останутся на каком-то блоке и дальше не будут идти".

   This is very close to Ethereum's model (activation at exact block number) + Cosmos-style explicit versioning for clean detection.

3. **Code Measurement Proof**
   - After the scheduled hard fork block, the producer should be able to prove (via attestation attached to blocks or periodic registration) that it is running the new `newMeasurement`. The combination of (new header version + correct TEE measurement + correct state root) gives very strong guarantees.

4. **State Transition Validity**
   - Full replay + fork-specific rule changes must succeed.

5. **Invalid Fork / Measurement Protection**
   - If after the scheduled block a producer uses the old measurement or produces state roots inconsistent with the new rules → the block is rejected by honest nodes.

This model is very close to how Ethereum schedules hard forks (e.g. "Shanghai at block X") while still using the TEE measurement as the cryptographic root of trust for "this is the real new code".

## 9. TEE Signing Service Requirements (2d-hsm impact)

The custom minimal PQ signing service must be able to:

- Generate and sign `AuthorizationTicket` payloads (for both types).
- Include fresh remote attestation in the ticket.
- (For network second factor) Accept a recent on-chain state snapshot (or light proof) over an attested channel (vsock) and refuse to arm the key until it sees its own activation ticket recorded.
- For hard fork mode: expose the new code measurement it was built with.

This directly influences the vsock API and the set of claims the service must support.

## 10. Anti-Spam & Economic Considerations (v1 lean)

- Base gas for ticket submission should be low (mostly crypto verification).
- Optional small bond (burned on invalid tickets) can be added later.
- Rate limiting per address or per measurement can be added via governance or reader policy.
- Malicious tickets are mostly harmless because clients ignore them unless they pass all checks.

## 11. Open Questions & Decisions Needed

1. **Encoding on the wire** — RLP vs a simpler custom format for the special tx?
2. **Attestation format** — Full report every time, or hash + registry of known good measurements?
3. **Governance integration** — Should `governanceRef` be mandatory for `HARD_FORK_ACTIVATION` in production?
4. **Measurement registry** — Do we want an on-chain allowlist of "known good" measurements for forks, or fully open?
5. **Activation height semantics** — Can a ticket force an immediate fork, or must there always be a planned height + possible halt window?
6. **Multiple simultaneous forks** — Do we allow overlapping activations or enforce strict linear history?
7. **Light client support** — What is the minimal proof size a light client needs to track the current authorized producer + active fork?

## 12. Next Steps (while keeping everything inside 2d-hsm)

- Refine this spec based on feedback.
- Add concrete RLP / transaction encoding examples.
- Write a small reference implementation sketch (Elixir precompile skeleton + test vectors).
- Update the 2d-hsm TASK-1 Notes with pointers to this document.
- Decide later (after a few iterations) whether to:
  - Keep the spec + reference code inside 2d-hsm,
  - Move the precompile implementation into the main 2d monorepo, or
  - Extract a standalone "2d-authorization-tickets" specification repo.

---

**Version history**

- v0.1 (2026-06-05) — Initial detailed draft after discussion of permissionless recovery + hard fork reuse.

This document is intentionally kept inside the 2d-hsm context for now, as requested.