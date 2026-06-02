# Permissionless BlockProducer Recovery via On-Chain Tickets

**Status**: Design proposal (integrated into TASK-1 ACs #13-15, DoD #8-9, Implementation Notes, and Plan as of 2026-06-05)

**Context**: Single active BlockProducer (2s target), reader/RPC nodes for queries, hot standby "под паром", public storage of encrypted TEE images for the custom minimal PQ signing service (2d-hsm TASK-1), anyone with image+launch material can instantiate in a matching TEE, register, and wait to become producer "на свои риски". Process must be fully automatic for decades of operation (no physical second factors like YubiKey).

## Core Requirements (from user, 2026-06-05)

- Право создавать recovery тикеты — permissionless (special tx inside 2D network).
- Catastrophic threshold: ~1 hour of no tip advance for 2s block production is "застрашный трешхолд". (Empirical: Solana 400ms slots had full outages of 4-19h historically; even shorter degradations cause thousands of missed slots. For 2s target, 1800 missed blocks is unambiguously catastrophic, not normal jitter.)
- Production model: 1 always-on producer + 1+ hot standbys under steam. Standby sends readiness tickets. Encrypted image public. Launch anywhere, register via ticket, become producer at own risk.
- If malicious producer emits invalid blocks / forged state transitions ("stay transition, которого на самом деле не было"), clients simply do not accept them.
- Network (genesis + recent finalized headers + on-chain recovery history) serves as the cryptographic second factor for the TEE signer.

## Proposed RecoveryTicket (concrete starting point for Phase 1)

Special tx or precompile call (recommend reserving a fixed 0x2D00... address or a small recovery contract in 2d-solidity).

```solidity
struct RecoveryTicket {
    uint64  nonce;
    bytes32 last_good_tip;           // tip the candidate observed as stalled
    uint64  observed_downtime_sec;
    bytes   tee_measurement;         // SEV-SNP measurement or Nitro PCRs of the signing service image
    bytes   pq_pubkey;               // ML-DSA/Dilithium (primary) pubkey for future block production
    bytes   attestation;             // full remote attestation document binding measurement + pq_pubkey
    bytes   sig_by_pq_key;           // proves the private key lives inside this exact TEE
}
```

On-chain validation (precompile/contract):
- Current on-chain tip has not advanced past `last_good_tip` for > threshold (3600s + grace, e.g. 120s).
- Attestation validates against trusted root(s); measurement matches published expected value for the release.
- `sig_by_pq_key` recovers to `pq_pubkey`.
- (Future) `pq_pubkey` not blacklisted.

On finality (or short window): `current_authorized_producer` storage updated. Reader nodes / clients now require this key for new blocks.

## Hot Standby "под паром" Flow

- Standby runs the exact same public encrypted TEE image.
- Submits periodic lightweight `ReadinessRegistration` (proves live TEE + measurement + key possession via attestation + sig, without requiring downtime).
- Multiple candidates can advertise safely.
- When primary stalls > threshold, any party (including a ready standby) submits a full `RecoveryTicket`. First valid one (or policy-chosen) activates.

## Client / Reader Node Safety Net (rejects malicious producer)

Every honest reader/RPC node and client/light client **must** enforce on every block:

1. Block (or its canonical header/root) is signed by the *current* `current_authorized_producer.pq_pubkey` (from on-chain recovery history + genesis bootstrap).
2. Full state transition replay: execute txs → recompute state_root / tx_root / block_hash → exact match to claimed values (existing `Chain.Verifier.Executor` logic).
3. Parent hash continuity, number gap check, timestamp monotonicity (TASK-107 already does part of this).
4. No forged "stay" or invalid transition: if claimed root does not match honest execution of the included txs (or txs are silently dropped while root pretends "nothing happened"), the block is rejected.

Result: even a producer that legitimately obtained a recovery ticket via the permissionless path cannot force honest nodes to accept invalid state. The chain view of honest participants simply ignores the bad blocks and waits for (or triggers) the next recovery ticket from a correct hot standby that continues from the last *accepted* good state.

This is the "clients will not accept some risks" mechanism.

## Network as Cryptographic Second Factor (inside the TEE)

The custom minimal PQ signing service (TASK-1) itself must treat the real network as a second factor:

- Enclave contains minimal light client / header chain verifier (genesis + trusted checkpoints + logic to follow recovery history).
- At unsealing / arming and periodically before signing, the host feeds recent finalized headers + short proofs over an attested channel (vsock).
- Enclave only enables the sealed PQ BlockProducer key for production signatures after it has verified a consistent view extending from genesis (or checkpoint) to a recent tip signed under the then-authorized producer key.
- On mismatch or stale view: enclave refuses to sign.

This prevents a fully compromised host from:
- Making the enclave sign on a fake fork.
- Reactivating a long-offline zombie after the real network has moved on.
- Bypassing the permissionless ticket discipline.

Combined with the on-chain ticket + public encrypted image + client-side rejection, this gives a fully automatic, permissionless, decades-viable BlockProducer authorization model without physical tokens.

## Integration Points with Existing 2d

- **Producer namespace path** (doc-3): today BP host → direct low-latency to `producer` ns in NetHSM (fixed shape, no OPA/Vault gate). Future: same direct path to the TEE signing service instance (still low latency, still no heavy policy gate for the fixed digest case).
- Reader/RPC nodes: already run verifier logic; will additionally check the authorized producer key from on-chain state.
- Bridge paths: continue with existing paranoid multi-layer (or migrate bridge keys to separate TEE instances later).
- Cross-links: 2d `backlog/docs/doc-3`, TASK-62 (SEV-SNP rehearsal), 2d-hsm TASK-1.

## Risks & Mitigations

- Malicious actor obtains image + launches TEE + gets ticket → clients reject bad blocks; network issues corrective ticket.
- Ticket spam → gas + threshold gate + optional bond.
- Attestation root / TEE 0-day (AMD PSP etc.) → same residual risk as current doc-3 SEV-SNP posture; mitigated by reproducible builds, published measurements, future multi-vendor TEEs.
- "Stay transition" forgery → closed by mandatory client-side replay (already implemented in verifier executor).

## Next Steps (tracked in TASK-1)

- Phase 0/1: finalize ticket format + precompile spec + reader policy + enclave freshness verifier design.
- Phase 1 threat model: "adversary who wins a recovery ticket fairly".
- Phase 4 runbook: operator procedures for public-image hot standby, recovery events, client/ explorer updates for authorized producer history.

This design directly implements the user's stated expectations for a permissionless, automatic, network-as-second-factor recovery model for the single BlockProducer.

## Using the Same Mechanism for Hard Forks

The ticket + TEE measurement + permissionless submission + client-enforced activation pattern is a powerful primitive. It can be reused (with small generalizations) for coordinating **hard forks** in a much more decentralized, verifiable, and automatic way than traditional social + release-gate coordination.

### Why this mechanism maps naturally to hard forks

Current 2D upgrades (see Mainnet Release Gate TASK-26.6.3, halt_consensus, governance precompiles, and coordinated migrations) are largely:
- Off-chain coordination + manual operator actions.
- Safety gates that check chain tip / placeholder governors.
- Bridge-specific halts recorded on-chain via precompiles.

A hard fork (change to state transition rules, precompile semantics, block format, or the producer software itself) currently requires significant human orchestration to decide "when everyone has upgraded" and to avoid chainsplits.

The recovery model already gives us:
- Permissionless submission of activation signals (anyone can post a ticket).
- Cryptographic proof that a real TEE is running a *specific* software image (via remote attestation measurement).
- On-chain recording of "from now on, this key / this code is authorized".
- Strong client/reader node enforcement (reject anything that doesn't match the on-chain record).
- The "network as second factor" inside the TEE itself.

These properties are extremely valuable for hard forks.

### Proposed generalization: typed Authorization Tickets

Instead of only `ProducerRecovery`, introduce (or extend the ticket to support) a `HardForkActivation` action.

Example extended ticket (illustrative):

```solidity
struct AuthorizationTicket {
    uint8   ticket_type;          // 0 = ProducerRecovery, 1 = HardForkActivation, ...
    uint64  nonce;
    bytes32 context_hash;         // for recovery: last_good_tip; for fork: fork_spec_hash or parent block
    uint64  activation_height;    // or 0 = immediate after finality
    bytes   new_measurement;      // TEE measurement of the *new* code (signer + executor + relevant precompiles)
    bytes   pq_pubkey;            // the producer key that will sign under the new rules (can be same or rotated)
    bytes   attestation;          // proves this TEE is running exactly the code with `new_measurement`
    bytes   sig_by_pq_key;
    // optional: governance_proposal_id that authorized this fork measurement
}
```

On-chain effect for a `HardForkActivation` ticket:
- Records that "starting at `activation_height`, the canonical chain rules + expected producer code measurement are version X with measurement M".
- May also atomically update (or require) the current `authorized_producer` to be one whose ticket referenced this new measurement.

### How activation and enforcement would work

1. **Pre-fork preparation**
   - Operators build the new hard-fork binary/image (new Elixir release + updated 2d-hsm signing service).
   - They publish the encrypted image + the expected TEE measurement(s) (reproducible builds are mandatory).
   - Hot standbys can already be running the *new* image and submitting "Readiness for Fork X" tickets (proving they have the correct new measurement live in a real TEE).

2. **Signaling / triggering the fork**
   - A successful `HardForkActivation` ticket (submitted permissionlessly by anyone running the new code) finalizes on-chain.
   - This can be triggered after a governance vote (that emits the blessed `new_measurement` and `fork_spec_hash`), or via an emergency path using the existing halt/governance machinery.
   - The ticket itself can reference a governance proposal for legitimacy.

3. **Client / Reader node behavior (the enforcement layer)**
   - Nodes that understand the fork watch for finalized `HardForkActivation` tickets.
   - Before `activation_height`: accept old rules + old measurement.
   - At/after `activation_height`: 
     - Only accept blocks whose producer can prove it was running the declared new measurement (the activation ticket + subsequent attestations or header extensions).
     - Reject blocks that follow old rules or come from a producer whose measurement doesn't match the activated one.
   - Old clients that never learned about the fork simply stop syncing or surface a clear "unrecognized fork" error.

4. **Inside the new TEE (network as second factor, strengthened)**
   - The updated signing service (and potentially more of the producer logic) running under the *new* measurement will refuse to produce blocks under the new rules until it has verified on-chain that a valid `HardForkActivation` ticket for *exactly its own measurement* has been recorded and finalized.
   - This closes the "zombie new code" and "accidental chainsplit" risks beautifully.

### Concrete benefits of reusing the mechanism

- **Much less social coordination** — the on-chain ticket + measurement becomes the source of truth for "the fork has activated".
- **Stronger verifiability** — anyone (including light clients, bridges, explorers, auditors) can cryptographically check that the live producer is running the exact code that was supposed to activate at that height.
- **Permissionless participation** — operators who correctly built and attested the new image can help push the fork through by submitting tickets, even if they are not the current primary producer.
- **Graceful + automatic** — hot standbys pre-deployed with the new image can take over production under the new rules with minimal manual intervention.
- **Unified primitive** — recovery from producer failure and activation of a planned (or emergency) hard fork become two instances of the same "authorized state transition" pattern.

### New questions and tensions this raises (to be resolved in design)

- **Who blesses the "official" new_measurement for a fork?**
  - Option A: Governance proposal (on-chain vote) that explicitly emits the expected measurement hash + fork spec.
  - Option B: The first valid ticket from a TEE running new code that also carries a sufficient governance signature or multi-sig from known operators.
  - Option C: A hybrid (governance proposes, permissionless tickets from correct measurements ratify/activate).

- **Conflicting or malicious fork proposals** — what if someone builds a slightly different "new" image and tries to activate a controversial fork? Client-side policy + governance allowlisting of acceptable measurements will be necessary.

- **Timing and activation height** — should forks always go through a planned "halt window" (using existing BridgeHalt or a new chain-wide halt), or can they be seamless (old producer stops at height N-1, new measurement producer starts at N)?

- **Measurement granularity** — do we measure only the 2d-hsm signing service, or the entire producer + executor + precompile logic? (The more we measure, the stronger the guarantee, but the harder reproducible builds become.)

- **Interaction with existing release gates and halt mechanisms** — the new ticket system should probably be able to trigger or be triggered by the current halt_consensus / CircuitState machinery.

- **Client upgrade story** — light clients and external verifiers must be able to discover and validate the new measurements without a full node. This may require embedding a small set of "blessed fork descriptors" or a light governance reader.

### Suggested next steps

- Add a dedicated subsection or separate design note extending this document.
- In TASK-1 Phase 0/1, treat hard-fork support as a stretch but architecturally important requirement (the ticket format and TEE claims should be forward-compatible with `ticket_type` or `action`).
- Create a small follow-up task (or section in an existing 2d governance/halt task) to map the ticket mechanism onto the current `halt_consensus` + governance precompile surface.
- Prototype (on paper or in a testnet branch) what a minimal `HardForkActivation` ticket would look like and what the reader node acceptance rule would become.

This direction turns the recovery mechanism from "a way to survive producer death" into a more general **"permissionless, TEE-attested, client-enforced state transition authorization"** primitive — which is exactly the kind of thing that makes long-lived, high-value chains more robust.

The same core ideas (public encrypted images, hot standbys, network-as-second-factor inside the enclave, client rejection of invalid transitions) apply almost unchanged.

**Detailed technical specification** (unified `AuthorizationTicket` struct, full Solidity ABI, proposed precompile address `0x2D00...A0`, submission methods, storage layout, reader verification rules, and exact impact on the 2d-hsm TEE service) is available in:

→ `backlog/docs/authorization-tickets-precompile-spec-draft.md` (v0.1)

