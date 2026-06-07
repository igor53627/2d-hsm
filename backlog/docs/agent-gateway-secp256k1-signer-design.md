# Agent Gateway secp256k1 signer backend design

## Goal

Add a `2d-hsm` Agent Gateway backend for ordinary 2D secp256k1 transactions. The backend runs inside the TEE, owns agent faucet and transfer private keys, exports only encrypted backup blobs, and enforces key-purpose and command-capability policy even if the host-side caller is compromised.

The TEE boundary prevents key extraction, generic digest signing, producer-key reuse, and unauthorized privileged commands. It does not replace every Agent Gateway business rule: transfer-key destination/amount policy remains primarily an app/OPA responsibility unless a later task adds TEE-side per-agent limits.

This is the `2d-hsm` side of 2D `TASK-132.5`.

## Production role/profile isolation

`2d-hsm` can remain one repository and protocol family, but production Agent Gateway signing must not share a live signer role with Block Producer signing. The Agent Gateway backend runs as a dedicated role/profile, separate from any producer role/profile that owns ML-DSA block-production keys, AuthorizationTicket authority, producer arming state, or network-second-factor state.

Production deployments must provide separate logical signer instances, and preferably separate TEE processes/enclaves, for producer and Agent Gateway roles. At minimum the roles have separate listener configuration, sealed state roots, keystores, authority/trust roots, and provisioning capabilities. Agent Gateway commands are disabled in producer signer instances, and producer/AuthorizationTicket commands are disabled in Agent Gateway signer instances. Resource controls must ensure high-volume Agent Gateway keygen, backup export, identity proof, faucet, or transfer workloads cannot starve producer signing. Agent Gateway upgrades or reprovisioning must not force producer signer reprovisioning.

## Non-goals

- No PQ account transaction format.
- No changes to producer ML-DSA AuthorizationTicket signing.
- No reuse of producer arming or network-second-factor state for agent keys.
- No production deployment that stores producer and Agent Gateway keys in one shared sealed state or enables both command families in one signer role/profile.
- No generic unrestricted digest signing for agent keys.
- No plaintext private-key export.
- No production restore automation in the first implementation slice.

## Key purposes

The new persistent multi-key keystore introduced by TASK-7 holds Agent Gateway keys only. Every key in that keystore has explicit purpose metadata:

- `agent_faucet_treasury_k1`
- `agent_transfer_k1`

Existing producer ML-DSA and AuthorizationTicket custody remains in the current sealed-blob path and is not migrated by TASK-7. Agent commands fail closed when the key purpose does not match the command, and producer commands fail closed for agent key purposes. `producer_mldsa` and `authorization_ticket` may appear in tests or reject-list constants only to prove cross-command fail-closed behavior; they are not stored in the new agent keystore unless a later, explicitly reviewed producer-custody migration supersedes this non-goal.

## Protocol version and command set

The wire protocol must allocate versioned Agent Gateway commands instead of overloading existing producer commands:

- `AGENT_K1_GENERATE_KEYS`: create one or more enclave-assigned key refs for an allowed agent key purpose. Transfer keys are batch-generated as `agent_transfer_k1`; the faucet treasury key is generated as `agent_faucet_treasury_k1` through the same command with `count = 1` and a stronger provisioning capability.
- `AGENT_K1_PUBLIC_IDENTITY`: return public key, derived 2D address, key purpose, and backend metadata for one key ref.
- `AGENT_K1_PROVE_IDENTITY`: sign a fixed-domain structured challenge bound to the key ref and public key.
- `AGENT_K1_SIGN_TRANSFER`: sign a structured ordinary 2D transfer envelope for `agent_transfer_k1` keys.
- `AGENT_K1_SIGN_FAUCET_DISPENSE`: sign a structured faucet treasury dispense envelope for `agent_faucet_treasury_k1` keys with TEE-enforced maximum spend caps.
- `AGENT_K1_CONFIGURE_TREASURY`: install or update faucet treasury caps under a privileged administrative capability. Its sub-operations are `set_limits`, `refill_budget`, `raise_lifetime_breaker`, and `reset_lifetime_breaker`, each with an explicitly mapped capability tier in TASK-7.1.
- `AGENT_KEYSTORE_EXPORT_BACKUP`: export an encrypted backup blob for selected key refs or a batch id.
- `AGENT_KEYSTORE_RESTORE_BACKUP`: restore from an encrypted backup blob under an explicit recovery ceremony. This command can be implemented after export, but the blob format must reserve for it.

All commands include protocol version, command domain, request id, and key ref or batch id. Unknown versions and unknown commands fail closed. TASK-7.1 must amend `backlog/docs/vsock-api-wire-format-spec-draft.md` because its current scope says this service does not sign user transactions. Agent commands should live under the existing frame version with an inner agent-command version unless the vsock spec update explicitly chooses a frame-version bump.

The protocol must also define the role/profile gate. A producer-profile signer rejects every Agent Gateway command before touching agent command state, and an Agent Gateway-profile signer rejects producer and AuthorizationTicket commands before touching producer state. Mixed-role development fixtures are allowed only for local tests when both key sets are test-only and the fixture cannot be deployed as a production profile.

Command failures return structured, bounded error codes. The protocol must define which distinctions are safe to expose to the untrusted host (for example cap exceeded vs malformed request) and which are collapsed to avoid key-purpose, identity, or capability oracle leaks.

Privileged commands (`GENERATE_KEYS`, backup export, restore, and treasury configuration) require a TEE-verified administrative capability signed by a configured operator/provisioning authority; a host-side Vault lookup alone is not sufficient. The authority public key is installed during the measured provisioning/sealing ceremony and bound to sealed state. Capabilities include command, key purpose, key refs or batch/count, request id, chain id, environment identifier, target enclave id or explicit fleet-wide marker, command-specific payload hash or exact command parameters, and a monotonic counter in the capability's scope. The host cannot attach a valid capability for one treasury sub-operation or limit amount to a different request payload.

`environment_identifier` is an operator-assigned deployment string installed during measured provisioning and sealed with the chain id. It distinguishes environments that share a chain id or key authority, such as `mainnet`, `testnet`, `staging`, or a fleet-specific production identifier. Runtime requests and administrative capabilities must match the sealed value exactly; the host cannot choose it per request. TASK-7.1 owns the exact encoding and allowed-character rules, and TASK-7.2 owns sealed-state storage.

The counter space is scoped by `(authority, environment_identifier, scope_class, scope_target)`, where `scope_class` is either `fleet` or `enclave` and `scope_target` is the fleet id or target enclave id. Each scope accepts only the next contiguous counter (`incoming = highest + 1`) so the host cannot present later capabilities while skipping earlier ones. All privileged commands sharing a scope also share one strictly ordered counter stream; operator tooling must serialize capability issuance within that scope or deliberately choose narrower command-class scope targets in TASK-7.1. Because a single lost, delayed, or reordered capability in a shared stream wedges every command class in that scope, the recommended default is to narrow `scope_target` per command class (equivalently, fold `command_class` into the counter tuple) so a stalled or withheld capability for one command cannot deny unrelated administrative operations; TASK-7.1 AC#18 owns this split. Fleet-wide and per-enclave streams do not share counters. Contiguity does not force an untrusted host to deliver a capability at all; operator runbooks must treat withholding as a residual availability/control risk. Expiry timestamps and unbounded nonce sets are not used for replay protection because enclave time is host-controlled and nonce storage can be exhausted.

A recovery/quorum capability can resynchronize a wedged counter scope and must be audited, but it must not be replayable to roll a scope backward. The MVP may define quorum as one higher-tier recovery authority key; a later threshold scheme can replace it without weakening command semantics. Any counter-resync command either sets the target counter strictly greater than the enclave's highest known counter for that scope, or is itself sequenced by an independent strict recovery counter that cannot be replayed.

Financial budget mutations are stricter than ordinary fleet administration. `AGENT_K1_CONFIGURE_TREASURY`, treasury refill, lifetime-breaker changes, and any command that raises or resets spend authority must be bound to a specific target enclave id unless the design also installs a global remote monotonic ledger shared by every restored clone of the faucet key. Fleet-wide markers are allowed for non-financial administrative scopes only; they must not multiply a single on-chain treasury key's spend budget across cloned TEEs.

The MVP supports one active `agent_faucet_treasury_k1` key per sealed agent keystore. A second faucet-treasury key generation request fails closed unless a later reviewed rotation protocol is active. Treasury rotation must specify whether spend counters are global across treasury keys or migrate to the replacement key; counters must never reset to zero merely because a new treasury key is generated. TASK-7.3 owns duplicate-treasury-key rejection, and TASK-7.2/TASK-7.4 own any reviewed rotation counter semantics.

## Structured transfer signing

`AGENT_K1_SIGN_TRANSFER` accepts semantic fields, not an arbitrary digest:

- `chain_id`: must equal the configured 2D chain id.
- `from`: derived from the selected key ref and must match the request.
- `to`: expected 20-byte recipient address, pending the authoritative 2D address-derivation vector referenced by TASK-7.3.
- `amount`: non-zero integer token amount in canonical 2D units.
- `nonce`: account nonce supplied by the 2D app. Nonce sequencing is a host-side 2D responsibility, not a TEE-enforced invariant; duplicate or gapped nonces can consume faucet budget and wedge accounts without leaking private keys.
- `gas_limit` and `gas_price` as defined by the authoritative 2D ordinary-transaction encoding used by the current verifier.
- `data`/`memo`: empty for MVP transfer-key signing. If a later task allows non-empty calldata, it must define TEE-side semantic parsing and limits for the allowed method instead of treating "structured tx" as sufficient policy.

TASK-7.1 owns pinning the concrete 2D ordinary-transaction encoding section or golden vector from the 2D repo. Pinning means checking a frozen in-repo test vector into `2d-hsm` (raw preimage bytes, semantic fields, expected hash/address/signature behavior), not merely citing a live sibling-repo source file. TASK-7.3 and TASK-7.4 consume that same pinned artifact. The enclave constructs that canonical transaction preimage, hashes it, and returns a low-S secp256k1 signature plus recovery id in the format expected by the current 2D verifier. It never accepts a caller-provided digest for agent keys.

**Unified-account model — eth surface MVP, TRON reserved.** 2D is a unified secp256k1 account: one key derives one 20-byte body (`keccak256(pubkey)[12:32]`) addressable as both an Ethereum `0x…` address and a TRON `T…` address (Base58Check of `0x41 ‖ body`), over two transaction surfaces — EIP-155 RLP (keccak256) and TRON protobuf (sha256). The MVP signs only the **eth EIP-155 surface** via `AGENT_K1_SIGN_TRANSFER`. A TRON-surface signing opcode and golden-vector slot are **reserved** (TASK-7.1 pins the wire decision in `vsock-api-wire-format-spec-draft.md` §10); `AGENT_K1_PUBLIC_IDENTITY` returns **both** address encodings so the unified identity is complete; and the identity-proof domain separation (TASK-7.3) is proven disjoint from both the eth RLP and the TRON protobuf preimages. Actually signing the TRON surface — which additionally needs host-supplied ref-block/expiration/timestamp the enclave cannot fully validate (host-controlled clock/block ref) — is deferred to a future reviewed task.

Transfer-key destination and amount safety are not TEE-enforced in the MVP. They depend on host-side 2D app validation and Agent OPA policy; a compromised host with a runtime transfer-signing credential can divert or drain a transfer key up to its on-chain balance until a later task adds TEE-side per-agent destination/amount/cumulative limits. Operators should keep transfer-key balances minimal and treat this as accepted residual risk.

`AGENT_K1_SIGN_FAUCET_DISPENSE` is separate from transfer-key signing. It signs only pure native-token transfers: `data`/`memo` must be empty. The recipient `to` address must match a known `agent_transfer_k1` public identity present in the TEE keystore, so a compromised host cannot spend the faucet treasury directly to an arbitrary external address in one command. This is not a complete exfiltration defense against a compromised host that also has runtime transfer-signing access, because the host can dispense to a valid transfer key and then ask that transfer key to forward funds externally. Until a later task adds TEE-side per-agent transfer destination/amount limits, the faucet cumulative signing budget is the hard TEE-enforced bound on compromised-host treasury loss. If a later faucet needs token-contract dispenses, it must use a separate command that parses the contract calldata and applies caps to the parsed token amount and approved method.

The TEE enforces faucet-specific limits from sealed configuration: maximum amount per dispense, maximum gas limit, maximum effective gas fee rate for the pinned 2D transaction encoding, and maximum cumulative native spend. The cap applies to the worst-case native debit `amount + gas_limit * effective_max_fee_rate`, not only to the transfer amount, and all arithmetic is checked and fail-closed on overflow. If the pinned 2D encoding supports EIP-1559-style fields, `effective_max_fee_rate` is `maxFeePerGas`, not legacy `gas_price`. Signing debits are counted when the signature is emitted; this is a worst-case signing budget, not a settlement oracle, so failed or unbroadcast transactions still consume budget unless a later reviewed reconciliation protocol exists.

A compromised host can exhaust the faucet signing budget by requesting signatures and never broadcasting them. A compromised host with both faucet and transfer runtime access can also move dispensed funds onward through transfer keys unless/until TEE-side transfer limits exist. The cumulative faucet budget therefore bounds both unbroadcast-signature lockup and direct compromised-host treasury misuse in the MVP; raising or refilling the budget requires the protected treasury capability flow.

`AGENT_K1_CONFIGURE_TREASURY` updates caps under a higher-authority administrative capability. Config version is monotonic and sealed; a normal config bump does not reset cumulative spend. Faucet dispense fails closed until mandatory per-dispense caps and a cumulative signing budget are sealed. Treasury key generation alone never authorizes signing. The primary faucet model is a sealed cumulative signing budget that can only be increased by an explicit treasury-refill capability counted in the same contiguous-counter scheme; it is rollback-resistant only when TASK-7.7's anti-rollback mechanism or production-funding block is in place. An optional quorum-resettable lifetime circuit breaker can cap total treasury usage across refills. Raising the breaker threshold does not lower recorded lifetime spend; any spend-value reset is a recovery operation bound to a strict recovery counter and target value, with residual risk recorded. These caps bound compromised-host treasury misuse; they do not replace the host-side Agent Gateway faucet policy.

The faucet cap model has two distinct sealed counters for one singleton treasury key: a mandatory refillable cumulative signing-budget counter and an optional quorum-resettable lifetime circuit-breaker counter. Both counters are debited by a single serialized sealed-state commit before the signature is emitted. Implementations must state the expected dispense rate and the anti-rollback/sealed-write latency budget; batching may not let a signature leave before its debit is durably committed. A dispense debits only these two faucet spend counters against the current sealed treasury config; it does not advance any administrative contiguous capability counter and does not bump the monotonic treasury config version. Administrative capability-counter advances are made only by the privileged `AGENT_K1_GENERATE_KEYS`, `AGENT_KEYSTORE_EXPORT_BACKUP`, `AGENT_KEYSTORE_RESTORE_BACKUP`, and `AGENT_K1_CONFIGURE_TREASURY` commands, and treasury config-version bumps only by `AGENT_K1_CONFIGURE_TREASURY` (including its `refill_budget` sub-operation); each seals its own write before returning success. If the required caps are absent, or sealing the faucet spend-counter debit fails, the command fails closed and emits no signature. Plain sealing makes these counters survive normal restarts; TASK-7.7 is required to make them rollback-resistant against a compromised host.

Capability tiers:

| Command | Required capability tier | TEE checks |
| --- | --- | --- |
| `AGENT_K1_PUBLIC_IDENTITY` | read identity | domain, key purpose, chain/environment binding |
| `AGENT_K1_PROVE_IDENTITY` | read identity | binds verifier-provided nonce into signed structure, domain, key purpose, chain/environment binding; verifier enforces nonce freshness |
| `AGENT_K1_SIGN_TRANSFER` | runtime transfer signing for the specific key ref | key purpose, chain id, structured transaction, no generic digest |
| `AGENT_K1_SIGN_FAUCET_DISPENSE` | faucet treasury signing | key purpose, chain id, structured native transfer, empty data/memo, spend caps, checked arithmetic |
| `AGENT_K1_GENERATE_KEYS` for transfer pool | transfer-refill admin capability | signed admin capability, scoped contiguous counter, transfer key-purpose limits |
| `AGENT_K1_GENERATE_KEYS` for faucet treasury | treasury-provisioning admin capability | signed admin capability, enclave-scoped contiguous counter, singleton treasury key-purpose limits |
| `AGENT_K1_CONFIGURE_TREASURY` | treasury admin or quorum capability | signed admin capability, enclave-scoped contiguous counter unless backed by a global monotonic ledger, monotonic config/budget rules |
| `AGENT_KEYSTORE_EXPORT_BACKUP` | backup-export admin capability | signed admin capability, scoped contiguous counter, backup scope |
| `AGENT_KEYSTORE_RESTORE_BACKUP` | recovery/quorum capability | signed recovery capability, anti-rollback/restore semantics |

`AGENT_K1_PUBLIC_IDENTITY` and `AGENT_K1_PROVE_IDENTITY` may be exposed as low-privilege read-identity commands to the local host path, but they still validate command domain, key purpose, chain/environment binding, and bounded request shape. If TASK-7.1 chooses to require an authenticated read capability, that requirement must be explicit in the protocol; otherwise identity reads are treated as non-secret metadata plus a verifier-fresh PoP challenge.

## Public identity

For secp256k1 keys, public identity consists of:

- compressed or uncompressed public key, with one canonical encoding chosen in the protocol spec;
- derived 20-byte 2D address using the same derivation as current ordinary accounts;
- key ref;
- key purpose;
- backend build/protocol version.

The 2D app uses this with `AGENT_K1_PROVE_IDENTITY` to verify the configured faucet treasury address and every transfer key before assignment. The identity proof challenge uses an EIP-191-style non-transaction domain beginning with `0x19` and signs only structured challenge fields, not caller-controlled arbitrary bytes. The structured challenge includes a fixed Agent Gateway proof label, chain id, environment identifier, key ref, public key, derived address, and a fresh 32-byte verifier-provided challenge nonce so proofs are live and cannot be replayed from cache. TASK-7.3 is blocked until it references the authoritative 2D secp256k1 public-key encoding and address-derivation vector, currently expected to come from `../2d/lib/chain/crypto/address.ex`. TASK-7.1 must pin the ordinary transaction preimage vector as a frozen in-repo test vector; TASK-7.3 proves the identity challenge preimage is disjoint from that pinned artifact by construction, because the `0x19` EIP-191 prefix cannot begin a 2D legacy/EIP-155 transaction preimage (an RLP list whose first byte is `>= 0xc0`). Disjointness from future EIP-2718 typed-transaction domains is not structural — `0x19` (= 25) is a legal EIP-2718 `TransactionType`, whose type byte ranges over `0x00..0x7f` — so it holds only as a pinned policy constraint: 2D must permanently reserve and never assign typed-transaction type `0x19`. TASK-7.1 records that reserved-type constraint and TASK-7.3 includes it in the non-collision argument. Because the 2d-hsm enclave cannot enforce a 2D-chain type assignment, the matching reservation must be tracked by a 2D-side acceptance criterion in the TASK-132.5 family, and TASK-7.3's non-collision vector asserts the pinned 2D encoding has not assigned `0x19`.

## Keystore and backup model

The agent keystore is persistent multi-key state inside the TEE runtime boundary. Private keys are generated inside the TEE and are encrypted at rest under the existing provisioning-root concept, but the existing single ML-DSA seal blob format is not reused as-is. The agent keystore encryption key must be derived from the provisioning root with explicit domain separation — a KDF (HKDF or a SHA3-based construction) bound to a unique agent-keystore label such as `2d-hsm-agent-keystore-v1` — so it cannot collide or overlap with producer ML-DSA key material derived from the same root. TASK-7.2 must define a new multi-key sealed keystore and backup format with an explicit format version, fail-closed unknown-version handling, and a reviewed forward-migration rule before any incompatible format change. The agent keystore is separate from producer sealed state and never stores producer ML-DSA keys or AuthorizationTicket state. It also owns sealed storage for the configured 2D chain id, environment identifier, administrative authority public key, recovery/quorum authority public key or threshold root, backup-recovery wrapping public material, the highest accepted capability counter per `(authority, environment_identifier, scope_class, scope_target)` scope, faucet cap values and cumulative spend counters, monotonic treasury config version, and any in-enclave audit metadata retained for privileged operations.

Key generation is a privileged sealed-state mutation. `AGENT_K1_GENERATE_KEYS` advances its administrative capability counter and persists the generated key metadata in one atomic sealed-state commit before returning any new key refs. If the counter advance or key persistence cannot be sealed together, the command fails closed and returns no usable refs; TASK-7.2 must define the recovery/reconcile signal for any implementation-level partial failure.

Administrative authority rotation is a recovery-tier operation. The design must define how a new authority key is installed, how old authorities are revoked, and how counter scopes migrate or reset without permitting replay under a retired authority. If this cannot be implemented safely in MVP, authority compromise requires full re-provisioning and that residual risk must be documented.

Standard sealed storage gives confidentiality and integrity, but not host-rollback resistance. Production use of replay counters or cumulative treasury caps requires an anti-rollback mechanism, such as an external append-only ledger, remote monotonic counter, or operator-signed boot authorization that binds the expected sealed-state sequence. An operator-signed boot authorization is itself rollback-resistant only if it cannot be replayed — it must be bound to a platform/hardware monotonic counter or established by challenge-response with a remote coordinator — because a host can otherwise reboot the enclave presenting a stale sealed state together with the matching stale boot authorization; TASK-7.7 must specify that freshness binding. If the deployment cannot provide that mechanism, the design must record the residual risk: the TEE cannot independently enforce absolute cumulative limits or capability replay protection against a host that can roll sealed state back.

The configured 2D chain id and environment identifier are installed during measured provisioning and sealed. Runtime requests and administrative capabilities are compared against those sealed values; host-supplied request fields are not authority for the chain or environment.

Backup export produces an opaque encrypted blob. The 2D app stores this blob on the filesystem and records metadata in Postgres, but cannot decrypt it. Normal runtime signing credentials cannot export backups. Provisioning/refill credentials can generate keys but cannot export backups unless they also present the distinct backup-export capability. Backup-export credentials can export encrypted backups but cannot decrypt or restore them. Export still performs a cheap authenticated self-check before returning success: parse the encrypted blob header/manifest, verify the authenticated key-ref list matches the requested refs, and reject truncated or malformed blobs. This self-check is a separate export-success prerequisite; `identity_verified` remains the 2D app's live public-identity check after a successful export, not a full backup-restore proof.

Same-process restart and cross-TEE disaster recovery require distinct keying assumptions. If restore onto a newly provisioned TEE is in scope, backup confidentiality must be rooted in operator/recovery material independent of the source enclave's local seal root; a blob wrapped only to the per-enclave seal root is same-enclave restart material, not DR backup. TASK-7.2 must specify where the recovery wrapping key is installed, how it is bound to attestation/provisioning, and how normal runtime credentials are prevented from accessing it.

The backup format must be designed for disaster recovery, not only same-process restart. It must define:

- blob version;
- key refs included;
- encrypted payload authentication domain;
- recovery wrapping mechanism;
- whether restore is same-measurement only, same-fleet only, or allowed onto a newly provisioned TEE;
- which operator-held recovery material or quorum is required;
- how restore verifies that key refs derive the same public identities after import.
- whether capability counters and faucet spend counters are carried forward in restore material, or explicitly reset only under recovery/quorum authorization with the residual risk recorded.

Restore onto a fresh TEE cannot initialize replay or spend counters from zero or from a stale backup alone. The recovery ceremony must seed counters from authenticated recovery material, a remote monotonic ledger, or an operator-signed boot authorization that states the expected high-water marks. If faucet dispense requires `to` to be present in the TEE transfer-key set, restore must either restore the faucet key and its eligible transfer-key allowlist as one consistent backup set or fail faucet signing closed until the allowlist is reconstructed and verified. Restoring the same faucet key onto a second live TEE is safe for production budgets only when all live clones share a global spend/capability ledger. Enclave-scoped budgets are safe only for strict failover where the prior enclave is provably decommissioned by operator procedure; the TEE cannot enforce decommissioning by itself, so active-active clones of one treasury key without a global ledger remain prohibited.

Privileged-operation audit metadata must have an authenticated export or attested log-streaming path before in-enclave ring-buffer rollover can discard entries required for operator review.

The MVP 2D gate is `identity_verified`: after export, the 2D app re-fetches public identities from the logical signer and verifies they match the DB rows. `restore_verified` is a later operator drill and must not be implied by `identity_verified`.

The secp256k1 keystore must follow the zeroization outcome of TASK-6. Sensitive key material and derived signing secrets are wiped on normal teardown paths where Rust can run destructors, and the design must state the residual behavior for process-abort paths that skip `Drop`.

ECDSA signing uses RFC 6979 deterministic nonce derivation or a vetted constant-time secp256k1 library that provides equivalent deterministic nonce safety. Raw ad-hoc RNG-only `k` generation is not acceptable. TASK-7.4 vectors must cover deterministic signing and low-S normalization.

## Success criteria

- Existing producer AuthorizationTicket commands remain wire-compatible unless the vsock spec explicitly bumps the frame version.
- Agent keys cannot be used through producer commands, and producer keys cannot be used through Agent Gateway commands.
- Agent keys cannot sign arbitrary caller-provided digests or identity challenges that collide with transaction preimages.
- Privileged commands reject missing, stale, replayed, wrongly scoped, or non-contiguous administrative capabilities per `(authority, environment_identifier, scope_class, scope_target)` counter space.
- Faucet treasury signing is bounded by TEE-side caps over both transfer amount and worst-case gas spend; those caps survive normal restart through sealing and become rollback-resistant against a compromised host only when the deployment provides the required anti-rollback mechanism.
- Transfer-key destination and amount limits are host-policy residual risk until TEE-side per-agent limits are added.
- Production deployments provide an anti-rollback mechanism for sealed counters, including both treasury caps and administrative-capability replay counters, or explicitly accept that those controls are host-rollback-sensitive and therefore unsuitable for production fund custody.
- Backup export emits only opaque encrypted blobs and records enough metadata for the 2D app to perform `identity_verified` gating.

## Host-side policy boundary

The host-side flow may mirror the existing NetHSM bridge shape:

```text
local validation -> Agent OPA policy -> Vault capability lookup -> 2d-hsm command
```

This is only a gate. The enclave still validates command domain, key purpose, chain id, structured transaction fields, and any required signed administrative capability. A host with a runtime signing credential must not be able to generate keys, export backups, restore backups, invoke faucet treasury signing without faucet-specific caps, or sign arbitrary digests. The runtime signing commands (`AGENT_K1_SIGN_TRANSFER`, `AGENT_K1_SIGN_FAUCET_DISPENSE`) are intentionally reachable by any host process that can open the vsock channel; the TEE does not separately authenticate the runtime caller. Restricting who may call is a host OS/hypervisor vsock access-control responsibility, and the TEE's non-bypassable bound on a compromised runtime caller is structured-signing, key-purpose, and faucet caps, not caller identity. TASK-7.1 may optionally add a lightweight runtime read/sign capability for these commands; absent that, this caller-authentication gap is an explicitly accepted residual risk.

## Implementation slices

1. Protocol/opcode allocation and test vectors.
2. Persistent agent keystore and encrypted backup/restore design.
3. secp256k1 key generation and public identity derivation.
4. Structured transfer signing.
5. Host integration contract for OPA/Vault capabilities after the canonical capability taxonomy is defined in slices 1, 2, and 4.
6. Production anti-rollback mechanism or an explicit production-funding block for sealed counters and faucet caps (TASK-7.7).
7. Implementation, split into narrower child tasks before code begins (TASK-7.6). Implementation may not authorize production fund custody until slice 6 / TASK-7.7 is complete or its funding block is active.

Each slice follows the dependency graph in the task files and is high-risk; run the repo's roborev matrix before merge.
