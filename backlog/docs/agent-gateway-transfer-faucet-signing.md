# Agent Gateway structured transfer + faucet-dispense signing (TASK-7.4)

The concrete signing contract for `AGENT_K1_SIGN_TRANSFER` and
`AGENT_K1_SIGN_FAUCET_DISPENSE`. Design-only: the secp256k1 signing code (k256, RFC 6979) is
TASK-7.6. This doc **consumes** TASK-7.1 (protocol §10 + frozen `ordinary_tx_v1.*` vector),
TASK-7.2 (sealed faucet caps/counters, seal-before-emit) and TASK-7.3 (keygen / key_ref /
public identity), and adds the structured-field → EIP-155 signing contract + cap model.

Refs: `vsock-api-wire-format-spec-draft.md` §10; `agent-gateway-secp256k1-signer-design.md`
§Structured transfer signing; keystore `agent-gateway-keystore-backup-format.md`; keygen
`agent-gateway-keygen-identity.md`; vectors `impl/rust/enclave-protocol/testvectors/agent-gateway/`;
2D encoding `../2d/lib/chain/crypto/envelope.ex` + `crypto.ex`.

## Decisions (adopted, TASK-7.4 — all follow from the pinned vector / prior tasks)

| Topic | Decision |
|-------|----------|
| Gas-fee field | Cap against the **legacy `gas_price`** field — the pinned `ordinary_tx_v1` is EIP-155 (`gas_price=1e9`), no EIP-1559. The sealed **cap** is `max_effective_gas_fee_rate` and the per-tx **operand** is `effective_max_fee_rate` (= the legacy `gas_price`); both names are encoding-agnostic. AC#8's "if EIP-1559… use `maxFeePerGas`" is a forward-conditional that does not apply until a 1559 surface is pinned. |
| Rotation (AC#15) | Specify only the **carry-over semantics** (a rotated treasury key keeps debiting the carried-over counters; never zero-reset on replacement); rotation itself stays **fail-closed** absent a reviewed protocol. TASK-7.3 owns duplicate-treasury rejection; 7.2/7.4 own counter carry-over. |
| Reconciliation (AC#11) | **None** in MVP — the cap is a worst-case *signing* budget, not a settlement oracle; failed/duplicate-nonce/unbroadcast signatures permanently consume budget. Documented residual; a credit-back protocol is deferred. |
| Anti-rollback (AC#14) | 7.4 owns durability (seal-before-emit); 7.7 owns the rollback **mechanism**. State the assumed freshness round-trip toward 7.7; gate production fund custody on 7.7 (or an explicit funding block). |
| Throughput (AC#14) | State the **model** (serialized single-writer, one seal per dispense, no batched amortization) + a conservative seal-latency-bound ceiling + budget-remaining observability; defer the exact benchmarked rate to TASK-7.6. |

## §1 `AGENT_K1_SIGN_TRANSFER` signing contract (AC#2, AC#3, AC#4, AC#13)

Opcode 4, **runtime** tier (no admin capability; reachable by any vsock caller),
`agent_transfer_k1` keys only. Payload (envelope key 7, vsock §10.4):
`{1: chain_id, 2: from, 3: to(20B), 4: amount, 5: nonce, 6: gas_limit, 7: gas_price,
8: data}`.

**Pre-build checks (fail closed, before any preimage build — AC#3):**
- `chain_id` **must equal the sealed `KeystoreConfig.twod_chain_id`** (never request-authoritative;
  `11565` is the current 2D deployment / golden-vector value, **not** a hardcoded protocol constant —
  a different sealed deployment binds a different chain_id, and the enclave rejects any request value
  that differs from the sealed one).
- `from` **must equal the selected `key_ref`'s derived eth address** (`keccak256(X‖Y)[12:32]`).
- `data` **must be empty** in the MVP (non-empty calldata requires a separate,
  semantically-parsed command with per-method TEE limits).

**Canonical EIP-155 preimage (reproduce 2D `Chain.Crypto.Envelope.unsigned_rlp/1`):**
`RLP([nonce, gas_price, gas, to, value, data, chain_id, «», «»])` with minimal-int encoding
(`0` → empty string, non-zero → big-endian no-leading-zeros), `to` a raw 20-byte binary,
`data` raw (empty in MVP), trailing two slots empty. The enclave builds this **internally**
and hashes with keccak256; it **never accepts a caller-provided digest**.

> Frozen comparison target (`ordinary_tx_v1.*`, do not re-derive — AC#1):
> preimage `0xed80843b9aca008252089470997970c51812dc3a010c7d01b50e0d17dc79c8880de0b6b3a764000080822d2d8080`,
> signing hash `0xd1690760dc3ced0dba0c77c4764f509a990886caa3bde11b9e97ed718a192d56`.

**Signature (keyed to the 2D verifier — AC#4):** secp256k1 over the keccak256 hash;
**low-S** enforced (`s ≤ n/2`, `secp256k1n_half = 0x7FFF…20A0`, EIP-2): the enclave
**normalizes** its own signature to low-S — if `s > n/2`, set `s = n − s` and **flip
`recovery_id`** — so an emitted signature is always low-S and the post-sign recovery
invariant still recovers `from` (a self-generated high-S signature is normalized, not
rejected); `recovery_id ∈ {0,1}`; `v = chain_id*2 + 35 + recovery_id ∈ {23165, 23166}`
(the 2D `signed_rlp` guard raises on any other `v` — fail closed). Wire form
`RLP([nonce, gas_price, gas, to, value, data, v, r, s])` with `r`/`s` minimally re-encoded.

**Post-sign invariant (AC#3):** recovery of the produced `(r,s,recovery_id)` over the signing
hash must recover `from` (the 2D verifier's path; pinned `recovered_from`
`0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266`).

**Wire encoding (TASK-15 / 7.6.4 impl decisions — §10.4 left these open).** The request map is
`{1: chain_id(uint), 2: from(20B bstr), 3: to(20B bstr), 4: amount, 5: nonce(uint), 6: gas_limit(uint),
7: gas_price, 8: data(bstr, empty in MVP)}`. The `u256` fields (`amount`, `gas_price`) are CBOR **byte
strings in CANONICAL minimal big-endian** — length `0..=32`, **no leading zero byte**, so each value has
exactly one wire encoding (empty = zero). An over-width value (> 32 bytes) or a non-minimal/non-`bstr`
encoding ⇒ `AGENT_MALFORMED` (0x40) — the §2 AC#8 "exceeding its width is rejected, never truncated"
rule, applied at decode. `chain_id`/`nonce`/`gas_limit` are CBOR uints (`u64`). The faucet slice reuses
this same `u256` wire form. The **success response** map is
`{1: signed_rlp(bstr), 2: r(32B), 3: s(32B), 4: recovery_id(uint), 5: v(uint), 6: signing_hash(32B),
7: from(20B)}`; key 1 is bytes so a success body is distinguishable from a `{1: code(uint), 2: reason}`
§10.9 error body.

**Error-code mapping (anti-oracle, §10.9).** Request-SHAPE failures that need no keystore — bad CBOR,
`chain_id` ≠ sealed (a public constant), non-empty `data`, a non-minimal/over-width integer — collapse
to `AGENT_MALFORMED` (0x40). Everything KEY-related — `key_ref` not found, wrong key purpose, and
`from` ≠ the key's derived address — collapses uniformly to `AGENT_KEY_PURPOSE_MISMATCH` (0x42), so the
error code never distinguishes "absent" from "present-but-…". `0x42` is therefore the **key-band /
internal-signing bucket**, not strictly a "purpose mismatch": a (≈2⁻¹²⁸) signing failure (the x-reduced
`recovery_id` rejection or the post-sign `recovery==from` invariant) also maps to 0x42 — SIGN_TRANSFER
never seals, so **not** the seal-reserved 0x46. The `u256` width/minimality rule above is the **same**
one §2 AC#8 defines, applied uniformly to both opcodes (one canonical wire form for `amount`/`gas_price`).

**Security boundary — transfer-tier non-goals (NOT the faucet tier).** SIGN_TRANSFER signs whatever
`(nonce, value, to)` the host supplies for a funded `agent_transfer_k1` key. The transfer tier enforces
**no spend cap, no anti-replay, and no recipient allowlist** — those are the *faucet* tier's
AC#5/AC#6/§2.1 contract (§2). It is **not** rollback-sensitive (it mutates no sealed counter), so it
carries no TASK-7.7 anti-rollback obligation; "not rollback-sensitive" must **not** be read as
"spend-bounded". Fund-custody safety for a transfer key rests entirely on the **AC#5 production funding
profile** + host-side nonce management — which is exactly why the opcode is production-gated
(`agent-sign-transfer-preview`, release-banned) until TASK-18 un-gates. `to` is always **exactly 20
bytes** (ordinary transfers only): contract-creation (empty `to`) is structurally unrepresentable and
out of scope. Semantically-valid-but-useless transfers (zero `amount`, zero `gas_limit`, self-transfer,
duplicate nonce) are **accepted** — they are host / on-chain concerns (the host owns nonce sequencing,
§Documented residuals), not TEE-enforced policy; the enclave signs them rather than inventing
inconsistent TEE-side rules.

## §2 `AGENT_K1_SIGN_FAUCET_DISPENSE` signing + cap contract (AC#5, AC#6, AC#8)

Opcode 5, **faucet-treasury** tier, the singleton `agent_faucet_treasury_k1` key only. Same
preimage / `from` / `chain_id` machinery as §1 (`from` = treasury key's derived address).
Differs by recipient allowlist + spend caps + sealed counter debit.

- **Recipient allowlist (AC#5):** `to` **must match an active `agent_transfer_k1` public
  identity in the keystore**. This blocks one-command faucet→external spend, but **not**
  two-step exfiltration (host dispenses to a transfer key, then signs a transfer out) until
  TEE-side per-agent transfer destination/amount limits exist — **documented residual**.
  `data`/memo **must be empty** (native transfers only).
- **Cap set (sealed in the 7.2 keystore faucet state):** per-dispense `max_amount`,
  `max_gas_limit`, `max_effective_gas_fee_rate`, a **mandatory refillable cumulative
  signing-budget** counter, and an **optional quorum-resettable lifetime circuit breaker**.
  Faucet signing **fails closed** until mandatory per-dispense caps + a cumulative budget are
  sealed.
- **Checked worst-case arithmetic + integer domain (AC#8):** EVM-value fields (`amount`,
  `value`, `gas_price`/`effective_max_fee_rate`) and the cumulative-spend / budget / breaker
  counters are **`u256`**; `nonce` and `gas_limit` are **`u64`** (the EVM / 2D domain — 2D
  `Chain.Crypto.Envelope` RLP-encodes them via `:binary.encode_unsigned`; witness
  `ordinary_tx_v1` has `nonce=0`, `gas_limit=21000`). An input exceeding its width is
  **rejected (fail-closed), never truncated/downcast**. The debit is the worst-case native cost
  `worst_case = amount + gas_limit * effective_max_fee_rate` (not just `amount`), computed with
  **checked** `u256` `mul`/`add`; overflow **or any out-of-range field fails closed**.
  `effective_max_fee_rate` is the legacy `gas_price` for the pinned encoding.
- **Per-dispense gate + counter debit (exact rule):** accept **iff all** of the following
  hold, else fail closed (per-field caps are enforced **individually**, not only the aggregate):
  - `amount ≤ max_amount`
  - `gas_limit ≤ max_gas_limit`
  - `effective_max_fee_rate ≤ max_effective_gas_fee_rate`
  - `worst_case = checked(amount + checked(gas_limit * effective_max_fee_rate))` (no overflow)
  - `cumulative_spend + worst_case ≤ cumulative_budget`
  - **if** a lifetime breaker is configured: `lifetime_spend + worst_case ≤ breaker`

  On accept, **always** debit **both** `cumulative_spend += worst_case` **and**
  `lifetime_spend += worst_case`. `lifetime_spend` is a total-usage counter maintained from
  treasury **genesis** whether or not a breaker threshold is configured — so an optional breaker
  installed *later* still caps **total** usage across refills and never under-counts pre-install
  dispenses. Only the **threshold check** (`lifetime_spend + worst_case ≤ breaker`, the last
  accept condition above) is conditional — skipped when no breaker is configured; the breaker is
  optional and its absence is **not** a failure (dispenses still succeed and still advance
  `lifetime_spend`). Both counters are keyed independently of the treasury `key_ref`, so they
  survive rotation (never zero-reset on key replacement — AC#15).
- **Signing-budget semantics (AC#11):** the debit is committed **at signature emission** — a
  worst-case signing budget, not a settlement oracle. A request **rejected before emission**
  (cap/overflow/validation/seal failure) consumes **no** budget; once a signature is emitted
  it permanently consumes budget even if it later fails on-chain, is a duplicate-nonce /
  replacement, or is never broadcast — unless a later reviewed reconciliation protocol exists. Nonce sequencing is a host-side 2D responsibility, not a TEE invariant.
  Normal config bumps do not reset spend; increases require the explicit treasury-refill
  capability (`CONFIGURE_TREASURY refill_budget`).

## §2.1 Cap mutation — refill / breaker raise / reset (AC#10)

Budget and breaker changes are **not** part of a dispense; they go through
`AGENT_K1_CONFIGURE_TREASURY` (vsock §10.7) with a TEE-verified, **replay-protected** admin
(or recovery/quorum) capability bound to the `(authority, environment_identifier, scope_class,
scope_target)` contiguous monotonic counter (§10.6) — a captured `refill_budget` / breaker
command cannot be replayed. **Host-controlled time never resets any limit.** `refill_budget`
raises the cumulative budget; `raise_lifetime_breaker` raises the breaker threshold and does
**not** lower recorded spend; because `lifetime_spend` is maintained from genesis (§2),
installing the **first** breaker simply applies a threshold to the already-accumulated total —
there is **no** first-install seeding choice (it is never re-seeded to 0 or from `cumulative_spend`). Any **spend-value reset** (`reset_lifetime_breaker`) is a
**recovery-tier** operation bound to a **strict recovery counter + explicit target value**
(§10.6), audited, and never replayable to roll a counter backward. Normal config bumps do not
reset cumulative spend.

## §3 Seal-before-emit, serialized commit, throughput & 7.4↔7.7 boundary (AC#9, AC#14, AC#7)

- **Seal-before-emit (AC#9):** the faucet spend debit (both counters — `cumulative_spend` +
  the always-maintained `lifetime_spend`, per §2) is **durably sealed
  before any signature leaves** the enclave; failure to seal emits **no** signature
  (fail-closed). A dispense debits only the two faucet spend counters against the current
  sealed treasury config — it does **not** advance an administrative capability counter and
  does **not** bump the monotonic treasury config version (those are written only by their own
  privileged commands).
- **Serialized commit:** both counters are debited in **one atomic serialized** sealed-state
  commit (single writer per treasury keystore); batching must not let any signature leave
  before its own debit is durably committed. No active-active treasury clones without a global
  ledger (per TASK-7.2).
- **Throughput / observability (AC#14):** the implementation states (a) the expected dispense
  rate — bounded by one fsync-class seal per dispense, a conservative low-tens/sec ceiling to
  be confirmed by a TASK-7.6 benchmark; (b) the serialization model (single writer, one seal
  per dispense, no batched amortization across distinct signatures); (c) the sealed-commit
  latency budget; (d) budget-remaining observability (`remaining = budget − cumulative_spend`
  exposed as non-secret metadata); (e) the anti-rollback round-trip assumed from 7.7.
- **7.4 vs 7.7 boundary:** 7.4 owns seal-before-emit durability + the atomic serialized
  commit; **7.7 owns the anti-rollback / freshness-binding mechanism**. Plain sealing gives
  confidentiality + integrity but **not** host-rollback resistance.
- **Residual (AC#7, verbatim with TASK-7.2 AC#10):** standard sealed storage of agent-gateway
  counters/caps provides confidentiality and integrity but not host-rollback resistance; a
  compromised host that rolls sealed state backward can replay counters and reset cumulative
  faucet spend toward earlier values; the TEE cannot independently enforce absolute cumulative
  limits or replay protection against such a host. These counters are host-rollback-sensitive
  until the TASK-7.7 mechanism is in place; **production fund custody requires it** (or an
  explicit production-funding block).

## §4 No generic digest, domain separation, key-purpose cross-rejection (AC#13, DoD#2)

- **No generic digest signing:** agent keys never sign caller-provided bytes/digests; there is
  **no** `signing_hash` / raw-bytes parameter on any agent command. A request carrying a
  precomputed digest is rejected (`AGENT_MALFORMED`).
- **Identity-proof non-coercion:** the identity-proof preimage begins with `0x19` (EIP-191);
  an eth EIP-155 preimage is an RLP list whose first byte is `≥ 0xc0` (this vector `0xed`).
  `0x19 < 0xc0`, so an identity-proof-shaped input can never be coerced into a transfer
  signature, and `SIGN_TRANSFER` refuses it (witnessed by `domain_separation.json`). EIP-2718
  caveat: `0x19` is a legal `TransactionType`, so cross-domain safety vs *typed* txs holds only
  as the pinned 2D policy reserving type `0x19` (2D-side AC, TASK-132.5 family / PR #144) — a
  **production gate**, not a design blocker (see `agent-gateway-keygen-identity.md`).
- **Key-purpose cross-rejection:** `SIGN_TRANSFER` accepts only `agent_transfer_k1`,
  `SIGN_FAUCET_DISPENSE` only `agent_faucet_treasury_k1`; cross-use and any producer purpose
  fail closed. Error codes collapse oracle-creating distinctions:
  `0x42 AGENT_KEY_PURPOSE_MISMATCH` (key-not-found ≡ wrong-purpose),
  `0x43 AGENT_CAPABILITY_REJECTED`. A producer-profile signer rejects every agent command
  before touching agent state, and vice versa.

## §5 Treasury-key rotation carry-over (conditional, AC#15)

If treasury-key rotation is in scope (per TASK-7.2 carry-over semantics): signing against a
rotated/replacement `agent_faucet_treasury_k1` **continues debiting** the carried-over
cumulative budget + lifetime breaker (counters keyed independently of `key_ref`, never
zero-reset on replacement); absent an active reviewed rotation protocol, rotation remains
**fail-closed**. TASK-7.3 owns duplicate-treasury rejection; TASK-7.2/7.4 own counter
carry-over semantics.

## §6 Golden-vector + test requirements (AC#1, AC#12, AC#16; DoD)

Consumed by TASK-7.6 (the live signed artifacts are produced with the implementation):
- **Transfer preimage/hash:** build from `ordinary_tx_v1.json` semantic fields and assert
  byte-exact equality to the frozen `…preimage.bin` and `…signing_hash.bin` (compare, not
  re-derive — AC#1).
- **Transfer signature:** produced `(r,s,recovery_id)` matches the frozen `r/s`, `low_s=true`,
  `v=23166`; `signed_rlp` matches; recovery yields `from=0xf39f…2266` (2D-verifier-accepted).
- **Deterministic + low-S (AC#12):** RFC 6979 — signing the pinned hash twice is byte-identical;
  raw RNG-only `k` is rejected; a high-S result is **normalized** (`s = n − s`, flip
  `recovery_id`), only `s ≤ n/2` emitted, and the normalized `(r,s,recovery_id,v)` still
  recovers `from`.
- **Rejections:** wrong `chain_id`; `from` ≠ derived(key_ref); non-empty `data`; caller digest /
  identity-proof-shaped input; key-purpose cross-use (transfer↔faucet, producer purposes);
  role/profile mismatch (before state touch).
- **Faucet positive + caps:** dispense treasury→known-transfer-key with caps satisfied succeeds;
  worst-case `amount + gas_limit*effective_max_fee_rate` (legacy `gas_price`) checked; both
  counters advance. **No-breaker variant:** with no breaker configured the dispense still
  succeeds and still advances `lifetime_spend` (no threshold check). **Breaker variant:** with a
  breaker configured, exceeding it is rejected, and a breaker installed *after* breaker-less
  dispenses caps the already-accumulated total.
- **Faucet rejections:** recipient not a known transfer key; **non-empty `data`/memo**;
  per-dispense cap / cumulative budget / lifetime breaker exceeded; checked-arithmetic overflow;
  mandatory caps/budget absent; any field outside its integer width.
- **Seal-before-emit (AC#9):** simulated seal failure emits no signature; on success both
  counters debited in one commit; no config-version bump / admin-counter advance.
- **Signing-budget (AC#11):** repeated/duplicate-nonce/unbroadcast dispenses each consume
  budget; no credit-back absent a reconciliation protocol.
- **Rotation carry-over (AC#15, if in scope):** signing a rotated treasury key debits
  carried-over counters, never a zero-reset; rotation fail-closed absent a reviewed protocol.
- **Roborev matrix/compact evidence recorded before merge (AC#16); final summary (DoD#3).**

## Documented residuals

- Two-step exfiltration through transfer keys (until TEE-side per-agent transfer limits).
- Unbroadcast-signature budget burn (a compromised host can exhaust the budget without broadcasting).
- Host-rollback sensitivity of sealed counters until TASK-7.7.
- No runtime-caller authentication on the signing commands (host OS/hypervisor vsock access
  control + structured-signing + caps are the bound; per the design's threat model).
- Nonce sequencing is a host-side 2D responsibility (duplicate/gapped nonces can consume
  budget / wedge accounts, no key leakage).
