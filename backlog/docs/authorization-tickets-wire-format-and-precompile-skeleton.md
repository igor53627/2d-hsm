# Authorization Tickets — Wire Format, Calldata & Precompile Skeleton (v0.1 draft)

**Date**: 2026-06-05  
**Status**: Grounded draft (based on real 2D precompile patterns)  
**Related**: `authorization-tickets-precompile-spec-draft.md`

## 1. Key Learnings from Existing Precompiles

The 2D chain uses a very specific, battle-tested pattern (see `Chain.Precompiles.BridgeHalt`, `Chain.Precompile` behaviour, `Registry`, and `Context`):

- Precompiles are **registered** in `state.precompiles` table (address + handler module name).
- They implement the `Chain.Precompile` behaviour:
  - `address/0` → 20-byte binary
  - `execute(selector, args, %Context{})` → `{:ok, result, logs}` | `{:revert, reason}`
  - `read(selector, args)` → read-only path
- Calldata is **standard Solidity ABI** (selectors + `ABI.TypeDecoder` from `ex_abi`).
- Context is a strict struct (`from`, `value`, `block_number`, `block_timestamp_ms`, `tx_index`).
- Errors are returned as short atom strings in `{:revert, "reason_atom"}`.
- BridgeHalt is the closest analog (governance action with nonces, signatures, deadlines).

**Conclusion for us**: Our Authorization Tickets precompile should follow **exactly** this model. No custom transaction type is strictly required for v1 (we can use normal calls to the precompile address). A dedicated special tx kind can be added later for gas/UX optimization.

## 2. Proposed Precompile Address

```elixir
@address <<0x2D, 0::144, 0xA0>>   # 0x2D000000000000000000000000000000000000A0
```

## 3. Recommended Functions & ABI (refined)

```solidity
interface IAuthorizationTickets {
    // Submit a ticket (state changing)
    function submit(bytes calldata ticket) external;

    // Views
    function getCurrentProducer() external view returns (bytes memory pqPubkey, bytes memory measurement, uint64 activatedAt);
    function getActiveFork(uint64 height) external view returns (bytes32 forkSpecHash, bytes memory codeMeasurement, uint64 activationHeight);
    function wasTicketAccepted(bytes32 ticketHash) external view returns (bool);
}
```

### Exact Selectors (to be used in skeleton)

We will compute them the same way BridgeHalt does:

```elixir
@submit_selector     :erlang.binary_part(ExKeccak.hash_256("submit(bytes)"), 0, 4)
@get_current_selector :erlang.binary_part(ExKeccak.hash_256("getCurrentProducer()"), 0, 4)
@get_fork_selector    :erlang.binary_part(ExKeccak.hash_256("getActiveFork(uint64)"), 0, 4)
@was_accepted_selector: :erlang.binary_part(ExKeccak.hash_256("wasTicketAccepted(bytes32)"), 0, 4)
```

## 4. Ticket Encoding (the `bytes` argument to `submit`)

We keep the high-level struct from the previous spec, but define a clean **ABI tuple encoding** for the `bytes` field:

```solidity
// This is what goes inside the outer `bytes` of submit(bytes).
// Field order matches authorization-tickets-precompile-spec-draft.md §4
// (canonical ticketHash preimage — NOT optional for hard-fork).
struct RawTicket {
    uint8   ticketType;        // 0 = PRODUCER_RECOVERY, 1 = HARD_FORK_ACTIVATION
    uint64  nonce;
    bytes32 contextHash;
    uint64  activationHeight;
    bytes   newMeasurement;    // dynamic
    bytes   pqPubkey;          // dynamic — ML-DSA-65: 1952 bytes (production)
    bytes   attestation;       // dynamic — TEE remote attestation document
    bytes   signature;         // dynamic — ML-DSA-65: 3309 bytes (production)
    bytes32 forkSpecHash;      // HARD_FORK: mandatory non-zero; RECOVERY: bytes32(0)
    uint32  newHeaderVersion;  // HARD_FORK: mandatory non-zero; RECOVERY: 0
    bytes32 governanceRef;     // NOT in signed ticketHash — metadata only
    uint256 bond;              // NOT in signed ticketHash — must be 0 in v1
}
```

**Canonical `ticketHash` (must match enclave + precompile):**

```solidity
bytes32 ticketHash = keccak256(abi.encode(
    ticketType,
    nonce,
    contextHash,
    activationHeight,
    newMeasurement,
    pqPubkey,
    forkSpecHash,
    newHeaderVersion
));
```

`governanceRef` and `bond` are **outside** the signed preimage (same as main precompile spec).

**Decoder rules (`decode_and_validate_ticket/1`):**

| `ticketType` | `forkSpecHash` | `newHeaderVersion` |
|--------------|----------------|---------------------|
| `0` RECOVERY | must be `bytes32(0)` | must be `0` |
| `1` HARD_FORK | must be non-zero | must be non-zero |

Reject if hard-fork fields are present on recovery tickets or absent/zero on hard-fork tickets — prevents canonicalization drift vs `AuthorizationTicketPayload` in `enclave-protocol`.

When calling `submit`, the caller ABI-encodes the `RawTicket` as a single `bytes` argument (standard dynamic bytes encoding).

This keeps the outer call simple (`submit(bytes)`) while allowing rich structured data inside.

## 5. Precompile Skeleton (Elixir style, following BridgeHalt exactly)

```elixir
defmodule Chain.Precompiles.AuthorizationTickets do
  @behaviour Chain.Precompile

  alias Chain.Precompile.Context

  @address <<0x2D, 0::144, 0xA0>>

  # Selectors (computed at compile time like BridgeHalt)
  @submit_sel     <<...>>  # first 4 bytes of keccak("submit(bytes)")
  @get_current_sel <<...>>
  @get_fork_sel    <<...>>
  @was_accepted_sel <<...>>

  @impl true
  def address, do: @address

  @impl true
  def execute(selector, args, %Context{} = ctx) do
    case selector do
      @submit_sel ->
        handle_submit(args, ctx)

      _ ->
        {:revert, "unknown selector"}
    end
  end

  @impl true
  def read(selector, args) do
    case selector do
      @get_current_sel -> handle_get_current()
      @get_fork_sel    -> handle_get_fork(args)
      @was_accepted_sel -> handle_was_accepted(args)
      _ -> {:revert, "unknown read selector"}
    end
  end

  # --- Handlers ---

  defp handle_submit(args, ctx) do
    # 1. Decode the outer bytes
    # 2. Decode the inner RawTicket using ABI.TypeDecoder
    # 3. Recompute ticket_hash
    # 4. Verify signature over ticket_hash using pqPubkey (Dilithium verify)
    # 5. Verify attestation (or at least record it)
    # 6. Apply business rules (downtime for recovery, governanceRef for forks, etc.)
    # 7. Write to state.authorization_* tables
    # 8. Emit events via logs if needed

    case decode_and_validate_ticket(args) do
      {:ok, ticket, ticket_hash} ->
        case apply_ticket(ticket, ticket_hash, ctx) do
          {:ok, _} -> {:ok, <<>>, []}                    # success, no return data
          {:error, reason} -> {:revert, Atom.to_string(reason)}
        end

      {:error, reason} ->
        {:revert, Atom.to_string(reason)}
    end
  end

  # ... read handlers ...

  defp decode_and_validate_ticket(_args) do
    # TODO: real implementation
    # 1. ABI-decode outer `bytes` → RawTicket tuple (all fields above, including forkSpecHash + newHeaderVersion)
    # 2. Enforce recovery vs hard-fork field rules (table in §4)
    # 3. ticketHash = keccak256(abi.encode(...)) — eight typed fields only
    # 4. verify ML-DSA-65 signature over ticketHash
  end
end
```

**Important implementation notes** (from real code):
- Use `try/rescue` around ABI decoding → `{:revert, "malformed calldata"}`
- Keep revert reasons short and non-leaking.
- All state writes must be done inside the caller's `Repo.transaction` (the precompile is called from `BlockExecutor`).
- Use the `prefix: "state"` pattern for security (as done everywhere in the hardened code).

## 6. Immediate Recommended Actions (next 3-5 days)

1. **Create the module skeleton** in the 2d-hsm repo under `design/precompile_skeletons/` (or directly in a branch of the real 2d code later).
2. Implement `decode_and_validate_ticket/1` for the `RawTicket` structure (the hardest part — get the ABI tuple types right).
3. Implement signature verification hook (call into whatever Dilithium/ML-DSA library we choose).
4. Write 5-6 test vectors (valid recovery ticket, valid hard-fork ticket, bad signature, insufficient downtime, etc.).
5. Update the main spec document with the exact ABI tuple definition for `RawTicket`.

## 7. Open Technical Decisions to Resolve Quickly

- Do we require `governanceRef != 0` for `HARD_FORK_ACTIVATION` tickets in the first version?
- How do we handle very large `attestation` blobs? (Store hash only + allow full report via separate mechanism?)
- Do we want a dedicated special transaction kind later for lower gas / better UX, or is calling the precompile address sufficient forever?

## 8. Critical Update: Hard Fork Signaling in v1 (2026-06-05)

Per latest requirements:

- There will be **no governance** for hard forks in the first version.
- Hard forks are signaled exclusively by the **current Block Producer(s)** via `HARD_FORK_ACTIVATION` tickets.
- The ticket **must** be signed by the currently active `pqPubkey`.
- The ticket **must** specify a concrete future block number (`activationHeight`) at which the new rules + new `newMeasurement` become mandatory (Ethereum-style scheduled fork).

This significantly changes the authorization logic for `HARD_FORK_ACTIVATION` compared to `PRODUCER_RECOVERY`:

- Recovery tickets: can come from hot standbys (permissionless path after downtime).
- Hard fork tickets (v1): only the current producer can credibly announce them.

The precompile must enforce that for `ticketType == HARD_FORK_ACTIVATION`, the signer of the ticket equals the current recorded producer key at the time of submission.

`forkSpecHash` becomes mandatory and meaningful (points to the specification of changes that will take effect at the scheduled block).

---

This document is intentionally kept inside 2d-hsm for now, exactly as requested.

Next concrete deliverable I can produce immediately after feedback: a working Elixir decoder + test vectors for the `RawTicket` structure.

## 9. Header Versioning for Hard Fork Enforcement (Ethereum-style + your observation)

You are right — this is a key point.

In Ethereum, hard forks are activated at a specific block number (or timestamp). Clients have the fork block hardcoded. When the chain reaches that height, new rules apply. Nodes that did not upgrade their software simply cannot validate the new blocks correctly (new fields in header, new EVM behavior, new transaction types, etc.) and either get stuck or follow a divergent minority chain.

For 2D, we can make this even more explicit and on-chain:

**Recommended design:**

- Add a `version` field to the 2D block header (small integer, similar to Tendermint's `Version` or Bitcoin's `nVersion`).
- The `HARD_FORK_ACTIVATION` ticket (sent by the current producer) includes:
  - `activationHeight` (specific future block)
  - `newMeasurement`
  - `forkSpecHash`
  - `newHeaderVersion` (the version number that must appear in headers from that block onward)

- Enforcement in every reader, verifier, and the producer code itself:
  - For all blocks with `number >= activationHeight` from a valid hard fork ticket:
    - `header.version` MUST equal `newHeaderVersion`
    - The block must be produced by a TEE whose measurement matches the one in the ticket
  - Blocks that violate this are invalid and rejected.

**Consequence for nodes that "don't read the message" (as you said):**

They will see one of two things after the scheduled block:
1. Headers with a version they don't recognize → reject.
2. Valid-looking version + signature, but state root / precompile behavior that doesn't match what their old software expects → they compute a different state root or fail validation.

In both cases, they naturally stop following the main chain. This is the desired "they get stuck" behavior, exactly like non-upgraded Ethereum nodes after a fork block.

This approach gives us:
- Clear on-chain commitment from the producer (via the signed ticket)
- Cryptographic binding to TEE measurement
- Simple, local check for all verifiers and light clients (just look at header.version + cross-check with latest on-chain fork ticket)
- No reliance on social coordination for "did everyone upgrade?"

We should decide soon what the initial version value is and how we plan to bump it on the first hard fork.

## 10. Opinion on Adding Block Header Version (response to "Да вроде нормально с версией")

**Да, я тоже считаю, что с версией — нормально и даже очень хорошо.**

### Почему это сильное решение именно для вашего случая:

1. **Простота и надёжность детекции**
   - Версия в заголовке — это самое раннее и дешёвое место для проверки несовместимости.
   - Reader nodes, light clients, explorers, мосты могут отваливаться на первой же проверке `if height >= fork_height and header.version != expected_version → reject`.
   - Не нужно ждать вычисления state_root, чтобы понять, что что-то пошло не так.

2. **Хорошо сочетается с вашей моделью single producer + TEE**
   - Продюсер (через тикет) явно объявляет "с блока N будет version = 2 и measurement = XXX".
   - Это даёт криптографическое обязательство от текущего продюсера + TEE.
   - Версия в заголовке делает это обязательство видимым для всех.

3. **Естественное "застревание" неготовых нод** (как ты и сказал)
   - Ноды без обновления увидят либо:
     - Неизвестную версию заголовка → immediate reject, или
     - Версию 2 + старый код → не смогут правильно исполнять новые прекомпайлы / state transitions → разные руты или ошибки.
   - Это именно то поведение, которое ты хочешь: они просто останавливаются.

4. **Похоже на проверенные паттерны**
   - Tendermint/CometBFT: Version.Block + Version.App в заголовке.
   - Bitcoin: nVersion (хотя больше для signaling soft forks).
   - Ethereum: неявно через появление новых полей в заголовке + hardcoded fork blocks в клиентах.

### Что я рекомендую сделать с версией технически:

- Сделать поле `version: smallint` или `integer` в таблице `blocks` и в структуре блока.
- Включить его в расчёт `block_hash` (это критично для безопасности).
- В `HARD_FORK_ACTIVATION` тикете добавить поле `new_header_version`.
- В `finalize_block` и верификации добавить явную проверку версии после activationHeight.
- При первом хардфорке поднять версию с 1 на 2 (или с текущей на +1).

**Моё мнение**: добавление явной версии в заголовок — это одно из самых чистых и правильных решений для вашей ситуации. Оно дешёвое в реализации, очень заметное и отлично работает вместе с on-chain тикетом + TEE measurement.

Если хочешь, можем прямо сейчас набросать:
- Как именно изменить `finalize_block` и хэширование.
- Миграцию на таблицу blocks.
- Проверки в Verifier.Executor.

Что скажешь — стоит ли углубляться в этот кусок кода/миграции?
