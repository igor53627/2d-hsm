---
id: TASK-1
title: Implement custom minimal post-quantum signing service inside TEE
status: In Progress
assignee: []
created_date: '2026-05-31 12:43'
updated_date: '2026-06-02 22:00'
labels:
  - pq
  - hsm
  - tee
  - signing
  - 2d
  - security
dependencies:
  - TASK-2
  - TASK-3
references:
  - backlog/tasks/task-4 - NixOS-reproducible-TEE-image-primary-delivery-path.md
  - impl/rust/enclave-protocol
  - backlog/docs/implementation-plan-vsock-api-and-hard-fork.md
  - backlog/docs/authorization-tickets-precompile-spec-draft.md
documentation:
  - impl/README.md
  - AGENTS.md
priority: high
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
We need a lightweight, highly auditable signing service (effectively our own software HSM) that runs inside a Trusted Execution Environment (TEE) and provides native support for post-quantum signature algorithms required by the 2d BlockProducer and bridge infrastructure.

## Context and Motivation

2d currently uses Nitrokey NetHSM (the software image) as the backend for operator and bridge signing. Access is mediated through a paranoid multi-layer path: local policy → OPA (Rego) → Vault (short-lived credentials) → NetHSM REST API.

As of mid-2026, the official Nitrokey NetHSM image does not yet have production support for NIST post-quantum signature algorithms (ML-DSA / Dilithium and SLH-DSA / SPHINCS+). The device is marketed as 'PQC-ready' (architecture allows software updates), but there is no committed timeline.

At the same time, 2d has a strategic direction toward 'software-NetHSM-in-TEE' (documented in doc-3 and actively prototyped in TASK-62 on SEV-SNP). The long-term posture is to run sensitive signing logic inside confidential VMs / enclaves rather than relying on external physical or opaque software HSMs.

For post-quantum work, 2d will need a signing backend capable of Dilithium (ML-DSA) and/or SPHINCS+ (SLH-DSA). Instead of waiting for vendor support, we intend to build a minimal, purpose-built service.

## Why a custom minimal service?

Instead of:
- Waiting for Nitrokey to ship PQC support, or
- Forking and maintaining a heavy general-purpose HSM image,

we propose building a purpose-built, minimal signing service that:
- Only implements the operations 2d actually needs.
- Is designed from day one to run inside TEEs (Nitro Enclaves, SEV-SNP, etc.).
- Natively supports the required post-quantum algorithms (starting with ML-DSA, with SLH-DSA to follow).
- Can be made auditable end-to-end.
- Integrates cleanly into the existing multi-layer authorization model (SignerPolicy + OPA + Vault).
- Supports the permissionless on-chain recovery + hot-standby model for the single BlockProducer (the core of long-term automatic operation).

Because the service will run inside a TEE, many traditional HSM hardware security requirements are significantly reduced — the TEE itself becomes the primary trust boundary for key material.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Define the minimal set of signing operations required by 2d BlockProducer and bridges
- [ ] #2 Choose implementation language and crypto stack (proposed: Rust + liboqs)
- [ ] #3 Design the service to run inside supported TEEs (Nitro Enclaves / SEV-SNP)
- [ ] #4 Implement support for at least one NIST PQC signature algorithm (ML-DSA recommended first)
- [ ] #5 Define integration approach with existing Chain.Bridge.Signer + OPA + Vault flow
- [ ] #6 Document key management, attestation, and operational model inside TEE
- [ ] #7 Inventory and document the exact operations currently performed by Chain.Bridge.Signer against NetHSM (including any pre- and post-processing done in Elixir)
- [ ] #8 Define the minimal set of operations the new service must support for 2d BlockProducer and bridge signing paths
- [ ] #9 Design and document the integration boundary with the existing multi-layer signing flow (SignerPolicy + OPA + Vault credential brokering)
- [ ] #10 Specify TEE runtime requirements and attestation model (Nitro Enclaves and/or SEV-SNP)
- [ ] #11 Implement support for at least ML-DSA (Dilithium) with the parameter sets required by 2d; SLH-DSA (SPHINCS+) support is a stretch goal for MVP
- [ ] #12 Achieve remote attestation verification on the caller side before trusting the service. _Partial: reference verifier `snp_verify::prevalidate_report` (structure + report_data key binding + measurement allowlist + DEBUG-off, tested vs golden); VCEK→ASK→ARK cert-chain to the AMD root remains the caller's job (see acceptance #3)._
- [ ] #13 Define the on-chain RecoveryTicket format, issuance rules (permissionless special tx after ~1h downtime for 2s blocks), TEE attestation binding, and activation semantics for BlockProducer failover
- [ ] #14 Design client/reader node verification rules that reject blocks from unauthorized producer keys or with invalid state transitions (including forged 'stay' transitions)
- [ ] #15 Specify how the TEE signing service uses the network (genesis + recent headers + on-chain recovery history) as a cryptographic second factor for freshness before signing
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Phase 0 – Discovery & Requirements (1-2 weeks)
- Full inventory of current signing call sites and data flows in the 2d orchestrator and BlockProducer (focus on producer namespace / block-header path first).
- Precise definition of the minimal operations that must be supported by the new service (BlockProducer canonical root / header digest signing is priority #1).
- Decision on API shape (how close to NetHSM REST we stay vs a clean internal protocol, especially vsock for TEE).
- Definition of TEE runtime requirements and attestation expectations.
- Detailed design of the permissionless RecoveryTicket format, 1h downtime detection rules, on-chain activation, reader node verification policy, and "network as second factor" freshness checks inside the enclave (this is now a first-class architectural requirement).

Phase 1 – Architecture & Design (1-2 weeks)
- High-level architecture of the service (language choice, crypto stack, TEE packaging — reproducible build critical).
- Detailed design of the secret-dependent core (what exactly runs inside the protected environment; sealing of the long-term PQ BlockProducer key).
- Interface definition between the Elixir side (BlockProducer / dedicated signer shim) and the signing service.
- Security & threat model document, including "malicious producer who obtained a valid recovery ticket" and supply-chain attacks on the public encrypted image.
- Concrete spec for RecoveryTicket (precompile or contract), attestation binding, hot-standby readiness registration, and client-side rejection rules for invalid state transitions.

Phase 2 – Core Implementation (3-5 weeks)
- Skeleton + CI + reproducible build for the TEE image — **primary path: TASK-4 (NixOS flake + measurement manifest)**; `cargo`/Ubuntu scripts remain dev-only fallback until TASK-4 AC #7–#8 are met.
- Implementation of the first PQ algorithm (ML-DSA recommended; parameter sets matching 2d requirements).
- Basic key management, sealing, and remote attestation support inside the TEE.
- Minimal light-client / freshness verifier inside the enclave (genesis + recent headers as second factor).
- Local + SEV-SNP development loop on aya (or equivalent).

Phase 3 – Integration & Validation (2-3 weeks)
- Thin adapter or direct integration from the BlockProducer (producer namespace path — low latency, fixed digest shape) and Chain.Bridge.Signer (bridge paths).
- End-to-end smoke tests using the existing pilot topology (including one simulated "primary down → recovery ticket → hot standby activation").
- Performance baseline on the **SNP host CPU** (AMD EPYC, e.g. aya's 9375F): ML-DSA-65 sign+verify latency + throughput vs the ~2s block budget. (Hot-path signing is a CPU op inside the SEV-SNP enclave — no GPU. The earlier "B200" referred to the **GPU slow path** — MAYO-iO in theory-378 — which is a separate service and not measured here.)
- Remote attestation verification in the caller + on-chain ticket path (reader node side).

Phase 4 – Hardening & Documentation (1-2 weeks)
- Security review and threat model validation (key never leaves TEE; network second factor actually works).
- Operational runbook (deployment of encrypted public image, hot standby launch procedure, attestation, monitoring, recovery event response, key rotation inside TEE, incident response for TEE compromise or malicious producer).
- Documentation for 2d operators, reader node operators, and auditors (how to verify authorized producer history, what clients must check).
- Cross-link to 2d doc-3 topology updates.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
=== Architectural Principles (2026-05-31, updated 2026-06-05) ===

**Minimalism and Auditability**
The service should do as little as possible. Every additional feature increases the attack surface and audit burden. We deliberately do *not* aim for general-purpose HSM feature parity.

**TEE as the Primary Security Boundary**
Because the service will run inside a modern TEE (Nitro Enclaves or SEV-SNP), many traditional HSM hardware security requirements are significantly reduced. The TEE itself provides memory encryption, attestation, and isolation from the host. The main remaining concerns are:
- Correct implementation of the cryptographic operations
- Secure key lifecycle inside the TEE (generation, sealing, rotation, destruction)
- Remote attestation (verifying that the expected code is running in a genuine enclave)
- Supply chain / build reproducibility

**Integration with Existing 2d Signing Flow**
The current bridge and operator signing paths go through a multi-layer model:
- Chain.Bridge.SignerPolicy (local)
- OPA/Rego policy evaluation
- Vault (short-lived credentials for NetHSM)
- Actual signing call

The new service should be pluggable into this model with minimal changes to the Elixir side. Two main integration strategies are under consideration:
1. Keep the existing flow as much as possible and only replace the final signing step (thinnest change) — especially for the low-latency `producer` namespace path used by BlockProducer for fixed-shape block-header digests.
2. Introduce a more native integration where the service can receive richer context (e.g., full envelope + policy decision) and perform more of the authorization logic internally (more relevant for bridge paths).

**Post-Quantum Focus from Day One**
Unlike traditional HSMs that are being retrofitted with PQC, this service is being designed with post-quantum algorithms as a first-class requirement. This allows us to make different trade-offs (e.g., around batching and what parts of the algorithm are worth protecting).

**BlockProducer + Permissionless Hot Standby + TEE Availability**
The primary long-term consumer for the BlockProducer path is the single active producer (2s block target). A hot standby instance ("под паром") runs the same encrypted TEE image, can prove readiness via on-chain tickets, and can be activated permissionlessly when the active producer stalls for a catastrophic threshold (~1h of no tip advance). See the dedicated section below for the full model. TEE/GPU availability remains a signal for graceful step-down / leader election, but the permissionless ticket mechanism is the automatic, human-free recovery path for decades-long operation.

=== Open Questions & Considerations (2026-05-31, updated 2026-06-05) ===

**Key Protection inside TEE (highest priority)**
- Как именно мы гарантируем, что приватный ключ (особенно долгосрочный PQ ключ) никогда не покидает enclave в открытом виде, даже при дампе памяти, краше процесса или атаке на хост?
- Какой механизм sealing мы будем использовать (например, через vTPM, через platform-specific sealing keys, через remote attestation + key release)?
- Нужно ли нам поддерживать key rotation внутри TEE без извлечения ключа наружу?
- Как мы будем обрабатывать случай компрометации enclave (key erasure / zeroization)?

**Permissionless Hot Standby & On-Chain Recovery Tickets (primary failover path)**
- See the full design in the new section below. Key open items to resolve in Phase 1:
  - Exact on-chain representation (precompile at fixed 0x2D00 address vs. dedicated recovery contract in 2d-solidity).
  - Attestation verification: on-chain light verification of SEV-SNP/Nitro reports (measurement + key binding) vs. off-chain oracle + event for reader nodes.
  - Spam / griefing protection for permissionless ticket submission (gas, small bond that is burned on invalid, or rate-limit per address).
  - How the TEE service inside the enclave proves "liveness + readiness" periodically without revealing the sealed key.
  - Exact threshold constant (propose 3600s with grace for 2s target; validate against Solana historical multi-hour outages on 400ms slots and real-world 2s-chain expectations).

**Интеграция с текущим signing flow (producer namespace priority)**
- Насколько глубоко мы хотим интегрировать новый сервис в существующий путь (Chain.Bridge.Signer + OPA + Vault credential brokering)?
- Для BlockProducer (producer namespace) — прямой вызов из vm-bp в TEE сервис (низкая латентность, фиксированная форма дайджеста) — это приоритет #1.
- Оставляем ли мы текущую модель «Vault отдаёт креды → сервис подписывает», или переходим на модель, где enclave сам является более сильным trust boundary и Vault/OPA роль меняется?
- Нужно ли нам поддерживать одновременную работу со старым NetHSM и новым сервисом во время миграции?

**Минимальный набор операций**
- Какие именно операции (из Бакета C) мы обязаны реализовать в первой версии, чтобы сервис был полезен для BlockProducer (block header / canonical root подписи) и мостов?
- Есть ли операции, которые сейчас идут в NetHSM, но которые мы можем полностью убрать или сильно упростить, потому что они нам не нужны для PQ BlockProducer пути?

**Аттестация и Trust**
- Какой уровень remote attestation мы требуем перед тем, как доверять enclave (measurement, runtime claims, etc.)?
- Кто будет верифицировать attestation — сам BlockProducer / reader nodes, отдельный attestation service, или это будет делаться на уровне on-chain ticket validation + reader node policy?
- Binding of attestation to the on-chain RecoveryTicket (the ticket must carry or commit to the report that binds tee_measurement + pq_pubkey).

**Долгосрочная эволюция (no iO drift)**
- Фокус строго на классических PQ подписях (ML-DSA mandatory, SLH-DSA stretch) + TEE + on-chain permissionless recovery. Гибридные iO схемы из theory-378 — отдельная исследовательская линия, не должны влиять на дизайн этого сервиса и его интеграцию в 2d (по явной просьбе).

Эти вопросы нужно проработать на этапе Architecture & Design (Phase 1).

=== Permissionless Producer Recovery via On-Chain Tickets (2026-06-05 — primary production model) ===

**Target Production Posture (verbatim from requirements)**
- Один активный BlockProducer всегда запущен в проде.
- Один hot standby стоит "под паром" (не производит блоки, но готов; может отправлять тикеты о готовности).
- Зашифрованный образ минимального PQ signing service (custom software HSM) можно хранить в публичном пространстве (S3, container registry, IPFS и т.д.). Кто угодно, у кого есть образ + правильный способ запуска (launch secret / decryption material, который работает только в подходящем TEE с нужным measurement), может поднять инстанс, зарегистрироваться через тикет и ждать активации "на свои риски".
- Право создавать recovery тикеты — permissionless: любой может отправить специальную транзакцию в 2D сеть, когда детектит даунтайм.
- Порог: при таргете 2 секунды на блок, 1 час без продвижения tip — "застрашный трешхолд" (catastrophic). Для сравнения: у Solana (400ms slots) исторически были полные остановки на 4–19 часов; даже короткие деградации вызывают тысячи пропущенных слотов. Для 2s-цепи 1800 пропущенных блоков — это уже не "нормальная задержка", а событие, после которого сеть ожидает автоматического восстановления.
- Если активный продюсер начнёт производить неправильные блоки (invalid state transitions, forged "stay" transitions, которые на самом деле не происходили), клиенты и reader nodes их просто не примут. Честные ноды продолжат смотреть на on-chain recovery history и примут следующего валидного продюсера, который построит корректное продолжение от последнего хорошего состояния.

**Почему это важно для 2d-hsm сервиса**
Сервис из TASK-1 — это и есть тот "правильный образ", который хранится публично в зашифрованном виде. Внутри TEE он:
- Генерит или unseals долгосрочный PQ ключ BlockProducer (тот, что сегодня живёт в `producer` namespace NetHSM).
- Экспортирует только публичный ключ + remote attestation report (binding measurement + pubkey + код).
- Подписывает только то, что ему скармливают (фиксированные block-header digests для продюсера).
- Может (и должен) требовать "network second factor" перед тем, как разрешить подпись.

**Concrete RecoveryTicket Proposal (Phase 1 детализация)**
Специальная транзакция / precompile call (предлагается зарезервировать fixed address в стиле 0x2D00... recovery).

Payload (примерная структура, будет в Solidity ABI или RLP для 2d):

```solidity
struct RecoveryTicket {
    uint64  nonce;                    // защита от replay
    bytes32 last_good_tip;            // хэш последнего известного tip, который кандидат считает "зависшим"
    uint64  observed_downtime_sec;    // сколько секунд по наблюдению кандидата не было новых блоков
    bytes   tee_measurement;          // SEV-SNP measurement (or Nitro PCR composite) образа signing service
    bytes   pq_pubkey;                // ML-DSA / Dilithium pubkey, которым будет подписываться будущие блоки
    bytes   attestation;              // полный remote attestation report (SEV-SNP report + certificate chain)
    bytes   sig_by_pq_key;            // подпись pq_privkey над (nonce || last_good_tip || ... || pq_pubkey)
}
```

Валидация on-chain (precompile / contract):
1. Текущий tip на момент включения тикета не продвинулся относительно `last_good_tip` дольше порога (threshold = 3600s + небольшая grace, напр. 120s для propagation).
2. `attestation` валидно (корректная цепочка до AMD root / AWS Nitro root, measurement соответствует опубликованному ожидаемому для данного релиза образа).
3. `sig_by_pq_key` валидна под `pq_pubkey` (доказывает, что ключ реально живёт внутри этого TEE).
4. (опционально) `pq_pubkey` не в blacklist (если предыдущий продюсер был злокачественным).

После финализации тикета (или короткого confirmation window) — on-chain storage обновляется:
`current_authorized_producer = (pq_pubkey, tee_measurement, activated_at_block)`

Reader nodes и клиенты с этого момента принимают только блоки, подписанные этим ключом (или следующим после нового recovery).

**Hot Standby Readiness Flow ("под паром")**
- Горячий резерв запускает тот же публичный зашифрованный образ в своём TEE.
- Периодически (или по триггеру) отправляет "ReadinessTicket" / "ProducerCandidate" — облегчённую версию (без требования downtime): "я жив, у меня measurement X, pubkey Y, я готов принять производство".
- Это позволяет нескольким кандидатам "зарегистрироваться" заранее, не спамя recovery path.
- Когда primary падает — первый (или любой) валидный recovery ticket от готового кандидата активирует его.

**Client & Reader Node Protection against Malicious Producer (the real backstop)**
Это именно то, о чём ты сказал: "Если блок-продюсер будет производить неправильные блоки, то клиенты не будут принимать некоторые риски, снимаемые, если вдруг сделать какой-то state transition, которого на самом деле не было".

Каждый reader node / RPC node / light client / bridge verifier ДОЛЖЕН:
1. Проверять, что блок (или его header / canonical root) подписан **текущим** `current_authorized_producer.pq_pubkey` (берётся из on-chain recovery истории + genesis bootstrap key).
2. Полностью реплеить state transition (execute_transactions → recompute state_root / tx_root / block_hash) и сравнивать с заявленным — ровно как сейчас делает `Chain.Verifier.Executor`.
3. Проверять parent_hash continuity, monotonic timestamp (TASK-107), отсутствие gaps.
4. Для "stay transition" / поддельных переходов — если заявленный state_root не соответствует тому, что получается при честном исполнении включённых tx (или если txs пропущены, а root "как будто ничего не изменилось") — блок **отвергается**.

Результат:
- Злонамеренный продюсер (даже получивший recovery ticket честным путём) не может заставить честную сеть принять фейковый state.
- Честные клиенты просто игнорируют его цепочку.
- Сеть остаётся живой: достаточно отправить новый recovery ticket с честного hot standby, который продолжит от последнего **принятого** хорошего состояния.

Это и есть криптографический "network as second factor" на уровне клиентов.

**Network (genesis + headers + on-chain state) как криптографический Second Factor для самого TEE Signer**
Ранее обсуждали YubiKey — не подходит для автоматической работы десятилетиями.

Вместо физического второго фактора — сама сеть:

Внутри TEE signing service (то, что мы пишем в TASK-1) реализуется минимальный light client / freshness verifier:
- При старте / unsealing enclave получает (по аттестованному каналу, vsock) recent header chain + proofs от хоста.
- Enclave содержит hardcoded или загружаемый genesis + trusted checkpoint + корневой authorized pubkey.
- Проверяет подписи в цепочке заголовков (используя историю recovery тикетов, которую может запросить или получить в виде compact proof).
- Только после успешной проверки свежей consistent view сеть "армит" ключ для подписи блоков.
- Периодически, перед подписью очередного блока, хост подкармливает enclave свежий tip + короткий incremental proof; enclave отвергает подпись, если view не консистентен.

Эффект:
- Скомпрометированный хост не может заставить enclave подписывать на фейковой вилке или после долгого отключения без реального сетевого контекста.
- TEE + on-chain ticket + реальная сеть (genesis + недавние finalized headers) = полный permissionless, автоматический, без-людской механизм авторизации долгосрочного BlockProducer ключа.

**Интеграция с текущим 2d (doc-3 топология + producer namespace)**
- Сегодня: BP host → прямой путь в `producer` namespace NetHSM (фиксированная форма, нет OPA/Vault gate, низкая латентность).
- Будущее: тот же прямой путь, но вместо NetHSM — вызов в наш minimal PQ signing service внутри TEE (на том же хосте или dedicated SEV-SNP VM).
- Reader nodes (RPC) и внешние клиенты видят только подписи + state roots; они будут проверять against on-chain authorized producer.
- Bridge signing paths (calldata-aware) могут продолжать использовать старую параноидальную цепочку или мигрировать на bridge-specific instance того же TEE сервиса позже.

**Risks & Mitigations (explicit)**
- Malicious hot standby запускает образ и пытается захватить производство → клиенты отвергают его блоки, если он кривится; новый ticket может его быстро выкинуть.
- Spam recovery tickets → gas cost + on-chain threshold gate + возможно small bond.
- Attestation root compromise (AMD PSP 0-day) → это уже за пределами модели TEE (как и сегодня в doc-3); mitigated by reproducible builds, published measurements, multiple TEE vendors в будущем.
- "Stay transition" forgery → полностью закрывается client-side replay verification (Verifier.Executor уже делает это).

**Next Steps for this model in TASK-1**
- Phase 0/1: детализировать ticket формат + precompile spec + reader node policy.
- Phase 1: threat model "malicious producer with valid ticket".
- Phase 4 (runbook): процедура "как оператору безопасно поднять hot standby из публичного зашифрованного образа", "как реагировать на recovery event", "как клиенты/эксплореры обновляют список authorized producers".

=== Hard Fork Coordination via the Same Ticket Mechanism (2026-06-05 brainstorm) ===

The permissionless RecoveryTicket + TEE measurement + client enforcement pattern generalizes very naturally to hard forks.

Idea: extend (or type) the ticket to support HardForkActivation.
- Ticket carries `new_code_measurement` (the TEE measurement of the updated signing service + executor/precompile logic for the fork).
- Hot standbys can pre-launch the *new* encrypted image and prove readiness for a specific fork version.
- On-chain activation records the new expected measurement + fork spec.
- Reader nodes and clients switch enforcement rules at the activation height: only accept blocks produced under the new measurement + new rules.
- The enclave running the *new* code uses the network (presence of its own activation ticket in recent finalized state) as a second factor before it will start signing under the forked rules.

This turns the mechanism into a general "TEE-attested, permissionless, client-enforced state transition authorization" primitive.

Benefits: dramatically less social coordination for forks, strong cryptographic evidence of "what code is actually live", unified hot-standby story for both failure recovery and planned upgrades.

Open questions (to be worked in Phase 0/1 alongside recovery design):
- How is the "blessed" new_measurement for a fork decided? (Governance proposal emitting it? First valid attested ticket? Hybrid?)
- Interaction with existing halt_consensus, BridgeHalt precompile, Mainnet Release Gate (TASK-26.6.3), and governance.
- Measurement scope (only signer vs full producer stack).
- Activation height semantics (seamless vs explicit halt window).

See the detailed exploration in `backlog/docs/permissionless-blockproducer-recovery-tickets.md` → section "Using the Same Mechanism for Hard Forks".

This direction should influence the ticket format (make it extensible with `ticket_type` or `action`) and the claims the TEE service must be able to produce.

**Detailed technical draft now available**

A focused spec document with:
- Unified `AuthorizationTicket` struct (covers both PRODUCER_RECOVERY and HARD_FORK_ACTIVATION)
- Full Solidity-compatible ABI for the precompile interface
- Proposed precompile address: 0x2D000000000000000000000000000000000000A0
- Special transaction vs precompile call options
- On-chain storage sketch
- Reader/client verification rules
- Direct implications for the TEE signing service (what claims and vsock APIs it must support)

is here:

`backlog/docs/authorization-tickets-precompile-spec-draft.md` (v0.1, 2026-06-05)

All of this is intentionally kept inside the 2d-hsm repo for now. We will decide later whether to move the spec, reference implementation, or precompile code into the main 2d repository or keep it as a semi-independent module.

=== Recommended Next Steps (as of 2026-06-05) ===

**Priority 0 (this week / early next week) — Ground the spec in reality**
- Study existing precompile implementation pattern (especially Chain.Precompiles.BridgeHalt + Chain.Precompile behaviour + Registry + Context).
- Produce a concrete wire format + ABI encoding document for AuthorizationTicket submission (special tx vs precompile calldata).
- Draft the actual Elixir precompile skeleton (Chain.Precompiles.AuthorizationTickets) following the real BridgeHalt style (selectors, ABI decoding, execute/3, error handling, state writes).

**Priority 1 (next 1-2 weeks)**
- Define the exact TEE service vsock API surface needed to support ticket generation + network second factor checks.
- Decide on attestation handling strategy (full report vs hash + registry).
- Write test vectors (valid + invalid tickets) and a small reference encoder/decoder.

**Priority 2 (parallel, lighter)**
- Map how AuthorizationTickets should interact with existing halt_consensus + governance machinery.
- Update the main 2d docs (doc-3, architecture) with high-level arrows (non-blocking for 2d-hsm work).
- Decide long-term ownership: keep the precompile + spec inside 2d-hsm, move to main 2d, or extract.

**Do not do yet**
- Full implementation of the precompile or the TEE service changes.
- Any changes in the main 2d repository until we have a stable v0.2 spec + skeleton.

All current detailed artifacts:
- authorization-tickets-precompile-spec-draft.md (ABI + high-level design)
- permissionless-blockproducer-recovery-tickets.md (motivation + hard fork reuse)

**Concrete artifact just produced (2026-06-05)**

New document created:
→ `authorization-tickets-wire-format-and-precompile-skeleton.md`

It contains:
- Real learnings from BridgeHalt + Chain.Precompile behaviour
- Proposed exact precompile address and selectors
- Refined ABI (submit(bytes) pattern)
- Detailed RawTicket ABI tuple encoding
- Full Elixir precompile skeleton following the actual 2D style (including error handling, decoding, state write expectations)
- Immediate 3-5 day action list

This is now the best next concrete thing to iterate on.

**Important design decision recorded (2026-06-05)**

User clarified v1 scope for hard forks:

- No governance in the first version.
- Hard forks are signaled by the current Block Producer(s) via HARD_FORK_ACTIVATION tickets.
- The ticket must be signed by the currently active pqPubkey.
- Must include a specific future block number (`activationHeight`) — Ethereum style scheduled fork activation.

This means:
- PRODUCER_RECOVERY remains relatively permissionless (hot standby path).
- HARD_FORK_ACTIVATION in v1 is a producer-driven announcement mechanism, not a permissionless activation.

All three main design documents have been updated with this constraint:
- authorization-tickets-precompile-spec-draft.md
- authorization-tickets-wire-format-and-precompile-skeleton.md
- permissionless-blockproducer-recovery-tickets.md (cross-reference)

This has direct impact on precompile validation logic and on what the TEE signing service needs to support when the current producer wants to announce a fork.

**User input on hard fork enforcement (2026-06-05)**

User emphasized:
- In v1 there is no governance for hard forks.
- Hard forks are signaled by current Block Producers via messages/tickets.
- Activation happens at a specific future block number (Ethereum model).
- Nodes that do not process/accept the hard fork message will simply stop progressing ("останутся на каком-то блоке и дальше не будут идти").
- Very likely we should introduce **block header versioning** as part of the fork (change the version field in the header when the fork activates).

This aligns perfectly with the current design direction. Documents updated accordingly:
- Strong recommendation to add explicit `version` field to 2D block headers.
- Enforcement: after the scheduled `activationHeight`, headers must carry the new version + producer must use the new TEE measurement from the ticket.
- Non-aware nodes naturally stall or reject — exactly the desired outcome.

This makes the combination (on-chain producer ticket + scheduled block + header version) the primary enforcement mechanism for hard forks in v1.

**User feedback + assessment (2026-06-05)**

User: "Да вроде нормально с версией."

Assessment: Согласен. Добавление явного поля `version` в блок-хедер — одно из самых правильных и практичных решений для v1 hard fork механизма.

Преимущества:
- Раннее отсечение несовместимых нод (ещё до проверки state_root).
- Делает scheduled hard fork очень видимым на wire уровне.
- Отлично сочетается с producer-signed HARD_FORK_ACTIVATION тикетом + TEE measurement.
- Ноды без обновления будут естественным образом застревать (как и ожидалось).

Рекомендация: 
- Добавить `version` в структуру блока и расчёт hash.
- Включить `new_header_version` в HARD_FORK_ACTIVATION тикет.
- Поднимать версию при каждом хардфорке.

Документы обновлены с конкретными предложениями по реализации.

**New task created (2026-06-05)**

TASK-2 created: "Design and implement vsock API + wire protocol for TEE signing service (Authorization Tickets + Hard Fork flows)"

This task is now the concrete next step. We are starting implementation work on the vsock API because we are building a real hard fork mechanism.

First artifact produced for TASK-2:
→ backlog/docs/vsock-api-wire-format-spec-draft.md (v0.1)

The document already contains:
- Rationale
- High-level command groups
- Initial command set (GET_MEASUREMENT, SIGN_AUTHORIZATION_TICKET, ARM_FOR_PRODUCTION, etc.)
- Security invariants (especially important for hard fork tickets)
- End-to-end hard fork flow sketch using the API
- Immediate next steps

We are moving from design into actual protocol definition and skeletons.

### Merged to main (2026-06-02, squash `60eeefc` — PR #1)

**PQ seal v1 staging slice (reference crate + offline CLI):**
- ML-DSA-65 ticket signing in `enclave-protocol` (`ml-dsa-65` feature); mock PQ only without the feature.
- Seal v1 (ChaCha20-Poly1305 + measurement digest + provisioning root); v0 XOR **test-only**.
- `set_pq_seal_v1_provisioning_root` at boot (not vsock); install once + mutex across verify/install.
- Offline `pq-seal-v1` CLI (`seal`, `verify`, `meas-digest`, `generate-keypair`); seal APIs behind `pq-seal-provisioning` (not in deploy enclave binary).
- Staging runbook: `backlog/docs/pq-seal-v1-provisioning-runbook.md`; vsock spec §2.1 updated.
- Roborev: Reduced + 2×3 + compact on high-risk paths; PR bot findings addressed in follow-up commits.

**Explicit follow-ups (still TASK-1):**
- Platform root derivation (vTPM / SNP / Nitro) → `set_pq_seal_v1_provisioning_root`.
- CI gate: no `reference-seal-v1-root` / testvectors in production artifacts.
- Verify path without copying SK into non-zeroizing `MlDsa65Signer` (accepted debt; runbook §8 documents CLI memory exposure).
- Full operator runbook (AC #5 / DoD #5): hot standby, attestation ceremony, incident response — beyond PQ seal slice.
- Elixir / Vault integration (AC #9 / DoD #6), remote attestation on caller (AC #12 / DoD #3).

### Current plan (2026-06-02 — next major increment)

**Prerequisites in tree (TASK-2 / TASK-3):**
- Reference crate `impl/rust/enclave-protocol/`: vsock framing, canonical `ticketHash`, enclave state machine (arm / hard-fork gating), Producer Chain Attestation v1 (TASK-3).
- **ML-DSA-65 + seal v1 install** — done in reference crate (see merged slice above).

**2026-06-03 — Staging ML-DSA on dev transport (branch `feat/task-1-staging-mldsa-dev-transport`):**
- Feature `staging-host`: `enclave-uds-staging` installs reference sealed signer at boot; shared `EnclaveState`.
- Tests with `reference-test-key`: fail-closed SIGN without seal; framed arm→HF asserts `ML_DSA65_SIGNATURE_LEN`.
- Dev mock path unchanged: `test-support` + `demo-mock-sign` (64 B).

**Recommended next slices (TASK-1):**
1. **Platform provisioning root** in real TEE images (wires `set_pq_seal_v1_provisioning_root`).
2. **Production build policy** — block `reference-seal-v1-root` in deploy artifacts.
3. **Key-handling hardening** — verify-without-signer-copy; `resolve_provisioning_root` out-param + zeroize (roborev compact #6670 low/medium debt).
4. Sync with **2d** precompile / header signing policy (same ML-DSA key as tickets?).

**Parent repo next increment:** **TASK-2** — vsock transport, Elixir shim, wire migration (see TASK-2 notes).

**Algorithm policy (agreed direction):**
- **ML-DSA** — primary for BlockProducer (~2s blocks) + AuthorizationTicket `pq_pubkey` / `signature` (size + latency).
- **SLH-DSA** — stretch / rare high-assurance paths only; not hot block-signing path.
- **Ed25519** (TASK-3) — separate producer **attestation** key for `RecentChainProof`; not a substitute for ticket PQ signatures.

**Out of scope for first TASK-1 slice:** Elixir shim (TASK-2 Phase 4), real vsock transport, full light client, SLH-DSA, theory-378 iO hybrids.

**Dual-path (2d TASK-122 / theory-378 TASK-92.1.8):** This service = **hot path only** (ML-DSA-65 every block + tickets). Optional **slow path** = MAYO-iO in theory-378 (~10 min checkpoints); must not change vsock/ticket wire format. No ML-DSA-in-iO on critical path.

**Blocked on / needs sync with 2d:** precompile verify hook shape; whether block-header digests use same ML-DSA key as tickets (default: yes).

See `backlog/docs/implementation-plan-vsock-api-and-hard-fork.md` § Progress update (2026-06-02).

**2026-06-06 — TASK-1.1 platform provisioning root (slice #1 above; branch `feat/task-1.1-snp-derive-root`, PR #21):**
- New crate `impl/rust/snp-derive-root/` (binary, NOT forbid-unsafe) owns `SNP_GET_DERIVED_KEY` on the
  guest-only `/dev/sev-guest` — the one ioctl `enclave-protocol` (`#![forbid(unsafe_code)]`) cannot do.
  Derives `root = SHA3-256("2d-hsm-pq-seal-v1-root" ‖ snp_derived_key)`, firmware key bound by default
  to launch MEASUREMENT (`guest_field_select` bit 3) under VCEK. Secret-to-platform, stable per-image,
  measurement-bound. Enclave **unchanged**: still reads the root only via `TWOD_HSM_PQ_SEAL_V1_ROOT_FILE`.
- CLI: `--out` (0600 boot file) / `--print` (ceremony) / `--selftest` (in-guest validation, secret-free
  SHA3-256 commitment) / `--field-select` / `--root-key` / `--svn`. 5 off-SNP unit tests (ABI sizes,
  `_IOWR('S',0x1,..)`=`0xC0205301`, derivation, no-device error). Clippy clean.
- Nix: `.#snp-derive-root` pkg; `.#disk-production-lab-selftest` image runs `--selftest` boot oneshot.
  Default outputs unchanged (lab, non-mainnet). CI builds + tests the crate. Runbook §7 documents the
  production ceremony.
- **Status:** local + eval verified; ✅ replaces the lab test-vector root with a real platform-derived
  one. ⏳ **aya in-guest validation pending** (boot the selftest image under SNP; confirm 32-byte key,
  stable across two reboots, MEASUREMENT binding changes it). **Follow-up (not this PR):** fully
  sealed-boot mainnet artifact (re-seal a blob against the derived root, bake it) — needs the operator
  ceremony; vTPM/Nitro backends later.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 mix test (or equivalent) passes for the new signing service
- [ ] #2 Security review of the service is completed (at minimum: key never leaves TEE in plaintext, proper use of sealing/attestation, no obvious exfiltration paths)
- [ ] #3 Remote attestation verification is implemented and tested on the caller side before any signing request is accepted. _Partial: reference relying-party verifier `snp_verify::prevalidate_report` (feature `snp-verify`) checks report structure + `report_data` key binding + measurement allowlist + DEBUG-off, tested vs the committed golden report (6 tests). **Still open:** the VCEK→ASK→ARK signature chain to the pinned AMD root (ECDSA-P384 + X.509 + KDS) — intentionally out of the forbid-unsafe enclave crate; the BP/on-chain consumer must add it. See snp-attestation-verifier-policy.md._
- [ ] #4 Basic failover scenario between at least two instances of the service (on different hosts/enclaves) is designed and documented
- [ ] #5 Operational runbook exists covering: deployment into TEE, key provisioning/rotation inside TEE, attestation, monitoring, and incident response for TEE compromise or unavailability
- [ ] #6 Integration with 2d's existing signing path (Chain.Bridge.Signer + OPA + Vault) is implemented and passes relevant tests
- [x] #7 Performance baseline captured on the **SNP host CPU** (AMD EPYC, e.g. aya's 9375F) for the hot-path PQ algorithm (ML-DSA-65 sign+verify latency + throughput vs the ~2s block budget). **Measured on aya (AMD EPYC 9375F, `examples/bench_mldsa65.rs`, 2026-06-06):** sign **71.8 µs/op** (13.9k ops/s), verify **26.7 µs/op** (37.4k ops/s), sig 3309 B → sign+verify ≈ **98.6 µs/block = 0.005%** of the ~2s budget (huge headroom). _Not a GPU/B200 workload — hot-path signing runs on the enclave CPU; the GPU "B200" path is the separate MAYO-iO slow path in theory-378._
- [ ] #8 Design + document the full permissionless on-chain RecoveryTicket + hot-standby model (including concrete format, 1h threshold rationale with Solana comparison, TEE binding, network-as-2nd-factor in the enclave, and client rejection rules for malicious producer state transitions)
- [ ] #9 Add/update reader node + light client verification spec that enforces authorized producer key + valid state transitions (covers 'stay transition' forgery case)
<!-- DOD:END -->
