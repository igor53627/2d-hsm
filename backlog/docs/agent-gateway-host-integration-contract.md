# Agent Gateway host policy + capability integration contract (TASK-7.5)

The 2D **host-side** integration contract for Agent Gateway callers: local validation, Agent
OPA policy, Vault capability lookup, and `2d-hsm` command invocation. Host gates are
**defense in depth**; the **TEE is the only non-bypassable signer-policy boundary** — it
re-enforces every security-relevant check. Design/contract only (no enclave code; the TEE
behaviour is specified by TASK-7.1/7.2/7.4).

Consumes: `vsock-api-wire-format-spec-draft.md` §10 (opcodes, capability format, counter
scheme, error band), `agent-gateway-keystore-backup-format.md` (sealed authorities/state),
`agent-gateway-transfer-faucet-signing.md`, `agent-gateway-keygen-identity.md`,
`agent-gateway-secp256k1-signer-design.md` §Host-side policy boundary. Mirrors the 2D
`Chain.Bridge.Signer` / OPA / Vault pattern with **distinct agent-specific namespaces**.

## Decisions (adopted, TASK-7.5)

| Topic | Decision |
|-------|----------|
| Doc landing | A focused companion doc (this file), parallel to the other `agent-gateway-*.md`; design doc stays enclave-centric. |
| Capability carrier | Operator ceremony **pre-signs** Ed25519 capabilities (admin/recovery authority, offline) → stored in tiered Vault paths **indexed by `request_id`** → host fetches and forwards at envelope key 5. Host sees cap fields but cannot forge/mutate them (TEE re-verifies the signature). |
| `command_class` folding (AC#18) | **Coarse** default — **five** folded classes `generate_transfer`, `generate_faucet`, `configure_treasury`, `export_backup`, `restore_backup` (vsock §10.6), each its own `scope_target` lane so a stalled cap in one can't wedge another. Recovery has **two distinct** properties: `restore_backup` is its own folded `command_class` lane, **and** recovery ops (`RESTORE_BACKUP` + `reset_lifetime_breaker`) are sequenced by the **independent strict recovery counter** (never rolls back). Finer per-sub-op lanes are an operator-tunable if `configure_treasury` self-wedges. |
| Expiry / revocation | **Host-side only** (Vault short-TTL tokens / drop the pre-signed cap on revoke) **plus counter-burn** for hard revocation. The **TEE does not enforce expiry** (no clock) — residual, see §5. |
| Transfer dest/amount limits | **Host/OPA only** (`data.config` allowlist) — there is **no** TEE per-agent transfer destination/amount cap yet. Residual, see §5. |

## §1 The five capability tiers (host model) — AC#1

The host treats these as the canonical authorization classes; each maps to a distinct OPA
selector, Vault path/role, and counter `command_class`. The defining axes: **who issues** the
Ed25519 capability (`admin_authority_pk` vs `recovery_authority_pk` vs none), the
counter/replay scheme, and `scope_class`/`scope_target`.

The **exactly five** distinct capabilities are those AC#1 enumerates. **Runtime signing and
faucet-treasury signing are distinct** host authorization classes — different key purpose,
different OPA selector, different coarse runtime credential/role, different audit label — even
though neither carries a key-5 capability; a transfer-runtime credential MUST NOT reach faucet
signing.

| # | Capability (AC#1) | Commands | Issuer / key-5 cap | Counter | Scope |
|---|-------------------|----------|--------------------|---------|-------|
| **1 runtime signing** | `SIGN_TRANSFER`(4), `agent_transfer_k1` | **none** (no cap) | none — bounded by sealed key-purpose + canonical EIP-155 + sealed chain_id | transfer key |
| **2 faucet-treasury signing** | `SIGN_FAUCET_DISPENSE`(5), `agent_faucet_treasury_k1` | **none** (no cap) | none — bounded by sealed key-purpose + per-dispense/cumulative/lifetime caps + seal-before-emit | `to` ∈ active transfer-key set |
| **3 provisioning/refill** | `GENERATE_KEYS`(1: transfer count≥1 \| faucet count=1 singleton), `CONFIGURE_TREASURY`(6: set_limits/refill_budget/raise_lifetime_breaker) | `admin_authority_pk` | contiguous per `(authority,env,scope_class,scope_target)`; `command_class`∈{generate_transfer, generate_faucet, configure_treasury} | transfer=**fleet**; treasury+config=**enclave** |
| **4 backup export** | `EXPORT_BACKUP`(7) | `admin_authority_pk` (export role) | contiguous; `command_class=export_backup` | enclave |
| **5 restore/recovery** | `RESTORE_BACKUP`(8), `CONFIGURE_TREASURY` reset_lifetime_breaker | `recovery_authority_pk` (`is_recovery=true`) | **single strict recovery counter** — shared by restore + reset_lifetime_breaker (per vsock §10.6), never rolls back | enclave, fresh-TEE |

**Distinctness + ordering (AC#1/#2):** runtime signing < faucet-treasury signing (distinct
key purpose + spend caps), both < provisioning/refill < backup export < restore/recovery
(strongest). Within provisioning, treasury keygen/config (enclave) is stronger than
transfer-refill (fleet). No capability substitutes for another: the TEE re-derives it from
`(opcode, sub_op, key_purpose, scope_class, is_recovery)`, verifies the Ed25519 signature
against the **correct** sealed authority (admin vs recovery), and checks `payload_binding` —
none forgeable by the host. A transfer-refill cap cannot mint a faucet key (purpose+scope+
payload_binding differ); runtime/faucet signing authorize nothing privileged. The host MUST
keep runtime-transfer and runtime-faucet as **separate** credentials/OPA selectors so an
ordinary transfer caller cannot reach faucet signing even when the (TEE-enforced) caps would
bound the spend.

## §2 OPA + Vault namespacing (AC#3) — distinct from bridge/operator

**OPA:** package **`signer.agent_gateway`** (not `signer.bridge`); `POST
/v1/data/signer/agent_gateway` (optionally `/{command_class}`). `default allow := false`
(fail-closed). Result `{allow:true}` or `{allow:false, reason:"<atom>"}` with reason atoms in
a **disjoint** set from `Chain.Bridge.SignerPolicy`. `data.config` carries per-command toggles
(`enable_keygen_provisioning`, `faucet_signing_enabled`, `backup_export_enabled`,
`restore_enabled`) and host soft-caps (transfer destination/amount allowlist — §5 residual).
Input is a map `{opcode, command_domain, chain_id, environment_identifier, request_id,
key_purpose, scope_class, scope_target, command_class, payload{…}}` — the `payload` carries the
**command-specific fields OPA needs to decide**. For `SIGN_TRANSFER` / `SIGN_FAUCET_DISPENSE`
the policy-relevant fields are `{to, amount, nonce, gas_limit, gas_price}` so the OPA
destination/amount allowlist (the host-side transfer cap residual, §5) can evaluate them; for
`GENERATE_KEYS` `{key_purpose, count}`; for `CONFIGURE_TREASURY` the `sub_op` + new limit/budget
values. (The TEE re-validates the same fields it enforces; OPA's transfer dest/amount check is
the only place those limits exist today.)

**Vault:** five tiered paths `secret/data/agent-gateway/{runtime-transfer, runtime-faucet,
provision, export, recovery}`, one per AC#1 capability. The two `runtime-*` paths hold only a
**coarse access credential** (a token whose presence the host checks before a runtime signing
call — runtime ops carry **no** key-5 capability); `provision`/`export`/`recovery` hold the
operator-pre-signed Ed25519 **capabilities**. **Migration:** supersedes the earlier two-path
`AGENT_SIGNER_VAULT_{RUNTIME,PROVISION}_PATH` — `runtime` splits into `runtime-transfer`/
`runtime-faucet`, and `export`/`recovery` are added; the host config gains the new path vars.
The mount may be shared with bridge, but **path hierarchy + token ACLs are distinct and
cross-tier reads are denied at the Vault ACL** (each tier's token reads only its own path;
runtime-transfer ✗ runtime-faucet/provision/export/recovery; provision ✗ export/recovery;
export ✗ recovery). **Bridge tokens MUST NOT be reused** for agent ops (and vice-versa).
Audit/metric namespace `agent_gateway_*` (not `bridge_operator`).

**Vault-is-not-keys boundary (AC#3, verbatim):** Vault holds **authorization/capability
material for TEE commands only** — operator-pre-signed Ed25519 capability blobs (and/or
short-lived capability tokens) bound to `(authority, environment_identifier, scope_class,
scope_target, counter, payload_binding)` and indexed by `request_id`, plus coarse access-tier
credentials. Vault does **NOT** store: agent private keys (opaque 32-byte `key_ref` is
generated in-enclave, never host-supplied), sealed keystore state, backup-decrypt material
(the ML-KEM recovery **private** key lives only in the offline recovery environment; backups
are wrapped to the recovery **public** key), or the admin/recovery authority **private** keys.
A tampered Vault response is rejected at the TEE (`0x43`).

## §3 Host caller flow — DoD#1 (mirrors `Chain.Bridge.Signer`, distinct namespaces)

1. **Local validation** (pure, pre-network): `command_domain == "2d-hsm/agent-gateway/v1"`;
   `opcode ∈ {1..8}` (reject 0/9/10+); `request_id` format; `environment_identifier` surface
   format (`[a-z0-9-]`, 1–64, no leading/trailing/double hyphen); Agent-Gateway role (not
   producer); payload schema; host hard-caps where applicable. Fail-closed with a local-only
   error atom (disjoint from bridge atoms).
2. **Agent OPA policy:** `POST /v1/data/signer/agent_gateway` → `{allow}`. Deny ⇒ log/metric
   `{opa_reason}`, **no Vault call**.
3. **Vault capability lookup** (privileged opcodes **{1,6,7,8}** only — runtime signing {4,5} **and** read-only identity {2,3} **skip** this entirely):
   GET the **tier path** (provision/export/recovery), fetch the operator-pre-signed Ed25519
   capability indexed by `request_id`, for the counter tuple `(authority,
   environment_identifier, scope_class, scope_target)` — with `command_class` **folded into**
   `scope_target` — at the next `counter`; `chain_id` is a separate sealed-equality check carried
   in the cap, not part of the counter tuple. Apply credential-response redaction (deny-substrings, token-prefix,
   length cap) as in `Chain.Bridge.Signer.Credentials`. Missing/expired ⇒ fail-closed
   `{vault_error_code}` (no oracle). Host attaches the cap at envelope key 5 (cannot forge/alter).
4. **`2d-hsm` invocation:** open vsock to `AGENT_SIGNER_2D_HSM_ENDPOINT`; build outer frame
   (`len`, protocol_version, message_type `0x40`) + inner CBOR (`agent_version=1`, opcode,
   command_domain, request_id, capability key 5, key_ref/batch_id key 6, payload key 7); the
   TEE runs the full §10.5 verification chain.
5. **Response + audit:** success ⇒ `{r,s,recovery_id}` / sealed `key_ref`s / opaque backup blob;
   record into the host's **own** audit namespace (`agent_gateway_*`). Failures log per-surface
   `{opa_reason}` / `{vault_error_code}` / TEE `0x40–0x46` with anti-oracle collapse. The
   **in-enclave audit ring + `last_exported_seq`** (TASK-7.2) is authoritative; host audit is advisory.

## §4 Host-vs-TEE check matrix — AC#4 + AC#2 no-escalation

**Global host-only gates (advisory, not security-load-bearing):** command-domain string,
request_id/opcode/environment_identifier format, payload schema, OPA default-deny, Vault path/role tier,
host transfer dest/amount allowlist (§5 residual).

**TEE Frame gates (non-bypassable, ALL opcodes, before dispatch):** (1) **role/profile gate** —
producer-profile rejects every agent opcode (`0x41`), Agent-Gateway-profile rejects
producer/AuthorizationTicket frame types (0x01/0x10/0x20/0x30); fail-closed routing, never
falls back to producer. (2) opcode allow-list + `agent_version==1` (unknown/0/9/10+ → `0x40`).
(3) `command_domain`, and — where the request carries them — `chain_id`/`environment_identifier`
byte-equal the **sealed** values.

**TEE Capability gates (non-bypassable, ONLY privileged opcodes {1,6,7,8}; runtime {4,5} and
reads {2,3} carry no key-5 capability and are NOT subject to these):** (4) `cap_format_version`.
(5) **Ed25519 verify** of capability keys 1–12 against the correct sealed authority (admin vs
recovery by `is_recovery`). (6) `cap.command_opcode==request.opcode` &&
`cap.treasury_sub_op==request.sub_op` && `cap.request_id==envelope.request_id`. (7)
`scope_class`/`scope_target` match the cap and the sealed scope. (8) **contiguous counter** for
the tuple (incoming==highest+1; reject lower=replay, gap=skip-ahead; the recovery counter is
separate + strict, **shared** by restore + reset_lifetime_breaker). (9) `payload_binding == keccak256(
opcode || sub_op || request_id || canonical params)`.

**Then (any mutating opcode):** mutate + **seal-before-return**. Errors collapse anti-oracle
into `0x42`–`0x46`. Runtime/read opcodes have their OWN non-capability TEE checks (key-purpose,
faucet caps, domain separation), per-command below.

**Per-command host→TEE (selected):**
- **SIGN_TRANSFER (4, runtime signing):** host = OPA allow (`runtime_transfer` selector) +
  runtime-transfer credential present (no cap fetch). TEE = key_purpose==transfer (`0x42`);
  chain_id == **sealed** chain_id (11565 in this deployment, not hardcoded); `from`==derived(key_ref);
  empty data; internal EIP-155 preimage + keccak256 + low-S; **never a caller digest**.
- **SIGN_FAUCET_DISPENSE (5, faucet-treasury signing):** host = OPA allow (**distinct**
  `runtime_faucet` selector) + **distinct** runtime-faucet credential. TEE = key_purpose==faucet;
  `to` ∈ active transfer set; per-field caps + checked `worst_case`; dual counter debit **sealed
  before** sig (`0x44`/`0x46`); `0x45` if caps unsealed.
- **GENERATE_KEYS (1, provisioning/refill):** host = provision Vault cap + OPA. TEE = capability
  gates; tier from key_purpose; treasury singleton; enclave (faucet) vs fleet (transfer) scope;
  in-enclave `key_ref`; atomic seal.
- **CONFIGURE_TREASURY (6, provisioning [set_limits/refill/raise] or recovery [reset_lifetime_breaker]):**
  host = admin (recovery for reset_lifetime_breaker) cap + OPA. TEE = sub_op ∈ {0..3}; reset_lifetime_breaker needs
  recovery authority + the shared strict recovery counter; config-version bump.
- **EXPORT_BACKUP (7, backup export):** host = export Vault cap + OPA. TEE = admin authority;
  export counter; opaque `pq-agent-backup-v1` only (cannot decrypt).
- **RESTORE_BACKUP (8, restore/recovery):** host = recovery Vault cap + OPA. TEE = recovery
  authority; shared strict recovery counter; fresh-TEE ceremony; measurement/chain/env/manifest/
  digest verify; counter seeded from authenticated material (never zero/stale).
- **PUBLIC_IDENTITY (2) / PROVE_IDENTITY (3):** host = OPA allow (read). TEE = no cap; structural
  domain separation; verifier-owned nonce freshness.

**AC#2 no-privilege-escalation (TEE-enforced, host-independent):** a runtime credential cannot
reach keygen/export/restore (key-5 cap required + verified before dispatch; host can't synthesize
a valid cap — no admin/recovery private key); cannot sign arbitrary digests (semantic fields
only; disjoint preimage first-bytes); cannot cross key purpose (`0x42`); cannot bypass faucet caps
(checked-arith + dual-counter + seal-before-emit); cannot substitute a lower tier for a higher one.

## §5 Residuals (honest limitations)

- **Capability expiry/revocation is host-side only.** The TEE has no clock and no revocation
  list — it enforces only counter contiguity + signature. Soft expiry = Vault short-TTL token /
  drop the pre-signed cap. **Counter-burn is per-`command_class` lane and only works where a
  harmless no-op exists.** Because the contiguous counter is per `(authority,
  environment_identifier, scope_class, scope_target)` with `command_class` folded into
  `scope_target`, each `command_class` is a **separate** lane — burning one lane does not touch
  the others. A `configure_treasury` cap can be burned by submitting a no-op `set_limits` at
  counter `N` (advancing that lane's `highest`, so the stale cap is rejected as replay → `0x43`).
  But the high-value lanes (`generate_transfer`, `generate_faucet`, `export_backup`,
  restore/recovery) have **no harmless command at counter `N`** — a keygen "burn" actually mints
  keys, an export "burn" actually exports. So for those lanes **counter-burn is NOT available**;
  hard-revocation of an unused leaked cap there is **host-side only** (drop it from Vault), and the
  cap stays TEE-acceptable until it is consumed or its `counter` is otherwise advanced. There is
  no TEE-side revocation list. A dedicated TEE revoke / counter-advance opcode (or an expiry/epoch
  field) that invalidates an unused cap **without** performing its action would be a **TASK-7.1
  §10.5 follow-up**; until then this is a documented residual.
- **No TEE per-agent transfer destination/amount cap.** `SIGN_TRANSFER` (runtime signing) is
  bounded only by key-purpose + canonical EIP-155 + sealed chain_id; destination/amount limits
  live in OPA `data.config` (host advisory). This is the documented host-residual (design
  success-criterion). A TEE-side per-agent transfer cap is recommended future hardening — do
  **not** treat it as enforced today.
- **Runtime credential model.** Runtime signing {4,5} and reads {2,3} carry **no** key-5
  capability; the host's `runtime-transfer` / `runtime-faucet` Vault entries are coarse access
  credentials (presence-checked), not capabilities. They give host-side caller separation only;
  the TEE bound is key-purpose + faucet caps + domain separation.
- **Operator counter-issuance serialization.** Because pre-signed caps are indexed by
  `request_id` but the TEE enforces a contiguous `counter` per `(authority,env,scope_class,
  scope_target)` tuple, the operator ceremony MUST assign counters **monotonically and serially**
  per tuple (no two outstanding caps with the same counter, no gaps) — otherwise valid caps wedge
  (gap) or collide (replay). The minting/Vault-store step is the serialization point.
- **OPA fail-closed on unknown input.** `default allow := false`; an input with an unknown/extra
  field, a missing required field, or an out-of-range `opcode` is denied (not silently allowed).
- **Host-rollback sensitivity until TASK-7.7.** Sealed faucet caps + replay counters are not
  host-rollback-resistant; production fund custody requires the TASK-7.7 mechanism (or an explicit
  funding block) — verbatim TASK-7.2 AC#10 / TASK-7.4 AC#7.
- **Caller is not authenticated by the TEE.** vsock access control is a host OS/hypervisor
  responsibility; the TEE's bound is structured signing + capability verification + sealed caps.

## §6 Negative-capability test requirements — DoD#2

Frozen alongside `impl/rust/enclave-protocol/testvectors/agent-gateway/`; the TEE rejection is
the load-bearing assertion (host stage also denies, but defense-in-depth):
- Runtime credential → GENERATE_KEYS / EXPORT_BACKUP / RESTORE_BACKUP with no/forged key-5 cap → `0x43`, no state touch (restore with an admin-signed — not recovery — cap also rejected).
- Runtime credential → arbitrary-digest: impossible by construction (semantic-fields-only vector).
- Runtime credential → faucet over caps / overflow → `0x44`.
- Cross-tier: transfer-refill cap minting a faucet key → `0x43` (purpose/scope/payload_binding).
- Cross-command: a GENERATE_KEYS cap used for CONFIGURE_TREASURY → `0x43` (opcode mismatch);
  set_limits cap used for refill_budget → `0x43` (sub_op mismatch).
- Recovery-only: reset_lifetime_breaker with admin authority, or against the operational counter → `0x43`.
- Counter: replay (==highest), rollback (<highest), skip-ahead (>highest+1) → `0x43`.
- Scope/env: wrong scope_target/scope_class, or environment_identifier ≠ sealed (testnet→mainnet) → `0x43`/AAD mismatch.
- Payload-binding mismatch with otherwise-valid sig/counter → `0x43`.
- Role/profile cross-rejection (`0x41`); treasury singleton; faucet seal-before-emit (`0x46`); faucet-not-configured (`0x45`).
- Host stage: OPA default-deny before any Vault call; missing/expired Vault cap fail-closed; bridge token on an agent Vault path denied at the Vault ACL.

## Cross-references

TEE capability format + counter scheme + error band: `vsock-api-wire-format-spec-draft.md` §10.
Sealed authorities/state: `agent-gateway-keystore-backup-format.md`. Signing contract:
`agent-gateway-transfer-faucet-signing.md`. The OPA package / Vault paths named here are the
canonical examples; the vsock spec references them as examples only and delegates concretization
to this doc.
