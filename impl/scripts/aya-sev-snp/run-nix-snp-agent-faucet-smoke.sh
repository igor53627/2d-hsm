#!/usr/bin/env bash
# TASK-15: combined agent-gateway FAUCET write-path live smoke on a real SNP host.
#
# Boots .#disk-production-lab-agent-faucet-smoke under SEV-SNP — the SAME long-running
# `twod-hsm-agent-gateway` serve unit as the keygen 6-7b-ii smoke, but built WITH ALL THREE preview gates
# (keygen-exec + configure-treasury + sign-faucet) so the guest executes the full fund-custody flow (each
# op: seal → 0x45 commit → ack-verify → swap → emit). The host 0x40 faucet client then drives the five
# combined phases over vsock port 5002 — mint + configure ALL at runtime (no throwaway sealed fixture):
#   F1 mint-treasury        GENERATE_KEYS(purpose=2, count=1) → the singleton treasury key
#   F2 configure-set-limits CONFIGURE_TREASURY set_limits → per-field caps
#   F3 configure-refill     CONFIGURE_TREASURY refill_budget → the budget window
#   F4 dispense             SIGN_FAUCET_DISPENSE → both spend counters debited (the EpochOnly witness)
#   F5 dispense-stranger    a dispense to an unknown recipient → 0x42 (the recipient-allowlist gate)
#
# BRING-UP ORDER IS LOAD-BEARING (same as the read-path): anchor stub → host relay → qemu guest →
# client. The guest dials the relay during boot AND for each per-op commit, so the relay + the (now
# COMMIT-capable, 6-5 stateful) lab anchor stub are started FIRST.
#
# MUTUALLY EXCLUSIVE with the read-path run-nix-snp-agent-smoke.sh: both bake the SAME guest serve/relay
# ports (5002/5001) + GUEST_CID 42 + ANCHOR_LISTEN 127.0.0.1:5003, so they cannot coexist on one host
# anyway — and this script's `twod_hsm_stop_stale_qemu` + the `$BIN_DIR`-scoped helper pkill will reap a
# concurrent read-path run. Run ONE smoke at a time (the single-tenant aya validation model).
#
# HOST-SIDE PASS = R1-R4 all hold:
#   R1 preflight  — anchor 'listening', relay 'listening on vsock relay port', image ensured
#   R2 boot-ready — serial: budget events, '[info] boot handshake outcome:' BEFORE the serve marker,
#                   relay 'pump ok', anchor 'signed response' (the boot freshness leg)
#   R3 client     — 'twod-hsm-agent-faucet-smoke: RESULT PASS phases=5' (the AUTHORITATIVE write-path
#                   proof: F4's in-band resealed-blob unseal showing the dual-counter debit) PLUS a
#                   post-boot anchor/relay wire-liveness BELT (a fresh round-trip occurred)
#   R4 witnesses  — in-guest journald-serve PASS, no '[warn] ... connection fault'
#
# SELF-MATCH GUARD: this script never echoes the grepped witness literals.
#
# Off-SNP: exit 2 — the EXPECTED-REFUSAL arm is the shared run-kvm-agent-refusal.sh (the faucet image
# refuses to boot under plain KVM exactly like the read-path image; same boot wrapper).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
RUST_DIR="$ROOT/impl/rust/enclave-protocol"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

DISK_ATTR="${DISK_ATTR:-disk-production-lab-agent-faucet-smoke}"
SEV_MODE="${SEV_MODE:-snp}"
GUEST_CID="${GUEST_CID:-42}"
MEMORY="${MEMORY:-2048}"
VCPUS="${VCPUS:-2}"
AGENT_PORT="${AGENT_PORT:-5002}"
RELAY_PORT="${RELAY_PORT:-5001}"
ANCHOR_LISTEN="${ANCHOR_LISTEN:-127.0.0.1:5003}"
# Boot-to-Ready budget (cached image build + boot + possible early crash-loop cycles).
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-300}"
# Client budget: two phases, each a FRESH connection with the client's own 60 s per-connection read
# timeout (twod_hsm_agent_faucet_smoke_client.rs) + a host-relayed commit leg. Must comfortably exceed
# 2×60 s so a legitimately-slow commit trips the CLIENT's clean per-phase FAIL, not this outer `timeout`
# (which would surface only an ambiguous RC 124). 240 s = ~2× margin. (Observed runs finish in seconds.)
CLIENT_TIMEOUT_SEC="${CLIENT_TIMEOUT_SEC:-240}"

if [[ "$SEV_MODE" != "snp" ]]; then
  echo "[skip] SEV_MODE=$SEV_MODE: the faucet write-path smoke is the SNP acceptance run." >&2
  echo "       The off-SNP EXPECTED-REFUSAL arm is the shared run-kvm-agent-refusal.sh" >&2
  exit 2
fi

twod_hsm_nix_init
twod_hsm_resolve_snp_qemu
echo "SNP: qemu=$QEMU_BIN bios=$SNP_BIOS"

echo "[1/4] host bins (lab anchor stub + host relay + 0x40 KEYGEN client)"
BIN_DIR="${BIN_DIR:-$RUST_DIR/target/debug}"
# ALWAYS rebuild (the matrix-flagged stale-target hazard — these host tools DEFINE the anchor behavior
# + the client cap/expectations). The faucet client needs all THREE preview gates (keygen-exec to mint
# the treasury key, configure-treasury to set caps + a budget, sign-faucet to dispense); building the
# anchor/relay with the extra features is harmless (additive).
if [[ "$BIN_DIR" == "$RUST_DIR/target/debug" ]]; then
  (cd "$RUST_DIR" && cargo build \
     --features agent-gateway,vsock-transport,lab-agent-smoke,agent-keygen-exec-preview,agent-configure-treasury-preview,agent-sign-faucet-preview \
     --bin twod-hsm-lab-anchor --bin twod-hsm-host-anchor-relay --bin twod-hsm-agent-faucet-smoke-client)
fi

echo "[2/4] nix .#${DISK_ATTR} (bootable EFI qcow2; agent unit = the preview serve build)"
DISK_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" "$DISK_ATTR" "${DISK_ATTR}")"
SRC_QCOW2="$(twod_hsm_nix_disk_qcow2 "$DISK_LINK")"
echo "      image: $SRC_QCOW2"

SMOKE_TMP="$(mktemp -d "/tmp/2d-hsm-snp-faucet-smoke-XXXXXX")"
WORK="$SMOKE_TMP/work.qcow2"
LOG="$SMOKE_TMP/serial.log"
ANCHOR_LOG="$SMOKE_TMP/anchor.log"
RELAY_LOG="$SMOKE_TMP/relay.log"
CLIENT_LOG="$SMOKE_TMP/client.log"
twod_hsm_make_work_overlay "$SRC_QCOW2" "$WORK"

GUEST_CID="$GUEST_CID" twod_hsm_stop_stale_qemu
# Also reap stale host helpers a previously ABORTED (SIGKILL / dropped-ssh) run may have left holding
# the anchor TCP / relay vsock ports — a clean exit's cleanup trap already reaps them, so this only
# matters for re-runs after a hard abort (otherwise the new bind fails and the run cleanly FAILs).
# Match the EXACT bin path ($BIN_DIR/…) — NOT a bare name — so a concurrent run from a different
# BIN_DIR (or any unrelated process) is never caught.
pkill -f "$BIN_DIR/twod-hsm-lab-anchor" 2>/dev/null || true
pkill -f "$BIN_DIR/twod-hsm-host-anchor-relay" 2>/dev/null || true
QPID=""; ANCHOR_PID=""; RELAY_PID=""
cleanup() {
  for pid in "$QPID" "$RELAY_PID" "$ANCHOR_PID"; do
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
  done
  if [[ -n "${KEEP_SMOKE_TMP:-}" ]]; then
    echo "[keep] logs preserved under $SMOKE_TMP" >&2
  else
    rm -rf "$SMOKE_TMP"
  fi
}
trap cleanup EXIT

fail_dump() {
  echo "---- client marker lines ----" >&2
  grep -a 'twod-hsm-agent-faucet-smoke:' "$CLIENT_LOG" >&2 2>/dev/null || true
  echo "---- anchor log tail ----" >&2
  tail -20 "$ANCHOR_LOG" >&2 2>/dev/null || true
  echo "---- relay log tail ----" >&2
  tail -20 "$RELAY_LOG" >&2 2>/dev/null || true
  echo "---- serial log: agent lines ----" >&2
  grep -a 'agent gateway\|agent boot\|boot budget\|boot handshake\|twod-hsm-agent-smoke' "$LOG" >&2 2>/dev/null | tail -40 || true
  echo "---- serial log tail (40) ----" >&2
  tail -40 "$LOG" >&2 2>/dev/null || true
}

wait_for_line() { # $1=file $2=pattern(F) $3=tries $4=sleep $5=label
  local _i
  for _i in $(seq 1 "$3"); do
    grep -aqF "$2" "$1" 2>/dev/null && return 0
    sleep "$4"
  done
  echo "[FAIL] $5 did not appear within bound" >&2
  return 1
}

echo "[3/4] R1 host-preflight: anchor stub -> relay (BEFORE the guest boots)"
TWOD_HSM_LAB_ANCHOR_LISTEN="$ANCHOR_LISTEN" \
  TWOD_HSM_LAB_ANCHOR_KEYSTORE_FILE="$RUST_DIR/testvectors/agent-gateway/agent_keystore_smoke_v1.sealed.bin" \
  TWOD_HSM_LAB_ANCHOR_SEAL_ROOT_FILE="$RUST_DIR/testvectors/seal_v1_provisioning_root.bin" \
  nohup "$BIN_DIR/twod-hsm-lab-anchor" </dev/null >"$ANCHOR_LOG" 2>&1 &
ANCHOR_PID=$!
wait_for_line "$ANCHOR_LOG" "twod-hsm-lab-anchor: listening on " 20 0.5 "anchor stub startup" || { fail_dump; exit 1; }

TWOD_HSM_ANCHOR_RELAY_PORT="$RELAY_PORT" TWOD_HSM_ANCHOR_ENDPOINT="$ANCHOR_LISTEN" \
  nohup "$BIN_DIR/twod-hsm-host-anchor-relay" </dev/null >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!
wait_for_line "$RELAY_LOG" "host-anchor-relay: listening on vsock relay port ${RELAY_PORT}" 20 0.5 "relay startup" || { fail_dump; exit 1; }

echo "[4/4] R2-R4: boot under SEV-SNP, then drive the write-path client phases"
DISK="$WORK" CLOUDINIT="" TWOD_HSM_SKIP_CLOUDINIT=1 \
  SEV_MODE="$SEV_MODE" GUEST_CID="$GUEST_CID" MEMORY="$MEMORY" VCPUS="$VCPUS" \
  nohup "$SCRIPT_DIR/run-guest-vm.sh" </dev/null >"$LOG" 2>&1 &
QPID=$!

# R2 boot-to-Ready: the EVENTUAL serve marker (crash-loop tolerant — restarts until relay/anchor up).
SERVE_MARKER="agent gateway: serving on vsock CID 4294967295 port ${AGENT_PORT}"
DEADLINE=$((SECONDS + BOOT_TIMEOUT_SEC))
while (( SECONDS < DEADLINE )); do
  if ! kill -0 "$QPID" 2>/dev/null; then
    echo "[FAIL] guest QEMU exited before reaching the serve marker" >&2
    fail_dump; exit 1
  fi
  grep -aqF "$SERVE_MARKER" "$LOG" 2>/dev/null && break
  sleep 4
done
if ! grep -aqF "$SERVE_MARKER" "$LOG" 2>/dev/null; then
  echo "[FAIL] R2: no serve marker within ${BOOT_TIMEOUT_SEC}s" >&2
  fail_dump; exit 1
fi

R2_PASS=1
grep -aq 'boot budget config (raw, pre-validate)' "$LOG" || { echo "[FAIL] R2: raw budget event missing" >&2; R2_PASS=0; }
grep -aq 'boot budget validated:' "$LOG" || { echo "[FAIL] R2: validated budget event missing" >&2; R2_PASS=0; }
OUTCOME_LN="$(grep -an '\[info\] boot handshake outcome:' "$LOG" | head -1 | cut -d: -f1 || true)"
SERVE_LN="$(grep -anF "$SERVE_MARKER" "$LOG" | head -1 | cut -d: -f1 || true)"
if [[ -z "$OUTCOME_LN" || -z "$SERVE_LN" ]] || (( OUTCOME_LN >= SERVE_LN )); then
  echo "[FAIL] R2: '[info] boot handshake outcome:' (line ${OUTCOME_LN:-absent}) must precede the serve marker (line ${SERVE_LN:-absent})" >&2
  R2_PASS=0
fi
grep -aq 'host-anchor-relay: pump ok' "$RELAY_LOG" || { echo "[FAIL] R2: relay never logged a forwarded handshake pump" >&2; R2_PASS=0; }
grep -aq 'twod-hsm-lab-anchor: signed response' "$ANCHOR_LOG" || { echo "[FAIL] R2: anchor stub never signed a response" >&2; R2_PASS=0; }
(( R2_PASS == 1 )) || { fail_dump; exit 1; }
echo "      R2 boot-to-Ready OK (handshake forwarded, signed, Ready before serve)"

# Snapshot the boot-leg counts so R3 can require a NEW anchor sign + relay pump after boot.
# `|| true` (NOT `|| echo 0`): `grep -c` already prints `0` and exits non-zero on no-match — chaining
# `echo 0` would yield the two-line value "0\n0" and break the later `(( ))` compare (a latent bug the
# R2 gate masks today since both counts are already ≥1). `|| true` keeps grep's own `0`.
ANCHOR_SIGNS_PRE="$(grep -ac 'twod-hsm-lab-anchor: signed response' "$ANCHOR_LOG" 2>/dev/null || true)"
RELAY_PUMPS_PRE="$(grep -ac 'host-anchor-relay: pump ok' "$RELAY_LOG" 2>/dev/null || true)"

# R3: the write-path client phases (fresh connection per phase; each commits via the relay+anchor).
set +e
TWOD_HSM_SMOKE_GUEST_CID="$GUEST_CID" TWOD_HSM_SMOKE_AGENT_PORT="$AGENT_PORT" \
  timeout "$CLIENT_TIMEOUT_SEC" "$BIN_DIR/twod-hsm-agent-faucet-smoke-client" 2>"$CLIENT_LOG"
CLIENT_RC=$?
set -e
if (( CLIENT_RC != 0 )); then
  echo "[FAIL] R3: faucet smoke client exited $CLIENT_RC" >&2
  fail_dump; exit 1
fi
if ! grep -aqE 'twod-hsm-agent-faucet-smoke: RESULT PASS phases=5([^0-9]|$)' "$CLIENT_LOG"; then
  echo "[FAIL] R3: the client did not report 'RESULT PASS phases=5'" >&2
  fail_dump; exit 1
fi
echo "      R3 client phases OK"
grep -a 'twod-hsm-agent-faucet-smoke: PHASE ' "$CLIENT_LOG" | sed 's/^/        /' || true

# R3 wire-liveness belt: require a NEW anchor sign + relay pump AFTER the boot snapshot — evidence the
# guest exercised the anchor/relay transport again post-boot (which the F1-F4 commits all do).
#
# SCOPE (honest, per the matrix review): this is a BELT, NOT a commit-isolated proof. The lab anchor
# stub logs one generic "signed response" for every leg, so a count delta alone cannot attribute the
# round-trip to a SPECIFIC phase vs. a crash-loop boot-freshness re-run. The AUTHORITATIVE write-path
# proofs are the client's IN-BAND per-phase assertions, already required above by `RESULT PASS phases=5`:
#   - F1-F3 (mint / set_limits / refill): each returns a resealed blob the client UNSEALS — which, by
#     `commit_before_emit`'s strict seal→COMMIT→swap→emit ordering (agent_dispatch.rs), the guest can only
#     have produced if the per-op anchor commit succeeded on the wire.
#   - F4 (`dispense`): the resealed blob UNSEALS to BOTH faucet spend counters debited by worst_case (the
#     dual-counter EpochOnly debit) — the authoritative end-to-end fund-custody witness.
#   - F5 (`dispense-stranger-rejected`): the exact `0x42` proves the recipient allowlist rejected the
#     stranger BEFORE any commit (a committed dispense would have returned a success body, failing F5).
# A positively-attributed per-phase wire witness (a commit-specific stub marker + per-phase snapshots) is
# a worthwhile NEXT-iteration hardening — it needs a stub log change + a re-run, so it is deferred, not
# blocking (the in-band gate dominates). Inherited from the keygen 6-7b-ii belt (TASK-20 residual).
R3_WIRE_OK=0
for _ in $(seq 1 20); do
  ANCHOR_SIGNS_NOW="$(grep -ac 'twod-hsm-lab-anchor: signed response' "$ANCHOR_LOG" 2>/dev/null || true)"
  RELAY_PUMPS_NOW="$(grep -ac 'host-anchor-relay: pump ok' "$RELAY_LOG" 2>/dev/null || true)"
  if (( ANCHOR_SIGNS_NOW > ANCHOR_SIGNS_PRE && RELAY_PUMPS_NOW > RELAY_PUMPS_PRE )); then
    R3_WIRE_OK=1; break
  fi
  sleep 1
done
if (( R3_WIRE_OK != 1 )); then
  echo "[FAIL] R3: no NEW anchor sign + relay pump after boot — the guest never re-exercised the commit transport (the in-band RESULT PASS above is the authoritative proof; this belt should also hold)" >&2
  fail_dump; exit 1
fi
echo "      R3 wire-liveness belt OK (a fresh post-boot anchor/relay round-trip occurred; F4's in-band dual-counter-debit unseal is the authoritative commit proof)"

# R4 witnesses (bounded wait for the in-guest journald witness). The witness oneshot is `After=` (not
# gating) the serve unit and retry-greps for up to ~120 s before emitting PASS/FAIL — and unlike the
# read-path smoke there is NO 300 s idle phase to give it slack, so R4 is reached within seconds of the
# serve marker. Wait the witness's FULL retry budget (120 s, not the sibling's incidental 30 s) so a
# slow/crash-looped boot's late-starting witness is not mistaken for a FAIL.
for _ in $(seq 1 120); do
  grep -aq 'twod-hsm-agent-smoke: journald-serve ' "$LOG" 2>/dev/null && break
  sleep 1
done
R4_PASS=1
grep -aq 'twod-hsm-agent-smoke: journald-serve PASS' "$LOG" || { echo "[FAIL] R4: in-guest journald-serve witness did not PASS" >&2; R4_PASS=0; }
if grep -aq 'agent gateway: connection fault' "$LOG"; then
  echo "[FAIL] R4: an unexpected connection fault was logged" >&2; R4_PASS=0
fi
(( R4_PASS == 1 )) || { fail_dump; exit 1; }

kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true
QPID=""

echo
echo "[PASS] TASK-15 agent-gateway FAUCET write-path live smoke on SEV-SNP: R1-R4 all hold"
echo "       (boot-to-Ready; mint-treasury + set_limits + refill + dispense seal→commit→swap→emit; dual-counter debit; 0x45 commit via relay+anchor)"
