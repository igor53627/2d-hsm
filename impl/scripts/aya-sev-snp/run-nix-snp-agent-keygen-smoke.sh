#!/usr/bin/env bash
# TASK-7.7 6-7b-ii: agent-gateway WRITE-PATH (GENERATE_KEYS) live smoke on a real SNP host.
#
# Boots .#disk-production-lab-agent-keygen-smoke under SEV-SNP — the SAME long-running
# `twod-hsm-agent-gateway` serve unit as the read-path 5b-2c-iii smoke, but built WITH
# `agent-keygen-exec-preview` so the guest actually EXECUTES GENERATE_KEYS (seal → 0x45 commit →
# ack-verify → swap → emit) and installs the per-op commit channel at boot (6-4b step G'). The host
# 0x40 keygen client then drives the two write-path phases over vsock port 5002:
#   W1  a real signed GENERATE_KEYS(count=2) → the reply's minted key list + a resealed blob that
#       UNSEALS to entries+2/structural+1/epoch+1 (the seal→commit→swap witness)
#   W2  a wrong-key cap → 0x43 fail-closed (the auth gate, isolated via counter=2)
#
# BRING-UP ORDER IS LOAD-BEARING (same as the read-path): anchor stub → host relay → qemu guest →
# client. The guest dials the relay during boot AND for each per-op commit, so the relay + the (now
# COMMIT-capable, 6-5 stateful) lab anchor stub are started FIRST.
#
# HOST-SIDE PASS = R1-R4 all hold:
#   R1 preflight  — anchor 'listening', relay 'listening on vsock relay port', image ensured
#   R2 boot-ready — serial: budget events, '[info] boot handshake outcome:' BEFORE the serve marker,
#                   relay 'pump ok', anchor 'signed response' (the boot freshness leg)
#   R3 client     — 'twod-hsm-agent-keygen-smoke: RESULT PASS phases=2' (the AUTHORITATIVE write-path
#                   proof: W1's in-band resealed-blob unseal to the advanced body) PLUS a post-boot
#                   anchor/relay wire-liveness BELT (a fresh round-trip occurred; NOT W1-attributed)
#   R4 witnesses  — in-guest journald-serve PASS, no '[warn] ... connection fault'
#
# SELF-MATCH GUARD: this script never echoes the grepped witness literals.
#
# Off-SNP: exit 2 — the EXPECTED-REFUSAL arm is the shared run-kvm-agent-refusal.sh (the keygen image
# refuses to boot under plain KVM exactly like the read-path image; same boot wrapper).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
RUST_DIR="$ROOT/impl/rust/enclave-protocol"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

DISK_ATTR="${DISK_ATTR:-disk-production-lab-agent-keygen-smoke}"
SEV_MODE="${SEV_MODE:-snp}"
GUEST_CID="${GUEST_CID:-42}"
MEMORY="${MEMORY:-2048}"
VCPUS="${VCPUS:-2}"
AGENT_PORT="${AGENT_PORT:-5002}"
RELAY_PORT="${RELAY_PORT:-5001}"
ANCHOR_LISTEN="${ANCHOR_LISTEN:-127.0.0.1:5003}"
# Boot-to-Ready budget (cached image build + boot + possible early crash-loop cycles).
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-300}"
# Client budget: two fast round-trips, each including a host-relayed commit leg. No idle phase.
CLIENT_TIMEOUT_SEC="${CLIENT_TIMEOUT_SEC:-120}"

if [[ "$SEV_MODE" != "snp" ]]; then
  echo "[skip] SEV_MODE=$SEV_MODE: the keygen write-path smoke is the SNP acceptance run." >&2
  echo "       The off-SNP EXPECTED-REFUSAL arm is the shared run-kvm-agent-refusal.sh" >&2
  exit 2
fi

twod_hsm_nix_init
twod_hsm_resolve_snp_qemu
echo "SNP: qemu=$QEMU_BIN bios=$SNP_BIOS"

echo "[1/4] host bins (lab anchor stub + host relay + 0x40 KEYGEN client)"
BIN_DIR="${BIN_DIR:-$RUST_DIR/target/debug}"
# ALWAYS rebuild (the matrix-flagged stale-target hazard — these host tools DEFINE the anchor behavior
# + the client cap/expectations). The keygen client needs agent-keygen-exec-preview; building the
# anchor/relay with the extra feature is harmless (additive).
if [[ "$BIN_DIR" == "$RUST_DIR/target/debug" ]]; then
  (cd "$RUST_DIR" && cargo build \
     --features agent-gateway,vsock-transport,lab-agent-smoke,agent-keygen-exec-preview \
     --bin twod-hsm-lab-anchor --bin twod-hsm-host-anchor-relay --bin twod-hsm-agent-keygen-smoke-client)
fi

echo "[2/4] nix .#${DISK_ATTR} (bootable EFI qcow2; agent unit = the preview serve build)"
DISK_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" "$DISK_ATTR" "${DISK_ATTR}")"
SRC_QCOW2="$(twod_hsm_nix_disk_qcow2 "$DISK_LINK")"
echo "      image: $SRC_QCOW2"

SMOKE_TMP="$(mktemp -d "/tmp/2d-hsm-snp-keygen-smoke-XXXXXX")"
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
  grep -a 'twod-hsm-agent-keygen-smoke:' "$CLIENT_LOG" >&2 2>/dev/null || true
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
  timeout "$CLIENT_TIMEOUT_SEC" "$BIN_DIR/twod-hsm-agent-keygen-smoke-client" 2>"$CLIENT_LOG"
CLIENT_RC=$?
set -e
if (( CLIENT_RC != 0 )); then
  echo "[FAIL] R3: keygen smoke client exited $CLIENT_RC" >&2
  fail_dump; exit 1
fi
if ! grep -aqE 'twod-hsm-agent-keygen-smoke: RESULT PASS phases=2([^0-9]|$)' "$CLIENT_LOG"; then
  echo "[FAIL] R3: the client did not report 'RESULT PASS phases=2'" >&2
  fail_dump; exit 1
fi
echo "      R3 client phases OK"
grep -a 'twod-hsm-agent-keygen-smoke: PHASE ' "$CLIENT_LOG" | sed 's/^/        /' || true

# R3 wire-liveness belt: require a NEW anchor sign + relay pump AFTER the boot snapshot — evidence the
# guest exercised the anchor/relay transport again post-boot (which the W1 GENERATE_KEYS commit does).
#
# SCOPE (honest, per the matrix review): this is a BELT, NOT a commit-isolated proof. The lab anchor
# stub logs one generic "signed response" for every leg, so a count delta alone cannot attribute the
# round-trip to W1 specifically vs. a crash-loop boot-freshness re-run or a (broken-auth) W2 commit.
# The AUTHORITATIVE write-path proofs are the client's IN-BAND per-phase assertions, already required
# above by `RESULT PASS phases=2`:
#   - W1 (`generate-keys`): the reply's resealed blob UNSEALS to entries+2/structural+1/epoch+1 — which,
#     by `commit_before_emit`'s strict seal→COMMIT→swap→emit ordering (agent_dispatch.rs), the guest can
#     only have produced if the per-op anchor commit succeeded on the wire.
#   - W2 (`generate-keys-bad-cap`): the exact `0x43` proves the wrong-key cap was rejected at
#     verify_capability BEFORE any commit (a commit would have returned success, failing the phase).
# A positively-attributed wire witness (snapshot BETWEEN W1 and W2 + a commit-specific stub marker,
# asserting +1 after W1 and NO further increase after W2) is a worthwhile NEXT-iteration hardening —
# it would need a stub log change + a re-run, so it is deferred, not blocking (the in-band gate dominates).
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
echo "      R3 wire-liveness belt OK (a fresh post-boot anchor/relay round-trip occurred; W1's in-band unseal is the authoritative commit proof)"

# R4 witnesses (bounded wait for the in-guest journald witness + clean close; no idle phase here).
for _ in $(seq 1 30); do
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
echo "[PASS] 6-7b-ii agent-gateway WRITE-path live smoke on SEV-SNP: R1-R4 all hold"
echo "       (boot-to-Ready, real GENERATE_KEYS seal→commit→swap→emit, 0x45 commit via relay+anchor)"
