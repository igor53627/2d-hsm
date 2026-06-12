#!/usr/bin/env bash
# TASK-7.7 5b-2c-iii: agent-gateway live smoke on a real SNP host.
#
# Boots .#disk-production-lab-agent-gateway under SEV-SNP. That image runs the DEBUG
# `twod-hsm-agent-gateway` bin as a long-running unit (Restart=always): boot = root → unseal the
# TEST-KEYS-ONLY smoke keystore → budget → ONE wired anchor handshake through the HOST-side relay +
# lab anchor stub → install-AFTER-Ready → the serial 0x40 serve loop on vsock port 5002. The host
# 0x40 client then drives the five checklisted phases.
#
# BRING-UP ORDER IS LOAD-BEARING: anchor stub → host relay → qemu guest → client. The guest dials
# the relay during boot and crash-loops (by design, fail-closed exits under Restart=always) until
# the relay+anchor answer — so they are started FIRST and the boot grep targets the EVENTUAL marker.
#
# HOST-SIDE PASS = R1–R4 all hold:
#   R1 preflight  — anchor 'listening', relay 'listening on vsock relay port', image ensured
#   R2 boot-ready — serial log: budget events, '[info] boot handshake outcome:' BEFORE the serve
#                   marker (the install-AFTER-Ready order observable), relay 'pump ok', anchor
#                   'signed response'
#   R3 client     — 'twod-hsm-agent-smoke: RESULT PASS phases=5' (count-anchored; the 300 s
#                   wall-clock idle-expiry phase is INSIDE this — the checklisted acceptance item)
#   R4 witnesses  — in-guest journald-serve PASS, the calm non-0x40 close, the POSITIVE clean idle
#                   close, and NO '[warn] ... connection fault'
#
# SELF-MATCH GUARD: this script never echoes the grepped witness literals.
#
# Dev iteration: TWOD_HSM_AGENT_SMOKE_SKIP_IDLE=1 skips the 300 s phase; the client then emits the
# structurally-unmatchable 'RESULT PASS-DEV phases=4' and this runner reports PASS-DEV loudly —
# NEVER the checklisted PASS (the SMOKE-PASS-CRITERIA checklist requires a full-window phases=5 run).
#
# Off-SNP: exit 2 — the EXPECTED-REFUSAL arm is its own first-class run: run-kvm-agent-refusal.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
RUST_DIR="$ROOT/impl/rust/enclave-protocol"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

DISK_ATTR="${DISK_ATTR:-disk-production-lab-agent-gateway}"
SEV_MODE="${SEV_MODE:-snp}"
GUEST_CID="${GUEST_CID:-42}"
MEMORY="${MEMORY:-2048}"
VCPUS="${VCPUS:-2}"
AGENT_PORT="${AGENT_PORT:-5002}"
RELAY_PORT="${RELAY_PORT:-5001}"
ANCHOR_LISTEN="${ANCHOR_LISTEN:-127.0.0.1:5003}"
# Boot-to-Ready budget (cached image build + boot + possible early crash-loop cycles).
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-300}"
# Client budget: 4 fast phases + the idle window (ceiling = IDLE_EXPIRY_CEILING_MS, 340 s) + margin.
CLIENT_TIMEOUT_SEC="${CLIENT_TIMEOUT_SEC:-600}"
SKIP_IDLE="${TWOD_HSM_AGENT_SMOKE_SKIP_IDLE:-0}"

if [[ "$SEV_MODE" != "snp" ]]; then
  echo "[skip] SEV_MODE=$SEV_MODE: the agent live smoke is the SNP acceptance run." >&2
  echo "       The off-SNP EXPECTED-REFUSAL arm is its own run: run-kvm-agent-refusal.sh" >&2
  exit 2
fi

twod_hsm_nix_init
twod_hsm_resolve_snp_qemu
echo "SNP: qemu=$QEMU_BIN bios=$SNP_BIOS"

echo "[1/4] host bins (lab anchor stub + host relay + 0x40 smoke client)"
BIN_DIR="${BIN_DIR:-$RUST_DIR/target/debug}"
# ALWAYS rebuild — never a presence-skip. The matrix flagged that a `! -x` skip lets STALE
# target/debug binaries from a prior checkout drive a freshly-built guest image and report a
# false-green (these host tools DEFINE the anchor behavior + client expectations, so a stale tool
# silently invalidates the acceptance). cargo incremental compilation makes this ~free when the
# sources are unchanged; the cost of a guaranteed-fresh build is negligible against a 300 s smoke.
# (Override BIN_DIR to point at a deliberately pre-built tree if you must skip — explicit, not silent.)
if [[ "$BIN_DIR" == "$RUST_DIR/target/debug" ]]; then
  (cd "$RUST_DIR" && cargo build --features agent-gateway,vsock-transport,lab-agent-smoke \
     --bin twod-hsm-lab-anchor --bin twod-hsm-host-anchor-relay --bin twod-hsm-agent-smoke-client)
fi

echo "[2/4] nix .#${DISK_ATTR} (bootable EFI qcow2 with the agent-gateway unit)"
DISK_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" "$DISK_ATTR" "${DISK_ATTR}")"
SRC_QCOW2="$(twod_hsm_nix_disk_qcow2 "$DISK_LINK")"
echo "      image: $SRC_QCOW2"

SMOKE_TMP="$(mktemp -d "/tmp/2d-hsm-snp-agent-smoke-XXXXXX")"
WORK="$SMOKE_TMP/work.qcow2"
LOG="$SMOKE_TMP/serial.log"
ANCHOR_LOG="$SMOKE_TMP/anchor.log"
RELAY_LOG="$SMOKE_TMP/relay.log"
CLIENT_LOG="$SMOKE_TMP/client.log"
twod_hsm_make_work_overlay "$SRC_QCOW2" "$WORK"

GUEST_CID="$GUEST_CID" twod_hsm_stop_stale_qemu
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
  grep -a 'twod-hsm-agent-smoke:' "$CLIENT_LOG" >&2 2>/dev/null || true
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
# The 'listening' line implies the startup unseal + seed<->anchor_root pairing assert PASSED.
wait_for_line "$ANCHOR_LOG" "twod-hsm-lab-anchor: listening on " 20 0.5 "anchor stub startup" || { fail_dump; exit 1; }

TWOD_HSM_ANCHOR_RELAY_PORT="$RELAY_PORT" TWOD_HSM_ANCHOR_ENDPOINT="$ANCHOR_LISTEN" \
  nohup "$BIN_DIR/twod-hsm-host-anchor-relay" </dev/null >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!
wait_for_line "$RELAY_LOG" "host-anchor-relay: listening on vsock relay port ${RELAY_PORT}" 20 0.5 "relay startup" || { fail_dump; exit 1; }

echo "[4/4] R2-R4: boot under SEV-SNP, then drive the client phases"
DISK="$WORK" CLOUDINIT="" TWOD_HSM_SKIP_CLOUDINIT=1 \
  SEV_MODE="$SEV_MODE" GUEST_CID="$GUEST_CID" MEMORY="$MEMORY" VCPUS="$VCPUS" \
  nohup "$SCRIPT_DIR/run-guest-vm.sh" </dev/null >"$LOG" 2>&1 &
QPID=$!

# R2 boot-to-Ready: the EVENTUAL serve marker (crash-loop tolerant — the unit restarts until the
# relay/anchor answered; they are already up).
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
# Install-AFTER-Ready order observable: the FIRST '[info]'-anchored outcome line (only a Ready
# outcome logs at info; refused outcomes log [warn]) must precede the FIRST serve marker line.
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

# R3: the client phases (fresh connection per phase; the 300 s idle window runs INSIDE the client).
set +e
TWOD_HSM_SMOKE_GUEST_CID="$GUEST_CID" TWOD_HSM_SMOKE_AGENT_PORT="$AGENT_PORT" \
  TWOD_HSM_AGENT_SMOKE_SKIP_IDLE="$SKIP_IDLE" \
  timeout "$CLIENT_TIMEOUT_SEC" "$BIN_DIR/twod-hsm-agent-smoke-client" 2>"$CLIENT_LOG"
CLIENT_RC=$?
set -e
if (( CLIENT_RC != 0 )); then
  echo "[FAIL] R3: smoke client exited $CLIENT_RC" >&2
  fail_dump; exit 1
fi
if [[ "$SKIP_IDLE" == "1" ]]; then
  # Dev iteration verdict — structurally NOT the checklisted PASS.
  if ! grep -aqE 'twod-hsm-agent-smoke: RESULT PASS-DEV phases=4([^0-9]|$)' "$CLIENT_LOG"; then
    echo "[FAIL] R3(dev): no 'RESULT PASS-DEV phases=4'" >&2
    fail_dump; exit 1
  fi
else
  if ! grep -aqE 'twod-hsm-agent-smoke: RESULT PASS phases=5([^0-9]|$)' "$CLIENT_LOG"; then
    echo "[FAIL] R3: the client did not report the checklisted 'RESULT PASS phases=5'" >&2
    fail_dump; exit 1
  fi
fi
echo "      R3 client phases OK"
# Diagnostic echo of the per-phase lines. `|| true`: this is the lone grep on the SUCCESS path under
# `set -euo pipefail` — R3 already passed, so a no-match here (a future client that emits RESULT
# without per-PHASE lines) must NOT abort an already-green run via pipefail+errexit.
grep -a 'twod-hsm-agent-smoke: PHASE ' "$CLIENT_LOG" | sed 's/^/        /' || true

# R4 witnesses (bounded wait for the in-guest journald witness oneshot + the close-taxonomy lines).
for _ in $(seq 1 30); do
  grep -aq 'twod-hsm-agent-smoke: journald-serve ' "$LOG" 2>/dev/null && break
  sleep 1
done
R4_PASS=1
grep -aq 'twod-hsm-agent-smoke: journald-serve PASS' "$LOG" || { echo "[FAIL] R4: in-guest journald-serve witness did not PASS" >&2; R4_PASS=0; }
# C3's calm peer-protocol-reject close (the non-0x40 probe) — [info], never a [warn] flood lever.
grep -aq '\[info\] agent gateway: closed connection (' "$LOG" || { echo "[FAIL] R4: the calm non-0x40 close line is missing" >&2; R4_PASS=0; }
if [[ "$SKIP_IDLE" != "1" ]]; then
  # Presence of the clean-close taxonomy line. NOTE (honest scope): the pump logs this on EVERY
  # clean close — the fast phases C1/C2/C5 each close cleanly too — so this is a generic
  # clean-close PRESENCE check, NOT an idle-specific witness. The idle-expiry is proven by C4's
  # `elapsed_ms` ∈ the window (the client's own assert, the primary gate); this line only guards
  # the close-TAXONOMY (clean vs fault vs peer-reject), ensuring the idle close lands on the
  # `closed cleanly` arm rather than `connection fault`. A truly idle-specific marker would need a
  # distinct serve-side log line (named follow-up, not added here to avoid perturbing the pump).
  grep -aq '\[info\] agent gateway: connection closed cleanly' "$LOG" || { echo "[FAIL] R4: the clean-close taxonomy line is missing" >&2; R4_PASS=0; }
fi
if grep -aq 'agent gateway: connection fault' "$LOG"; then
  echo "[FAIL] R4: an unexpected connection fault was logged" >&2; R4_PASS=0
fi
(( R4_PASS == 1 )) || { fail_dump; exit 1; }

kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true
QPID=""

echo
if [[ "$SKIP_IDLE" == "1" ]]; then
  echo "[PASS-DEV] 5b-2c-iii agent smoke (idle-expiry SKIPPED) — NOT the checklisted run;"
  echo "           the SMOKE-PASS-CRITERIA checklist requires a full-window 'RESULT PASS phases=5' run."
else
  echo "[PASS] 5b-2c-iii agent-gateway live smoke on SEV-SNP: R1-R4 all hold"
  echo "       (boot-to-Ready via relay+anchor, 0x40 round-trips, 300s idle window, witnesses)"
fi
