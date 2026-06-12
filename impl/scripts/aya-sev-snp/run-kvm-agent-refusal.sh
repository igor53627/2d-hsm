#!/usr/bin/env bash
# TASK-7.7 5b-2c-iii: the (iii) outcome-refusal E2E arm — a FIRST-CLASS expected-refusal run,
# never recorded as a skip (SMOKE-PASS-CRITERIA: the bin acceptance is split BY PATH; one happy
# smoke is NOT enough).
#
# Boots .#disk-production-lab-agent-gateway under PLAIN KVM (SEV_MODE=none) with NO relay and NO
# anchor on the host. Off SNP the boot handshake's quote child fails BEFORE any vsock dial
# (configfs-tsm is guest-SNP-only) ⇒ retryable ⇒ attempts exhaust ⇒ a non-Ready outcome ⇒ the bin
# fail-closes and exits ⇒ systemd (Restart=always) restarts it — forever, by design.
#
# PASS = ALL FOUR in the captured serial log:
#   1. '[warn] boot handshake outcome:'        — the refused-outcome event at warn priority
#   2. '[err] agent-gateway boot failed:'      — the rendered FATAL cause at err priority
#   3. >= 2 'boot budget config (raw, pre-validate)' lines — RESTART EVIDENCE: supervision restarts
#      the process (each cycle re-emits the raw budget event); pins "no in-process handshake retry"
#      live (an in-process retry loop would emit ONE raw line per boot, not one per cycle)
#   4. NO 'serving on vsock' anywhere          — a refused outcome must never serve
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

DISK_ATTR="${DISK_ATTR:-disk-production-lab-agent-gateway}"
GUEST_CID="${GUEST_CID:-42}"
MEMORY="${MEMORY:-2048}"
VCPUS="${VCPUS:-2}"
# Boot + at least two refusal/restart cycles (each cycle: a fast off-SNP quote failure burst + 3 s
# RestartSec).
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-240}"

twod_hsm_nix_init

echo "[1/2] nix .#${DISK_ATTR} (same image as the SNP smoke; KVM boot, no relay/anchor)"
DISK_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" "$DISK_ATTR" "${DISK_ATTR}")"
SRC_QCOW2="$(twod_hsm_nix_disk_qcow2 "$DISK_LINK")"
echo "      image: $SRC_QCOW2"

SMOKE_TMP="$(mktemp -d "/tmp/2d-hsm-kvm-agent-refusal-XXXXXX")"
WORK="$SMOKE_TMP/work.qcow2"
LOG="$SMOKE_TMP/serial.log"
twod_hsm_make_work_overlay "$SRC_QCOW2" "$WORK"

GUEST_CID="$GUEST_CID" twod_hsm_stop_stale_qemu
QPID=""
cleanup() {
  [[ -n "$QPID" ]] && kill -0 "$QPID" 2>/dev/null && { kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }
  rm -rf "$SMOKE_TMP"
}
trap cleanup EXIT

fail_dump() {
  echo "---- serial log: agent lines ----" >&2
  grep -a 'agent gateway\|agent boot\|boot budget\|boot handshake' "$LOG" >&2 2>/dev/null | tail -40 || true
  echo "---- serial log tail (40) ----" >&2
  tail -40 "$LOG" >&2 2>/dev/null || true
}

echo "[2/2] boot under KVM (SEV_MODE=none; expected refusal + restart loop)"
DISK="$WORK" CLOUDINIT="" TWOD_HSM_SKIP_CLOUDINIT=1 \
  SEV_MODE=none GUEST_CID="$GUEST_CID" MEMORY="$MEMORY" VCPUS="$VCPUS" \
  nohup "$SCRIPT_DIR/run-guest-vm.sh" </dev/null >"$LOG" 2>&1 &
QPID=$!

# Wait for the restart evidence: >= 2 raw-budget lines (two boot cycles of the agent unit).
DEADLINE=$((SECONDS + BOOT_TIMEOUT_SEC))
while (( SECONDS < DEADLINE )); do
  if ! kill -0 "$QPID" 2>/dev/null; then
    echo "[FAIL] guest QEMU exited before two refusal cycles were observed" >&2
    fail_dump; exit 1
  fi
  RAW_COUNT="$(grep -ac 'boot budget config (raw, pre-validate)' "$LOG" 2>/dev/null || true)"
  [[ "${RAW_COUNT:-0}" -ge 2 ]] && break
  sleep 4
done

PASS=1
RAW_COUNT="$(grep -ac 'boot budget config (raw, pre-validate)' "$LOG" 2>/dev/null || true)"
if [[ "${RAW_COUNT:-0}" -lt 2 ]]; then
  echo "[FAIL] 3/4: only ${RAW_COUNT:-0} raw-budget line(s) within ${BOOT_TIMEOUT_SEC}s — no restart evidence" >&2
  PASS=0
fi
grep -aq '\[warn\] boot handshake outcome:' "$LOG" || { echo "[FAIL] 1/4: no [warn] refused-outcome line" >&2; PASS=0; }
grep -aq '\[err\] agent-gateway boot failed:' "$LOG" || { echo "[FAIL] 2/4: no [err] boot-failed render" >&2; PASS=0; }
if grep -aq 'serving on vsock' "$LOG"; then
  echo "[FAIL] 4/4: the agent SERVED under a refused outcome" >&2
  PASS=0
fi

kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true
QPID=""

if (( PASS != 1 )); then
  fail_dump
  exit 1
fi

echo
echo "[PASS] (iii) outcome-refusal E2E under KVM: warn-outcome + err-render + ${RAW_COUNT} restart cycles, never served"
