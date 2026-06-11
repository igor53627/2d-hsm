#!/usr/bin/env bash
# TASK-7.7 5b-2b-ii (d-ii)/4c: in-guest quote smoke on a real SNP host.
#
# Boots .#disk-production-lab-quote-smoke under SEV-SNP. That image runs the lab-only
# `twod-hsm-quote-smoke` oneshot at boot (alongside the enclave — standalone diagnostic, it does
# not gate the enclave unit), which drives the seven (4c) phases and prints, to journald AND the
# serial console (ttyS0):
#
#   twod-hsm-quote-smoke: START
#   twod-hsm-quote-smoke: PHASE <name> PASS|FAIL <detail>
#   twod-hsm-quote-smoke: RESULT PASS phases=7 | RESULT FAIL phase=<first-failed>
#
# HOST-SIDE PASS = ALL THREE witnesses in the captured serial log (TWO independent facts: the bin
# verdict, and the breadcrumb — the latter double-attested across two TRANSPORTS, console + journald,
# which is the point: it proves the inherited-stderr fan-out reaches both sinks):
#   1. the bin's own verdict        — 'twod-hsm-quote-smoke: RESULT PASS phases=7' (count anchored)
#   2. the raw child breadcrumb     — the staged ERR(1) child's stderr line on ttyS0 (console tee)
#   3. the in-guest journald assert — 'twod-hsm-quote-smoke: journald-breadcrumb PASS'
#      (the unit's ExecStartPost retry-grep proving the SAME breadcrumb ARRIVED in journald)
#
# SELF-MATCH GUARD: this script never echoes the breadcrumb literal — grep #2's pattern must only
# ever match the child's own stderr write in the log.
#
# Runs on aya (see memory aya-snp-validation-host). configfs-tsm is guest-SNP-only, so KVM
# (SEV_MODE=none) cannot PASS the configfs phases — this script requires a real SNP launch
# (use the run-book's KVM dry-run via run-guest-vm.sh directly for the deviceless phases).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

DISK_ATTR="${DISK_ATTR:-disk-production-lab-quote-smoke}"
SEV_MODE="${SEV_MODE:-snp}"
GUEST_CID="${GUEST_CID:-42}"
MEMORY="${MEMORY:-2048}"
VCPUS="${VCPUS:-2}"
# The smoke oneshot runs early in boot; allow time for the (cached) image build + boot.
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-240}"

if [[ "$SEV_MODE" != "snp" ]]; then
  echo "[skip] SEV_MODE=$SEV_MODE: the quote smoke needs guest configfs-tsm (real SNP launch only)." >&2
  exit 2
fi

twod_hsm_nix_init
twod_hsm_resolve_snp_qemu
echo "SNP: qemu=$QEMU_BIN bios=$SNP_BIOS"

echo "[1/2] nix .#${DISK_ATTR} (bootable EFI qcow2 with the quote-smoke oneshot)"
DISK_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" "$DISK_ATTR" "${DISK_ATTR}")"
SRC_QCOW2="$(twod_hsm_nix_disk_qcow2 "$DISK_LINK")"
echo "      image: $SRC_QCOW2"

WORK="$(mktemp -u "/tmp/2d-hsm-snp-quote-smoke-XXXXXX.qcow2")"
LOG="$(mktemp "/tmp/2d-hsm-snp-quote-smoke-XXXXXX.log")"
twod_hsm_make_work_overlay "$SRC_QCOW2" "$WORK"

GUEST_CID="$GUEST_CID" twod_hsm_stop_stale_qemu
QPID=""
cleanup() {
  [[ -n "$QPID" ]] && kill -0 "$QPID" 2>/dev/null && { kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }
  rm -f "$WORK" "$LOG"
}
trap cleanup EXIT

fail_dump() {
  echo "---- twod-hsm-quote-smoke marker lines ----" >&2
  grep -a 'twod-hsm-quote-smoke:' "$LOG" >&2 || true
  echo "---- log tail (60) ----" >&2
  tail -60 "$LOG" >&2 || true
}

echo "[2/2] boot under SEV-SNP (fresh overlay; capture serial log)"
DISK="$WORK" CLOUDINIT="" TWOD_HSM_SKIP_CLOUDINIT=1 \
  SEV_MODE="$SEV_MODE" GUEST_CID="$GUEST_CID" MEMORY="$MEMORY" VCPUS="$VCPUS" \
  nohup "$SCRIPT_DIR/run-guest-vm.sh" </dev/null >"$LOG" 2>&1 &
QPID=$!

VERDICT=""
DEADLINE=$((SECONDS + BOOT_TIMEOUT_SEC))
while (( SECONDS < DEADLINE )); do
  if ! kill -0 "$QPID" 2>/dev/null; then
    # -no-reboot: a failed boot may halt the guest; surface whatever was captured either way.
    VERDICT="$(grep -a 'twod-hsm-quote-smoke: RESULT ' "$LOG" | tail -1 || true)"
    [[ -n "$VERDICT" ]] && break
    echo "guest QEMU exited before emitting a RESULT line" >&2
    fail_dump
    exit 1
  fi
  VERDICT="$(grep -a 'twod-hsm-quote-smoke: RESULT ' "$LOG" 2>/dev/null | tail -1 || true)"
  [[ -n "$VERDICT" ]] && break
  sleep 4
done

if [[ -z "$VERDICT" ]]; then
  echo "[FAIL] no 'twod-hsm-quote-smoke: RESULT ' line within ${BOOT_TIMEOUT_SEC}s" >&2
  fail_dump
  exit 1
fi
echo "      verdict: $VERDICT"

# Poll for witness #3 (the unit's ExecStartPost journald assert, which runs AFTER ExecStart exits and
# retries journalctl up to ~10s) with a BOUNDED wait instead of a blind grace — a slow cold/loaded
# 2-vCPU boot could otherwise still be in the retry loop when a fixed sleep elapses (review hardening).
for _ in $(seq 1 30); do
  grep -aq 'twod-hsm-quote-smoke: journald-breadcrumb \(PASS\|FAIL\)' "$LOG" 2>/dev/null && break
  sleep 0.5
done
kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true
QPID=""

PASS=1
# Anchor on the FULL verdict incl. the phases=7 count — a future phase add/remove or a miscount that
# still lands on the no-fail branch would emit e.g. 'RESULT PASS phases=6' and a bare 'RESULT PASS'
# grep would still pass, silently breaking the documented 7-phase contract (review finding).
if ! grep -aq 'twod-hsm-quote-smoke: RESULT PASS phases=7' "$LOG"; then
  echo "[FAIL] witness 1/3: the bin did not report RESULT PASS phases=7" >&2
  PASS=0
fi
if ! grep -aq 'twod-hsm quote child: exit 1' "$LOG"; then
  echo "[FAIL] witness 2/3: the raw child breadcrumb never reached ttyS0" >&2
  PASS=0
fi
if ! grep -aq 'twod-hsm-quote-smoke: journald-breadcrumb PASS' "$LOG"; then
  echo "[FAIL] witness 3/3: the in-guest journald-arrival assert did not PASS" >&2
  PASS=0
fi

if (( PASS != 1 )); then
  fail_dump
  exit 1
fi

echo
echo "[PASS] (4c) in-guest quote smoke on SEV-SNP: all three witnesses present"
echo "       RESULT PASS + raw breadcrumb on ttyS0 + journald-breadcrumb PASS"
