#!/usr/bin/env bash
# TASK-1.1: validate the SEV-SNP firmware-derived pq-seal root *in-guest* on a real SNP host.
#
# Boots the .#disk-production-lab-selftest NixOS image under SEV-SNP. That image runs a
# `snp-derive-root --selftest` oneshot at boot (before the enclave) which exercises
# SNP_GET_DERIVED_KEY on /dev/sev-guest and logs, to the serial console, a line:
#
#   snp-derive-root selftest: PASS (nonzero=true, binding_changes=true) measurement_root_commit=<hex>
#
# This script captures that console line and asserts the plan's crux:
#   (a) the ioctl returns a usable 32-byte key  -> nonzero=true
#   (c) MEASUREMENT binding actually changes it  -> binding_changes=true (=> PASS)
#   (b) the derived root is STABLE across reboots -> the SHA3-256 commitment is identical
#       across two independent boots of the same image on this platform.
# The commitment is a SHA3-256 of the root, never the root itself, so it is safe to log/compare.
#
# Runs on aya (see memory aya-snp-validation-host). KVM fallback (SEV_MODE=none) cannot derive a
# key — the oneshot will fail to find /dev/sev-guest — so this script requires a real SNP launch.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

DISK_ATTR="${DISK_ATTR:-disk-production-lab-selftest}"
SEV_MODE="${SEV_MODE:-snp}"
GUEST_CID="${GUEST_CID:-42}"
MEMORY="${MEMORY:-2048}"
VCPUS="${VCPUS:-2}"
# The selftest oneshot runs early in boot; allow time for the (cached) image build + boot.
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-240}"

if [[ "$SEV_MODE" != "snp" ]]; then
  echo "[skip] SEV_MODE=$SEV_MODE: the derived-key ioctl needs a real SNP launch (no /dev/sev-guest under KVM)." >&2
  exit 2
fi

twod_hsm_nix_init
twod_hsm_resolve_snp_qemu
echo "SNP: qemu=$QEMU_BIN bios=$SNP_BIOS"

echo "[1/3] nix .#${DISK_ATTR} (bootable EFI qcow2 with the selftest oneshot)"
DISK_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" "$DISK_ATTR" "${DISK_ATTR}")"
SRC_QCOW2="$(twod_hsm_nix_disk_qcow2 "$DISK_LINK")"
echo "      image: $SRC_QCOW2"

# Boot the image once and return the captured "snp-derive-root selftest:" console line.
# Each boot uses a fresh thin overlay over the read-only store qcow2 (so a reboot is a genuinely
# independent launch, not a resumed disk) — the derived root must still come out identical.
boot_once() {
  local label=$1 work log selftest_line=""
  work="$(mktemp -u "/tmp/2d-hsm-snp-selftest-${label}-XXXXXX.qcow2")"
  log="$(mktemp "/tmp/2d-hsm-snp-selftest-${label}-XXXXXX.log")"
  twod_hsm_make_work_overlay "$SRC_QCOW2" "$work"

  GUEST_CID="$GUEST_CID" twod_hsm_stop_stale_qemu
  local qpid=""
  cleanup_boot() {
    [[ -n "$qpid" ]] && kill -0 "$qpid" 2>/dev/null && { kill "$qpid" 2>/dev/null || true; wait "$qpid" 2>/dev/null || true; }
    rm -f "$work"
  }

  DISK="$work" CLOUDINIT="" TWOD_HSM_SKIP_CLOUDINIT=1 \
    SEV_MODE="$SEV_MODE" GUEST_CID="$GUEST_CID" MEMORY="$MEMORY" VCPUS="$VCPUS" \
    nohup "$SCRIPT_DIR/run-guest-vm.sh" </dev/null >"$log" 2>&1 &
  qpid=$!

  local deadline=$((SECONDS + BOOT_TIMEOUT_SEC))
  while (( SECONDS < deadline )); do
    if ! kill -0 "$qpid" 2>/dev/null; then
      # -no-reboot: a FAILED oneshot may panic/halt; surface the log either way.
      selftest_line="$(grep -a 'snp-derive-root selftest:' "$log" | tail -1 || true)"
      [[ -n "$selftest_line" ]] && break
      echo "guest QEMU exited before emitting the selftest line; log tail:" >&2
      tail -40 "$log" >&2 || true
      cleanup_boot; return 1
    fi
    selftest_line="$(grep -a 'snp-derive-root selftest:' "$log" 2>/dev/null | tail -1 || true)"
    [[ -n "$selftest_line" ]] && break
    sleep 4
  done
  cleanup_boot

  if [[ -z "$selftest_line" ]]; then
    echo "[FAIL] no 'snp-derive-root selftest:' line within ${BOOT_TIMEOUT_SEC}s ($label); log tail:" >&2
    tail -60 "$log" >&2 || true
    return 1
  fi
  echo "      [$label] $selftest_line" >&2
  printf '%s' "$selftest_line"
}

# Parse the measurement_root_commit=<hex> field out of a selftest line.
commit_of() { printf '%s' "$1" | sed -n 's/.*measurement_root_commit=\([0-9a-f]\{1,\}\).*/\1/p'; }

echo "[2/3] boot #1 under SEV-SNP"
LINE1="$(boot_once boot1)"
echo "$LINE1" | grep -q 'selftest: PASS' || { echo "[FAIL] boot #1 selftest did not PASS" >&2; exit 1; }
echo "$LINE1" | grep -q 'binding_changes=true' || { echo "[FAIL] boot #1 MEASUREMENT binding had no effect" >&2; exit 1; }
C1="$(commit_of "$LINE1")"
[[ -n "$C1" ]] || { echo "[FAIL] boot #1 emitted no measurement_root_commit" >&2; exit 1; }

echo "[3/3] boot #2 under SEV-SNP (stability across an independent reboot)"
LINE2="$(boot_once boot2)"
echo "$LINE2" | grep -q 'selftest: PASS' || { echo "[FAIL] boot #2 selftest did not PASS" >&2; exit 1; }
C2="$(commit_of "$LINE2")"
[[ -n "$C2" ]] || { echo "[FAIL] boot #2 emitted no measurement_root_commit" >&2; exit 1; }

if [[ "$C1" != "$C2" ]]; then
  echo "[FAIL] derived root NOT stable across reboots: $C1 != $C2" >&2
  exit 1
fi

echo
echo "[PASS] snp-derive-root in-guest validation on SEV-SNP:"
echo "       selftest PASS (nonzero + MEASUREMENT binding effective)"
echo "       derived-root commitment STABLE across two independent boots:"
echo "       measurement_root_commit=$C1"
