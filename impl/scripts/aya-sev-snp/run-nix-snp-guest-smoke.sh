#!/usr/bin/env bash
# TASK-5 Phase 3 / AC#5: boot the *NixOS* production guest under SEV-SNP and prove
# GET_MEASUREMENT returns a REAL launch measurement (not the KVM/dev placeholder).
#
# vs the other launchers:
#   run-nix-vm-guest-smoke.sh  → NixOS guest, KVM only (qemu-vm runner)
#   run-snp-smoke.sh           → Ubuntu golden disk + *staging* binary, under SNP
#   THIS                       → NixOS *prod* disk image (.#disk-production-lab),
#                                self-booting EFI qcow2, under SNP
#
# The enclave is baked into the image as a systemd unit, so unlike the Ubuntu path
# there is no scp/SSH step: boot the image, then run the host→guest vsock smoke.
#
# The gates auto-adjust to the disk + mode (no manual env needed):
#   DISK_ATTR=disk-production-lab (default) ships the lab-sealed PQ signer → under
#     SNP the enclave binds + caches a real measurement (require_real, require_pq).
#   DISK_ATTR=disk-production (transport-only) has no operational signer → boot-only
#     (require_real=0, require_pq=0; placeholder measurement expected).
#   SEV_MODE=none (KVM fallback, no SNP host) → require_real=0 and the smoke matches
#     the placeholder label instead. Override any gate via the VSOCK_SMOKE_* env.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

DISK_ATTR="${DISK_ATTR:-disk-production-lab}"
SEV_MODE="${SEV_MODE:-snp}"
GUEST_CID="${GUEST_CID:-42}"
MEMORY="${MEMORY:-2048}"
VCPUS="${VCPUS:-2}"
TWOD_HSM_VSOCK_PORT="${TWOD_HSM_VSOCK_PORT:-5000}"
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-240}"
# Per-PID work disk so concurrent runs don't clobber each other's live qemu disk.
WORK_DISK="${WORK_DISK:-/tmp/2d-hsm-nixos-snp-${DISK_ATTR}-$$.qcow2}"
LOG="${SNP_NIX_LOG:-/tmp/2d-hsm-nixos-snp-qemu.log}"

# Gate defaults derived from the disk + launch mode so every documented invocation
# works without manual env. Only the lab disk ships an operational PQ signer
# (transport disk has none); a real launch measurement needs BOTH that signer AND
# an SNP host (off-SNP / transport ⇒ the enclave serves the placeholder label).
case "$DISK_ATTR" in
  *-lab) HAS_SIGNER=1 ;;
  *) HAS_SIGNER=0 ;;
esac
if [[ "$SEV_MODE" == "snp" && "$HAS_SIGNER" == 1 ]]; then
  REQUIRE_REAL="${VSOCK_SMOKE_REQUIRE_REAL_MEASUREMENT:-1}"
else
  REQUIRE_REAL="${VSOCK_SMOKE_REQUIRE_REAL_MEASUREMENT:-0}"
fi
REQUIRE_PQ="${VSOCK_SMOKE_REQUIRE_PQ_READY:-$HAS_SIGNER}"
# When not asserting a real measurement, match the placeholder label the enclave
# falls back to (otherwise host-guest-vsock-smoke.sh's default marker prod-enclave-v1
# — a staging label — would never match the prod guest's measurement).
if [[ "$REQUIRE_REAL" != 1 ]]; then
  export VSOCK_SMOKE_MEASUREMENT_MARKER="${VSOCK_SMOKE_MEASUREMENT_MARKER:-enclave-measurement-placeholder}"
fi

twod_hsm_ensure_python_cbor2

# --- QEMU + firmware (SNP only) -------------------------------------------------
if [[ "$SEV_MODE" == "snp" ]]; then
  if [[ -x /opt/qemu-snp/bin/qemu-system-x86_64 ]]; then
    QEMU_BIN="${QEMU_BIN:-/opt/qemu-snp/bin/qemu-system-x86_64}"
  else
    QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
  fi
  if [[ ! -x "$QEMU_BIN" ]] || ! "$QEMU_BIN" -object help 2>&1 | grep -q sev-snp-guest; then
    echo "SEV_MODE=snp needs QEMU with sev-snp-guest (run ./install-qemu-snp.sh, or SEV_MODE=none)" >&2
    exit 1
  fi
  SNP_BIOS="$(twod_hsm_snp_ovmf_path)"
  export SNP_BIOS QEMU_BIN
  echo "SNP: qemu=$QEMU_BIN bios=$SNP_BIOS"
else
  QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
  export QEMU_BIN
  echo "KVM baseline (SEV_MODE=none): no real measurement expected"
fi

# --- Build the bootable NixOS prod disk image -----------------------------------
echo "[1/4] nix .#${DISK_ATTR} (bootable EFI qcow2)"
DISK_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" "$DISK_ATTR" "${DISK_ATTR}")"
SRC_QCOW2="$(twod_hsm_nix_disk_qcow2 "$DISK_LINK")"
echo "      image: $SRC_QCOW2"

# The store qcow2 is read-only and QEMU must write the guest disk. Prefer a thin
# qcow2 overlay over the read-only store image (near-instant vs copying ~2 GiB);
# fall back to a full writable copy if qemu-img is unavailable.
rm -f "$WORK_DISK"
QEMU_IMG="${QEMU_IMG:-$(dirname "$QEMU_BIN")/qemu-img}"
[[ -x "$QEMU_IMG" ]] || QEMU_IMG="$(command -v qemu-img || true)"
if [[ -n "$QEMU_IMG" && -x "$QEMU_IMG" ]]; then
  "$QEMU_IMG" create -q -f qcow2 -F qcow2 -b "$SRC_QCOW2" "$WORK_DISK"
else
  cp -f "$SRC_QCOW2" "$WORK_DISK"
  chmod u+w "$WORK_DISK"
fi

# --- Launch under SNP (reuse the proven SNP QEMU line in run-guest-vm.sh) --------
twod_hsm_stop_stale_qemu

QEMU_PID=""
cleanup() {
  if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  rm -f "$WORK_DISK"
}
trap cleanup EXIT

: >"$LOG"
echo "[2/4] boot NixOS guest (disk=$WORK_DISK, cid=$GUEST_CID, mode=$SEV_MODE, mem=${MEMORY}M)"
# No cloud-init: the NixOS image is self-contained (enclave is a baked systemd unit).
DISK="$WORK_DISK" CLOUDINIT="" TWOD_HSM_SKIP_CLOUDINIT=1 \
  SEV_MODE="$SEV_MODE" GUEST_CID="$GUEST_CID" MEMORY="$MEMORY" VCPUS="$VCPUS" \
  nohup "$SCRIPT_DIR/run-guest-vm.sh" </dev/null >"$LOG" 2>&1 &
QEMU_PID=$!
echo "      qemu pid=$QEMU_PID log=$LOG"

# --- Wait for the guest vsock to serve GET_MEASUREMENT --------------------------
echo "[3/4] waiting for guest vsock (up to ${BOOT_TIMEOUT_SEC}s; require_real=${REQUIRE_REAL} require_pq=${REQUIRE_PQ})"
deadline=$((SECONDS + BOOT_TIMEOUT_SEC))
ok=0
while (( SECONDS < deadline )); do
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "guest QEMU exited early; log tail:" >&2
    tail -40 "$LOG" >&2 || true
    exit 1
  fi
  if GUEST_CID="$GUEST_CID" TWOD_HSM_VSOCK_PORT="$TWOD_HSM_VSOCK_PORT" \
     VSOCK_SMOKE_REQUIRE_REAL_MEASUREMENT="$REQUIRE_REAL" \
     VSOCK_SMOKE_REQUIRE_PQ_READY="$REQUIRE_PQ" \
     VSOCK_SMOKE_LABEL="run-nix-snp-guest-smoke" \
     "$SCRIPT_DIR/host-guest-vsock-smoke.sh" 2>/dev/null; then
    ok=1
    break
  fi
  sleep 5
done

if [[ "$ok" != 1 ]]; then
  echo "[FAIL] guest vsock smoke timed out (${BOOT_TIMEOUT_SEC}s); log tail:" >&2
  tail -100 "$LOG" >&2 || true
  exit 1
fi

echo "[4/4] [PASS] run-nix-snp-guest-smoke: NixOS .#${DISK_ATTR} under SEV_MODE=${SEV_MODE}, real_measurement=${REQUIRE_REAL}, pq_ready=${REQUIRE_PQ}"
