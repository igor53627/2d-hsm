#!/usr/bin/env bash
# One-time (or after flake.lock / guest image changes): populate TWOD_HSM_CACHE for fast smokes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
BAKE_GOLDEN="${TWOD_HSM_BAKE_SNPDISK:-1}"

twod_hsm_ensure_cache_dirs
twod_hsm_nix_init
twod_hsm_ensure_python_cbor2

echo "=== warm-smoke-cache: $(twod_hsm_cache_root) ==="

echo "[1/5] nix out-links (enclave-staging, vm, vm-production, vm-production-lab)"
twod_hsm_nix_ensure "$FLAKE_DIR" enclave-staging enclave-staging >/dev/null
twod_hsm_nix_ensure "$FLAKE_DIR" vm vm-hsm-runner-vm >/dev/null
twod_hsm_nix_ensure "$FLAKE_DIR" vm-production vm-hsm-runner-vm-production >/dev/null
twod_hsm_nix_ensure "$FLAKE_DIR" vm-production-lab vm-hsm-runner-vm-production-lab >/dev/null

echo "[2/5] SNP Ubuntu cloud image + base overlay + cloud-init"
"$SCRIPT_DIR/setup-guest-image.sh"

echo "[3/5] firmware (link OVMF into cache if present)"
twod_hsm_link_firmware_cache
if [[ ! -f "$(twod_hsm_cache_firmware)/OVMF.fd" ]] \
  && [[ "$(twod_hsm_snp_ovmf_path)" == */OVMF.amdsev.fd ]]; then
  echo "WARN: AMD OVMF not found — SNP boot may hang at reset vector." >&2
  echo "  Build: cd /tmp/AMDSEV && sed -i 's/GCCVERS=\"GCC13\"/GCCVERS=\"GCC\"/' common.sh" >&2
  echo "        ./build.sh ovmf --install /opt/amde-ovmf && cp .../OVMF.fd /opt/amde-ovmf/share/qemu/" >&2
  echo "  Then re-run: TWOD_HSM_BAKE_SNPDISK=1 ./warm-smoke-cache.sh" >&2
  BAKE_GOLDEN=0
fi

echo "[4/5] touch Nix VM disk paths (qcow2 created on first smoke boot)"
for attr in vm vm-production vm-production-lab; do
  disk="$(twod_hsm_nix_vm_disk "$attr")"
  if [[ ! -f "$disk" ]]; then
    : >"${disk}.placeholder"
    rm -f "${disk}.placeholder"
    echo "  will create on first boot: $disk"
  else
    echo "  exists: $disk"
  fi
done

if [[ "$BAKE_GOLDEN" == "1" ]] && [[ ! -f "$(twod_hsm_snp_golden_disk)" ]]; then
  echo "[5/5] bake SNP golden disk (first cloud-init + ssh; may take several minutes)"
  QEMU_BIN="${QEMU_BIN:-/opt/qemu-snp/bin/qemu-system-x86_64}"
  if [[ ! -x "$QEMU_BIN" ]] || ! "$QEMU_BIN" -object help 2>&1 | grep -q sev-snp-guest; then
    echo "WARN: skip golden bake — SNP QEMU not ready (./install-qemu-snp.sh)" >&2
  else
    export SNP_BIOS
    SNP_BIOS="$(twod_hsm_snp_ovmf_path)"
    export SEV_MODE=snp MEMORY="${MEMORY:-2048}" VCPUS="${VCPUS:-2}"
    twod_hsm_snp_prepare_work_disk "$SCRIPT_DIR" || {
      echo "warm: snp work disk missing after setup-guest-image" >&2
      exit 1
    }
    ci_iso="$(twod_hsm_snp_cloudinit_iso)"
    [[ -f "$ci_iso" ]] && ln -sf "$ci_iso" "$SCRIPT_DIR/cloud-init.iso"
    LOG=/tmp/warm-snp-bake.log
    : >"$LOG"
    nohup "$SCRIPT_DIR/run-guest-vm.sh" >"$LOG" 2>&1 &
    QEMU_PID=$!
    cleanup_bake() {
      kill "$QEMU_PID" 2>/dev/null || true
      wait "$QEMU_PID" 2>/dev/null || true
    }
    trap cleanup_bake EXIT
    ssh_timeout="$(twod_hsm_snp_ssh_ready_timeout)"
    if twod_hsm_wait_guest_ssh 2222 "$ssh_timeout" "$LOG" 0; then
      ready_deadline=$((SECONDS + 180))
      while (( SECONDS < ready_deadline )); do
        if ssh $(twod_hsm_ssh_opts) -o ConnectTimeout=2 -p 2222 ubuntu@127.0.0.1 \
          'test -f /var/log/hsm-guest-ready || echo ready | sudo tee /var/log/hsm-guest-ready >/dev/null' 2>/dev/null \
          && ssh $(twod_hsm_ssh_opts) -o ConnectTimeout=2 -p 2222 ubuntu@127.0.0.1 \
          test -f /var/log/hsm-guest-ready 2>/dev/null; then
          golden="$(twod_hsm_snp_golden_disk)"
          cp -f "$SCRIPT_DIR/vm-disk.qcow2" "$golden"
          echo "golden disk: $golden"
          break
        fi
        sleep 5
      done
      if [[ ! -f "$(twod_hsm_snp_golden_disk)" ]]; then
        echo "WARN: SSH up but hsm-guest-ready missing after 180s" >&2
      fi
    fi
    if [[ ! -f "$(twod_hsm_snp_golden_disk)" ]]; then
      echo "WARN: golden bake failed — run-snp-smoke will use base overlay + longer timeout" >&2
      tail -20 "$LOG" >&2 || true
    fi
    trap - EXIT
    cleanup_bake
  fi
else
  echo "[5/5] skip SNP golden bake (TWOD_HSM_BAKE_SNPDISK=0 or golden exists)"
fi

echo "warm-smoke-cache: done"
echo "  Nix smokes: ./run-nix-enclave-staging.sh && ./run-nix-vm-guest-smoke*.sh"
echo "  SNP smoke:  ./run-snp-smoke.sh"