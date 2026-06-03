#!/usr/bin/env bash
# Boot confidential (or plain KVM) guest with vsock CID 42 and SSH :2222
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VCPUS="${VCPUS:-2}"
MEMORY="${MEMORY:-4096}"
DISK="${DISK:-vm-disk.qcow2}"
CLOUDINIT="${CLOUDINIT:-cloud-init.iso}"
SSH_PORT="${SSH_PORT:-2222}"
GUEST_CID="${GUEST_CID:-42}"
SEV_MODE="${SEV_MODE:-snp}"

if [[ -x /opt/qemu-snp/bin/qemu-system-x86_64 ]]; then
  QEMU_BIN="${QEMU_BIN:-/opt/qemu-snp/bin/qemu-system-x86_64}"
else
  QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
fi

[[ -f "$DISK" && -f "$CLOUDINIT" ]] || {
  echo "Run ./setup-guest-image.sh first"
  exit 1
}

if [[ -f /usr/share/OVMF/OVMF_CODE_4M.fd ]]; then
  OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
  OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
else
  echo "OVMF firmware not found"
  exit 1
fi
cp -f "$OVMF_VARS" ./ovmf-vars.fd

SEV_OPTS=""
MACHINE_OPTS="q35"

if [[ "$SEV_MODE" == "none" ]]; then
  echo "KVM baseline (no SEV)"
elif [[ "$(cat /sys/module/kvm_amd/parameters/sev 2>/dev/null)" != "Y" ]]; then
  echo "SEV not available — use SEV_MODE=none"
  exit 1
elif [[ "$SEV_MODE" == "snp" ]] && $QEMU_BIN -object help 2>&1 | grep -q sev-snp-guest; then
  echo "SEV-SNP guest (sev-snp-guest)"
  SEV_OPTS="-object memory-backend-memfd-private,id=ram1,size=${MEMORY}M,share=true"
  SEV_OPTS+=" -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1"
  MACHINE_OPTS="q35,confidential-guest-support=sev0,memory-backend=ram1"
elif [[ "$SEV_MODE" == "es" ]] && $QEMU_BIN -object help 2>&1 | grep -q sev-guest; then
  echo "SEV-ES guest (sev-guest) — often EPERM on SNP-only hosts; prefer SEV_MODE=snp"
  SEV_OPTS="-object sev-guest,id=sev0,sev-device=/dev/sev,cbitpos=51,reduced-phys-bits=1"
  MACHINE_OPTS="q35,confidential-guest-support=sev0"
else
  echo "Requested SEV_MODE=$SEV_MODE not supported by $QEMU_BIN"
  echo "Run ./install-qemu-snp.sh for SEV_MODE=snp"
  exit 1
fi

VSOCK_OPTS="-device vhost-vsock-pci,guest-cid=${GUEST_CID}"

echo "Starting VM: ${VCPUS} vCPU, ${MEMORY}MB RAM, SSH localhost:${SSH_PORT}, vsock guest-cid=${GUEST_CID}"
echo "Ctrl+A X to exit QEMU console"

exec $QEMU_BIN \
  -enable-kvm \
  -cpu host \
  -smp "$VCPUS" \
  -m "$MEMORY" \
  -machine "$MACHINE_OPTS" \
  -drive if=pflash,format=raw,unit=0,file="$OVMF_CODE",readonly=on \
  -drive if=pflash,format=raw,unit=1,file=./ovmf-vars.fd \
  -drive file="$DISK",format=qcow2,if=virtio \
  -drive file="$CLOUDINIT",format=raw,if=virtio \
  -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
  -device virtio-net-pci,netdev=net0 \
  $VSOCK_OPTS \
  -nographic \
  $SEV_OPTS