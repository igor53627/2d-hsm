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
SNP_BIOS="${SNP_BIOS:-/opt/amde-ovmf/OVMF.fd}"

if [[ -x /opt/qemu-snp/bin/qemu-system-x86_64 ]]; then
  QEMU_BIN="${QEMU_BIN:-/opt/qemu-snp/bin/qemu-system-x86_64}"
else
  QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
fi

[[ -f "$DISK" && -f "$CLOUDINIT" ]] || {
  echo "Run ./setup-guest-image.sh first"
  exit 1
}

if [[ ! -f "$SNP_BIOS" ]]; then
  SNP_BIOS="/usr/share/ovmf/OVMF.amdsev.fd"
fi

USE_SNP=0
SEV_OPTS=""
MACHINE_OPTS="q35"
QEMU_CPU="${QEMU_CPU:-host}"

if [[ "$SEV_MODE" == "none" ]]; then
  echo "KVM baseline (no SEV)"
elif [[ "$(cat /sys/module/kvm_amd/parameters/sev 2>/dev/null)" != "Y" ]]; then
  echo "SEV not available — use SEV_MODE=none"
  exit 1
elif [[ "$SEV_MODE" == "snp" ]] && $QEMU_BIN -object help 2>&1 | grep -q sev-snp-guest; then
  echo "SEV-SNP guest (AMDSEV-style launch, bios=$SNP_BIOS)"
  USE_SNP=1
  QEMU_CPU="${QEMU_CPU:-EPYC-v4,+la57,phys-bits=52}"
elif [[ "$SEV_MODE" == "es" ]] && $QEMU_BIN -object help 2>&1 | grep -q sev-guest; then
  echo "SEV-ES guest (legacy; often EPERM on SNP-only hosts)"
  SEV_OPTS="-object sev-guest,id=sev0,sev-device=/dev/sev,cbitpos=51,reduced-phys-bits=1"
  MACHINE_OPTS="q35,confidential-guest-support=sev0"
else
  echo "Requested SEV_MODE=$SEV_MODE not supported by $QEMU_BIN"
  echo "Run ./install-qemu-snp.sh and ./prepare-snp-host.sh"
  exit 1
fi

VSOCK="-device vhost-vsock-pci,guest-cid=${GUEST_CID}"
NET="-netdev user,id=vmnic,hostfwd=tcp::${SSH_PORT}-:22 -device virtio-net-pci,netdev=vmnic"

echo "Starting VM: ${VCPUS} vCPU, ${MEMORY}MB RAM, SSH localhost:${SSH_PORT}, vsock guest-cid=${GUEST_CID}"
echo "Ctrl+A X to exit QEMU console"

if [[ "$USE_SNP" == 1 ]]; then
  exec $QEMU_BIN \
    -enable-kvm -cpu "$QEMU_CPU" -machine q35 \
    -smp "$VCPUS" -m "${MEMORY}M,slots=5,maxmem=$((MEMORY + 8192))M" -no-reboot \
    -bios "$SNP_BIOS" \
    -drive "file=$DISK,format=qcow2,if=virtio" \
    -drive "file=$CLOUDINIT,format=raw,if=virtio" \
    $NET $VSOCK -nographic \
    -machine confidential-guest-support=sev0,vmport=off \
    -object "memory-backend-memfd,id=ram1,size=${MEMORY}M,share=true,prealloc=false" \
    -machine memory-backend=ram1 \
    -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1
fi

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
cp -f "$OVMF_VARS" ./ovmf-vars.fd

exec $QEMU_BIN \
  -enable-kvm -cpu "$QEMU_CPU" -smp "$VCPUS" -m "$MEMORY" -machine "$MACHINE_OPTS" \
  -drive if=pflash,format=raw,unit=0,file="$OVMF_CODE",readonly=on \
  -drive if=pflash,format=raw,unit=1,file=./ovmf-vars.fd \
  -drive "file=$DISK,format=qcow2,if=virtio" \
  -drive "file=$CLOUDINIT,format=raw,if=virtio" \
  $NET $VSOCK -nographic $SEV_OPTS