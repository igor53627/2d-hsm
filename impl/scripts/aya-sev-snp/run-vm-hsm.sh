#!/usr/bin/env bash
# Launch NixOS vm-hsm qcow2 under QEMU (KVM or SEV-SNP when configured).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
VM_IMAGE="${VM_IMAGE:-/tmp/vm-hsm.qcow2}"
SEV_MODE="${SEV_MODE:-none}" # none | snp
QEMU="${QEMU:-qemu-system-x86_64}"
GUEST_CID="${GUEST_CID:-42}"

if command -v nix >/dev/null; then
  [ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ] \
    && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
fi

cd "$FLAKE_DIR"
git -C "$ROOT" add -f impl/nix/vm-hsm 2>/dev/null || true

echo "[1/2] nix build .#qcow2"
nix build .#qcow2 --out-link /tmp/vm-hsm-qcow2-result
cp -f /tmp/vm-hsm-qcow2-result/nixos.qcow2 "$VM_IMAGE"

echo "[2/2] starting QEMU (SEV_MODE=$SEV_MODE)"
case "$SEV_MODE" in
  snp)
    # Requires QEMU with memory-backend-memfd-private (e.g. /opt/qemu-snp on aya).
    exec "$QEMU" \
      -enable-kvm \
      -cpu EPYC-v4 \
      -machine "q35,confidential-guest-support=sev0,memory-backend=ram1" \
      -object "memory-backend-memfd-private,id=ram1,size=512M,share=true" \
      -object "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1" \
      -m 512M \
      -smp 2 \
      -drive "file=$VM_IMAGE,if=virtio,format=qcow2" \
      -device "vhost-vsock-pci,guest-cid=$GUEST_CID" \
      -nographic \
      -serial mon:stdio
    ;;
  none|*)
    exec "$QEMU" \
      -enable-kvm \
      -cpu host \
      -m 512M \
      -smp 2 \
      -drive "file=$VM_IMAGE,if=virtio,format=qcow2" \
      -device "vhost-vsock-pci,guest-cid=$GUEST_CID" \
      -nographic \
      -serial mon:stdio
    ;;
esac