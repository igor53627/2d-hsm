#!/usr/bin/env bash
# Launch NixOS vm-hsm via nixpkgs qemu-vm (KVM dev; optional SNP via QEMU_OPTS).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
VM_LINK="${VM_LINK:-/tmp/vm-hsm-runner}"
DISK_IMAGE="${NIX_DISK_IMAGE:-/tmp/vm-hsm.qcow2}"
GUEST_CID="${GUEST_CID:-42}"
SEV_MODE="${SEV_MODE:-none}"

if command -v nix >/dev/null; then
  [ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ] \
    && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
fi

cd "$FLAKE_DIR"

echo "[1/2] nix build .#vm -> $VM_LINK"
nix build .#vm --out-link "$VM_LINK"

RUNNER="$(twod_hsm_find_vm_runner "$VM_LINK")"

export NIX_DISK_IMAGE="$DISK_IMAGE"

# vsock for host↔guest smoke (host-guest-vsock-smoke.sh uses GUEST_CID).
VSOCK_DEV="-device vhost-vsock-pci,guest-cid=$GUEST_CID"
case "$SEV_MODE" in
  snp)
    QEMU_BIN="${QEMU:-/opt/qemu-snp/bin/qemu-system-x86_64}"
    if [ ! -x "$QEMU_BIN" ]; then
      echo "SEV_MODE=snp requires QEMU with memfd-private (e.g. /opt/qemu-snp on aya)" >&2
      exit 1
    fi
    # qemu-vm runner embeds its own QEMU; SNP path is manual until we unify launchers.
    echo "SEV_MODE=snp: use dedicated SNP launcher after qcow2 exists at $DISK_IMAGE" >&2
    echo "  $QEMU_BIN ... -drive file=$DISK_IMAGE ... $VSOCK_DEV" >&2
    exit 2
    ;;
  none|*)
    export QEMU_OPTS="${QEMU_OPTS:-} -display none $VSOCK_DEV"
    ;;
esac

echo "[2/2] starting NixOS vm-hsm (disk=$DISK_IMAGE, cid=$GUEST_CID)"
exec "$RUNNER"