#!/usr/bin/env bash
# Launch NixOS vm-hsm via nixpkgs qemu-vm (KVM dev; optional SNP via QEMU_OPTS).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"
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
    # The nixpkgs qemu-vm runner embeds its own QEMU and injects the kernel
    # directly — it cannot carry the SEV-SNP launch objects. The SNP path uses a
    # self-booting EFI disk image (.#disk-production-lab) instead (TASK-5 AC#5).
    echo "SEV_MODE=snp is not served by the qemu-vm runner; use the dedicated launcher:" >&2
    echo "  $SCRIPT_DIR/run-nix-snp-guest-smoke.sh" >&2
    exit 2
    ;;
  none|*)
    export QEMU_OPTS="${QEMU_OPTS:-} -display none $VSOCK_DEV"
    ;;
esac

echo "[2/2] starting NixOS vm-hsm (disk=$DISK_IMAGE, cid=$GUEST_CID)"
exec "$RUNNER"