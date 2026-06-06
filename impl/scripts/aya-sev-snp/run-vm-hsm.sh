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

# SNP needs a self-booting EFI image, not the qemu-vm runner; hand off to the
# dedicated launcher *before* building the (KVM-only) .#vm runner so we don't waste
# a build (TASK-5 AC#5). The launcher reads SEV_MODE / GUEST_CID from the env.
if [[ "$SEV_MODE" == "snp" ]]; then
  echo "SEV_MODE=snp: handing off to run-nix-snp-guest-smoke.sh (qemu-vm runner can't carry SNP)" >&2
  exec "$SCRIPT_DIR/run-nix-snp-guest-smoke.sh"
fi

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
# SEV_MODE=snp already handed off above; this runner path is KVM only.
VSOCK_DEV="-device vhost-vsock-pci,guest-cid=$GUEST_CID"
export QEMU_OPTS="${QEMU_OPTS:-} -display none $VSOCK_DEV"

echo "[2/2] starting NixOS vm-hsm (disk=$DISK_IMAGE, cid=$GUEST_CID)"
exec "$RUNNER"