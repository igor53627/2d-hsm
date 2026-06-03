#!/usr/bin/env bash
# One-time: Ubuntu 24.04 cloud image + cloud-init for SSH on :2222
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
IMAGE_FILE="ubuntu-24.04-cloudimg.qcow2"
DISK_FILE="vm-disk.qcow2"

if [[ -f "$DISK_FILE" ]]; then
  echo "VM disk already exists: $DISK_FILE"
  exit 0
fi

if [[ ! -f "$IMAGE_FILE" ]]; then
  echo "Downloading cloud image..."
  wget -O "$IMAGE_FILE" "$IMAGE_URL"
fi

echo "Creating ${DISK_FILE} (20G overlay)..."
qemu-img create -f qcow2 -F qcow2 -b "$IMAGE_FILE" "$DISK_FILE" 20G

SSH_KEY="${SSH_KEY:-}"
if [[ -z "$SSH_KEY" ]]; then
  if [[ -f /root/.ssh/id_ed25519.pub ]]; then
    SSH_KEY="$(cat /root/.ssh/id_ed25519.pub)"
  elif [[ -f /root/.ssh/id_rsa.pub ]]; then
    SSH_KEY="$(cat /root/.ssh/id_rsa.pub)"
  else
    ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ""
    SSH_KEY="$(cat /root/.ssh/id_ed25519.pub)"
  fi
fi

cat > cloud-init-user-data <<EOF
#cloud-config
hostname: hsm-sev-guest
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${SSH_KEY}
packages:
  - rsync
runcmd:
  - echo ready > /var/log/hsm-guest-ready
EOF

cat > cloud-init-meta-data <<'META'
instance-id: hsm-sev-guest-1
local-hostname: hsm-sev-guest
META

cloud-localds cloud-init.iso cloud-init-user-data cloud-init-meta-data
echo "setup-guest-image: OK"