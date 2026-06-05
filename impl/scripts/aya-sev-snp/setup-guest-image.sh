#!/usr/bin/env bash
# One-time: Ubuntu 24.04 cloud image + cloud-init for SSH on :2222 (cached under TWOD_HSM_CACHE).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
IMAGE_FILE="$(twod_hsm_snp_ubuntu_image)"
BASE_DISK="$(twod_hsm_snp_base_disk)"
CLOUD_ISO="$(twod_hsm_snp_cloudinit_iso)"
WORK_DISK="${SCRIPT_DIR}/vm-disk.qcow2"

twod_hsm_ensure_cache_dirs

if [[ -f "$BASE_DISK" && "${TWOD_HSM_REGEN_SNPDISK:-0}" != "1" ]]; then
  echo "SNP base disk cached: $BASE_DISK"
else
  if [[ ! -f "$IMAGE_FILE" ]]; then
    echo "Downloading cloud image -> $IMAGE_FILE"
    wget -O "$IMAGE_FILE" "$IMAGE_URL"
  fi
  echo "Creating base overlay -> $BASE_DISK (20G)"
  qemu-img create -f qcow2 -F qcow2 -b "$IMAGE_FILE" "$BASE_DISK" 20G
fi

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

if [[ ! -f "$CLOUD_ISO" || "${TWOD_HSM_REGEN_CLOUDINIT:-0}" == "1" ]]; then
  cat >"${SCRIPT_DIR}/cloud-init-user-data" <<EOF
#cloud-config
hostname: hsm-sev-guest
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${SSH_KEY}
packages:
  - openssh-server
  - rsync
runcmd:
  - systemctl enable --now ssh.socket
  - echo ready > /var/log/hsm-guest-ready
EOF
  cat >"${SCRIPT_DIR}/cloud-init-meta-data" <<'META'
instance-id: hsm-sev-guest-cache-1
local-hostname: hsm-sev-guest
META
  cloud-localds "$CLOUD_ISO" "${SCRIPT_DIR}/cloud-init-user-data" \
    "${SCRIPT_DIR}/cloud-init-meta-data"
  echo "cloud-init iso: $CLOUD_ISO"
fi

ln -sf "$CLOUD_ISO" "${SCRIPT_DIR}/cloud-init.iso"
cp -f "$BASE_DISK" "$WORK_DISK"
echo "setup-guest-image: OK (base=$BASE_DISK work=$WORK_DISK)"