#!/usr/bin/env bash
# One-time: Ubuntu 24.04 cloud image + cloud-init for SSH on :2222 (cached under TWOD_HSM_CACHE).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

IMAGE_BASE_URL="${TWOD_HSM_UBUNTU_IMAGE_BASE_URL:-https://cloud-images.ubuntu.com/noble/current}"
IMAGE_NAME="${TWOD_HSM_UBUNTU_IMAGE_NAME:-noble-server-cloudimg-amd64.img}"
IMAGE_URL="${IMAGE_BASE_URL}/${IMAGE_NAME}"
IMAGE_SHA256="${TWOD_HSM_UBUNTU_IMAGE_SHA256:-}"
IMAGE_FILE="$(twod_hsm_snp_ubuntu_image)"
BASE_DISK="$(twod_hsm_snp_base_disk)"
CLOUD_ISO="$(twod_hsm_snp_cloudinit_iso)"
WORK_DISK="${SCRIPT_DIR}/vm-disk.qcow2"

twod_hsm_ensure_cache_dirs

verify_ubuntu_image() {
  local image=$1 expected actual sums
  expected="$IMAGE_SHA256"
  if [[ -z "$expected" ]]; then
    sums="$(curl -fsSL "${IMAGE_BASE_URL}/SHA256SUMS")"
    expected="$(printf '%s\n' "$sums" | awk -v f="${IMAGE_NAME}" '$2 == "*" f || $2 == f { print $1; exit }')"
  fi
  if [[ -z "$expected" ]]; then
    echo "setup-guest-image: no sha256 for ${IMAGE_NAME}; set TWOD_HSM_UBUNTU_IMAGE_SHA256" >&2
    return 1
  fi
  actual="$(sha256sum "$image" | awk '{ print $1 }')"
  if [[ "$actual" != "$expected" ]]; then
    echo "setup-guest-image: sha256 mismatch for $(basename "$image")" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    return 1
  fi
}

if [[ -f "$BASE_DISK" && "${TWOD_HSM_REGEN_SNPDISK:-0}" != "1" ]]; then
  echo "SNP base disk cached: $BASE_DISK"
else
  if [[ ! -f "$IMAGE_FILE" ]]; then
    echo "Downloading cloud image -> $IMAGE_FILE"
    wget -O "$IMAGE_FILE" "$IMAGE_URL"
  fi
  verify_ubuntu_image "$IMAGE_FILE"
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
