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
  case "${IMAGE_BASE_URL%/}" in
    */current)
      if [[ -n "$expected" ]]; then
        echo "setup-guest-image: warning: pinned SHA with moving current URL; prefer a dated image URL" >&2
      fi
      ;;
  esac
  if [[ -z "$expected" ]]; then
    if [[ "${TWOD_HSM_TRUST_UPSTREAM_SHA256SUMS:-0}" != "1" ]]; then
      echo "setup-guest-image: set TWOD_HSM_UBUNTU_IMAGE_SHA256 for trusted builds" >&2
      echo "  lab-only fallback: TWOD_HSM_TRUST_UPSTREAM_SHA256SUMS=1 fetches ${IMAGE_BASE_URL}/SHA256SUMS" >&2
      return 1
    fi
    echo "setup-guest-image: lab-only SHA256SUMS fallback is integrity-only; it does not protect against a compromised mirror" >&2
    if ! sums="$(curl -fsSL "${IMAGE_BASE_URL}/SHA256SUMS")"; then
      echo "setup-guest-image: failed to fetch ${IMAGE_BASE_URL}/SHA256SUMS" >&2
      return 1
    fi
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
    echo "  recovery: delete $IMAGE_FILE and rerun with TWOD_HSM_REGEN_SNPDISK=1" >&2
    return 1
  fi
}

if [[ -f "$BASE_DISK" && -f "$IMAGE_FILE" && "${TWOD_HSM_REGEN_SNPDISK:-0}" != "1" ]]; then
  echo "SNP base disk cached: $BASE_DISK"
else
  image_verified=0
  if [[ ! -f "$IMAGE_FILE" ]]; then
    echo "Downloading cloud image -> $IMAGE_FILE"
    tmp_image="$(mktemp "${IMAGE_FILE}.tmp.XXXXXX")"
    if ! wget -O "$tmp_image" "$IMAGE_URL"; then
      rm -f "$tmp_image"
      exit 1
    fi
    if ! verify_ubuntu_image "$tmp_image"; then
      rm -f "$tmp_image"
      exit 1
    fi
    mv "$tmp_image" "$IMAGE_FILE"
    image_verified=1
  fi
  if [[ "$image_verified" != "1" ]]; then
    verify_ubuntu_image "$IMAGE_FILE"
  fi
  echo "Creating base overlay -> $BASE_DISK (20G)"
  tmp_base="$(mktemp "${BASE_DISK}.tmp.XXXXXX")"
  if ! qemu-img create -f qcow2 -F qcow2 -b "$IMAGE_FILE" "$tmp_base" 20G; then
    rm -f "$tmp_base"
    exit 1
  fi
  # Atomic replace: a failed create above never clobbers the existing base, and the
  # rename keeps any running VM's open inode intact (no leaked *.stale.* copies).
  mv "$tmp_base" "$BASE_DISK"
  # A golden disk was baked from the previous base/image; it takes precedence in
  # run-snp-smoke.sh and twod_hsm_snp_prepare_work_disk and would silently shadow this
  # rebuild, so drop it. warm-smoke-cache.sh re-bakes it on the next run.
  golden_disk="$(twod_hsm_snp_golden_disk)"
  if [[ -f "$golden_disk" ]]; then
    echo "Invalidating stale SNP golden disk -> $golden_disk"
    rm -f "$golden_disk"
  fi
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
