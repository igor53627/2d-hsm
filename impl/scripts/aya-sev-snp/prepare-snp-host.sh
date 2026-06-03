#!/usr/bin/env bash
# One-time host prep for SEV-SNP on aya (before ./run-snp-smoke.sh)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== 1/3 QEMU 10 with sev-snp-guest ==="
"$SCRIPT_DIR/install-qemu-snp.sh"

echo "=== 2/3 Linux 6.17 HWE (guest_memfd / SNP KVM paths) ==="
if [[ -f /boot/vmlinuz-6.17.0-23-generic ]]; then
  echo "Kernel 6.17.0-23 already installed"
else
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    linux-image-6.17.0-23-generic linux-headers-6.17.0-23-generic
fi

RUNNING="$(uname -r)"
echo "Running kernel: $RUNNING"
if [[ "$RUNNING" != 6.17.* ]]; then
  echo ""
  echo "REBOOT REQUIRED: select 6.17.0-23-generic, then run:"
  echo "  cd $SCRIPT_DIR && ./run-snp-smoke.sh"
  echo ""
fi

echo "=== 3/3 (optional) SNP OVMF from AMDSEV edk2 ==="
OVMF_OUT="${SNP_OVMF_PREFIX:-/opt/amde-ovmf}"
if [[ -f "${OVMF_OUT}/OVMF.fd" ]]; then
  echo "OVMF already at ${OVMF_OUT}/OVMF.fd"
else
  echo "To build (30–60 min):"
  echo "  git clone https://github.com/AMDESE/AMDSEV.git /tmp/AMDSEV"
  echo "  cd /tmp/AMDSEV && ./build.sh ovmf --install ${OVMF_OUT}"
  echo "  export SNP_BIOS=${OVMF_OUT}/OVMF.fd"
fi

sevctl ok 2>&1 | tail -5
echo "prepare-snp-host: done"