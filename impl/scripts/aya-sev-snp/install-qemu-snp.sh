#!/usr/bin/env bash
# Build QEMU with sev-snp-guest (stock Ubuntu 8.2 only has legacy sev-guest).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${QEMU_SNP_PREFIX:-/opt/qemu-snp}"
VERSION="${QEMU_SNP_VERSION:-10.0.0}"
BUILD_ROOT="${SCRIPT_DIR}/qemu-build"
SRC="${BUILD_ROOT}/qemu-${VERSION}"

if [[ -x "${PREFIX}/bin/qemu-system-x86_64" ]] \
  && "${PREFIX}/bin/qemu-system-x86_64" -object help 2>&1 | grep -q sev-snp-guest; then
  echo "install-qemu-snp: already OK at ${PREFIX}"
  "${PREFIX}/bin/qemu-system-x86_64" --version
  exit 0
fi

echo "=== install-qemu-snp: QEMU ${VERSION} -> ${PREFIX} ==="
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential git curl ca-certificates \
  libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev \
  libslirp-dev libcap-ng-dev libattr1-dev libusb-1.0-0-dev

mkdir -p "$BUILD_ROOT"
if [[ ! -d "$SRC" ]]; then
  echo "Downloading QEMU ${VERSION}..."
  curl -fsSL "https://download.qemu.org/qemu-${VERSION}.tar.xz" -o "${BUILD_ROOT}/qemu-${VERSION}.tar.xz"
  tar -C "$BUILD_ROOT" -xf "${BUILD_ROOT}/qemu-${VERSION}.tar.xz"
fi

cd "$SRC"
./configure --prefix="$PREFIX" --target-list=x86_64-softmmu
make -j "$(nproc)"
make install

if ! "${PREFIX}/bin/qemu-system-x86_64" -object help 2>&1 | grep -q sev-snp-guest; then
  echo "install-qemu-snp: build missing sev-snp-guest object"
  exit 1
fi

echo "install-qemu-snp: success"
"${PREFIX}/bin/qemu-system-x86_64" --version