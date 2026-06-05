#!/usr/bin/env bash
# Build QEMU with sev-snp-guest (stock Ubuntu 8.2 only has legacy sev-guest).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${QEMU_SNP_PREFIX:-/opt/qemu-snp}"
VERSION="${QEMU_SNP_VERSION:-10.0.0}"
BUILD_ROOT="${SCRIPT_DIR}/qemu-build"
SRC="${BUILD_ROOT}/qemu-${VERSION}"

if [[ -x "${PREFIX}/bin/qemu-system-x86_64" ]] \
  && "${PREFIX}/bin/qemu-system-x86_64" --version 2>&1 | grep -q "version ${VERSION}" \
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

verify_qemu_tarball() {
  local tarball=$1
  local sums expected actual
  sums="$(curl -fsSL "https://download.qemu.org/sha256sum")"
  expected="$(printf '%s\n' "$sums" | awk -v f="qemu-${VERSION}.tar.xz" '$2 == f { print $1; exit }')"
  if [[ -z "$expected" ]]; then
    echo "install-qemu-snp: no upstream sha256 for qemu-${VERSION}.tar.xz" >&2
    return 1
  fi
  actual="$(sha256sum "$tarball" | awk '{ print $1 }')"
  if [[ "$actual" != "$expected" ]]; then
    echo "install-qemu-snp: sha256 mismatch for $(basename "$tarball")" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    return 1
  fi
}

mkdir -p "$BUILD_ROOT"
TARBALL="${BUILD_ROOT}/qemu-${VERSION}.tar.xz"
if [[ ! -d "$SRC" ]]; then
  if [[ ! -f "$TARBALL" ]]; then
    echo "Downloading QEMU ${VERSION}..."
    tmp_tarball="$(mktemp "${TARBALL}.tmp.XXXXXX")"
    if ! curl -fsSL "https://download.qemu.org/qemu-${VERSION}.tar.xz" -o "$tmp_tarball"; then
      rm -f "$tmp_tarball"
      exit 1
    fi
    if ! verify_qemu_tarball "$tmp_tarball"; then
      rm -f "$tmp_tarball"
      exit 1
    fi
    mv "$tmp_tarball" "$TARBALL"
  else
    verify_qemu_tarball "$TARBALL"
  fi
  tar -C "$BUILD_ROOT" -xf "$TARBALL"
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