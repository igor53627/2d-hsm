#!/usr/bin/env bash
# TASK-1.1 sealed-boot loop: prove the enclave unseals its ML-DSA-65 signer against the SNP
# FIRMWARE-DERIVED root (not a baked lab fixture), end to end, on a real SEV-SNP host.
#
# The enclave already reads its 32-byte pq-seal provisioning root from a FILE
# (TWOD_HSM_PQ_SEAL_V1_ROOT_FILE) and unseals the signer against (root, measurement). This ceremony
# makes that FILE the firmware-derived root and proves the loop closes:
#   1. Boot .#disk-production-lab-print-ceremony under SNP — it runs `snp-derive-root --print` and
#      logs the SECRET derived root (64 hex) to the serial console. Capture it. CEREMONY ONLY: the
#      root lands in the host's local QEMU log, so run on a trusted host.
#   2. Seal the committed reference ML-DSA-65 keypair against (that root, b"enclave-measurement-
#      placeholder" — the measurement the lab enclave unseals with) offline via pq-seal-v1 →
#      ceremony-sealed-signer.bin.
#   3. Force-add that blob into the worktree flake source and build .#disk-production-lab-snp-rooted:
#      sealRootSource="snp" adds a boot oneshot that writes the derived root to /run and points the
#      enclave's root file there; the baked blob is the one we just sealed against that derived root.
#   4. Boot it under SNP and assert the enclave reaches pq_signing_ready AND serves a real launch
#      measurement (run-nix-snp-guest-smoke.sh) — only possible if it unsealed with the derived root.
#
# Run on aya in a throwaway worktree (see memory aya-snp-validation-host). SNP only (the derived key
# needs /dev/sev-guest). The staged blob is discarded with the worktree.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FLAKE_DIR="$ROOT_DIR/impl/nix/vm-hsm"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

SEV_MODE="${SEV_MODE:-snp}"
GUEST_CID="${GUEST_CID:-42}"
MEMORY="${MEMORY:-2048}"
VCPUS="${VCPUS:-2}"
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-240}"
TV="$ROOT_DIR/impl/rust/enclave-protocol/testvectors"
CEREMONY_BLOB="$FLAKE_DIR/ceremony-sealed-signer.bin"

if [[ "$SEV_MODE" != "snp" ]]; then
  echo "[skip] SEV_MODE=$SEV_MODE: the derived root needs a real SNP launch (/dev/sev-guest)." >&2
  exit 2
fi

twod_hsm_nix_init
twod_hsm_resolve_snp_qemu
echo "SNP: qemu=$QEMU_BIN bios=$SNP_BIOS"

# The lab enclave unseals against this exact measurement (boot_lab_pq_seal::LAB_PROD_MEASUREMENT),
# since the guest sets no TWOD_HSM_ENCLAVE_MEASUREMENT_FILE. Seal against the same bytes.
MEAS_HEX="$(printf '%s' "enclave-measurement-placeholder" | od -An -v -tx1 | tr -d ' \n')"

WORK1=""
QPID=""
cleanup() {
  if [[ -n "$QPID" ]] && kill -0 "$QPID" 2>/dev/null; then
    kill "$QPID" 2>/dev/null || true
    wait "$QPID" 2>/dev/null || true
  fi
  [[ -n "$WORK1" ]] && rm -f "$WORK1"
}
trap cleanup EXIT

# --- Phase 1: derive the root in-guest (printed to the serial console) -----------
echo "[1/4] build + boot .#disk-production-lab-print-ceremony → capture derived root"
PRINT_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" disk-production-lab-print-ceremony disk-production-lab-print-ceremony)"
PRINT_QCOW2="$(twod_hsm_nix_disk_qcow2 "$PRINT_LINK")"
WORK1="$(mktemp -u /tmp/2d-hsm-snp-ceremony-print-XXXXXX.qcow2)"
LOG1="$(mktemp /tmp/2d-hsm-snp-ceremony-print-XXXXXX.log)"
twod_hsm_make_work_overlay "$PRINT_QCOW2" "$WORK1"
twod_hsm_stop_stale_qemu

DISK="$WORK1" CLOUDINIT="" TWOD_HSM_SKIP_CLOUDINIT=1 \
  SEV_MODE="$SEV_MODE" GUEST_CID="$GUEST_CID" MEMORY="$MEMORY" VCPUS="$VCPUS" \
  nohup "$SCRIPT_DIR/run-guest-vm.sh" </dev/null >"$LOG1" 2>&1 &
QPID=$!

# The console line is `<ts> snp-derive-root[pid]: <64-hex root>` (no other 64-hex follows that
# prefix — the selftest commitment line has text after `]: `, not hex).
root_hex_from_log() {
  grep -aoE 'snp-derive-root\[[0-9]+\]: [0-9a-f]{64}' "$LOG1" | tail -1 | grep -oE '[0-9a-f]{64}' || true
}
ROOT_HEX=""
deadline=$((SECONDS + BOOT_TIMEOUT_SEC))
while (( SECONDS < deadline )); do
  ROOT_HEX="$(root_hex_from_log)"
  [[ -n "$ROOT_HEX" ]] && break
  kill -0 "$QPID" 2>/dev/null || { ROOT_HEX="$(root_hex_from_log)"; break; }
  sleep 4
done
if [[ -n "$QPID" ]] && kill -0 "$QPID" 2>/dev/null; then
  kill "$QPID" 2>/dev/null || true
  wait "$QPID" 2>/dev/null || true
fi
QPID=""
if [[ -z "$ROOT_HEX" ]]; then
  echo "[FAIL] no derived root printed within ${BOOT_TIMEOUT_SEC}s; log tail:" >&2
  tail -60 "$LOG1" >&2 || true
  exit 1
fi
echo "      derived root captured (64 hex; not echoed)"

# --- Phase 2: seal the reference keypair against the derived root (offline) ------
echo "[2/4] seal reference ML-DSA-65 keypair against the derived root (pq-seal-v1)"
ROOTBIN="$(mktemp /tmp/2d-hsm-snp-ceremony-root-XXXXXX.bin)"
python3 -c "import binascii; open('$ROOTBIN','wb').write(binascii.unhexlify('$ROOT_HEX'))"
sz="$(wc -c < "$ROOTBIN" | tr -d ' ')"
[[ "$sz" == 32 ]] || { echo "[FAIL] derived root is $sz bytes, expected 32" >&2; rm -f "$ROOTBIN"; exit 1; }

# pq-seal-v1 is a path-dep crate (on enclave-protocol), not a nix package; build with cargo (on PATH
# or via the flake devShell, which guarantees the toolchain).
PQSEAL="$ROOT_DIR/impl/rust/pq-seal-v1/target/release/pq-seal-v1"
if command -v cargo >/dev/null 2>&1; then
  ( cd "$ROOT_DIR/impl/rust/pq-seal-v1" && cargo build --release )
else
  nix develop "$FLAKE_DIR" -c bash -c "cd '$ROOT_DIR/impl/rust/pq-seal-v1' && cargo build --release"
fi
[[ -x "$PQSEAL" ]] || { echo "[FAIL] pq-seal-v1 not built at $PQSEAL" >&2; rm -f "$ROOTBIN"; exit 1; }

rm -f "$CEREMONY_BLOB"
"$PQSEAL" seal \
  --secret-key-file "$TV/mldsa65_reference_sk.bin" \
  --public-key-file "$TV/mldsa65_reference_pk.bin" \
  --provisioning-root-file "$ROOTBIN" \
  --measurement-hex "$MEAS_HEX" \
  -o "$CEREMONY_BLOB"
shred -u "$ROOTBIN" 2>/dev/null || rm -f "$ROOTBIN"
echo "      sealed signer → ceremony-sealed-signer.bin ($(wc -c < "$CEREMONY_BLOB" | tr -d ' ') bytes)"

# Stage the blob so the (git) flake source includes it (nix flake eval ignores untracked files).
( cd "$ROOT_DIR" && git add -f impl/nix/vm-hsm/ceremony-sealed-signer.bin )

# --- Phase 3 + 4: build the snp-rooted image with that blob and prove it unseals -
echo "[3/4] build + boot .#disk-production-lab-snp-rooted (derive oneshot → /run; baked blob)"
echo "[4/4] assert enclave unseals (pq_signing_ready) + serves a real measurement (vsock smoke)"
DISK_ATTR=disk-production-lab-snp-rooted \
  SEV_MODE="$SEV_MODE" GUEST_CID="$GUEST_CID" MEMORY="$MEMORY" VCPUS="$VCPUS" \
  VSOCK_SMOKE_REQUIRE_REAL_MEASUREMENT=1 \
  VSOCK_SMOKE_REQUIRE_PQ_READY=1 \
  bash "$SCRIPT_DIR/run-nix-snp-guest-smoke.sh"

echo
echo "[PASS] sealed-boot loop: the enclave unsealed its ML-DSA-65 signer against the SNP"
echo "       firmware-derived root (boot oneshot → /run/twod-hsm/pq-seal-root.bin) and serves a"
echo "       real launch measurement. The derived root is now load-bearing end to end."
