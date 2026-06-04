#!/usr/bin/env bash
# Interactive debug: NixOS vm-hsm + host→guest vsock (aya).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
VM_LINK="${VM_LINK:-/tmp/vm-hsm-runner}"
DISK_IMAGE="${NIX_DISK_IMAGE:-/tmp/vm-hsm-debug.qcow2}"
GUEST_CID="${GUEST_CID:-42}"
HSM_VSOCK_PORT="${HSM_VSOCK_PORT:-5000}"
SSH_PORT="${SSH_PORT:-2223}"
LOG="${VM_HSM_LOG:-/tmp/vm-hsm-debug.log}"

if command -v nix >/dev/null; then
  [ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ] \
    && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
fi

stop_vm() {
  pgrep -f 'qemu-system-x86_64.*-name vm-hsm' | xargs -r kill 2>/dev/null || true
  sleep 2
}

find_runner() {
  local r=""
  for candidate in "$VM_LINK"/bin/run-*-vm "$VM_LINK"/bin/*run*nixos*; do
    if [ -e "$candidate" ]; then
      r=$(readlink -f "$candidate")
      break
    fi
  done
  [ -n "$r" ] && [ -x "$r" ] || { echo "no run-nixos-vm under $VM_LINK/bin" >&2; exit 1; }
  echo "$r"
}

vsock_probe() {
  python3 <<'PY'
import os, socket, struct, sys
cid = int(os.environ.get("PROBE_CID", "42"))
port = int(os.environ.get("HSM_VSOCK_PORT", "5000"))
AF_VSOCK = 40
print(f"probe cid={cid} port={port}")
try:
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((cid, port))
    print("  connect: OK")
    try:
        payload = bytes([0xA1, 0x01, 0x01])
        body = bytes([1, 0x01]) + payload
        frame = struct.pack(">I", len(body)) + body
        s.sendall(frame)
        print("  sent frame", len(frame), "bytes")
        resp = s.recv(256)
        print("  recv:", len(resp), resp[:80])
    except Exception as e:
        print("  io:", type(e).__name__, e)
    s.close()
except Exception as e:
    print("  connect:", type(e).__name__, e)
PY
}

echo "=== [1] nix build .#vm ==="
cd "$FLAKE_DIR"
nix build .#vm --out-link "$VM_LINK"
RUNNER=$(find_runner)
echo "runner=$RUNNER"

echo "=== [2] stop old VM, start fresh (disk=$DISK_IMAGE) ==="
stop_vm
: >"$LOG"
export NIX_DISK_IMAGE="$DISK_IMAGE"
export QEMU_NET_OPTS="${QEMU_NET_OPTS:-hostfwd=tcp::${SSH_PORT}-:22}"
export QEMU_OPTS="${QEMU_OPTS:-} -display none -device vhost-vsock-pci,guest-cid=${GUEST_CID}"
nohup "$RUNNER" </dev/null >>"$LOG" 2>&1 &
VM_PID=$!
echo "VM pid=$VM_PID log=$LOG"

echo "=== [3] serial log (grep enclave / diag) ==="
for i in $(seq 1 40); do
  kill -0 "$VM_PID" 2>/dev/null || { echo "VM died"; tail -50 "$LOG"; exit 1; }
  if grep -qE 'enclave-vsock-staging|vm-hsm|login:' "$LOG" 2>/dev/null; then
    grep -E 'enclave|vm-hsm|listening|error|failed|login:' "$LOG" | tail -20 || true
    break
  fi
  sleep 5
done

echo "=== [4] host vsock probe (CID 1, 3, 42) ==="
for c in 1 3 42; do PROBE_CID=$c HSM_VSOCK_PORT=$HSM_VSOCK_PORT vsock_probe; done

echo "=== [5] SSH guest (password smoke, if openssh enabled in module) ==="
if command -v sshpass >/dev/null; then
  for i in $(seq 1 24); do
    if sshpass -p smoke ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o ConnectTimeout=4 -p "$SSH_PORT" root@127.0.0.1 true 2>/dev/null; then
      echo "SSH up"
      sshpass -p smoke ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -p "$SSH_PORT" root@127.0.0.1 bash -s <<'GUEST' || true
set -x
systemctl is-enabled enclave-vsock-staging 2>&1 || true
systemctl is-active enclave-vsock-staging 2>&1 || true
systemctl status enclave-vsock-staging 2>&1 | head -25 || true
journalctl -u enclave-vsock-staging -b --no-pager 2>&1 | tail -20 || true
lsmod | grep -i vsock || true
cat /proc/net/vsock 2>/dev/null | head -10 || true
ss -l 2>/dev/null | head -5 || true
GUEST
      break
    fi
    sleep 5
  done
else
  echo "sshpass missing; skip SSH"
fi

echo "=== [6] manual enclave on guest (SSH) ==="
if command -v sshpass >/dev/null; then
  sshpass -p smoke ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -p "$SSH_PORT" root@127.0.0.1 bash -s <<'GUEST' 2>&1 || true
pkill -x enclave-vsock-staging 2>/dev/null || true
env 2D_HSM_VSOCK_CID=42 2D_HSM_VSOCK_PORT=5000 enclave-vsock-staging >/tmp/enclave-manual.log 2>&1 &
sleep 2
pgrep -a enclave || true
head -5 /tmp/enclave-manual.log || true
GUEST
  sleep 2
  echo "=== [7] vsock smoke after manual start ==="
  PROBE_CID=$GUEST_CID vsock_probe
  GUEST_CID=$GUEST_CID "$SCRIPT_DIR/host-guest-vsock-smoke.sh" 2>&1 || true
fi

echo "=== [8] QEMU cmd / shared dir ==="
pgrep -a qemu | grep vm-hsm || true
echo "log tail:"
tail -30 "$LOG"

echo "=== debug done (VM still running; kill with: pkill -f 'qemu.*vm-hsm') ==="