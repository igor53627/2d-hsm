#!/usr/bin/env bash
# Host-only vsock loopback (no VM). Same as manual test on aya with CID=1.
set -euo pipefail

BIN="${HSM_BIN:-/root/2d-hsm/impl/rust/enclave-protocol/target/debug/enclave-vsock-staging}"
PORT="${HSM_VSOCK_PORT:-5000}"

if [[ ! -x "$BIN" ]]; then
  echo "Build first: cd impl/rust/enclave-protocol && cargo build --bin enclave-vsock-staging --features staging-vsock"
  exit 1
fi

pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true
sleep 2

env 2D_HSM_VSOCK_CID=1 "2D_HSM_VSOCK_PORT=$PORT" nohup "$BIN" >/tmp/enclave-vsock-staging.log 2>&1 &
sleep 1
grep -q listening /tmp/enclave-vsock-staging.log || { cat /tmp/enclave-vsock-staging.log; exit 1; }

export HSM_VSOCK_PORT="$PORT"
python3 <<'PY'
import os, socket, struct
port = int(os.environ["HSM_VSOCK_PORT"])
payload = bytes([0xA1, 0x01, 0x01])  # CBOR {1: 1}
body = bytes([1, 0x01]) + payload
frame = struct.pack(">I", len(body)) + body
s = socket.socket(40, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((1, port))
s.sendall(frame)
resp = b""
while len(resp) < 4:
    resp += s.recv(8192)
total = struct.unpack(">I", resp[:4])[0]
while len(resp) < 4 + total:
    resp += s.recv(8192)
assert b"prod-enclave-v1" in resp, "missing staging measurement in response"
print("host-loopback-smoke: OK", len(resp), "bytes")
PY

pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true
echo "host-loopback-smoke: passed"