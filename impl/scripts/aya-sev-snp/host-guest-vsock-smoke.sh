#!/usr/bin/env bash
# From aya host: vsock connect to confidential guest (QEMU guest-cid)
set -euo pipefail

GUEST_CID="${GUEST_CID:-42}"
export GUEST_CID="${GUEST_CID:-42}"
export TWOD_HSM_VSOCK_PORT="${TWOD_HSM_VSOCK_PORT:-5000}"
# Staging GET_MEASUREMENT uses prod-enclave-v1; production profile uses enclave-measurement-placeholder.
export VSOCK_SMOKE_MEASUREMENT_MARKER="${VSOCK_SMOKE_MEASUREMENT_MARKER:-prod-enclave-v1}"
python3 <<'PY'
import os, socket, struct
cid = int(os.environ["GUEST_CID"])
port = int(os.environ["TWOD_HSM_VSOCK_PORT"])
payload = bytes([0xA1, 0x01, 0x01])
body = bytes([1, 0x01]) + payload
frame = struct.pack(">I", len(body)) + body
s = socket.socket(40, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((cid, port))
s.sendall(frame)
resp = b""
while len(resp) < 4:
    resp += s.recv(8192)
total = struct.unpack(">I", resp[:4])[0]
while len(resp) < 4 + total:
    resp += s.recv(8192)
marker = os.environ["VSOCK_SMOKE_MEASUREMENT_MARKER"].encode()
assert marker in resp, (marker, resp[:200])
print("host-guest-vsock-smoke: OK cid=%d port=%d bytes=%d" % (cid, port, len(resp)))
PY