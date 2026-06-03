#!/usr/bin/env bash
# From aya host: vsock connect to confidential guest (QEMU guest-cid)
set -euo pipefail

GUEST_CID="${GUEST_CID:-42}"
PORT="${2D_HSM_VSOCK_PORT:-5000}"

python3 <<PY
import socket, struct, os
cid = int(os.environ.get("GUEST_CID", "${GUEST_CID}"))
port = int(os.environ.get("PORT", "${PORT}"))
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
assert b"prod-enclave-v1" in resp, resp[:200]
print("host-guest-vsock-smoke: OK cid=%d port=%d bytes=%d" % (cid, port, len(resp)))
PY