#!/usr/bin/env python3
"""Shared GET_MEASUREMENT vsock probe (host-guest / loopback smokes)."""
from __future__ import annotations

import os
import socket
import struct
import sys


def recv_until(sock: socket.socket, n: int, timeout: float) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(8192, n - len(buf)))
        if not chunk:
            raise ConnectionError("peer closed before %d bytes (got %d)" % (n, len(buf)))
        buf += chunk
    return buf


def get_measurement(
    *,
    cid: int,
    port: int,
    connect_timeout: float = 10.0,
    marker: bytes | None = None,
    require_pq_ready: bool = False,
) -> bytes:
    payload = bytes([0xA1, 0x01, 0x01])
    body = bytes([1, 0x01]) + payload
    frame = struct.pack(">I", len(body)) + body
    s = socket.socket(40, socket.SOCK_STREAM)
    s.settimeout(connect_timeout)
    s.connect((cid, port))
    s.sendall(frame)
    resp = recv_until(s, 4, connect_timeout)
    total = struct.unpack(">I", resp[:4])[0]
    resp += recv_until(s, 4 + total - 4, connect_timeout)
    if marker is not None and marker not in resp:
        raise AssertionError((marker, resp[:200]))
    if require_pq_ready and b"\x06\xf5" not in resp:
        raise AssertionError(("pq_signing_ready not true", resp[:120]))
    return resp


def main() -> None:
    cid = int(os.environ.get("GUEST_CID", os.environ.get("VSOCK_CID", "1")))
    port = int(os.environ["TWOD_HSM_VSOCK_PORT"])
    marker_s = os.environ.get("VSOCK_SMOKE_MEASUREMENT_MARKER")
    marker = marker_s.encode() if marker_s else None
    pq = os.environ.get("VSOCK_SMOKE_REQUIRE_PQ_READY") == "1"
    timeout = float(os.environ.get("VSOCK_SMOKE_TIMEOUT", "10"))
    resp = get_measurement(
        cid=cid,
        port=port,
        connect_timeout=timeout,
        marker=marker,
        require_pq_ready=pq,
    )
    label = os.environ.get("VSOCK_SMOKE_LABEL", "vsock-smoke")
    print("%s: OK cid=%d port=%d bytes=%d" % (label, cid, port, len(resp)))


if __name__ == "__main__":
    main()