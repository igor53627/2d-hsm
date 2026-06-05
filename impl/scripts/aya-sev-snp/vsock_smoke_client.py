#!/usr/bin/env python3
"""Shared GET_MEASUREMENT vsock probe (host-guest / loopback smokes)."""
from __future__ import annotations

import os
import socket
import struct
import sys
import time


def recv_until(sock: socket.socket, n: int, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    buf = b""
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout(
                "recv_until: %.1fs deadline exceeded (got %d/%d bytes)" % (timeout, len(buf), n)
            )
        sock.settimeout(remaining)
        chunk = sock.recv(min(8192, n - len(buf)))
        if not chunk:
            raise ConnectionError("peer closed before %d bytes (got %d)" % (n, len(buf)))
        buf += chunk
    return buf


def _decode_framed_get_measurement(frame: bytes) -> dict[int, object]:
    """Parse [u32 len][u8 ver][u8 type][cbor map] and return integer-keyed map."""
    if len(frame) < 6:
        raise ValueError("frame too short")
    total = struct.unpack(">I", frame[:4])[0]
    body = frame[4 : 4 + total]
    if len(body) < 2:
        raise ValueError("frame body too short")
    cbor = body[2:]
    try:
        import cbor2  # type: ignore
    except ImportError as e:
        raise ImportError(
            "vsock smoke requires cbor2 (apt install python3-cbor2 or pip install cbor2)"
        ) from e
    val = cbor2.loads(cbor)
    if not isinstance(val, dict):
        raise ValueError("GET_MEASUREMENT payload is not a CBOR map")
    out: dict[int, object] = {}
    for k, v in val.items():
        if isinstance(k, int):
            out[k] = v
        elif isinstance(k, str) and k.isdigit():
            out[int(k)] = v
        else:
            raise ValueError("unexpected CBOR map key type: %r" % (type(k),))
    return out


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
    if total > 1 << 20:
        raise ValueError("frame length %d exceeds 1 MiB cap" % total)
    resp += recv_until(s, 4 + total - 4, connect_timeout)

    fields = _decode_framed_get_measurement(resp)
    if marker is not None:
        measurement = fields.get(2)
        if not isinstance(measurement, (bytes, bytearray)) or marker not in measurement:
            raise AssertionError(("measurement marker missing", marker, measurement))
    if require_pq_ready:
        ready = fields.get(6)
        if ready is not True:
            raise AssertionError(("pq_signing_ready not true", ready, list(fields.keys())))
    return resp


def main() -> None:
    cid = int(os.environ.get("GUEST_CID", os.environ.get("VSOCK_CID", "1")))
    port = int(os.environ.get("TWOD_HSM_VSOCK_PORT", "5000"))
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