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


# SEV-SNP ATTESTATION_REPORT launch measurement is 48 bytes (report offset 0x90);
# the raw VCEK-signed report is 1184 bytes (version 5). See snp_report.rs
# (MIN_REPORT_LEN / the committed golden report).
SNP_MEASUREMENT_LEN = 48
SNP_REPORT_MIN_LEN = 1184
# Non-attested measurement labels: the *staging/reference* build serves
# prod-enclave-v1; the production build falls back to enclave-measurement-placeholder
# off-SNP/dev (lib.rs resolve_measurement_and_attestation). Either means "not a real
# SNP measurement". The matching attestation fallback is attestation-placeholder.
PLACEHOLDER_MEASUREMENTS = (b"enclave-measurement-placeholder", b"prod-enclave-v1")
PLACEHOLDER_ATTESTATION = b"attestation-placeholder"


def assert_measurement_fields(
    fields: dict[int, object],
    *,
    marker: bytes | None = None,
    require_pq_ready: bool = False,
    require_real_measurement: bool = False,
) -> None:
    """Validate a decoded GET_MEASUREMENT CBOR map (raises AssertionError on mismatch).

    Pure (no I/O) so the SNP/marker gates are unit-testable without a live guest.
    """
    if require_real_measurement:
        # AC#5 live SNP gate: GET_MEASUREMENT must carry the real launch measurement,
        # not the placeholder label the enclave falls back to on KVM/dev hosts.
        measurement = fields.get(2)
        if not isinstance(measurement, (bytes, bytearray)):
            raise AssertionError(("measurement is not bytes", measurement))
        if len(measurement) != SNP_MEASUREMENT_LEN:
            raise AssertionError(
                ("measurement not %d bytes (SNP launch measurement)" % SNP_MEASUREMENT_LEN,
                 len(measurement), bytes(measurement))
            )
        if bytes(measurement) in PLACEHOLDER_MEASUREMENTS:
            raise AssertionError(("measurement is a placeholder label, not a real SNP measurement", bytes(measurement)))
        attestation = fields.get(3)
        if not isinstance(attestation, (bytes, bytearray)):
            raise AssertionError(("attestation is not bytes", attestation))
        # Structural shape check only (this is a smoke, not a verifier): a real
        # report is >= 1184 bytes and not the 23-byte placeholder. Cryptographic
        # VCEK-chain verification + measurement binding is the deferred verifier work.
        if bytes(attestation) == PLACEHOLDER_ATTESTATION or len(attestation) < SNP_REPORT_MIN_LEN:
            raise AssertionError(("attestation is not a real SNP report", len(attestation)))
    elif marker is not None:
        measurement = fields.get(2)
        if not isinstance(measurement, (bytes, bytearray)) or marker not in measurement:
            raise AssertionError(("measurement marker missing", marker, measurement))
    if require_pq_ready:
        ready = fields.get(6)
        if ready is not True:
            raise AssertionError(("pq_signing_ready not true", ready, list(fields.keys())))


def get_measurement(
    *,
    cid: int,
    port: int,
    connect_timeout: float = 10.0,
    marker: bytes | None = None,
    require_pq_ready: bool = False,
    require_real_measurement: bool = False,
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
    assert_measurement_fields(
        fields,
        marker=marker,
        require_pq_ready=require_pq_ready,
        require_real_measurement=require_real_measurement,
    )
    return resp


def main() -> None:
    cid = int(os.environ.get("GUEST_CID", os.environ.get("VSOCK_CID", "1")))
    port = int(os.environ.get("TWOD_HSM_VSOCK_PORT", "5000"))
    marker_s = os.environ.get("VSOCK_SMOKE_MEASUREMENT_MARKER")
    require_real = os.environ.get("VSOCK_SMOKE_REQUIRE_REAL_MEASUREMENT") == "1"
    # A real SNP measurement is 48 raw bytes — no text marker applies; the
    # require_real assertion supersedes any inherited marker default.
    marker = None if require_real else (marker_s.encode() if marker_s else None)
    pq = os.environ.get("VSOCK_SMOKE_REQUIRE_PQ_READY") == "1"
    timeout = float(os.environ.get("VSOCK_SMOKE_TIMEOUT", "10"))
    resp = get_measurement(
        cid=cid,
        port=port,
        connect_timeout=timeout,
        marker=marker,
        require_pq_ready=pq,
        require_real_measurement=require_real,
    )
    label = os.environ.get("VSOCK_SMOKE_LABEL", "vsock-smoke")
    print("%s: OK cid=%d port=%d bytes=%d" % (label, cid, port, len(resp)))
    if os.environ.get("VSOCK_SMOKE_PRINT_MEASUREMENT") == "1":
        # Print the GET_MEASUREMENT measurement (CBOR key 2) + attestation length so
        # the SNP launch-measurement anchor can be captured for the manifest/verifier.
        fields = _decode_framed_get_measurement(resp)
        meas = fields.get(2)
        att = fields.get(3)
        meas_hex = meas.hex() if isinstance(meas, (bytes, bytearray)) else repr(meas)
        att_len = len(att) if isinstance(att, (bytes, bytearray)) else "n/a"
        print("%s: measurement=%s attestation_len=%s pq_ready=%s"
              % (label, meas_hex, att_len, fields.get(6)))


if __name__ == "__main__":
    main()