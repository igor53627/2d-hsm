#!/usr/bin/env python3
"""Producer vsock smoke — exercises all 4 producer commands against the
staging enclave over AF_VSOCK (TASK-122 AC#3 staging evidence).

Usage:
  # Start the enclave first (loopback CID=1 or guest CID=42):
  #   env TWOD_HSM_VSOCK_CID=1 TWOD_HSM_VSOCK_PORT=5000 enclave-vsock-staging &
  # Then:
  VSOCK_CID=1 TWOD_HSM_VSOCK_PORT=5000 python3 producer_vsock_smoke.py
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import time

if any(a in ("-h", "--help") for a in sys.argv[1:]):
    print(__doc__)
    sys.exit(0)

try:
    import cbor2  # type: ignore
except ImportError:
    sys.exit("Requires cbor2: apt install python3-cbor2 or pip install cbor2")

CID = int(os.environ.get("VSOCK_CID", "1"))
PORT = int(os.environ.get("TWOD_HSM_VSOCK_PORT", "5000"))
TIMEOUT = float(os.environ.get("VSOCK_SMOKE_TIMEOUT", "10"))
FAILURES: list[str] = []


def vsock_connect(cid: int, port: int, timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((cid, port))
    return sock


def encode_frame(msg_type: int, payload: bytes) -> bytes:
    total = 2 + len(payload)
    return struct.pack(">I", total) + bytes([1, msg_type]) + payload


def recv_frame(sock: socket.socket, timeout: float) -> tuple[int, bytes]:
    deadline = time.monotonic() + timeout
    header = recv_until(sock, 4, timeout)
    total = struct.unpack(">I", header)[0]
    if total > 1_048_576:
        raise ValueError(f"frame too large: {total}")
    body = recv_until(sock, total, max(deadline - time.monotonic(), 0.1))
    if len(body) < 2:
        raise ValueError("frame body too short")
    version, msg_type = body[0], body[1]
    if version != 1:
        raise ValueError(f"unexpected protocol version: {version}")
    return msg_type, body[2:]


def recv_until(sock: socket.socket, n: int, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    buf = b""
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout(f"recv {n} bytes: timed out (got {len(buf)})")
        sock.settimeout(remaining)
        chunk = sock.recv(min(8192, n - len(buf)))
        if not chunk:
            raise ConnectionError(f"peer closed (got {len(buf)}/{n})")
        buf += chunk
    return buf


def send_recv(msg_type: int, payload: bytes, label: str) -> tuple[int, bytes]:
    frame = encode_frame(msg_type, payload)
    sock = vsock_connect(CID, PORT, TIMEOUT)
    try:
        sock.sendall(frame)
        mt, resp_payload = recv_frame(sock, TIMEOUT)
        return mt, resp_payload
    finally:
        sock.close()


def check(cond: bool, msg: str) -> None:
    status = "OK" if cond else "FAIL"
    print(f"  [{status}] {msg}")
    if not cond:
        FAILURES.append(msg)


# Message type bytes (spec §8)
GET_MEASUREMENT = 0x01
SIGN_AUTHORIZATION_TICKET = 0x10
ARM_FOR_PRODUCTION = 0x20
GET_STATUS = 0x30


def test_get_measurement() -> None:
    print("\n=== GET_MEASUREMENT (0x01) ===")
    payload = cbor2.dumps({1: 1})  # version=1
    mt, resp = send_recv(GET_MEASUREMENT, payload, "GET_MEASUREMENT")
    check(mt == GET_MEASUREMENT, f"response type=0x{mt:02x} (expected 0x01)")
    m = cbor2.loads(resp)
    check(isinstance(m, dict), "response is CBOR map")
    check(m.get(1) == 1, f"version=1 (got {m.get(1)})")
    pubkey = m.get(4, b"")
    check(len(pubkey) == 1952, f"pq_pubkey is 1952 bytes ML-DSA-65 (got {len(pubkey)})")
    global ENCLAVE_PUBKEY
    ENCLAVE_PUBKEY = pubkey
    ready = m.get(6)
    check(ready is True, f"pq_signing_ready=True (got {ready})")
    types = m.get(5, [])
    check(types == [0, 1], f"supported_ticket_types=[0,1] (got {types})")
    print(f"  measurement: {len(m.get(2, b''))} bytes, attestation: {len(m.get(3, b''))} bytes")


def test_get_status() -> None:
    print("\n=== GET_STATUS (0x30) ===")
    payload = cbor2.dumps({1: 1})
    mt, resp = send_recv(GET_STATUS, payload, "GET_STATUS")
    check(mt == GET_STATUS, f"response type=0x{mt:02x} (expected 0x30)")
    m = cbor2.loads(resp)
    check(isinstance(m, dict), "response is CBOR map")
    check(m.get(1) == 1, f"version=1 (got {m.get(1)})")
    armed = m.get(2)
    check(armed is False, f"armed=False (not armed yet; got {armed})")
    print(f"  armed={armed}, last_known_block={m.get(9)}")


ENCLAVE_PUBKEY = None  # populated by test_get_measurement; used by test_sign_authorization_ticket


def test_sign_authorization_ticket() -> None:
    print("\n=== SIGN_AUTHORIZATION_TICKET (0x10) ===")
    # Use the REAL enclave pubkey from GET_MEASUREMENT (roborev 10811: using a
    # placeholder pubkey but accepting a signature could bless a mismatched-key bug).
    pubkey = ENCLAVE_PUBKEY or b"\x42" * 1952
    ticket = {
        1: 0,  # ticket_type = PRODUCER_RECOVERY
        2: 1,  # nonce
        3: b"\xAB" * 32,  # context_hash
        4: 1000,  # activation_height
        5: b"\x55" * 48,  # new_measurement
        6: pubkey,  # pq_pubkey (real enclave key from GET_MEASUREMENT)
        7: None,  # fork_spec_hash (null for recovery)
        8: None,  # new_header_version (null for recovery)
        9: None,  # governance_ref (always null in v1)
    }
    payload = cbor2.dumps({1: 1, 2: ticket})
    mt, resp = send_recv(SIGN_AUTHORIZATION_TICKET, payload, "SIGN_AUTHORIZATION_TICKET")
    check(mt == SIGN_AUTHORIZATION_TICKET, f"response type=0x{mt:02x} (expected 0x10)")
    m = cbor2.loads(resp)

    if isinstance(m.get(1), int) and isinstance(m.get(2), str):
        # Wire error shape {1: code, 2: reason}
        code = m[1]
        reason = m[2]
        check(code == 2, f"wire error code=2 (semantic error; got code={code})")
        print(f"  wire error (expected — enclave rejects unsigned ticket): code={code} reason={reason}")
    elif m.get(1) == 1 and isinstance(m.get(2), bytes):
        # Success: {1: version, 2: signature, 3: ticket_hash}
        sig = m[2]
        check(len(sig) == 3309, f"signature is 3309 bytes ML-DSA-65 (got {len(sig)})")
        ticket_hash = m.get(3, b"")
        check(len(ticket_hash) == 32, f"ticket_hash is 32 bytes (got {len(ticket_hash)})")
        print(f"  SUCCESS: signature={len(sig)} bytes, ticket_hash={ticket_hash.hex()[:16]}...")
    else:
        check(False, f"unexpected response shape: keys={list(m.keys())}")


def test_arm_for_production() -> None:
    print("\n=== ARM_FOR_PRODUCTION (0x20) ===")
    # ARM requires a valid RecentChainProof with a real Ed25519 signature.
    # Without one, the enclave should refuse (code=2 semantic error).
    authorized_state = {
        1: b"\x42" * 1952,  # pq_pubkey
        2: b"\x5A" * 48,  # measurement
        3: 99,  # activated_at_height
        4: b"\xCC" * 32,  # source_ticket_hash
    }
    recent_chain_proof = {
        1: 100,  # finalized_height
        2: b"\xDD" * 32,  # finalized_header_hash
        3: [b"\xEE" * 32],  # recovery_history_tail
        4: b"\x01",  # proof_data (format 0x01)
        5: b"\xAA" * 64,  # signature_from_recent_producer (bogus Ed25519)
    }
    payload = cbor2.dumps({1: 1, 2: authorized_state, 3: recent_chain_proof})
    mt, resp = send_recv(ARM_FOR_PRODUCTION, payload, "ARM_FOR_PRODUCTION")
    check(mt == ARM_FOR_PRODUCTION, f"response type=0x{mt:02x} (expected 0x20)")
    m = cbor2.loads(resp)
    if m.get(1) == "armed":
        check(False, "ARM should NOT succeed with a bogus RecentChainProof (security regression)")
    elif isinstance(m.get(1), int) and isinstance(m.get(2), str):
        code = m[1]
        reason = m[2]
        check(code == 2, f"refused with code=2 (expected — bogus proof; got code={code})")
        print(f"  refused (expected — bogus RecentChainProof): code={code} reason={reason}")
    else:
        check(False, f"unexpected response shape: keys={list(m.keys())}")


def main() -> None:
    print(f"Producer vsock smoke: CID={CID} PORT={PORT} TIMEOUT={TIMEOUT}s")
    test_get_measurement()
    test_get_status()
    test_sign_authorization_ticket()
    test_arm_for_production()

    print(f"\n{'='*60}")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("ALL PRODUCER COMMANDS PASSED — enclave handles the full vsock producer protocol")
        sys.exit(0)


if __name__ == "__main__":
    main()
