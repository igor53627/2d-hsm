#!/usr/bin/env python3
"""vsock↔UDS relay: bridges AF_UNIX (for the Elixir :gen_tcp UDS client) to
AF_VSOCK (the enclave). This is a minimal TASK-180 proxy (~30 lines).

Usage:
  python3 vsock_uds_relay.py /tmp/phsm.sock 1 5000 &
  # Then the Elixir client connects to /tmp/phsm.sock via :gen_tcp({:local, ...})
"""
import os
import signal
import socket
import struct
import sys
import threading

UDS_PATH = sys.argv[1] if len(sys.argv) > 1 else "/tmp/phsm.sock"
VSOCK_CID = int(sys.argv[2]) if len(sys.argv) > 2 else 1
VSOCK_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 5000

def relay(src: socket.socket, dst: socket.socket):
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
    except (OSError, ConnectionError):
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass

def handle_conn(uds_conn: socket.socket):
    try:
        vsock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        vsock.settimeout(5)
        vsock.connect((VSOCK_CID, VSOCK_PORT))
        vsock.settimeout(None)
        t1 = threading.Thread(target=relay, args=(uds_conn, vsock), daemon=True)
        t2 = threading.Thread(target=relay, args=(vsock, uds_conn), daemon=True)
        t1.start(); t2.start()
    except Exception as e:
        print(f"relay: connect failed: {e}", file=sys.stderr)
        uds_conn.close()

def main():
    if os.path.exists(UDS_PATH):
        os.unlink(UDS_PATH)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(UDS_PATH)
    srv.listen(8)
    srv.settimeout(None)
    print(f"vsock↔UDS relay: {UDS_PATH} → vsock({VSOCK_CID}:{VSOCK_PORT})", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: (srv.close(), os.unlink(UDS_PATH), sys.exit(0)))
    while True:
        conn, _ = srv.accept()
        handle_conn(conn)

if __name__ == "__main__":
    main()
