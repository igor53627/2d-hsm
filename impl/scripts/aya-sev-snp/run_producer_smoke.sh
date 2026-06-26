#!/usr/bin/env bash
set -euo pipefail
trap 'pkill -f "[/]enclave-vsock-staging" 2>/dev/null || true; pkill -f vsock_uds_relay 2>/dev/null || true; rm -f /tmp/phsm.sock' EXIT
cd /root/producer_smoke

echo "=== Cleanup ==="
pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true
pkill -f vsock_uds_relay 2>/dev/null || true
sleep 1
rm -f /tmp/phsm.sock

echo "=== Start staging enclave (vsock loopback CID=1:5000) ==="
setsid env TWOD_HSM_VSOCK_CID=1 TWOD_HSM_VSOCK_PORT=5000 \
  /root/2d-hsm/impl/rust/enclave-protocol/target/debug/enclave-vsock-staging \
  >/tmp/ep.log 2>&1 </dev/null &
sleep 2

if ! grep -q listening /tmp/ep.log; then
  echo "ENCLAVE FAIL:"; cat /tmp/ep.log; exit 1
fi
echo "Enclave up"

echo "=== Start vsock↔UDS relay ==="
setsid python3 vsock_uds_relay.py /tmp/phsm.sock 1 5000 >/tmp/relay.log 2>&1 </dev/null &
sleep 1
cat /tmp/relay.log

echo "=== Run Elixir producer smoke ==="
/opt/elixir-1.16/bin/elixir producer_vsock_smoke.exs
SMOKE_EXIT=$?

echo "=== Cleanup ==="
pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true
pkill -f vsock_uds_relay 2>/dev/null || true

echo "=== Enclave log (last 5 lines) ==="
tail -5 /tmp/ep.log

exit $SMOKE_EXIT
