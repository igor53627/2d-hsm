#!/usr/bin/env bash
# Full SEV-SNP attested guest producer smoke (TASK-122 AC#3 full staging evidence)
#
# Starts a SEV-SNP guest VM, launches the staging enclave INSIDE the attested
# guest, then exercises all 4 producer commands via:
#   Elixir Chain.ProducerHsm.Wire → UDS → relay → vsock CID=42 → enclave
#
# This yields complete AC#3 evidence: 2D Elixir producer client → attested
# SEV-SNP guest enclave → real launch measurement + real ML-DSA-65 signature.
set -euo pipefail

case "${1:-}" in
  -h|--help)
    cat <<'USAGE'
Full SEV-SNP attested guest producer smoke (TASK-122 AC#3).
Starts a SEV-SNP guest VM (guest-cid=42, SSH :2222), launches the staging enclave
inside the attested guest, and drives all 4 producer commands via the Elixir
client through a vsock<->UDS relay.

Requires SEV-SNP hardware and the /root/2d-hsm staging layout (hard-coded paths);
it starts and kills a guest VM, so run it ONLY on an exclusive staging host.
USAGE
    exit 0
    ;;
esac

SCRIPT_DIR="/root/2d-hsm/impl/scripts/aya-sev-snp"
SMOKE_DIR="/root/producer_smoke"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null"
GUEST_CID=42
# Pidfile in a FIXED root-owned private runtime dir (mode 0700) — never world-writable /tmp and never
# a user-controlled XDG path, so a non-root user cannot plant/symlink the pidfile the kill below
# trusts. Create then VERIFY it is root-owned 0700 (mkdir -m does not fix a pre-existing dir); bail
# fail-closed otherwise. This smoke runs as root on a dedicated staging host (see --help).
RUNTIME_DIR=/run/2d-hsm-snp-smoke
install -d -m 700 -o root -g root "$RUNTIME_DIR" 2>/dev/null || mkdir -p "$RUNTIME_DIR"
if [ "$(stat -c '%u:%a' "$RUNTIME_DIR" 2>/dev/null)" != "0:700" ]; then
  echo "FATAL: $RUNTIME_DIR is not a root-owned 0700 dir; refusing (untrusted pidfile)" >&2
  exit 1
fi
VM_PIDFILE="$RUNTIME_DIR/vm.pid"
VM_PID=""
RELAY_PID=""
vm_start=""  # recorded at launch; init here so cleanup() (EXIT trap) can reference it under set -u
# Echo field 22 (starttime, clock ticks since boot) of /proc/$1/stat, or nothing if unreadable.
# starttime is fixed at fork and survives exec, so it pins identity across run-guest-vm.sh's exec
# into qemu and distinguishes a reused PID. comm (field 2) can contain spaces and ')', so strip
# through the LAST ") " before counting fields.
proc_starttime() {
  awk '{s=$0; sub(/^.*\) /,"",s); split(s,f," "); print f[20]}' "/proc/$1/stat" 2>/dev/null || true
}
# kill_tracked <pid> <expected_starttime>: signal the process GROUP of <pid> — but ONLY if it is
# still the SAME process. Reads pgrp (field 5) and starttime (field 22) from ONE /proc/<pid>/stat
# snapshot and signals the group only when the live starttime equals <expected_starttime>. Doing
# both from a single read closes the TOCTOU where the verified PID could exit and be reused before
# a separate `ps`/kill. Mismatch (process gone / reused / wrong starttime) -> skip, never signal.
# comm (field 2) can contain spaces and ')', so strip through the LAST ") " before counting fields.
kill_tracked() {
  _kt_pid=$1; _kt_want=$2
  printf '%s' "$_kt_pid"  | grep -qE '^[0-9]+$' || return 0
  printf '%s' "$_kt_want" | grep -qE '^[0-9]+$' || return 0
  _kt_snap=$(awk '{s=$0; sub(/^.*\) /,"",s); split(s,f," "); print f[3], f[20]}' "/proc/$_kt_pid/stat" 2>/dev/null || true)
  _kt_pgrp=${_kt_snap%% *}
  _kt_start=${_kt_snap##* }
  [ "$_kt_start" = "$_kt_want" ] || return 0   # gone / reused / wrong starttime -> never signal
  if printf '%s' "$_kt_pgrp" | grep -qE '^[0-9]+$' && [ "$_kt_pgrp" != 0 ]; then
    kill -- -"$_kt_pgrp" 2>/dev/null || true   # SIGTERM the whole group (pgrp from the same snapshot)
  else
    kill "$_kt_pid" 2>/dev/null || true        # no usable pgrp -> single PID; never PID-as-PGID
  fi
}
# Tear down via tracked PIDs (the VM is setsid-launched, so VM_PID is its process
# group leader) — never a global `pkill qemu`, which would also kill unrelated SNP
# guests that share the qemu cmdline (guest CID cannot disambiguate them).
cleanup() {
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  # Kill our VM only if VM_PID STILL refers to it. bash can async-reap an exited background qemu
  # (freeing the PID for reuse) before this trap runs; kill_tracked re-verifies the recorded
  # starttime against a fresh /proc snapshot and signals the group from that SAME snapshot.
  kill_tracked "$VM_PID" "$vm_start"
  rm -f "$VM_PIDFILE"
}
trap cleanup EXIT

echo "=== Tear down a prior run of THIS smoke (tracked pid-file, not global pkill) ==="
if [ -f "$VM_PIDFILE" ]; then
  # Pidfile format "<pid> <starttime>" (see write below). kill_tracked reaps the prior run ONLY if
  # that PID's live starttime still matches the recorded one — a reused PID has a different
  # starttime, and legacy single-field pidfiles (no starttime) never match, so they are skipped.
  prev_pid=""; prev_start=""  # set -u: a failed read redirect (file vanished post -f) must not leave these unset
  read -r prev_pid prev_start _ <"$VM_PIDFILE" 2>/dev/null || true
  kill_tracked "$prev_pid" "$prev_start"
  rm -f "$VM_PIDFILE"
fi
sleep 1

echo "=== Start SEV-SNP guest VM (CID=42, SSH :2222) ==="
cd "$SCRIPT_DIR"
DISK=vm-disk.qcow2 CLOUDINIT=cloud-init.iso \
  SEV_MODE=snp MEMORY=4096 VCPUS=2 \
  setsid ./run-guest-vm.sh >/tmp/guest-vm.log 2>&1 </dev/null &
VM_PID=$!
# Record "<pid> <starttime>" — a race-free identity (a reused PID has a different starttime) so both
# the reap above and the EXIT trap never signal an unrelated process.
vm_start=$(proc_starttime "$VM_PID")
if ! printf '%s' "$vm_start" | grep -qE '^[0-9]+$'; then
  # Could not read our own VM's starttime (procfs anomaly): kill it now (safe — no PID-reuse window
  # yet, this is our just-forked child) and bail rather than record an unverifiable pid.
  echo "FATAL: could not read starttime for VM pid $VM_PID" >&2
  kill "$VM_PID" 2>/dev/null || true
  exit 1
fi
echo "$VM_PID $vm_start" > "$VM_PIDFILE"
echo "Guest VM PID: $VM_PID"
sleep 5
if ! kill -0 "$VM_PID" 2>/dev/null; then
  echo "VM exited early:"; cat /tmp/guest-vm.log; exit 1
fi

echo "=== Wait for guest SSH (port 2222, up to 90s) ==="
GUEST_READY=0
for i in $(seq 1 90); do
  if ssh $SSH_OPTS -p 2222 ubuntu@127.0.0.1 "echo guest_ready" 2>/dev/null | grep -q guest_ready; then
    echo "Guest SSH up after ${i}s"
    GUEST_READY=1
    break
  fi
  sleep 1
  if ! kill -0 "$VM_PID" 2>/dev/null; then
    echo "VM died during SSH wait:"; tail -20 /tmp/guest-vm.log; exit 1
  fi
done
if [ "$GUEST_READY" -ne 1 ]; then
  echo "Guest SSH timeout (90s)"; tail -20 /tmp/guest-vm.log; exit 1
fi

echo "=== Start enclave inside SEV-SNP guest ==="
HSM_BIN=/root/2d-hsm/impl/rust/enclave-protocol/target/debug/enclave-vsock-staging \
  ./guest-start-hsm.sh 2>&1

echo "=== Start vsock↔UDS relay → CID=42 ==="
rm -f /tmp/phsm.sock
setsid python3 "$SMOKE_DIR/vsock_uds_relay.py" /tmp/phsm.sock 42 5000 >/tmp/relay.log 2>&1 </dev/null &
RELAY_PID=$!
sleep 1
cat /tmp/relay.log

echo "=== Run Elixir producer smoke (via relay → CID=42 attested guest) ==="
cd "$SMOKE_DIR"
SMOKE_EXIT=0
/opt/elixir-1.16/bin/elixir producer_vsock_smoke.exs 2>&1 || SMOKE_EXIT=$?

echo "=== Cleanup (handled by the EXIT trap: tracked VM process group + relay) ==="

echo "=== Guest VM log (last 10 lines) ==="
tail -10 /tmp/guest-vm.log

exit $SMOKE_EXIT
