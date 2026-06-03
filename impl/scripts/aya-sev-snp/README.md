# 2d-hsm smoke on **aya** (SEV host)

Three levels (in order):

| Step | Script | What it proves |
|------|--------|----------------|
| 0 | `host-loopback-smoke.sh` | vsock framing on **host** (`CID=1`, `vsock_loopback`) |
| 1 | `setup-guest-image.sh` | Ubuntu cloud image + cloud-init (once) |
| 2 | `run-guest-vm.sh` | SEV-ES guest (or `SEV_MODE=none` baseline) + **vhost-vsock** `guest-cid=42` |
| 3 | `guest-start-hsm.sh` | `scp` binary, start `enclave-vsock-staging` **inside guest** |
| 4 | `host-guest-vsock-smoke.sh` | Host → guest `GET_MEASUREMENT` (`CID=42:5000`) |

## Prerequisites (aya)

- SEV enabled: `/dev/sev`, `kvm_amd` `sev=Y` (see `plinko-rs/tee-test/01-verify-sev-snp.sh`)
- Built binary: `impl/rust/enclave-protocol` with `staging-vsock`
- `qemu-system-x86_64`, `cloud-image-utils`, `wget`

## Quick start

```bash
cd /root/2d-hsm
git pull   # branch feat/task-1-vsock-staging-transport

cd impl/rust/enclave-protocol
cargo build --bin enclave-vsock-staging --features staging-vsock

cd ../../scripts/aya-sev-snp
./host-loopback-smoke.sh

# One-time (~700MB download):
./setup-guest-image.sh

# Terminal A — guest VM (SEV-ES; use SEV_MODE=none for KVM-only debug)
SEV_MODE=sev MEMORY=4096 VCPUS=2 ./run-guest-vm.sh

# Terminal B — after SSH on :2222 works:
./guest-start-hsm.sh

# Terminal C — from host:
./host-guest-vsock-smoke.sh
```

**Inside the guest**, bind uses `2D_HSM_VSOCK_CID=4294967295` (`VMADDR_CID_ANY`). **On the host**, connect to `GUEST_CID=42` (QEMU `vhost-vsock-pci`).

Full **SEV-SNP** needs QEMU with `sev-snp-guest` (not in stock Ubuntu 24.04 QEMU 8.2 here). SEV-ES (`sev-guest`) is the usual step on this host until AMD QEMU is installed.