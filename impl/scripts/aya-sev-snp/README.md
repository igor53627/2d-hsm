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
- Determinate Nix (for cached `nix build` artifacts)
- `qemu-system-x86_64`, `cloud-image-utils`, `wget`, `python3-cbor2`

## Smoke cache (recommended)

Heavy assets live under **`TWOD_HSM_CACHE`** (default `/var/cache/2d-hsm`):

| Path | Content |
|------|---------|
| `nix/` | Nix out-links (`enclave-staging`, `vm-hsm-runner-*`) |
| `images/` | Ubuntu cloud img, Nix `qcow2`, SNP golden disk |
| `firmware/` | Symlink to AMD `OVMF.fd` when installed |

**One-time warm-up** (download ~600MB image, `nix build` all smoke attrs, optional SNP golden disk bake):

```bash
cd impl/scripts/aya-sev-snp
./warm-smoke-cache.sh
```

After warm-up, routine smokes skip rebuilds and reuse disks:

```bash
./run-nix-enclave-staging.sh
./run-nix-vm-guest-smoke.sh
./run-nix-vm-guest-smoke-prod.sh
./run-nix-vm-guest-smoke-prod-lab.sh
./run-snp-smoke.sh    # fast if golden disk exists (~1–3 min)
```

Force refresh (lab): `TWOD_HSM_TRUST_UPSTREAM_SHA256SUMS=1 TWOD_HSM_REGEN_SNPDISK=1 ./setup-guest-image.sh` or `TWOD_HSM_REGEN_CLOUDINIT=1`. The `run-*-smoke.sh` / `warm-smoke-cache.sh` wrappers already default this trust flag, so only direct `setup-guest-image.sh` invocations need it.
Existing runners that relied on implicit upstream checksum fetches must now set either
`TWOD_HSM_UBUNTU_IMAGE_SHA256` with a dated image URL/name (preferred) or lab-only
`TWOD_HSM_TRUST_UPSTREAM_SHA256SUMS=1`.
`setup-guest-image.sh` requires `TWOD_HSM_UBUNTU_IMAGE_SHA256` for trusted builds; pin
`TWOD_HSM_UBUNTU_IMAGE_BASE_URL` / `TWOD_HSM_UBUNTU_IMAGE_NAME` to a dated image directory
at the same time. A bare SHA against the default Ubuntu `noble/current` URL is discouraged
(the script warns) because `current` moves when Ubuntu respins images.
For lab-only convenience, `TWOD_HSM_TRUST_UPSTREAM_SHA256SUMS=1` fetches `SHA256SUMS` from the
same image directory (integrity-only, not authenticity against a compromised mirror; real authenticity
requires obtaining the pinned SHA or verifying `SHA256SUMS.gpg` via a trusted Ubuntu signing key path).
If a bad image was cached, delete `$TWOD_HSM_CACHE/images/ubuntu-24.04-cloudimg.qcow2`
(default `/var/cache/2d-hsm/images/ubuntu-24.04-cloudimg.qcow2`) and rerun with
`TWOD_HSM_TRUST_UPSTREAM_SHA256SUMS=1 TWOD_HSM_REGEN_SNPDISK=1` (or a pinned
`TWOD_HSM_UBUNTU_IMAGE_SHA256`). The rebuild writes the new base overlay atomically and drops the
stale golden disk (`vm-disk-snp-ready.qcow2`), which would otherwise shadow the new image.

## Quick start

```bash
cd /root/2d-hsm
git pull   # branch feat/task-1-vsock-staging-transport

cd impl/rust/enclave-protocol
cargo build --bin enclave-vsock-staging --features staging-vsock

cd ../../scripts/aya-sev-snp
./host-loopback-smoke.sh

# One-time (~700MB download; lab integrity-only checksum fetch):
TWOD_HSM_TRUST_UPSTREAM_SHA256SUMS=1 ./setup-guest-image.sh

# Terminal A — guest VM (SEV-ES; use SEV_MODE=none for KVM-only debug)
SEV_MODE=sev MEMORY=4096 VCPUS=2 ./run-guest-vm.sh

# Terminal B — after SSH on :2222 works:
./guest-start-hsm.sh

# Terminal C — from host:
./host-guest-vsock-smoke.sh
```

**On the host**, connect to `GUEST_CID=42` (`vhost-vsock-pci`, same as QEMU `guest-cid`). **Inside guests**, the enclave binds `TWOD_HSM_VSOCK_CID=4294967295` (`VMADDR_CID_ANY`) on NixOS (`nixos-module.nix`) and via `guest-start-hsm.sh` on Ubuntu SNP — the hypervisor-assigned CID can differ from 42; the host always dials QEMU `guest-cid`. All operator env vars use the `TWOD_` prefix.

**SNP host prep** (once per machine):

```bash
./prepare-snp-host.sh    # QEMU 10 + kernel 6.17; then REBOOT into 6.17
./run-snp-smoke.sh       # SNP VM + guest HSM + host vsock smoke
```

If boot stops at `Convert non guest_memfd ... 0xfee00000`, build AMD OVMF:

```bash
git clone https://github.com/AMDESE/AMDSEV.git /tmp/AMDSEV
cd /tmp/AMDSEV && ./build.sh ovmf --install /opt/amde-ovmf
export SNP_BIOS=/opt/amde-ovmf/OVMF.fd
./run-snp-smoke.sh
```

Stock Ubuntu QEMU 8.2 only has legacy `sev-guest` (EPERM on this host).

## NixOS vm-hsm smokes (TASK-4 Phase B)

From repo root on aya (after `git pull`): run `./warm-smoke-cache.sh` once, then:

```bash
cd impl/scripts/aya-sev-snp
./run-nix-enclave-staging.sh
./run-nix-vm-guest-smoke.sh
./run-nix-vm-guest-smoke-prod.sh
./run-nix-vm-guest-smoke-prod-lab.sh
```

Pass criteria (bytes, markers, `pq_signing_ready`): see [SMOKE-PASS-CRITERIA.md](./SMOKE-PASS-CRITERIA.md).

`vm-production` is **transport smoke only** (lab trust VK) — not a mainnet guest image. See `impl/nix/vm-hsm/README.md`.
