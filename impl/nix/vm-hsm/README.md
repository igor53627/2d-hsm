# vm-hsm — Nix flake (TASK-4)

Primary **production** delivery path for 2d-hsm TEE vsock binaries. Ubuntu/`cargo` on the host remain dev fallbacks until this flake is green on CI and aya.

## Quick start (Linux / `x86_64-linux`)

```bash
cd impl/nix/vm-hsm
nix flake lock                   # first time / after input bumps
nix build .#enclave              # release: bin/enclave-vsock
nix build .#enclave-staging      # debug: bin/enclave-vsock-staging (aya smokes)
nix build .#measurement-manifest # JSON artifact for CI / forkSpecHash input
cat result/manifest.json | jq .
```

### macOS (Apple Silicon)

Nix is installed via **Determinate Nix**; new shells load it from `/etc/zshrc`.

This flake targets **`x86_64-linux` only**. On a Mac you need one of:

1. **Native Linux builder** (Determinate): `determinate-nixd auth login` (FlakeHub) + access from Determinate — then  
   `nix build .#packages.x86_64-linux.enclave`
2. **Linux host** (e.g. aya, GitHub Actions) — recommended for first full build
3. **CI** — workflow `.github/workflows/nix-hsm.yml`

Pre-built `nixpkgs#legacyPackages.x86_64-linux.*` may work from cache; **compiling this Rust crate** needs a Linux builder or a Linux machine.

## Outputs

| Flake output | Binary | Features | Use |
|--------------|--------|----------|-----|
| `enclave` | `enclave-vsock` | `production-vsock` (release) | Production CVM (trust file at boot) |
| `enclave-production-transport` | `enclave-vsock` | `production-vsock` (debug) | `vm-production` guest only — transport smoke |
| `enclave-staging` | `enclave-vsock-staging` | `staging-vsock` | aya vsock smokes, `prod-enclave-v1` |
| `measurement-manifest` | `manifest.json` | — | Reproducibility + on-chain `forkSpecHash` helper (hashes release `.#enclave`, not transport debug) |

## Production runtime env

| Variable | Required | Purpose |
|----------|----------|---------|
| `TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE` | yes | 32-byte Ed25519 verifying key (producer attestation, not PQ key) |
| `TWOD_HSM_VSOCK_CID` / `TWOD_HSM_VSOCK_PORT` | no | vsock bind (NixOS guest defaults to `VMADDR_CID_ANY`; host uses QEMU `guest-cid`; see vsock spec §2.4) |
| Platform PQ seal / sealed signer | platform | `boot_configure_pq_seal_v1_platform_root` + `install_sealed_pq_signer` |

## Manifest schema (v2) — build identity vs TEE measurement (TASK-5 AC#4)

See `scripts/write-measurement-manifest.sh`. The manifest keeps **two identities strictly
separate**:

**1. Build identity (this manifest, reproducible):** `git_revision`, `flake_lock` (hash of
`flake.lock`), `artifacts.*.sha256`, `enclave_derivation`, and `fork_spec_hash_input` for 2d
tooling. `artifacts.*.protocol_measurement_label` is a **software-protocol label** (`label_kind`
says so) — the value the enclave advertises **absent SNP** (`enclave-measurement-placeholder`
for prod, `prod-enclave-v1` for staging) — **not** a TEE measurement.

**2. TEE measurement (runtime, `tee_measurement` block — descriptor only, no value):** the
SEV-SNP **launch measurement** returned live by `GET_MEASUREMENT` (CBOR key 2, 48 bytes, report
offset `0x90`). It is **not** a build output and is intentionally **not** emitted in the manifest
because it is OVMF-dependent (see below). The PQ producer key is bound into the report separately
via `report_data` (offset `0x50`, 64 bytes) `= SHA3-512("2d-hsm-snp-report-data-v1" || pq_pubkey)`.

### Why the launch measurement ≠ build identity (measured on aya, 2026-06-06)

The NixOS prod guest (`.#disk-production-lab`) and the Ubuntu staging guest produce the **identical**
SEV-SNP launch measurement under the same OVMF:

```
3e39e33ab71f37ec9391fb285620dc5e50b67dd7cb59447726138596f9c502ed971ae0d095ea2ab3f93a8b8f6016b488
```

So the launch measurement anchors the **OVMF launch firmware + SNP launch config** (memory, vCPUs,
policy) — **not** the guest disk image / enclave binary / kernel, which OVMF loads *after* the
measurement is taken. Binding the actual enclave identity needs the build `sha256` (above) +
`report_data` key binding, and (to bind the running image) measured boot / dm-verity — tracked in
the forthcoming verifier policy / VCEK cert-chain work. The value above is OVMF-specific (AMDSEV
OVMF on aya) and belongs in the verifier policy/runbook, not this build manifest.

| Do | Do not |
|----|--------|
| Use `fork_spec_hash_input` for hard-fork **build reproducibility** tickets | Whitelist an on-chain producer from this manifest's labels |
| Compare CI artifact SHA256 across rebuilds | Treat `protocol_measurement_label` as live attestation |
| Whitelist against the **live-attested** measurement + `report_data` + VCEK chain (verifier policy) | Assume the launch measurement pins the guest image (it pins OVMF; same value across guests) |
| Capture the live value via `VSOCK_SMOKE_PRINT_MEASUREMENT=1 ./run-nix-snp-guest-smoke.sh` | Deploy `vm-production` / `disk-production*` to mainnet (lab trust only — see below) |

Staging manifest label `prod-enclave-v1` matches the reference staging signer image, not production PQ provisioning.

## Phase B / TASK-5 guest profiles

> **Deployment warning:** None of the `vm-*` outputs below are mainnet Block Producer images.
> They use **lab/reference** attestation trust and (for `-lab`) file-based PQ seal. Do not ship
> `vm-production` or `vm-production-lab` to production without platform trust + SNP measurement (TASK-5 Phase 3).

| Flake output | Guest binary | Trust / seal | Use |
|--------------|--------------|--------------|-----|
| `vm` | `enclave-vsock-staging` | reference staging signer | Default aya guest smoke |
| `vm-production` | debug `enclave-vsock` (`enclave-production-transport`) | **lab** Ed25519 VK only (`lab-prod-fixtures`) | **Transport smoke** — `TWOD_HSM_TRANSPORT_ONLY_MODE=1`; no PQ seal |
| `vm-production-lab` | debug `lab-production-vsock` | lab VK + `TWOD_HSM_PQ_SEAL_*` files | Lab prod path; `pq_signing_ready` smoke |

Why `vm-production` still injects a **lab** trust file: `enclave-vsock` fails closed at boot without
`TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE`. Platform-provisioned production VK is TASK-5 #2 (not merged here).

| | `vm-production` | `vm-production-lab` |
|--|-----------------|---------------------|
| Nix enclave attr | `enclave-production-transport` (debug `production-vsock`) | `enclave-production-lab` (`lab-production-vsock`) |
| PQ seal | no (`TRANSPORT_ONLY_MODE`) | yes (file-based, lab only) |
| Safe for mainnet | **no** | **no** |

## SEV-SNP disk images (TASK-5 Phase 3 / AC#5)

The `vm-*` outputs build the nixpkgs **qemu-vm runner** (a wrapper that embeds its
own QEMU and injects the kernel directly): KVM only — there is no hook to pass the
SEV-SNP launch objects. The confidential launch needs a **self-booting** disk, so:

| Flake output | Guest | Boots under SNP? | `GET_MEASUREMENT` |
|--------------|-------|------------------|-------------------|
| `disk-production-lab` | `enclave-production-lab` (lab PQ seal) | yes | **real** 48-byte launch measurement (operational signer ⇒ AC#4 capture) |
| `disk-production` | `enclave-production-transport` (transport-only) | yes | placeholder by design (no operational signer to bind) |

Both are bootable GPT/EFI **qcow2** images (`nix build .#disk-production-lab` →
`result/nixos.qcow2`) built via `make-disk-image.nix` (`disk-image.nix`). GRUB is
installed to the removable media path (`EFI/BOOT/BOOTX64.EFI`) so they boot under
the AMD `-bios OVMF.fd` SNP line with no persistent EFI NVRAM. Launch + smoke:

```bash
cd impl/scripts/aya-sev-snp
./run-nix-snp-guest-smoke.sh                 # SNP NixOS prod guest + real measurement
SEV_MODE=none ./run-nix-snp-guest-smoke.sh   # KVM fallback (placeholder; gate auto-relaxed)
```

`vm.nix` and `disk-image.nix` share the profile→enclave mapping (`guest-profile.nix`),
so the SNP image runs the same binary/trust/seal as the KVM smoke for that profile.
Still **not mainnet**: lab trust + lab PQ seal (`productionMode = false`). The mainnet gate +
build-time trust provisioning (AC#2/#10) landed — see *Mainnet gate* below; the remaining
dependency is the platform-**derived** root (vTPM/SNP/Nitro).

Real TEE `measurement` in `GET_MEASUREMENT` → captured under SNP (AC#4); live NixOS
guest boot under SNP is AC#5 (this launcher), validated on aya.

## Mainnet gate & trust provisioning (TASK-5 AC#2 / AC#10)

The `vm-production*` / `disk-production*` outputs are **lab/dev** (`productionMode = false`)
and ship lab attestation trust + lab PQ seal — never mainnet. A mainnet guest must set
`productionMode = true` and supply **operator-provisioned** material.

**AC#10 — the gate.** `nixos-module.nix` has build-time assertions (fail `nix build`/eval,
not a silent boot): with `productionMode = true` it refuses

- any **lab fixture** in use (`labFixtures` — lab trust VK / lab PQ seal), and
- a **transport-only** profile (no operational signer).

`guest-profile.nix` derives `labFixtures` and threads `productionMode` into the module.
`labFixtures` is true when an override is absent **or points back at the in-repo lab fixture**
(compared by store path), so the gate can't be bypassed by aiming an override at the lab file.
The trust term applies to both prod profiles; the seal terms only to the operational
(`production-lab`) profile. The lab/dev outputs keep `productionMode = false`, so the gate is
inert for them (their derivations are byte-identical; the gate logic is regression-tested by
`nix flake check` → `checks.mainnet-gate`). `productionMode` is a `guest-profile` arg (the
"or equivalent" of `services.twod-hsm.productionMode`).

**AC#2 — provisioning policy.** Operator material is injected at **build time** via
`guest-profile.nix` args — from a sealed store or a build-time secret, **never fetched over vsock
at runtime** (the systemd unit sets `TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE` to the in-image
store path):

| Arg | Replaces | Source (mainnet) |
|-----|----------|------------------|
| `trustFileOverride` | lab `ProducerAttestationTrust` VK (32 B Ed25519) | platform / build-time secret |
| `pqSealRootOverride` | lab PQ seal provisioning root | platform (vTPM / SNP VMPL / Nitro) — *not yet wired* |
| `pqSealedSignerOverride` | lab sealed ML-DSA signer (v1 blob) | offline `pq-seal-v1` against the platform root |

Operator responsibilities (NOT enforced by the gate — it only checks the material isn't the lab
fixture):

- The trust VK **must be an independent producer attestation key — not derived from `pq_pubkey`**
  (vsock spec §9.3); otherwise a host that knows the public PQ key could forge chain proofs.
- Provide a valid 32-byte VK + a real v1 sealed signer; the enclave self-tests the signer at
  install, but a malformed trust file only fails at runtime.
- The seal overrides require the **operational** profile (`production-lab`-shaped, which installs
  a signer); on the transport `production` profile they are ignored and the transport-only
  assertion blocks `productionMode`.
- **Runtime/image binding:** the gate is build-time. It does not by itself stop a host that can
  tamper with the disk image from swapping the file — binding the running image needs measured
  boot / dm-verity (the launch measurement pins OVMF, not the image; see
  `snp-attestation-verifier-policy.md` §3).

A mainnet config builds a guest with all overrides set to real, non-lab material (so
`labFixtures = false`) and `productionMode = true`; the gate then passes. The
platform-**derived** root (vTPM/SNP/Nitro) is still future — until it ships, no
`productionMode = true` output exists, and the gate keeps any lab-trust image from masquerading
as mainnet.

## Related

- `backlog/tasks/task-4 - NixOS-reproducible-TEE-image-primary-delivery-path.md`
- `impl/rust/enclave-protocol/`
- `impl/scripts/aya-sev-snp/`