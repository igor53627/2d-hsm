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
| `enclave` | `enclave-vsock` | `production-vsock` | Production CVM (trust file at boot) |
| `enclave-staging` | `enclave-vsock-staging` | `staging-vsock` | aya vsock smokes, `prod-enclave-v1` |
| `measurement-manifest` | `manifest.json` | — | Reproducibility + on-chain `forkSpecHash` helper |

## Production runtime env

| Variable | Required | Purpose |
|----------|----------|---------|
| `TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE` | yes | 32-byte Ed25519 verifying key (producer attestation, not PQ key) |
| `TWOD_HSM_VSOCK_CID` / `TWOD_HSM_VSOCK_PORT` | no | vsock bind (must match QEMU `guest-cid`; see vsock spec §2.4) |
| Platform PQ seal / sealed signer | platform | `boot_configure_pq_seal_v1_platform_root` + `install_sealed_pq_signer` |

## Manifest schema (v1)

See `scripts/write-measurement-manifest.sh`. Fields include `git_revision`, `flake_lock` (hash of `flake.lock`), `artifacts.production.sha256`, and `fork_spec_hash_input` for 2d tooling.

**Note:** `protocol_measurement_label` for production is still `enclave-measurement-placeholder` until platform SNP/Nitro measurement is wired into `GET_MEASUREMENT`. Staging uses `prod-enclave-v1` (reference signer).

## Phase B (follow-on)

`packages.vm` — minimal NixOS qcow2 with systemd unit wrapping `enclave-vsock` or staging binary.

## Related

- `backlog/tasks/task-4 - NixOS-reproducible-TEE-image-primary-delivery-path.md`
- `impl/rust/enclave-protocol/`
- `impl/scripts/aya-sev-snp/`