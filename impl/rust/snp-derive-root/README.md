# snp-derive-root

Boot helper that derives the **2d-hsm pq-seal v1 provisioning root** from the **SEV-SNP firmware**
(`SNP_GET_DERIVED_KEY`) and hands it to the enclave as a file. TASK-1.1.

## Why a separate crate

The enclave (`enclave-protocol`) is `#![forbid(unsafe_code)]`, but `SNP_GET_DERIVED_KEY` is an
**ioctl** on the guest-only `/dev/sev-guest` (unlike the attestation report, there is no configfs /
file interface). So the one `unsafe` ioctl is isolated here, in a sibling binary that runs at guest
boot **before** the enclave. The enclave is unchanged: it still reads its 32-byte root only from the
file named by `TWOD_HSM_PQ_SEAL_V1_ROOT_FILE`.

## Derivation

```
root = SHA3-256("2d-hsm-pq-seal-v1-root" ‖ snp_derived_key)
```

`snp_derived_key` is the 32-byte key the PSP derives from a platform secret, bound by default to the
**launch MEASUREMENT** (`guest_field_select` bit 3) under the **VCEK** root key. The output is:

- **Secret to the platform** — the host cannot compute it.
- **Stable** for a given image on a given platform — so the enclave unseals across reboots.
- **Bound to the measurement** — changes when the enclave image changes (re-seal required).

Domain separation means the raw firmware key is never exposed and could feed other domains.

## Usage

```
# Boot (NixOS oneshot, before the enclave): write the root to a tmpfs file, mode 0600.
snp-derive-root --out /run/twod-hsm/pq-seal-root.bin

# Provisioning ceremony (run ONCE inside the target image; seal offline against this root):
snp-derive-root --print

# In-guest validation — no secret leaves the guest; prints PASS/FAIL + a SHA3-256 commitment.
snp-derive-root --selftest
```

Options: `--field-select <measurement|policy|none|all|u64|0xHEX>` (default `measurement`),
`--root-key <vcek|vmrk>` (default `vcek`), `--svn <n>` (default `0`). Run `--help` for details.

`--selftest` confirms the derived key is non-zero, that selecting MEASUREMENT actually changes the
key (so the offset and binding are correct), and emits a commitment that is stable across reboots iff
the firmware key is stable — compare two boots to prove stability without revealing the secret.

## ABI

`SNP_GET_DERIVED_KEY = _IOWR('S', 0x1, snp_guest_request_ioctl)` = `0xC0205301`. The `#[repr(C)]`
request/response structs mirror `uapi/linux/sev-guest.h`; the 32-byte key sits at offset `0x20`
within the 64-byte `snp_derived_key_resp.data`. The off-SNP unit tests assert the struct sizes, the
ioctl number, the domain-separated derivation, and that an absent `/dev/sev-guest` errors cleanly
(the ioctl itself can only be exercised in-guest, on aya).

## Nix

```
nix build .#snp-derive-root            # the boot helper
nix build .#disk-production-lab-selftest   # production-lab image that runs --selftest at boot
```

See `backlog/docs/pq-seal-v1-provisioning-runbook.md` §7 for the full production ceremony.
