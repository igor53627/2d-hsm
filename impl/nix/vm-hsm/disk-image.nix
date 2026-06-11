# Bootable EFI qcow2 disk image for the 2d-hsm NixOS guest (TASK-5 Phase 3 / AC#5).
#
# vm.nix builds a nixpkgs qemu-vm *runner* that embeds its own QEMU and injects
# the kernel directly — there is no hook to pass the SEV-SNP launch objects
# (`sev-snp-guest`, `memory-backend-memfd`, AMD OVMF `-bios`). The confidential
# launch therefore needs a *self-booting* disk: this builds a GPT/EFI qcow2 that
# the dedicated SNP launcher (run-guest-vm.sh `-bios $SNP_BIOS`) boots under
# SEV-SNP, so the production enclave can return a real launch measurement from
# GET_MEASUREMENT (AC#4 capture path) instead of the placeholder.
#
# Returns a derivation (the qcow2 under $out), NOT a nixosSystem — the flake
# exposes it directly as `.#disk-production` / `.#disk-production-lab`.
{
  nixpkgs,
  enclave,
  enclave-staging,
  enclave-production-lab,
  enclave-production-transport,
  guestProfile ? "production-lab",
  # TASK-1.1: opt-in SNP derived-root self-check baked into the image (default off).
  snp-derive-root ? null,
  deriveRootSelftest ? false,
  # TASK-1.1 sealed-boot loop: "snp" makes the enclave unseal against the boot-derived root (see
  # nixos-module). pqSealedSignerOverride supplies the signer blob sealed against that derived root
  # (the ceremony output); deriveRootPrintCeremony is the ceremony-only secret-root print (default off).
  sealRootSource ? "file",
  deriveRootPrintCeremony ? false,
  pqSealedSignerOverride ? null,
  # TASK-7.7 (d-ii)/4c: opt-in in-guest quote-smoke oneshot (the lab-only twod-hsm-quote-smoke bin;
  # see nixos-module.nix). Default off — only disk-production-lab-quote-smoke sets it.
  quoteSmokePackage ? null,
}:

let
  profile = import ./guest-profile.nix {
    inherit
      nixpkgs
      enclave
      enclave-staging
      enclave-production-lab
      enclave-production-transport
      guestProfile
      pqSealedSignerOverride
      ;
  };
  inherit (profile) system;
  pkgs = nixpkgs.legacyPackages.${system};
  lib = nixpkgs.lib;

  nixos = lib.nixosSystem {
    inherit system;
    specialArgs = profile.specialArgs // {
      snpDeriveRootPackage = snp-derive-root;
      inherit deriveRootSelftest sealRootSource deriveRootPrintCeremony quoteSmokePackage;
    };
    modules = [
      ./nixos-module.nix
      (
        { lib, ... }:
        {
          # Self-booting EFI image. GRUB is installed to the removable media path
          # (EFI/BOOT/BOOTX64.EFI) so the guest boots under `-bios OVMF.fd` with
          # NO persistent EFI NVRAM — which is exactly how the SEV-SNP launch line
          # runs (run-guest-vm.sh SNP branch: `-bios`, no `-drive if=pflash`).
          # nixos-module disables GRUB for the qemu-vm path; re-enable here.
          boot.loader.grub.enable = lib.mkForce true;
          boot.loader.grub.efiSupport = true;
          boot.loader.grub.efiInstallAsRemovable = true;
          boot.loader.grub.device = "nodev";
          # The SNP/KVM launchers run `-nographic`; send GRUB itself to the serial
          # console (kernel already uses console=ttyS0) so a stuck/edited GRUB menu
          # is visible instead of a silent hang to the boot timeout.
          boot.loader.grub.extraConfig = ''
            serial --unit=0 --speed=115200
            terminal_input serial
            terminal_output serial
          '';

          # make-disk-image (partitionTableType = "efi") labels the root ext4
          # partition "nixos" and the FAT32 ESP "ESP". nixos-module pins root to
          # /dev/vda (correct for the qemu-vm runner); override to the GPT label.
          fileSystems."/" = lib.mkForce {
            device = "/dev/disk/by-label/nixos";
            fsType = "ext4";
          };
          fileSystems."/boot" = {
            device = "/dev/disk/by-label/ESP";
            fsType = "vfat";
          };
        }
      )
    ];
  };
in
import "${nixpkgs}/nixos/lib/make-disk-image.nix" {
  inherit pkgs lib;
  config = nixos.config;
  format = "qcow2";
  partitionTableType = "efi";
  diskSize = "auto";
  additionalSpace = "512M";
  # This is a single-purpose enclave appliance — don't copy the nixpkgs channel
  # source into the image (smaller qcow2, faster build, smaller attack surface).
  copyChannel = false;
  # switch-to-configuration boot installs GRUB into the ESP at build time.
  # touchEFIVars stays false: the build sandbox has no efivars, and the SNP
  # launch carries no NVRAM anyway — the removable BOOTX64.EFI is what runs.
  installBootLoader = true;
  touchEFIVars = false;
  label = "nixos";
}
