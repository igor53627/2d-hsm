# NixOS qcow2 / vm runner for 2d-hsm guest (TASK-4 Phase B).
#
# This builds the nixpkgs `qemu-vm` *runner* (config.system.build.vm): a wrapper
# script that embeds its own QEMU, creates $NIX_DISK_IMAGE on first boot and
# injects the kernel directly. It is KVM-only — there is no hook to add the
# SEV-SNP launch objects. For the confidential (SNP) launch, see disk-image.nix,
# which produces a self-booting EFI qcow2 instead (TASK-5 AC#5).
{
  nixpkgs,
  enclave-staging,
  enclave,
  enclave-production-lab,
  enclave-production-transport,
  guestProfile ? "staging",
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
      ;
  };
in
nixpkgs.lib.nixosSystem {
  inherit (profile) system specialArgs;
  modules = [
    ./nixos-module.nix
    "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
    {
      virtualisation.memorySize = 1024;
      virtualisation.cores = 2;
      virtualisation.diskSize = 2048;
      virtualisation.qemu.options = [ "-nographic" ];
    }
  ];
}
