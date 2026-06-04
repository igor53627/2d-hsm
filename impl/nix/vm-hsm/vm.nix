# NixOS qcow2 / vm runner for 2d-hsm guest (TASK-4 Phase B).
{
  nixpkgs,
  enclave-staging,
  enclave,
  guestProfile ? "staging",
}:

let
  system = "x86_64-linux";
  labFixtures = import ./lab-prod-fixtures.nix {
    pkgs = nixpkgs.legacyPackages.${system};
  };
  isProd = guestProfile == "production";
  enclavePackage = if isProd then enclave else enclave-staging;
  enclaveMode = guestProfile;
  producerAttestationTrustFile =
    if isProd then labFixtures.producerAttestationTrustFile else null;
in
nixpkgs.lib.nixosSystem {
  inherit system;
  specialArgs = {
    inherit enclavePackage enclaveMode producerAttestationTrustFile;
  };
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