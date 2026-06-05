# NixOS qcow2 / vm runner for 2d-hsm guest (TASK-4 Phase B).
{
  nixpkgs,
  enclave-staging,
  enclave,
  enclave-production-lab,
  enclave-production-transport,
  guestProfile ? "staging",
}:

let
  system = "x86_64-linux";
  labFixtures = import ./lab-prod-fixtures.nix {
    pkgs = nixpkgs.legacyPackages.${system};
  };
  # Both prod profiles use lab attestation VK until platform trust is provisioned (TASK-5 #2).
  # vm-production = transport smoke only; vm-production-lab = + file PQ seal. NOT mainnet-ready.
  isProd = guestProfile == "production" || guestProfile == "production-lab";
  isProdLab = guestProfile == "production-lab";
  # vm-production: debug production-vsock only (no lab-pq-seal-from-file) + transport-only env.
  enclavePackage =
    if guestProfile == "staging" then
      enclave-staging
    else if guestProfile == "production" then
      enclave-production-transport
    else if isProdLab then
      enclave-production-lab
    else
      enclave;
  enclaveMode = if isProdLab then "production" else guestProfile;
  producerAttestationTrustFile =
    if isProd then labFixtures.producerAttestationTrustFile else null;
  pqSealProvisioningRootFile =
    if isProdLab then labFixtures.pqSealProvisioningRootFile else null;
  pqSealedSignerFile = if isProdLab then labFixtures.pqSealedSignerFile else null;
  enclaveTransportOnly = guestProfile == "production";
in
nixpkgs.lib.nixosSystem {
  inherit system;
  specialArgs = {
    inherit
      enclavePackage
      enclaveMode
      producerAttestationTrustFile
      pqSealProvisioningRootFile
      pqSealedSignerFile
      enclaveTransportOnly
      ;
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