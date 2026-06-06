# Shared guest-profile → enclave/specialArgs mapping for the 2d-hsm NixOS guest.
#
# Consumed by:
#   - vm.nix         (nixpkgs qemu-vm *runner*; KVM aya smokes, TASK-4 Phase B)
#   - disk-image.nix (bootable EFI qcow2 for the SEV-SNP launch, TASK-5 AC#5)
#
# Keeping the profile selection in one place guarantees the qemu-vm guest and the
# SNP disk-image guest run the *same* enclave package, mode, trust VK and seal
# fixtures — so a measurement captured under SNP corresponds to the binary the
# KVM smokes exercise.
{
  nixpkgs,
  enclave,
  enclave-staging,
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
{
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
}
