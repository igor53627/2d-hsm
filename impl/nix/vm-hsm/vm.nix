# NixOS qcow2 / vm runner for 2d-hsm staging guest (TASK-4 Phase B).
{ nixpkgs, enclave-staging }:

let
  system = "x86_64-linux";
in
nixpkgs.lib.nixosSystem {
  inherit system;
  specialArgs = { inherit enclave-staging; };
  modules = [
    ./nixos-module.nix
    "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
    {
      virtualisation.memorySize = 512;
      virtualisation.cores = 2;
      virtualisation.diskSize = 1024;
    }
  ];
}