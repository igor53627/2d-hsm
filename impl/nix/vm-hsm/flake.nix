{
  description = "Reproducible 2d-hsm TEE enclave builds (TASK-4 Phase A)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        enclave-staging = pkgs.callPackage ./enclave.nix {
          profile = "staging";
        };
        enclave = pkgs.callPackage ./enclave.nix {
          profile = "production";
        };
        enclave-production-lab = pkgs.callPackage ./enclave.nix {
          profile = "production-lab";
        };
        enclave-production-transport = pkgs.callPackage ./enclave.nix {
          profile = "production-transport";
        };
        flakeMeta = {
          gitRevision = self.shortRev or self.dirtyShortRev or "dirty";
          flakeLock = builtins.hashFile "sha256" (self + "/flake.lock");
        };
        measurement-manifest = pkgs.callPackage ./measurement-manifest.nix {
          inherit enclave enclave-staging flakeMeta;
        };
        nixosVmStaging = import ./vm.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            ;
          guestProfile = "staging";
        };
        nixosVmProduction = import ./vm.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            ;
          guestProfile = "production";
        };
        nixosVmProductionLab = import ./vm.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            ;
          guestProfile = "production-lab";
        };
      in
      {
        packages = {
          inherit enclave enclave-staging enclave-production-transport measurement-manifest;
          # qemu-vm: runner creates $NIX_DISK_IMAGE qcow2 on first boot (see run-vm-hsm.sh).
          vm = nixosVmStaging.config.system.build.vm;
          vm-production = nixosVmProduction.config.system.build.vm;
          vm-production-lab = nixosVmProductionLab.config.system.build.vm;
          default = enclave;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustc
            cargo
            openssl
            pkg-config
            jq
          ];
          shellHook = ''
            echo "2d-hsm vm-hsm dev shell (native cargo: impl/rust/enclave-protocol)"
            echo "  nix build .#enclave          # production vsock binary"
            echo "  nix build .#enclave-staging  # staging vsock (aya smokes)"
            echo "  nix build .#measurement-manifest"
            echo "  nix build .#vm               # Phase B NixOS guest (staging)"
            echo "  nix build .#vm-production       # TRANSPORT SMOKE ONLY (debug prod bin + lab trust VK)"
            echo "  nix build .#vm-production-lab   # lab prod (+ PQ seal, pq_signing_ready) — NOT mainnet"
          '';
        };

        formatter = pkgs.nixpkgs-fmt;
      }
    );
}