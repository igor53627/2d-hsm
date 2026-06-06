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
        # Self-booting EFI qcow2 images for the SEV-SNP launch (TASK-5 AC#5).
        # disk-production-lab is the AC#5 target: it ships the lab-sealed PQ signer,
        # so under SNP the enclave binds + caches a real launch measurement.
        # disk-production is transport-only (no operational signer) → boot check
        # only; its GET_MEASUREMENT stays the placeholder by design.
        diskImageFor = guestProfile: import ./disk-image.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            guestProfile
            ;
        };
        diskProduction = diskImageFor "production";
        diskProductionLab = diskImageFor "production-lab";
      in
      {
        packages = {
          inherit enclave enclave-staging enclave-production-transport measurement-manifest;
          # qemu-vm: runner creates $NIX_DISK_IMAGE qcow2 on first boot (see run-vm-hsm.sh).
          vm = nixosVmStaging.config.system.build.vm;
          vm-production = nixosVmProduction.config.system.build.vm;
          vm-production-lab = nixosVmProductionLab.config.system.build.vm;
          # Bootable EFI qcow2 for the SEV-SNP launcher (run-nix-snp-guest-smoke.sh).
          disk-production = diskProduction;
          disk-production-lab = diskProductionLab;
          default = enclave;
        };

        checks = {
          # Exercise the mainnet gate (TASK-5 AC#10) logic so a regression in the labFixtures
          # derivation / override handling is caught in CI — no productionMode=true output ships,
          # so this is the only place the gate is evaluated. Asserts run at eval; the trivial
          # build just materializes the pass.
          mainnet-gate =
            let
              labArgs = guestProfile: {
                inherit
                  nixpkgs
                  enclave
                  enclave-staging
                  enclave-production-lab
                  enclave-production-transport
                  guestProfile
                  ;
              };
              gp = args: (import ./guest-profile.nix args).specialArgs;
              labOf = args: (gp args).labFixtures;
              labTrust = (import ./lab-prod-fixtures.nix { inherit pkgs; }).producerAttestationTrustFile;
              real = { trustFileOverride = "/run/secrets/trust"; pqSealRootOverride = "/run/secrets/root"; pqSealedSignerOverride = "/run/secrets/signer"; };
            in
            assert labOf (labArgs "production");                                   # transport ⇒ lab trust
            assert labOf (labArgs "production-lab");                               # lab trust + seal
            assert !(gp (labArgs "production")).productionMode;                    # outputs default off
            assert !(labOf (labArgs "production-lab" // real));                    # full real override ⇒ not lab
            assert labOf (labArgs "production-lab" // real // { trustFileOverride = labTrust; }); # override AT lab file ⇒ still lab (no bypass)
            pkgs.runCommand "twod-hsm-mainnet-gate-check" { } "echo gate-logic-ok > $out";
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
            echo "  nix build .#disk-production-lab # bootable EFI qcow2 for SEV-SNP launch (AC#5; real measurement)"
          '';
        };

        formatter = pkgs.nixpkgs-fmt;
      }
    );
}