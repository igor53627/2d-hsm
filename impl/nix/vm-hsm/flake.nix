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
        # TASK-7.7 (d-ii)/4c: the lab-only in-guest quote-smoke bin (agent-gateway role; a SEPARATE
        # derivation from the producer profiles — role-isolation compile_error, see enclave.nix).
        enclave-quote-smoke = pkgs.callPackage ./enclave.nix {
          profile = "quote-smoke";
        };
        # TASK-7.7 5b-2c-iii: the DEBUG agent-gateway serve bin (agent-gateway role; SEPARATE
        # derivation — role isolation, see enclave.nix; lab keystore file source, release-banned).
        enclave-agent-gateway = pkgs.callPackage ./enclave.nix {
          profile = "agent-gateway";
        };
        # TASK-1.1: SNP firmware-derived pq-seal provisioning root boot helper.
        snp-derive-root = pkgs.callPackage ./snp-derive-root.nix { };
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
        # TASK-1.1: production-lab image + the SNP derived-root self-check oneshot (validates the
        # derived-key path in-guest on a real SNP host; logs PASS + a secret-free commitment).
        diskProductionLabSelftest = import ./disk-image.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            snp-derive-root
            ;
          guestProfile = "production-lab";
          deriveRootSelftest = true;
        };
        # TASK-1.1 sealed-boot ceremony (run on a trusted host; see run-nix-snp-sealed-boot.sh).
        # PRINT image dumps the SECRET derived root to the console so the signer can be sealed against
        # it offline. CEREMONY ONLY — never deploy this image (it leaks the provisioning root).
        diskProductionLabPrintCeremony = import ./disk-image.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            snp-derive-root
            ;
          guestProfile = "production-lab";
          deriveRootPrintCeremony = true;
        };
        # TASK-1.1 sealed-boot loop: the enclave unseals against the BOOT-DERIVED root (the derive
        # oneshot writes /run/twod-hsm/pq-seal-root.bin; sealRootSource="snp"). The signer blob must be
        # sealed against that derived root — supplied via ceremony-sealed-signer.bin (produced by the
        # ceremony script and force-added in the validation worktree; gitignored so it never lands in a
        # real commit). When absent (CI eval), it falls back to the lab fixture so the output still
        # instantiates — but it will NOT unseal at boot until the matching ceremony blob is present.
        # TASK-7.7 (d-ii)/4c: production-lab image + the in-guest quote-smoke oneshot (validates the
        # production spawn shape / dispatch re-exec / configfs GC / vsock-lapse / journald breadcrumb
        # on a real SNP host; see run-nix-snp-quote-smoke.sh). The `*-lab-*` name keeps the generic
        # launcher's HAS_SIGNER/REQUIRE_REAL auto-derivation convention.
        diskProductionLabQuoteSmoke = import ./disk-image.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            ;
          guestProfile = "production-lab";
          quoteSmokePackage = enclave-quote-smoke;
        };
        # TASK-7.7 5b-2c-iii: production-lab image + the agent-gateway serve unit (the aya SNP live
        # smoke target: boot-to-Ready against the host relay + lab anchor stub, then the host 0x40
        # client phases; see run-nix-snp-agent-smoke.sh). The `*-lab-*` name keeps the generic
        # launcher's auto-derivation convention (the quote-smoke precedent).
        diskProductionLabAgentGateway = import ./disk-image.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            ;
          guestProfile = "production-lab";
          agentGatewayPackage = enclave-agent-gateway;
        };
        ceremonySignerPath = ./ceremony-sealed-signer.bin;
        diskProductionLabSnpRooted = import ./disk-image.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            snp-derive-root
            ;
          guestProfile = "production-lab";
          sealRootSource = "snp";
          pqSealedSignerOverride =
            if builtins.pathExists ceremonySignerPath then ceremonySignerPath else null;
        };
      in
      {
        packages = {
          inherit enclave enclave-staging enclave-production-transport measurement-manifest snp-derive-root;
          # TASK-7.7 (d-ii)/4c quote smoke (lab-only bin + bootable image carrying its oneshot).
          inherit enclave-quote-smoke;
          disk-production-lab-quote-smoke = diskProductionLabQuoteSmoke;
          # TASK-7.7 5b-2c-iii agent-gateway live smoke (DEBUG serve bin + bootable image carrying
          # its long-running unit + journald witness).
          inherit enclave-agent-gateway;
          disk-production-lab-agent-gateway = diskProductionLabAgentGateway;
          # qemu-vm: runner creates $NIX_DISK_IMAGE qcow2 on first boot (see run-vm-hsm.sh).
          vm = nixosVmStaging.config.system.build.vm;
          vm-production = nixosVmProduction.config.system.build.vm;
          vm-production-lab = nixosVmProductionLab.config.system.build.vm;
          # Bootable EFI qcow2 for the SEV-SNP launcher (run-nix-snp-guest-smoke.sh).
          disk-production = diskProduction;
          disk-production-lab = diskProductionLab;
          disk-production-lab-selftest = diskProductionLabSelftest;
          # TASK-1.1 sealed-boot loop + ceremony (see run-nix-snp-sealed-boot.sh).
          disk-production-lab-print-ceremony = diskProductionLabPrintCeremony;
          disk-production-lab-snp-rooted = diskProductionLabSnpRooted;
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