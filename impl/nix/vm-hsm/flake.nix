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
        # TASK-7.7 6-7b-ii: the SAME serve bin built WITH agent-keygen-exec-preview — so the guest
        # executes GENERATE_KEYS (write-path smoke). SEPARATE derivation (preview is release-banned).
        enclave-agent-gateway-keygen = pkgs.callPackage ./enclave.nix {
          profile = "agent-gateway-keygen";
        };
        # TASK-15: the SAME serve bin built WITH all three preview gates (keygen-exec +
        # configure-treasury + sign-faucet) — so the guest can mint + configure + dispense (the combined
        # faucet write-path smoke). SEPARATE derivation (all three previews are release-banned).
        enclave-agent-gateway-faucet = pkgs.callPackage ./enclave.nix {
          profile = "agent-gateway-faucet";
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
        # TASK-7.7 6-7b-ii: the WRITE-path smoke image — identical to the read-path agent-gateway image
        # but the serve unit runs the agent-keygen-exec-preview build, so the host's
        # twod-hsm-agent-keygen-smoke-client can drive a real GENERATE_KEYS (see
        # run-nix-snp-agent-keygen-smoke.sh). The serve unit already provisions
        # TWOD_HSM_PQ_SEAL_V1_ROOT_FILE = the lab reference root (= SMOKE_SEAL_ROOT), so the guest's
        # resealed blob unseals under the same root the host client expects.
        diskProductionLabAgentKeygenSmoke = import ./disk-image.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            ;
          guestProfile = "production-lab";
          agentGatewayPackage = enclave-agent-gateway-keygen;
        };
        # TASK-15: the combined FAUCET write-path smoke image — identical to the keygen smoke image but
        # the serve unit runs the all-three-previews build, so the host's twod-hsm-agent-faucet-smoke-client
        # can drive mint-treasury → set_limits → refill_budget → dispense (see
        # run-nix-snp-agent-faucet-smoke.sh). Same lab reference seal root, so the resealed blobs unseal.
        diskProductionLabAgentFaucetSmoke = import ./disk-image.nix {
          inherit
            nixpkgs
            enclave
            enclave-staging
            enclave-production-lab
            enclave-production-transport
            ;
          guestProfile = "production-lab";
          agentGatewayPackage = enclave-agent-gateway-faucet;
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
          # TASK-7.7 6-7b-ii write-path (GENERATE_KEYS) live smoke: preview serve bin + bootable image.
          inherit enclave-agent-gateway-keygen;
          disk-production-lab-agent-keygen-smoke = diskProductionLabAgentKeygenSmoke;
          # TASK-15 combined faucet write-path live smoke: all-three-previews serve bin + bootable image.
          inherit enclave-agent-gateway-faucet;
          disk-production-lab-agent-faucet-smoke = diskProductionLabAgentFaucetSmoke;
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

          # AC#5 Layer-1 funding gate (TASK-7.7 §5, TASK-16). Exercise the build-time gate logic at eval —
          # no funding profile exists yet (TASK-15), so the nixos-module assertion is a dormant tripwire on
          # every shipped output; this check is where its BOTH polarities are verified, so a regression in
          # the derivation / assertion can't slip through unexercised (the mainnet-gate precedent).
          agent-anti-rollback-gate =
            let
              gp = args: (import ./guest-profile.nix args).specialArgs;
              base = guestProfile: {
                inherit
                  nixpkgs
                  enclave
                  enclave-staging
                  enclave-production-lab
                  enclave-production-transport
                  guestProfile
                  ;
              };
              # Synthesize a production FUNDING profile: a non-null funding-signer package DERIVES
              # agentAntiRollbackEnabled = true (TASK-15 wires the real package); productionMode on.
              funding = mode: extra: base "production-lab" // {
                productionMode = true;
                agentTransferFaucetSignerPackage = enclave-production-lab; # any non-null ⇒ gate armed
                agentAntiRollbackMode = mode;
              } // extra;
              # The Layer-1 predicate — apply the SAME single-source ./ac5-funding-gate.nix function the
              # nixos-module derives its assertion from (to guest-profile's primitives), so the check and the
              # live assertion are the SAME formula by construction (review mechanism B / job 7523).
              gate = args:
                let s = gp args; in
                import ./ac5-funding-gate.nix {
                  inherit (s) productionMode agentAntiRollbackEnabled agentAntiRollbackMode antiRollbackResidualOptOut;
                };
              # The ALWAYS-PRESENT coupling invariant the nixos-module asserts (productionMode ⇒ isProd,
              # isProd = enclaveMode == "production") — closes the isProd/productionMode decoupling
              # fail-open (review mechanism A). true = the coupling assertion passes.
              couplingOk = args: let s = gp args; in (s.enclaveMode == "production") || !s.productionMode;
              # DIRECT-module path: apply the shared predicate to a synthetic armed funding build with an
              # arbitrary mode string, BYPASSING guest-profile.nix's enum `throw` — exactly what a direct
              # `nixos-module.nix` consumer could do. Proves the predicate is fail-closed by ALLOWLIST
              # (compact job 7539), not merely `!= "none"`.
              directGate = mode: import ./ac5-funding-gate.nix {
                productionMode = true;
                agentAntiRollbackEnabled = true;
                agentAntiRollbackMode = mode;
                antiRollbackResidualOptOut = false;
              };
            in
            # A production funding profile with mode "none" + no opt-out FAILS the gate (must not deploy).
            assert !(gate (funding "none" { }));
            # A configured mechanism PASSES.
            assert gate (funding "remote-counter" { });
            assert gate (funding "external-ledger" { });
            # mode "none" WITH the audited opt-out PASSES — the ONLY escape.
            assert gate (funding "none" { antiRollbackResidualOptOut = true; });
            # A NON-funding profile (no signer ⇒ gate NOT armed) PASSES even at mode "none" — the gate
            # guards fund custody only, not read/attestation profiles.
            assert gate (base "production-lab" // { productionMode = true; });
            # productionMode = false (lab/dev) PASSES even when armed+none — Layer-1 is a productionMode control.
            assert gate (funding "none" { productionMode = false; });
            # agentAntiRollbackEnabled is genuinely DERIVED from the signer package (not a free-defaulting param).
            assert (gp (funding "remote-counter" { })).agentAntiRollbackEnabled;
            # DORMANCY PIN: every SHIPPED guest profile leaves the gate DISARMED (no funding signer wired
            # until TASK-15) — so the gate is a true dormant tripwire and these images can't trip it. If a
            # future profile inadvertently arms it, this fails loudly rather than silently arming.
            assert !((gp (base "staging")).agentAntiRollbackEnabled);
            assert !((gp (base "production")).agentAntiRollbackEnabled);
            assert !((gp (base "production-lab")).agentAntiRollbackEnabled);
            # Coupling invariant: a coherent prod profile PASSES; a productionMode build on a non-prod
            # guestProfile (staging) FAILS the coupling assertion (which would otherwise silently drop the
            # whole isProd-gated assertion list — funding gate included).
            assert couplingOk (funding "remote-counter" { });
            assert !(couplingOk (base "staging" // { productionMode = true; }));
            # The enum-throw rejects any non-listed mode — incl. the §5-forbidden standalone "operator-signed-boot"
            # and any typo — so a passing (non-"none") mode is always one of the three sanctioned mechanisms.
            # tryEval must FORCE the throwing value (the validated mode); forcing the bare specialArgs attrset
            # to WHNF is lazy and would not trigger the throw.
            assert !((builtins.tryEval ((gp (funding "operator-signed-boot" { })).agentAntiRollbackMode)).success);
            assert !((builtins.tryEval ((gp (funding "remote-conter" { })).agentAntiRollbackMode)).success); # typo ⇒ throws
            # non-string mode ⇒ REJECTED (throws). NB `builtins.tryEval` only reports success/failure, not
            # WHICH error, so it can't distinguish the intended enum diagnostic from a `toString` coerce
            # error — that the message is the typeOf-guarded enum diagnostic (not a coerce crash) is ensured
            # by the `isString`/`typeOf` guard in guest-profile.nix at the code level, not asserted here.
            assert !((builtins.tryEval ((gp (funding 42 { })).agentAntiRollbackMode)).success);
            # DIRECT-module fail-closed (compact 7539): on the path that bypasses guest-profile's enum
            # throw, the predicate must FAIL for any non-sanctioned mode (allowlist, not just != "none").
            assert !(directGate "none");
            assert !(directGate "remote-conter"); # typo ⇒ fails closed (NOT a no-op pass)
            assert !(directGate "operator-signed-boot"); # §5-forbidden standalone ⇒ fails closed
            assert !(directGate ""); # empty/garbage ⇒ fails closed
            assert directGate "remote-counter"; # sanctioned ⇒ passes
            assert directGate "external-ledger"; # sanctioned ⇒ passes
            pkgs.runCommand "twod-hsm-agent-anti-rollback-gate-check" { } "echo ac5-layer1-gate-ok > $out";
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