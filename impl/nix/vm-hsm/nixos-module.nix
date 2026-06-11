# Minimal NixOS guest for 2d-hsm TEE (TASK-4 Phase B / TASK-5 prod mode).
{
  config,
  lib,
  pkgs,
  enclavePackage,
  enclaveMode ? "staging",
  producerAttestationTrustFile ? null,
  pqSealProvisioningRootFile ? null,
  pqSealedSignerFile ? null,
  enclaveTransportOnly ? false,
  # Mainnet gate (TASK-5 AC#10): productionMode asserts no lab fixtures are in use.
  productionMode ? false,
  labFixtures ? false,
  # TASK-1.1: opt-in boot self-check of the SNP firmware-derived pq-seal root. When enabled (prod),
  # a oneshot runs `snp-derive-root --selftest` and logs PASS + a (secret-free) commitment to the
  # console — used to validate the derived-key path on a real SNP host. Default off.
  snpDeriveRootPackage ? null,
  deriveRootSelftest ? false,
  # TASK-1.1 (sealed-boot loop): where the enclave's pq-seal provisioning root comes from.
  #   "file" (default) — the build-time file (lab fixture or operator override), as before.
  #   "snp"            — derived at boot by `snp-derive-root --out`, written to a tmpfs file the
  #                      enclave reads. The sealed signer MUST have been sealed against that derived
  #                      root (provisioning ceremony) or unseal fails closed.
  sealRootSource ? "file",
  # CEREMONY ONLY: add a oneshot that PRINTS the secret derived root to the console (so an operator
  # can seal the signer against it offline). Leaks the root to the serial log — never enable on a
  # shipped image. Default off.
  deriveRootPrintCeremony ? false,
  # TASK-7.7 (d-ii)/4c: opt-in in-guest quote-smoke oneshot (the lab-only `twod-hsm-quote-smoke`
  # bin). Default off — only the disk-production-lab-quote-smoke image sets it.
  quoteSmokePackage ? null,
  ...
}:

let
  mode = enclaveMode;
  isProd = mode == "production";
  binName = if isProd then "enclave-vsock" else "enclave-vsock-staging";
  unitName = if isProd then "enclave-vsock" else "enclave-vsock-staging";
  # Sealed-boot loop: the SNP-derived root lands here on tmpfs (written by the derive oneshot,
  # mode 0600 under a 0700 dir the tool creates) and the enclave reads it instead of a baked file.
  snpRoot = sealRootSource == "snp";
  runtimeRootFile = "/run/twod-hsm/pq-seal-root.bin";
  enclaveRootFile =
    if snpRoot then
      runtimeRootFile
    else if pqSealProvisioningRootFile != null then
      "${pqSealProvisioningRootFile}"
    else
      null;
  trustFile =
    if !isProd then
      null
    else if producerAttestationTrustFile != null then
      producerAttestationTrustFile
    else
      throw "production guest requires producerAttestationTrustFile (lab: lab-prod-fixtures)";
  # TASK-7.7 (d-ii)/4c: in-guest journald-ARRIVAL assert for the child breadcrumb (pin (2)
  # stderr->journald leg). SELF-MATCH GUARD: never echo the breadcrumb literal; no `set -x`.
  # Attribution note: the child writes on the parent's inherited stream socket, so journald
  # attributes the line to THIS unit's stream — the grep matches message text only, never the
  # ident[pid] prefix.
  journaldAssert = pkgs.writeShellScript "twod-hsm-quote-smoke-journald-assert" ''
    ${pkgs.systemd}/bin/journalctl --sync 2>/dev/null || true
    for i in $(seq 1 20); do
      if ${pkgs.systemd}/bin/journalctl -u twod-hsm-quote-smoke -b --no-pager 2>/dev/null \
           | grep -qF 'twod-hsm quote child: exit 1'; then
        echo "twod-hsm-quote-smoke: journald-breadcrumb PASS"; exit 0
      fi
      sleep 0.5
    done
    echo "twod-hsm-quote-smoke: journald-breadcrumb FAIL"; exit 1
  '';
in
{
  # Mainnet gate (TASK-5 AC#10): a productionMode guest must NOT ship lab attestation
  # trust / lab PQ seal, and must run an operational signer (not transport-only). These
  # fail the build (eval) rather than silently booting a lab-trust image as "mainnet".
  # The lab/dev outputs (vm-production*, disk-production*) keep productionMode = false and
  # remain explicitly non-mainnet. Operator-provisioned trust comes from a sealed store /
  # build-time secret injection (guest-profile *Override args), never from vsock — AC#2.
  assertions = lib.optionals isProd [
    {
      assertion = !(productionMode && labFixtures);
      message =
        "twod-hsm: productionMode refuses lab ProducerAttestationTrust / lab PQ seal. "
        + "Supply operator platform-provisioned trust + sealed signer "
        + "(guest-profile trustFileOverride / pqSealRootOverride / pqSealedSignerOverride; "
        + "build-time injection or sealed store, never via vsock). See nix/vm-hsm/README.md.";
    }
    {
      assertion = !(productionMode && enclaveTransportOnly);
      message =
        "twod-hsm: productionMode cannot run transport-only (no operational PQ signer). "
        + "Use a profile that installs a sealed signer.";
    }
    {
      # Couple the env-gate and the unit-gate: sealRootSource="snp" points the enclave's root file at
      # the tmpfs path the derive oneshot writes, but that oneshot only exists when snpDeriveRootPackage
      # is set. Without it the enclave would read a file nothing writes — fail at eval, not at boot.
      assertion = !(snpRoot && snpDeriveRootPackage == null);
      message =
        "twod-hsm: sealRootSource=\"snp\" requires snpDeriveRootPackage (the twod-hsm-snp-derive-seal-root "
        + "oneshot writes the root file the enclave reads). Pass snp-derive-root to the image.";
    }
  ];

  boot.loader.grub.enable = false;
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_net"
    "vsock"
  ];
  boot.kernelModules = [
    "vsock"
    "vmw_vsock_virtio_transport"
    # SEV-SNP guest attestation provider: registers configfs-tsm
    # (/sys/kernel/config/tsm/report) and /dev/sev-guest so the enclave can fetch
    # the launch measurement for GET_MEASUREMENT (TASK-5 Phase 3 / AC#4). Inert on
    # non-SNP launches (KVM): the module just does not bind.
    "sev-guest"
  ];
  boot.kernelParams = [ "console=ttyS0" ];

  fileSystems."/" = {
    device = "/dev/vda";
    fsType = "ext4";
  };

  networking.hostName = "vm-hsm";
  networking.firewall.enable = false;
  services.openssh.enable = false;
  documentation.enable = false;

  environment.systemPackages = [ enclavePackage pkgs.coreutils ];

  systemd.services.${unitName} = {
    description = "2d-hsm vsock enclave (${mode})";
    after = [
      "systemd-modules-load.service"
      "systemd-udev-settle.service"
    ] ++ lib.optionals isProd [ "sys-kernel-config.mount" ];
    wantedBy = [ "multi-user.target" ];
    # AC#4: ensure configfs (/sys/kernel/config) is mounted and ordered before the enclave so the
    # SNP measurement capture via configfs-tsm does not fail (which would trip the release
    # fail-closed gate). Prod only.
    unitConfig = lib.optionalAttrs isProd {
      RequiresMountsFor = "/sys/kernel/config";
    };
    serviceConfig = {
      ExecStart = "${enclavePackage}/bin/${binName}";
      Restart = "always";
      RestartSec = "3";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
    }
    // lib.optionalAttrs isProd {
      # AC#4: the enclave fetches the SNP launch measurement via configfs-tsm at boot, which
      # creates and writes /sys/kernel/config/tsm/report/*. Whitelist that subtree read-write so
      # the hardening sandbox (ProtectSystem=strict / ProtectKernelTunables) does not block the
      # capture and silently force the placeholder fallback. Live-validated by the passing
      # disk-production-lab SNP smoke (TASK-5 AC#5); the twod-hsm-quote-smoke unit below extends
      # the validation to the /proc/self/exe re-exec spawn shape under the same knobs (TASK-7.7 4c).
      ReadWritePaths = [ "/sys/kernel/config/tsm" ];
    };
    preStart = ''
      echo "[vm-hsm] starting ${binName} (${mode})" >/dev/console
    '';
    environment =
      {
        # VMADDR_CID_ANY — accept on hypervisor-assigned guest CID (see vsock spec §2.4).
        TWOD_HSM_VSOCK_CID = "4294967295";
        TWOD_HSM_VSOCK_PORT = "5000";
      }
      // lib.optionalAttrs isProd {
        TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE = "${trustFile}";
      }
      // lib.optionalAttrs (isProd && pqSealedSignerFile != null && enclaveRootFile != null) {
        # sealRootSource="snp" → enclaveRootFile is the tmpfs path the derive oneshot writes;
        # otherwise it is the build-time root file. The sealed signer is always a baked blob.
        TWOD_HSM_PQ_SEAL_V1_ROOT_FILE = enclaveRootFile;
        TWOD_HSM_PQ_SEALED_SIGNER_FILE = "${pqSealedSignerFile}";
      }
      // lib.optionalAttrs (isProd && enclaveTransportOnly) {
        TWOD_HSM_TRANSPORT_ONLY_MODE = "1";
      };
  };

  # TASK-1.1: opt-in SNP firmware-derived pq-seal root self-check (default off). Runs at boot,
  # independently of the enclave; logs PASS + a secret-free commitment to the console (for validating
  # the derived-key path on a real SNP host). Does NOT feed the enclave's root yet — wiring the
  # derived root into the sealed-boot needs the provisioning ceremony (re-seal against it), a follow-up.
  systemd.services."twod-hsm-snp-derive-root-selftest" =
    lib.mkIf (isProd && deriveRootSelftest && snpDeriveRootPackage != null) {
      description = "2d-hsm SNP derived pq-seal root self-check (TASK-1.1)";
      # Standalone diagnostic: it must NOT gate the enclave. The check feeds the signer nothing yet,
      # so a FAIL should log to the console — not cancel enclave-vsock's start job (which a
      # requiredBy/Requires= coupling would do). Hence wantedBy multi-user.target, no before/requiredBy.
      wantedBy = [ "multi-user.target" ];
      # It opens the udev-created /dev/sev-guest node (not configfs-tsm), so wait for udev to settle —
      # the same barrier the enclave unit uses. No /sys/kernel/config dependency: --selftest never
      # touches configfs.
      after = [ "systemd-modules-load.service" "systemd-udev-settle.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${snpDeriveRootPackage}/bin/snp-derive-root --selftest";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

  # TASK-7.7 (d-ii)/4c: in-guest quote smoke (production spawn shape + dispatch re-exec + configfs
  # GC + vsock-lapse + journald breadcrumb). Lab images only (quoteSmokePackage is a debug build of
  # the release-banned lab-quote-smoke feature). NB systemd runs ExecStartPost only after ExecStart
  # succeeds — on a bin FAIL the journald-breadcrumb marker is absent, which the host PASS-set
  # (run-nix-snp-quote-smoke.sh, three greps) catches anyway.
  systemd.services."twod-hsm-quote-smoke" = lib.mkIf (isProd && quoteSmokePackage != null) {
    description = "2d-hsm (4c) in-guest quote smoke (TASK-7.7 5b-2b-ii d-ii/4c)";
    wantedBy = [ "multi-user.target" ]; # standalone diagnostic — deliberately does NOT gate the enclave
    after = [ "systemd-modules-load.service" "systemd-udev-settle.service" "sys-kernel-config.mount" ];
    unitConfig.RequiresMountsFor = "/sys/kernel/config";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${quoteSmokePackage}/bin/twod-hsm-quote-smoke"; # bin directly — 5b-2c unit template
      ExecStartPost = "${journaldAssert}";
      SyslogIdentifier = "twod-hsm-quote-smoke";
      StandardOutput = "journal+console"; # markers + breadcrumbs -> journald AND ttyS0
      StandardError = "journal+console";
      # PRODUCTION SANDBOX KNOBS (mirror the enclave unit's block above). What this newly validates
      # is NOT configfs-under-hardening per se (the passing disk-production-lab smoke already
      # validates that for the enclave unit) but the PRODUCTION SPAWN SHAPE under the knobs:
      # /proc/self/exe re-exec + child configfs create/write/GC + inherited-stderr->journald with
      # NoNewPrivileges/ProtectSystem=strict/etc. — the 5b-2c unit SEED.
      # ESCAPE HATCH (recorded): if a knob blocks a SMOKE-ONLY step (journalctl), relax THAT knob
      # with an in-file comment; the spawn/configfs legs must stay under the production set.
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      ReadWritePaths = [ "/sys/kernel/config/tsm" ];
    };
  };

  # TASK-1.1 (sealed-boot loop): derive the pq-seal root from the SNP firmware into a tmpfs file the
  # enclave reads (sealRootSource="snp"). Unlike the selftest, this IS load-bearing — the enclave
  # unseals its signer against this root — so it gates the enclave (requiredBy + before): if the
  # derivation fails, the enclave could not unseal anyway, so failing closed is correct.
  systemd.services."twod-hsm-snp-derive-seal-root" =
    lib.mkIf (isProd && snpRoot && snpDeriveRootPackage != null) {
      description = "2d-hsm SNP firmware-derived pq-seal root → ${runtimeRootFile} (TASK-1.1)";
      requiredBy = [ "${unitName}.service" ];
      before = [ "${unitName}.service" ];
      # Opens the udev-created /dev/sev-guest node — wait for udev to settle (the enclave's barrier).
      after = [ "systemd-modules-load.service" "systemd-udev-settle.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # The tool creates /run/twod-hsm (0700) and writes the root 0600; /run is tmpfs, so the
        # secret root never touches persistent storage. The enclave (ProtectSystem=strict) reads it.
        ExecStart = "${snpDeriveRootPackage}/bin/snp-derive-root --out ${runtimeRootFile}";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

  # CEREMONY ONLY — never enable on a shipped image. Prints the SECRET derived root to the console so
  # an operator can seal the signer against it offline (runbook §7.1 step 1). This dumps the
  # provisioning root to the serial log, so it is gated behind deriveRootPrintCeremony (default off)
  # and only ever set by the sealed-boot ceremony script on a trusted host.
  systemd.services."twod-hsm-snp-derive-root-print-ceremony" =
    lib.mkIf (isProd && deriveRootPrintCeremony && snpDeriveRootPackage != null) {
      description = "2d-hsm SNP derived pq-seal root PRINT (CEREMONY ONLY — leaks the secret root)";
      wantedBy = [ "multi-user.target" ];
      after = [ "systemd-modules-load.service" "systemd-udev-settle.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${snpDeriveRootPackage}/bin/snp-derive-root --print";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

  system.stateVersion = "25.05";
}