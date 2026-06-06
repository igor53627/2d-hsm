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
  ...
}:

let
  mode = enclaveMode;
  isProd = mode == "production";
  binName = if isProd then "enclave-vsock" else "enclave-vsock-staging";
  unitName = if isProd then "enclave-vsock" else "enclave-vsock-staging";
  trustFile =
    if !isProd then
      null
    else if producerAttestationTrustFile != null then
      producerAttestationTrustFile
    else
      throw "production guest requires producerAttestationTrustFile (lab: lab-prod-fixtures)";
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
      # capture and silently force the placeholder fallback. NOTE: needs live validation once the
      # NixOS guest boots under SNP (TASK-5 AC#5).
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
      // lib.optionalAttrs (
        isProd && pqSealProvisioningRootFile != null && pqSealedSignerFile != null
      ) {
        TWOD_HSM_PQ_SEAL_V1_ROOT_FILE = "${pqSealProvisioningRootFile}";
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

  system.stateVersion = "25.05";
}