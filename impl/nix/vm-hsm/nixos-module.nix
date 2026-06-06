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

  system.stateVersion = "25.05";
}