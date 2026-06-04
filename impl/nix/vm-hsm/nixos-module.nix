# Minimal NixOS guest for 2d-hsm TEE staging (TASK-4 Phase B).
{ config, lib, pkgs, enclave-staging, ... }:

{
  boot.loader.grub.enable = false;
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_net"
    "vsock"
  ];
  boot.kernelModules = [ "vsock" ];
  boot.kernelParams = [ "console=ttyS0" ];

  fileSystems."/" = {
    device = "/dev/vda";
    fsType = "ext4";
  };

  networking.hostName = "vm-hsm";
  networking.firewall.enable = false;
  services.openssh.enable = false;
  documentation.enable = false;

  environment.systemPackages = [ enclave-staging pkgs.coreutils ];

  systemd.services.enclave-vsock-staging = {
    description = "2d-hsm vsock staging enclave";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${enclave-staging}/bin/enclave-vsock-staging";
      Restart = "on-failure";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
    environment = {
      # Bind all guest CIDs (host connects to GUEST_CID, e.g. 42).
      "2D_HSM_VSOCK_CID" = "4294967295";
      "2D_HSM_VSOCK_PORT" = "5000";
    };
  };

  system.stateVersion = "25.05";
}