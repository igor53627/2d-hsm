# Minimal NixOS guest for 2d-hsm TEE staging (TASK-4 Phase B).
# Uses enclave-staging until platform PQ seal + prod enclave are wired in the guest.
{ config, lib, pkgs, enclave-staging, ... }:

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

  environment.systemPackages = [ enclave-staging pkgs.coreutils ];

  systemd.services.enclave-vsock-staging = {
    description = "2d-hsm vsock staging enclave";
    after = [
      "systemd-modules-load.service"
      "systemd-udev-settle.service"
    ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${enclave-staging}/bin/enclave-vsock-staging";
      Restart = "always";
      RestartSec = "3";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
    preStart = ''
      echo "[vm-hsm] starting enclave-vsock-staging" >/dev/console
    '';
    environment = {
      # Must match QEMU vhost-vsock-pci guest-cid; TWOD_* (not 2D_*) is valid in systemd.
      TWOD_HSM_VSOCK_CID = "42";
      TWOD_HSM_VSOCK_PORT = "5000";
    };
  };

  system.stateVersion = "25.05";
}