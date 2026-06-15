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
  # TASK-7.7 5b-2c-iii: opt-in agent-gateway serve unit (the DEBUG `twod-hsm-agent-gateway` bin +
  # the lab keystore file source). Default off — only the disk-production-lab-agent-gateway image
  # sets it. Lab-only by the eval assert below (the keystore source feature is release-banned).
  agentGatewayPackage ? null,
  # AC#5 Layer-1 funding gate (TASK-7.7 §5, TASK-16). guest-profile.nix derives these: a productionMode
  # FUNDING profile (installs an operational faucet/transfer signer ⇒ agentAntiRollbackEnabled) with
  # agentAntiRollbackMode "none" FAILS the build unless antiRollbackResidualOptOut is recorded (assertion
  # below). All default to the hard-block-safe values so non-funding profiles pass unchanged.
  agentAntiRollbackMode ? "none",
  agentAntiRollbackEnabled ? false,
  antiRollbackResidualOptOut ? false,
  ...
}:

let
  mode = enclaveMode;
  isProd = mode == "production";
  # AC#5 Layer-1 funding-gate predicate — DERIVED HERE from the module's OWN primitive args via the
  # single-source ./ac5-funding-gate.nix (the SAME function the flake `checks.agent-anti-rollback-gate`
  # imports), so (a) the formula can't drift between the module assertion and the self-test, and (b) a
  # direct module consumer cannot fail the gate OPEN by omitting a pre-computed flag — the assertion is
  # computed from the raw params the module already holds (review job 7523 codex / wf_a2cce791 mech B).
  agentAntiRollbackGatePass = import ./ac5-funding-gate.nix {
    inherit productionMode agentAntiRollbackEnabled agentAntiRollbackMode antiRollbackResidualOptOut;
  };
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
  # TASK-7.7 5b-2c-iii: the TEST-KEYS-ONLY smoke agent keystore (lab-prod-fixtures; length-pinned
  # copy of the committed testvector). Referenced directly here rather than threaded through
  # guest-profile specialArgs: the agent unit is lab-only BY THE EVAL ASSERT below, and the lab
  # fixture IS its only keystore source today (the production attested host-vsock source is a
  # deferred slice with its own wiring).
  agentSmokeKeystoreFile = (import ./lab-prod-fixtures.nix { inherit pkgs; }).agentSealedKeystoreFile;
  # TASK-7.7 5b-2c-iii: journald-ARRIVAL witness for the agent unit's serve marker. A long-running
  # unit cannot use the (4c) ExecStartPost trick (fires at start, skipped on start failure) — this
  # runs as a SEPARATE After=-ordered oneshot, retry-grepping bounded 120×1s (the agent may
  # crash-loop until the host relay/anchor answer; the marker is the EVENTUAL Ready evidence).
  # SELF-MATCH GUARD: echoes ONLY the distinct journald-serve marker, never the grepped literal.
  agentJournaldWitness = pkgs.writeShellScript "twod-hsm-agent-smoke-journald-witness" ''
    ${pkgs.systemd}/bin/journalctl --sync 2>/dev/null || true
    for i in $(seq 1 120); do
      if ${pkgs.systemd}/bin/journalctl -u twod-hsm-agent-gateway -b --no-pager 2>/dev/null \
           | grep -qF 'agent gateway: serving on vsock'; then
        echo "twod-hsm-agent-smoke: journald-serve PASS"; exit 0
      fi
      sleep 1
    done
    echo "twod-hsm-agent-smoke: journald-serve FAIL"; exit 1
  '';
in
{
  # Mainnet gate (TASK-5 AC#10): a productionMode guest must NOT ship lab attestation
  # trust / lab PQ seal, and must run an operational signer (not transport-only). These
  # fail the build (eval) rather than silently booting a lab-trust image as "mainnet".
  # The lab/dev outputs (vm-production*, disk-production*) keep productionMode = false and
  # remain explicitly non-mainnet. Operator-provisioned trust comes from a sealed store /
  # build-time secret injection (guest-profile *Override args), never from vsock — AC#2.
  assertions = [
    {
      # AC#5/AC#10 coupling invariant (review wf_a2cce791 mechanism A): productionMode (mainnet intent)
      # MUST imply a production/production-lab guestProfile (isProd). Otherwise the entire
      # `lib.optionals isProd [...]` list below — the mainnet trust/seal gates AND the AC#5 funding gate —
      # would be SILENTLY dropped for a productionMode=true build on a non-prod guestProfile (the guard
      # variable `isProd`/guestProfile is decoupled from the trigger `productionMode`). ALWAYS-PRESENT (not
      # isProd-wrapped) so it catches exactly that decoupling, hardening every productionMode-keyed gate.
      assertion = isProd || !productionMode;
      message =
        "twod-hsm: productionMode (mainnet intent) requires a production/production-lab guestProfile "
        + "(enclaveMode == \"production\"). A productionMode build on a non-prod guestProfile would "
        + "SILENTLY skip the isProd-gated mainnet trust/seal + AC#5 funding assertions. See "
        + "nix/vm-hsm/guest-profile.nix + backlog/docs/agent-gateway-anti-rollback.md §5.";
    }
    {
      # AC#5 Layer-1 funding gate (TASK-7.7 §5, TASK-16) — ALWAYS-PRESENT (belt-and-suspenders: the
      # predicate is self-guarded by its own `productionMode` term, a no-op for non-funding/non-prod
      # profiles, but being OUTSIDE the isProd wrapper it fires even if the coupling invariant above were
      # ever weakened). `agentAntiRollbackGatePass` is DERIVED in the `let` above from this module's own
      # raw params via the single-source ./ac5-funding-gate.nix — FAIL-CLOSED BY ALLOWLIST (a productionMode
      # funding build passes ONLY for an EXACT sanctioned mode {remote-counter, external-ledger} or the
      # audited opt-out; any other value incl. an unvalidated direct-consumer string fails) — and drift-proof
      # vs the flake check. A productionMode FUNDING profile (installs an operational faucet/transfer signer
      # ⇒ agentAntiRollbackEnabled) with mode "none" FAILS the build unless the audited measured/sealed
      # residual opt-out (verbatim TASK-7.2 AC#10 ack) is recorded — the ONLY escape, never silent. No
      # funding profile exists yet (TASK-15) so this is a dormant tripwire; checks.agent-anti-rollback-gate
      # exercises both polarities. (Runtime Layer-2b is already live.)
      assertion = agentAntiRollbackGatePass;
      message =
        "twod-hsm: AC#5 funding gate (TASK-7.7 §5) — a productionMode funding profile (one that installs "
        + "a faucet/transfer signer) must set agentAntiRollbackMode to remote-counter | external-ledger, "
        + "or record the audited antiRollbackResidualOptOut (the verbatim TASK-7.2 AC#10 residual-risk "
        + "acknowledgment, captured in the measured/sealed config). mode \"none\" with no opt-out is a "
        + "hard block — fund custody must not deploy without an anti-rollback mechanism. "
        + "See backlog/docs/agent-gateway-anti-rollback.md §5.";
    }
  ]
  ++ lib.optionals isProd [
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
      # TASK-7.7 (d-ii)/4c: the quote-smoke is a DEBUG, release-BANNED lab diagnostic (synthetic
      # configfs writes, vsock black-hole probing). Make "lab-only" MECHANICAL, not just prose: a
      # mainnet (productionMode) image must NEVER embed it — fail at eval, not silently ship the
      # debug smoke into a mainnet build. Only the lab outputs (disk-production-lab-quote-smoke,
      # productionMode=false) may pass quoteSmokePackage. EVAL-ENFORCED: fires on every module
      # evaluation, so the `disk-production-lab-quote-smoke` eval (CI eval-regression + run-book)
      # exercises the PASS side; the FAIL side has no output to point at precisely BECAUSE this guard
      # makes a mainnet-with-quoteSmokePackage image un-constructible (it throws here at eval).
      assertion = quoteSmokePackage == null || !productionMode;
      message =
        "twod-hsm: quoteSmokePackage (the (4c) debug quote-smoke) MUST NOT be embedded in a "
        + "productionMode/mainnet image — it is a lab-only, release-banned diagnostic.";
    }
    {
      # TASK-7.7 5b-2c-iii: the agent-gateway smoke image is the SAME mechanical lab-only discipline —
      # its keystore source (lab-agent-keystore-from-file, a DEBUG-only release-banned feature) reads
      # the TEST-KEYS-ONLY smoke fixture; a mainnet image embedding it is un-constructible at eval.
      assertion = agentGatewayPackage == null || !productionMode;
      message =
        "twod-hsm: agentGatewayPackage (the 5b-2c-iii DEBUG agent-gateway + lab keystore source) "
        + "MUST NOT be embedded in a productionMode/mainnet image — the production agent keystore "
        + "source (attested host-vsock install/restore) is a deferred slice.";
    }
    {
      # The agent unit bakes TWOD_HSM_PQ_SEAL_V1_ROOT_FILE from the profile's provisioning-root
      # fixture; without it the env would dangle — fail at eval (use the production-lab profile).
      assertion = agentGatewayPackage == null || pqSealProvisioningRootFile != null;
      message =
        "twod-hsm: agentGatewayPackage requires pqSealProvisioningRootFile (the production-lab "
        + "profile supplies the lab fixture).";
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
      # 5b-2c TEMPLATE CAVEAT: this is harmless HERE (the smoke parent writes nothing to its own
      # stdout — all child PROTOCOL frames are PIPED to the parent, never inherited). The 5b-2c serve
      # bin MUST re-evaluate StandardOutput: if its own process stdout ever becomes a protocol
      # transport, journal+console would tee binary frames to journald+ttyS0 — set it to `null`/`journal`.
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

  # TASK-7.7 5b-2c-iii: the agent-gateway serve unit for the aya SNP live smoke. LONG-RUNNING (the
  # bin diverges into the serial 0x40 serve loop after Ready), `Restart=always` — the boot wrapper's
  # exit-for-supervisor-restart design: every boot failure (root/unseal/budget/handshake/install) is
  # a process exit, and the unit restarts until the host-side relay+anchor answer (the smoke runner
  # starts them BEFORE qemu; `StartLimitIntervalSec=0` gives the crash-loop unlimited headroom).
  # Standalone — deliberately does NOT gate or order against the producer enclave unit (distinct
  # ports: producer serve 5000, boot-relay dial 5001, agent serve 5002).
  systemd.services."twod-hsm-agent-gateway" = lib.mkIf (isProd && agentGatewayPackage != null) {
    description = "2d-hsm agent-gateway 0x40 serve bin (TASK-7.7 5b-2c-iii lab smoke)";
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-modules-load.service" "systemd-udev-settle.service" "sys-kernel-config.mount" ];
    unitConfig = {
      # The boot handshake's quote child writes configfs-tsm — same barrier as the enclave unit.
      RequiresMountsFor = "/sys/kernel/config";
      # Unlimited restart headroom: until the host relay/anchor are reachable the boot fail-closes
      # and exits by design; the default start-limit would wedge the unit in `failed` instead of
      # reaching the EVENTUAL Ready the smoke's boot-to-Ready grep polls for.
      StartLimitIntervalSec = 0;
    };
    serviceConfig = {
      ExecStart = "${agentGatewayPackage}/bin/twod-hsm-agent-gateway";
      Restart = "always";
      RestartSec = "3";
      SyslogIdentifier = "twod-hsm-agent-gateway";
      # DISCHARGES the (4c) template caveat recorded on the quote-smoke unit: the agent bin's stdout
      # is PROTOCOL-ONLY (the 0x40 protocol rides vsock and stdout stays EMPTY in a normal boot, but
      # the dispatch-first quote child CAN write protocol frames to it) — so stdout goes to journal
      # ONLY, never teed to ttyS0. All operator/marker lines are stderr → journal AND the serial
      # console (the smoke's boot-to-Ready grep reads them off the serial log).
      StandardOutput = "journal";
      StandardError = "journal+console";
      # PRODUCTION SANDBOX KNOBS (mirror the enclave unit): without ReadWritePaths the quote child
      # cannot create/write /sys/kernel/config/tsm/report/* under ProtectSystem=strict /
      # ProtectKernelTunables and the smoke would never reach Ready.
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
    preStart = ''
      echo "[vm-hsm] starting twod-hsm-agent-gateway (5b-2c-iii lab smoke)" >/dev/console
    '';
    environment = {
      # VMADDR_CID_ANY; serve port 5002 — structurally absent collision with the producer's 5000
      # (relay!=serve is boot-validated; producer-vs-agent is avoided by construction here).
      TWOD_HSM_VSOCK_CID = "4294967295";
      TWOD_HSM_VSOCK_PORT = "5002";
      # Boot-relay DIAL port (the guest dials host CID 2 : 5001 during the handshake).
      TWOD_HSM_ANCHOR_RELAY_PORT = "5001";
      # The agent's lab keystore source: the SAME provisioning-root env var name as the producer
      # (domain-separated KDFs inside agent_keystore provide isolation) + the TEST-KEYS-ONLY smoke
      # blob (lab-prod-fixtures; the production attested host-vsock source is a deferred slice).
      TWOD_HSM_PQ_SEAL_V1_ROOT_FILE = "${pqSealProvisioningRootFile}";
      TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE = "${agentSmokeKeystoreFile}";
      # No TWOD_HSM_ENCLAVE_MEASUREMENT_FILE: the blob is sealed under the placeholder measurement
      # (the genesis precedent; the attested 48-byte measurement is the deferred production slice —
      # recorded smoke non-coverage in SMOKE-PASS-CRITERIA.md).
    };
  };

  # TASK-7.7 5b-2c-iii: journald-ARRIVAL witness for the agent serve marker. The (4c) ExecStartPost
  # trick does NOT transfer to a long-running unit (it fires at start, not after the interesting
  # output, and is skipped on a start failure) — so this is a SEPARATE After=-ordered oneshot doing a
  # bounded retry-grep. SELF-MATCH GUARD: echoes ONLY the distinct `journald-serve PASS|FAIL` marker,
  # never the grepped literal.
  systemd.services."twod-hsm-agent-smoke-journald" =
    lib.mkIf (isProd && agentGatewayPackage != null) {
      description = "2d-hsm 5b-2c-iii journald witness for the agent serve marker";
      wantedBy = [ "multi-user.target" ]; # standalone witness — does NOT gate the agent unit
      after = [ "twod-hsm-agent-gateway.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${agentJournaldWitness}";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
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