# Shared guest-profile → enclave/specialArgs mapping for the 2d-hsm NixOS guest.
#
# Consumed by:
#   - vm.nix         (nixpkgs qemu-vm *runner*; KVM aya smokes, TASK-4 Phase B)
#   - disk-image.nix (bootable EFI qcow2 for the SEV-SNP launch, TASK-5 AC#5)
#
# Keeping the profile selection in one place guarantees the qemu-vm guest and the
# SNP disk-image guest run the *same* enclave package, mode, trust VK and seal
# fixtures — so a measurement captured under SNP corresponds to the binary the
# KVM smokes exercise.
{
  nixpkgs,
  enclave,
  enclave-staging,
  enclave-production-lab,
  enclave-production-transport,
  guestProfile ? "staging",
  # Mainnet intent (TASK-5 AC#10): when true, the NixOS module refuses lab trust /
  # lab PQ seal (see nixos-module.nix assertions) and requires operator-provided
  # platform trust + sealed signer.
  productionMode ? false,
  # Build-time injection of platform-provisioned material (TASK-5 AC#2). When null,
  # the prod *lab/dev* profiles fall back to the lab fixtures (NOT mainnet). A mainnet
  # guest (productionMode = true) MUST supply real, non-lab files here — from a sealed
  # store or build-time secret, never from vsock at runtime.
  trustFileOverride ? null,
  pqSealRootOverride ? null,
  pqSealedSignerOverride ? null,
  # AC#5 Layer-1 funding gate (TASK-7.7 §5, TASK-16). The anti-rollback mechanism mode is provisioned
  # at BUILD TIME (captured in the measured/sealed config — NEVER a runtime/host-settable input; a host
  # cannot flip it). A productionMode FUNDING profile (one that installs an operational faucet/transfer
  # signer ⇒ `agentAntiRollbackEnabled` below) with mode "none" FAILS the build (nixos-module assertion),
  # unless the audited `antiRollbackResidualOptOut` is recorded. See backlog/docs/agent-gateway-anti-rollback.md §5.
  #   enum: none | remote-counter | external-ledger. ("operator-signed-boot" is NOT a standalone passing
  #   mode — §3 replay-vulnerable alone — only a challenge-response sub-mode of remote-counter.)
  agentAntiRollbackMode ? "none",
  # The measured/sealed audited opt-out (verbatim TASK-7.2 AC#10 residual-risk acknowledgment, build-time,
  # captured in the enclave measurement). The ONLY way the gate passes with mode "none". Default = hard block.
  antiRollbackResidualOptOut ? false,
  # Forward-declared (TASK-15 transfer/faucet signing): the operational funding-signer package. Its
  # presence DERIVES `agentAntiRollbackEnabled = true`, so a new funding profile can never silently leave
  # the gate disabled (Nix optional params default falsy). null today ⇒ no funding profile ⇒ gate dormant.
  agentTransferFaucetSignerPackage ? null,
}:

let
  system = "x86_64-linux";
  labFx = import ./lab-prod-fixtures.nix {
    pkgs = nixpkgs.legacyPackages.${system};
  };
  # vm-production = transport smoke only; vm-production-lab = + file PQ seal. NOT mainnet-ready.
  isProd = guestProfile == "production" || guestProfile == "production-lab";
  isProdLab = guestProfile == "production-lab";
  enclavePackage =
    if guestProfile == "staging" then
      enclave-staging
    else if guestProfile == "production" then
      enclave-production-transport
    else if isProdLab then
      enclave-production-lab
    else
      throw "guest-profile.nix: invalid guestProfile '${guestProfile}' (expected staging | production | production-lab)";
  enclaveMode = if isProdLab then "production" else guestProfile;

  # An override counts as "lab" if it is absent OR points at the in-repo lab fixture — so the
  # gate can't be bypassed by aiming an override at the lab file. Compared by store path.
  usesLab = override: labFile: override == null || toString override == toString labFile;

  # Resolve trust/seal: operator override > lab fixture (dev/lab only) > none.
  # Seal material only exists on the operational (signer-installing) profile; seal overrides on
  # a transport/staging profile are ignored (those profiles install no signer).
  producerAttestationTrustFile =
    if !isProd then
      null
    else if trustFileOverride != null then
      trustFileOverride
    else
      labFx.producerAttestationTrustFile;
  pqSealProvisioningRootFile =
    if !isProdLab then
      null
    else if pqSealRootOverride != null then
      pqSealRootOverride
    else
      labFx.pqSealProvisioningRootFile;
  pqSealedSignerFile =
    if !isProdLab then
      null
    else if pqSealedSignerOverride != null then
      pqSealedSignerOverride
    else
      labFx.pqSealedSignerFile;
  enclaveTransportOnly = guestProfile == "production";

  # True when ANY lab fixture is in use (operator did not override it, or pointed the override
  # back at the lab file). The mainnet gate (nixos-module assertions) refuses this when
  # productionMode = true.
  labFixtures =
    (isProd && usesLab trustFileOverride labFx.producerAttestationTrustFile)
    || (isProdLab && usesLab pqSealRootOverride labFx.pqSealProvisioningRootFile)
    || (isProdLab && usesLab pqSealedSignerOverride labFx.pqSealedSignerFile);

  # AC#5 Layer-1 (TASK-7.7 §5, TASK-16). Validate the mode enum at eval; surface the gate inputs for the
  # nixos-module assertion. `agentAntiRollbackEnabled` is DERIVED (the gate is armed iff a funding signer
  # is installed) — never a free-defaulting param a funding profile could forget to set. No funding signer
  # exists yet (TASK-15), so this is `false` for every current profile and the gate is a dormant tripwire
  # that the `checks.agent-anti-rollback-gate` flake check still exercises with synthetic funding args.
  validatedAntiRollbackMode =
    if builtins.elem agentAntiRollbackMode [ "none" "remote-counter" "external-ledger" ] then
      agentAntiRollbackMode
    else
      throw "guest-profile.nix: invalid agentAntiRollbackMode '${agentAntiRollbackMode}' (expected none | remote-counter | external-ledger)";
  agentAntiRollbackEnabled = agentTransferFaucetSignerPackage != null;
  # SINGLE-SOURCED gate predicate (true = the build may pass; false = a productionMode funding profile
  # with no mechanism + no opt-out, which the nixos-module assertion turns into a build failure). Defined
  # ONCE here so the nixos-module assertion AND the flake `checks.agent-anti-rollback-gate` self-test
  # consume the SAME expression — the two can never drift (review wf_a2cce791 mechanism B).
  agentAntiRollbackGatePass =
    !(productionMode && agentAntiRollbackEnabled && validatedAntiRollbackMode == "none" && !antiRollbackResidualOptOut);
in
{
  inherit system;
  specialArgs = {
    inherit
      enclavePackage
      enclaveMode
      producerAttestationTrustFile
      pqSealProvisioningRootFile
      pqSealedSignerFile
      enclaveTransportOnly
      productionMode
      labFixtures
      agentAntiRollbackEnabled
      antiRollbackResidualOptOut
      agentAntiRollbackGatePass
      ;
    # AC#5 Layer-1 (TASK-7.7 §5): the validated mode (enum-checked above). nixos-module asserts the gate.
    agentAntiRollbackMode = validatedAntiRollbackMode;
    # nixos-module declares these (TASK-1.1 derived-root self-check + sealed-boot loop); the NixOS
    # module system requires every module arg to be present in specialArgs. Defaults here keep the
    # existing behavior (file-based root, no self-check/ceremony); disk-image.nix overrides them for
    # the self-check and snp-rooted image outputs.
    snpDeriveRootPackage = null;
    deriveRootSelftest = false;
    sealRootSource = "file";
    deriveRootPrintCeremony = false;
    # TASK-7.7 (d-ii)/4c: in-guest quote-smoke oneshot package (disk-image.nix overrides it for the
    # disk-production-lab-quote-smoke output).
    quoteSmokePackage = null;
    # TASK-7.7 5b-2c-iii: in-guest agent-gateway serve bin (disk-image.nix overrides it for the
    # disk-production-lab-agent-gateway output).
    agentGatewayPackage = null;
  };
}
