# Build enclave-protocol vsock binaries (TASK-4 Phase A).
{ lib, rustPlatform, stdenv, profile ? "production" }:

let
  src = ../../rust/enclave-protocol;
  staging = profile == "staging";
  labProd = profile == "production-lab";
  transportSmoke = profile == "production-transport";
  # TASK-7.7 (d-ii)/4c in-guest quote smoke. A SEPARATE derivation is MANDATORY — role isolation:
  # the producer profiles (production*/staging) pull ml-dsa-65, and a shared feature graph with
  # agent-gateway trips the `ml-dsa-65 ⊕ agent-gateway` compile_error (lib.rs, vsock §10.2). A
  # future "consolidate builds" cleanup MUST NOT merge this arm into the producer derivations.
  quoteSmoke = profile == "quote-smoke";
  # TASK-7.7 5b-2c-iii: the agent-gateway serve bin for the aya SNP live smoke. SEPARATE derivation
  # for the same role-isolation reason as quoteSmoke (ml-dsa-65 ⊕ agent-gateway compile_error).
  # Features = the §8 manifest pin (agent-gateway + vsock-transport) PLUS lab-agent-keystore-from-file
  # (the only wired keystore source today; release-banned ⇒ this MUST stay a debug build) — and
  # NOT lab-agent-smoke (that feature gates HOST-side smoke tooling, never a guest bin).
  agentGateway = profile == "agent-gateway";
  # TASK-7.7 6-7b-ii: the WRITE-path smoke build — the SAME `twod-hsm-agent-gateway` bin as
  # `agent-gateway`, but with `agent-keygen-exec-preview` ADDED so the guest actually executes
  # GENERATE_KEYS (seal→commit→swap→emit) and installs the per-op commit channel at boot (6-4b's
  # cfg-gated step G'). preview is release-banned (compile_error under STRICT_RELEASE_GUARDS), so this
  # stays a debug build for the same reason as `agent-gateway`. A SEPARATE profile (not a flag on the
  # read-path image) keeps the preview feature off the read-path smoke.
  agentGatewayKeygen = profile == "agent-gateway-keygen";
  # TASK-15: the combined FAUCET write-path smoke build — the SAME `twod-hsm-agent-gateway` bin, but with
  # ALL THREE preview gates (keygen-exec + configure-treasury + sign-faucet) so the guest can mint the
  # treasury key, configure caps + a budget, and dispense — the full fund-custody flow at runtime. All
  # three are release-banned (compile_errors under STRICT_RELEASE_GUARDS), so this stays a debug build for
  # the same reason as the keygen smoke. A SEPARATE profile keeps the preview features off the other images.
  agentGatewayFaucet = profile == "agent-gateway-faucet";
  pname =
    if staging then "enclave-vsock-staging"
    else if quoteSmoke then "twod-hsm-quote-smoke"
    else if (agentGateway || agentGatewayKeygen || agentGatewayFaucet) then "twod-hsm-agent-gateway"
    else "enclave-vsock";
  buildFeatures =
    if staging then
      [ "staging-vsock" ]
    else if labProd then
      [ "lab-production-vsock" ]
    else if quoteSmoke then
      [ "agent-gateway" "vsock-transport" "lab-quote-smoke" ]
    else if agentGatewayKeygen then
      [ "agent-gateway" "vsock-transport" "lab-agent-keystore-from-file" "agent-keygen-exec-preview" ]
    else if agentGatewayFaucet then
      [ "agent-gateway" "vsock-transport" "lab-agent-keystore-from-file" "agent-keygen-exec-preview" "agent-configure-treasury-preview" "agent-sign-faucet-preview" ]
    else if agentGateway then
      [ "agent-gateway" "vsock-transport" "lab-agent-keystore-from-file" ]
    else
      [ "production-vsock" ];
  # quoteSmoke/agentGateway/agentGatewayKeygen MUST stay debug builds: lab-quote-smoke /
  # lab-agent-keystore-from-file / agent-keygen-exec-preview are release-banned (lib.rs compile_errors),
  # and debug ⇒ TWOD_HSM_STRICT_RELEASE_GUARDS unset ⇒ the bans do not trip (by design). The
  # release-built agent spawn shape stays the recorded 5b-2c residual.
  debugBuild = staging || labProd || transportSmoke || quoteSmoke || agentGateway || agentGatewayKeygen || agentGatewayFaucet;
in

rustPlatform.buildRustPackage {
  inherit pname src;
  version = "0.1.0";

  cargoLock.lockFile = "${src}/Cargo.lock";

  buildFeatures = buildFeatures;
  buildType = if debugBuild then "debug" else "release";

  # Custom cargo profiles skip PROFILE=release; enforce key-safety compile_errors on prod builds.
  env =
    if (!debugBuild) then
      { TWOD_HSM_STRICT_RELEASE_GUARDS = "1"; }
    else
      { };

  cargoBuildFlags = [ "--bin ${pname}" ];

  # No checkPhase here: release artifact must not run tests that need reference-test-key.
  # ARM/signing regression tests run in CI via `cargo test` (see .github/workflows/nix-hsm.yml).
  doCheck = false;

  meta = with lib; {
    description = "2d-hsm TEE vsock server (${profile} profile)";
    homepage = "https://github.com/privacy-scaling-explorations/2d-hsm";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = pname;
  };
}