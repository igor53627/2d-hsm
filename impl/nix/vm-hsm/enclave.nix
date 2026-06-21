# Build enclave-protocol vsock binaries (TASK-4 Phase A).
{ lib, rustPlatform, stdenv, profile ? "production" }:

let
  src = ../../rust/enclave-protocol;
  staging = profile == "staging";
  labProd = profile == "production-lab";
  transportSmoke = profile == "production-transport";
  quoteSmoke = profile == "quote-smoke";
  agentGateway = profile == "agent-gateway";
  # TASK-25 AC#1 + TASK-18 18-6..9: the PRODUCTION agent-gateway release image with ALL un-gated previews.
  # RELEASE build, STRICT_RELEASE_GUARDS=1, NO lab features. Provenance: attested provisioning channel.
  agentGatewayRelease = profile == "agent-gateway-release";
  agentGatewayKeygen = profile == "agent-gateway-keygen";
  agentGatewayFaucet = profile == "agent-gateway-faucet";
  pname =
    if staging then "enclave-vsock-staging"
    else if quoteSmoke then "twod-hsm-quote-smoke"
    else if (agentGatewayRelease || agentGateway || agentGatewayKeygen || agentGatewayFaucet) then "twod-hsm-agent-gateway"
    else "enclave-vsock";
  buildFeatures =
    if staging then [ "staging-vsock" ]
    else if labProd then [ "lab-production-vsock" ]
    else if quoteSmoke then [ "agent-gateway" "vsock-transport" "lab-quote-smoke" ]
    else if agentGatewayRelease then
      [ "agent-gateway" "vsock-transport" "agent-keygen-exec-preview" "agent-configure-treasury-preview" "agent-sign-faucet-preview" "agent-sign-transfer-preview" "agent-backup-export-preview" "agent-prove-identity-preview" ]
    else if agentGatewayKeygen then
      [ "agent-gateway" "vsock-transport" "lab-agent-keystore-from-file" "agent-keygen-exec-preview" ]
    else if agentGatewayFaucet then
      [ "agent-gateway" "vsock-transport" "lab-agent-keystore-from-file" "agent-keygen-exec-preview" "agent-configure-treasury-preview" "agent-sign-faucet-preview" ]
    else if agentGateway then
      [ "agent-gateway" "vsock-transport" "lab-agent-keystore-from-file" ]
    else [ "production-vsock" ];
  # agentGatewayRelease is a RELEASE build — all preview features un-gated (18-6..9), no lab features.
  debugBuild = staging || labProd || transportSmoke || quoteSmoke || agentGateway || agentGatewayKeygen || agentGatewayFaucet;
in
rustPlatform.buildRustPackage {
  inherit pname src;
  version = "0.1.0";
  cargoLock.lockFile = "${src}/Cargo.lock";
  buildFeatures = buildFeatures;
  buildType = if debugBuild then "debug" else "release";
  env = if (!debugBuild) then { TWOD_HSM_STRICT_RELEASE_GUARDS = "1"; } else { };
  cargoBuildFlags = [ "--bin ${pname}" ];
  doCheck = false;
  meta = with lib; {
    description = "2d-hsm TEE vsock server (${profile} profile)";
    homepage = "https://github.com/privacy-scaling-explorations/2d-hsm";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = pname;
  };
}
