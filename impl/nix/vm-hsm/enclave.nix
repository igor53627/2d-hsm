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
  pname =
    if staging then "enclave-vsock-staging"
    else if quoteSmoke then "twod-hsm-quote-smoke"
    else "enclave-vsock";
  buildFeatures =
    if staging then
      [ "staging-vsock" ]
    else if labProd then
      [ "lab-production-vsock" ]
    else if quoteSmoke then
      [ "agent-gateway" "vsock-transport" "lab-quote-smoke" ]
    else
      [ "production-vsock" ];
  # quoteSmoke MUST stay a debug build: lab-quote-smoke is release-banned (lib.rs compile_error),
  # and debug ⇒ TWOD_HSM_STRICT_RELEASE_GUARDS unset ⇒ the ban does not trip (by design).
  debugBuild = staging || labProd || transportSmoke || quoteSmoke;
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