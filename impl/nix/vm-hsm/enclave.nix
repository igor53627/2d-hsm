# Build enclave-protocol vsock binaries (TASK-4 Phase A).
{ lib, rustPlatform, stdenv, profile ? "production" }:

let
  src = ../../rust/enclave-protocol;
  staging = profile == "staging";
  labProd = profile == "production-lab";
  pname = if staging then "enclave-vsock-staging" else "enclave-vsock";
  buildFeatures =
    if staging then
      [ "staging-vsock" ]
    else if labProd then
      [ "lab-production-vsock" ]
    else
      [ "production-vsock" ];
in

rustPlatform.buildRustPackage {
  inherit pname src;
  version = "0.1.0";

  cargoLock.lockFile = "${src}/Cargo.lock";

  buildFeatures = buildFeatures;
  buildType = if staging || labProd then "debug" else "release";

  cargoBuildFlags = [ "--bin ${pname}" ];

  # Reference/staging keys must not ship in release artifacts (enforced in lib.rs too).
  doCheck = false;

  meta = with lib; {
    description = "2d-hsm TEE vsock server (${profile} profile)";
    homepage = "https://github.com/privacy-scaling-explorations/2d-hsm";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = pname;
  };
}