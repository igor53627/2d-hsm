# Build the snp-derive-root boot helper (TASK-1.1). Separate from the enclave (it owns the
# SNP_GET_DERIVED_KEY ioctl the forbid-unsafe enclave crate cannot do).
{ lib, rustPlatform }:

let
  src = ../../rust/snp-derive-root;
in
rustPlatform.buildRustPackage {
  pname = "snp-derive-root";
  version = "0.1.0";
  inherit src;

  cargoLock.lockFile = "${src}/Cargo.lock";
  buildType = "release";

  meta = with lib; {
    description = "Derive the 2d-hsm pq-seal v1 provisioning root from SEV-SNP firmware (boot helper)";
    homepage = "https://github.com/privacy-scaling-explorations/2d-hsm";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "snp-derive-root";
  };
}
