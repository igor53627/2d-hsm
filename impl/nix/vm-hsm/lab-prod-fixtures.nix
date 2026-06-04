# Lab-only fixtures for production enclave guest (TASK-5 Phase 2).
# NOT for mainnet — reference ML-DSA key + test provisioning root.
{ pkgs }:

let
  tv = ../../rust/enclave-protocol/testvectors;
  copy32 = name: src: pkgs.runCommand name { } ''
    cp ${src} $out
    sz=$(wc -c < "$out" | tr -d ' ')
    if [ "$sz" != "32" ]; then
      echo "expected 32 bytes, got $sz" >&2
      exit 1
    fi
  '';
in
{
  producerAttestationTrustFile = copy32 "twod-hsm-lab-producer-attestation-vk" "${tv}/reference_attestation_vk.bin";
  pqSealProvisioningRootFile = copy32 "twod-hsm-lab-pq-seal-root" "${tv}/seal_v1_provisioning_root.bin";
  pqSealedSignerFile = pkgs.runCommand "twod-hsm-lab-pq-sealed-signer" { } ''
    cp ${tv}/lab_prod_enclave.sealed $out
    sz=$(wc -c < "$out" | tr -d ' ')
    if [ "$sz" != "6053" ]; then
      echo "expected 6053-byte v1 sealed blob, got $sz" >&2
      exit 1
    fi
  '';
}