# Lab-only fixtures for production enclave smoke (TASK-5 Phase 1).
# NOT for mainnet — same Ed25519 VK as `reference_test_attestation_trust` (test-support).
{ pkgs }:

let
  src = ../../rust/enclave-protocol/testvectors/reference_attestation_vk.bin;
in
{
  producerAttestationTrustFile = pkgs.runCommand "twod-hsm-lab-producer-attestation-vk" { } ''
    cp ${src} $out
    sz=$(wc -c < "$out" | tr -d ' ')
    if [ "$sz" != "32" ]; then
      echo "expected 32-byte Ed25519 VK, got $sz" >&2
      exit 1
    fi
  '';
}