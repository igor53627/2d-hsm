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
  # TASK-7.7 5b-2c-iii: the minted SMOKE agent keystore (TEST KEYS ONLY — the anchor seed and the
  # secp scalar are public in-repo constants; see lab_agent_smoke.rs + the .json sidecar). NAMING: the
  # `_v1` suffix is the SMOKE-FIXTURE revision (first cut), NOT the on-disk keystore format — the blob
  # carries pq-agent-keystore FORMAT_VERSION 2 (header bytes [0x00,0x02]; the in-crate freeze + sidecar
  # assert it). Don't conflate the two on the next format bump. The exact byte length pins the committed
  # blob; a regen changes it — update in the SAME commit (the in-crate byte-exact freeze + sidecar tests
  # catch a blob/sidecar split, this catches a blob/nix split).
  agentSealedKeystoreFile = pkgs.runCommand "twod-hsm-lab-agent-smoke-keystore" { } ''
    cp ${tv}/agent-gateway/agent_keystore_smoke_v1.sealed.bin $out
    sz=$(wc -c < "$out" | tr -d ' ')
    if [ "$sz" != "4418" ]; then
      echo "expected the 4418-byte smoke agent keystore blob (format_version 2), got $sz" >&2
      exit 1
    fi
  '';
}