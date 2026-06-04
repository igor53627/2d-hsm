# Emit build manifest JSON for CI and forkSpecHash helpers (TASK-4 AC #3).
{ lib, runCommand, jq, bash, coreutils, enclave, enclave-staging, flakeMeta ? { } }:

runCommand "vm-hsm-measurement-manifest"
  {
    inherit enclave enclave-staging;
    passthru.version = enclave.version;
  }
  ''
    export GIT_REVISION="${flakeMeta.gitRevision or "unknown"}"
    export FLAKE_LOCK="${flakeMeta.flakeLock or "unknown"}"
    export ENCLAVE_DRV="${enclave.drvPath}"
    export ENCLAVE_STAGING_DRV="${enclave-staging.drvPath}"
    export PATH="${lib.makeBinPath [ jq coreutils ]}:$PATH"
    mkdir -p "$out/bin"
    ${bash}/bin/bash ${./scripts/write-measurement-manifest.sh} \
      "$out/manifest.json" \
      "${enclave}/bin/enclave-vsock" \
      "${enclave-staging}/bin/enclave-vsock-staging"
    install -m755 ${./scripts/write-measurement-manifest.sh} "$out/bin/write-measurement-manifest.sh"
  ''