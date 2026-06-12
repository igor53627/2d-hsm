# Shared smoke asset cache helpers (source only; do not execute).
# shellcheck shell=bash
[[ -n "${_TWOD_HSM_SMOKE_CACHE_LIB:-}" ]] && return 0
_TWOD_HSM_SMOKE_CACHE_LIB=1

twod_hsm_cache_root() {
  printf '%s' "${TWOD_HSM_CACHE:-/var/cache/2d-hsm}"
}

twod_hsm_cache_images() {
  printf '%s/images' "$(twod_hsm_cache_root)"
}

twod_hsm_cache_nix() {
  printf '%s/nix' "$(twod_hsm_cache_root)"
}

twod_hsm_cache_firmware() {
  printf '%s/firmware' "$(twod_hsm_cache_root)"
}

twod_hsm_ensure_cache_dirs() {
  mkdir -p "$(twod_hsm_cache_images)" "$(twod_hsm_cache_nix)" "$(twod_hsm_cache_firmware)"
}

twod_hsm_nix_init() {
  # shellcheck source=/dev/null
  if [[ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]]; then
    . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
  fi
  export PATH="/nix/var/nix/profiles/default/bin:${PATH:-}"
}

twod_hsm_nix_outlink_hit() {
  local link=$1 attr=$2
  case "$attr" in
    enclave-staging)
      [[ -x "${link}/bin/enclave-vsock-staging" ]]
      ;;
    enclave | enclave-production-lab)
      [[ -x "${link}/bin/enclave-vsock" ]]
      ;;
    vm | vm-production | vm-production-lab)
      local c
      for c in "${link}"/bin/run-*-vm; do
        [[ -e "$c" ]] && return 0
      done
      return 1
      ;;
    disk-production | disk-production-lab | disk-production-lab-selftest | \
      disk-production-lab-quote-smoke | disk-production-lab-agent-gateway)
      # make-disk-image emits a bootable qcow2 under the out path (TASK-5 AC#5;
      # disk-production-lab-selftest adds the TASK-1.1 derived-root self-check oneshot;
      # disk-production-lab-quote-smoke adds the TASK-7.7 (4c) quote-smoke oneshot;
      # disk-production-lab-agent-gateway adds the TASK-7.7 5b-2c-iii agent serve unit — the build
      # stamp already hashes all enclave-protocol src/*.rs + Cargo.* + testvectors + the smoke
      # scripts, so editing the smoke Rust/fixtures auto-invalidates the cached image).
      local c
      for c in "${link}"/*.qcow2; do
        [[ -e "$c" ]] && return 0
      done
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

# One sha256 over the enclave, flake, fixture, and smoke harness inputs per shell
# (warm-smoke-cache calls ensure 4×).
twod_hsm_cat_tree() {
  local dir=$1
  shift
  [[ -d "$dir" ]] || return 0
  find "$dir" -type f "$@" -print0 2>/dev/null | LC_ALL=C sort -z | while IFS= read -r -d '' f; do
    printf '%s\0' "${f#"$dir"/}"
    cat "$f"
  done
}

twod_hsm_nix_build_stamp() {
  local flake_dir=$1
  if [[ -n "${_TWOD_HSM_NIX_BUILD_STAMP:-}" ]]; then
    printf '%s' "$_TWOD_HSM_NIX_BUILD_STAMP"
    return 0
  fi
  local repo_root rust_dir snp_dir script_dir
  repo_root="$(cd "${flake_dir}/../../.." && pwd)"
  rust_dir="${repo_root}/impl/rust/enclave-protocol"
  # TASK-1.1: snp-derive-root is a separate crate baked into the disk-production-lab-selftest image,
  # so it must contribute to the stamp — otherwise editing its sources leaves a stale cached image.
  snp_dir="${repo_root}/impl/rust/snp-derive-root"
  script_dir="${repo_root}/impl/scripts/aya-sev-snp"
  _TWOD_HSM_NIX_BUILD_STAMP=$(
    {
      cat "${flake_dir}/flake.lock" "${flake_dir}/flake.nix" 2>/dev/null
      cat "${flake_dir}/"*.nix 2>/dev/null
      twod_hsm_cat_tree "${flake_dir}/scripts" -name '*.sh'
      [[ -f "${rust_dir}/Cargo.toml" ]] && cat "${rust_dir}/Cargo.toml"
      [[ -f "${rust_dir}/Cargo.lock" ]] && cat "${rust_dir}/Cargo.lock"
      [[ -f "${rust_dir}/build.rs" ]] && cat "${rust_dir}/build.rs"
      twod_hsm_cat_tree "${rust_dir}/src" -name '*.rs'
      twod_hsm_cat_tree "${rust_dir}/examples" -name '*.rs'
      twod_hsm_cat_tree "${rust_dir}/testvectors" -type f
      [[ -f "${snp_dir}/Cargo.toml" ]] && cat "${snp_dir}/Cargo.toml"
      [[ -f "${snp_dir}/Cargo.lock" ]] && cat "${snp_dir}/Cargo.lock"
      twod_hsm_cat_tree "${snp_dir}/src" -name '*.rs'
      # Script-dir markdown docs are intentionally excluded: they do not affect Nix build outputs.
      twod_hsm_cat_tree "${script_dir}" \( -name '*.sh' -o -name '*.py' \)
    } | sha256sum | awk '{print $1}'
  )
  printf '%s' "$_TWOD_HSM_NIX_BUILD_STAMP"
}

# Resolve NixOS `run-*-vm` runner under a vm out-link.
twod_hsm_find_vm_runner() {
  local vm_link=$1
  local candidate runner=""
  for candidate in "$vm_link"/bin/run-*-vm "$vm_link"/bin/*run*nixos*; do
    if [[ -e "$candidate" ]]; then
      runner=$(readlink -f "$candidate")
      break
    fi
  done
  if [[ -z "$runner" || ! -x "$runner" ]]; then
    echo "twod_hsm_find_vm_runner: no run-nixos-vm under ${vm_link}/bin" >&2
    ls -la "$vm_link/bin" >&2 || true
    return 1
  fi
  printf '%s' "$runner"
}

# Resolve the bootable qcow2 emitted by make-disk-image under a disk out-link.
twod_hsm_nix_disk_qcow2() {
  local disk_link=$1 candidate
  for candidate in "$disk_link"/*.qcow2; do
    if [[ -f "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  echo "twod_hsm_nix_disk_qcow2: no *.qcow2 under ${disk_link}" >&2
  ls -la "$disk_link" >&2 || true
  return 1
}

# Usage: link=$(twod_hsm_nix_ensure "$flake_dir" attr cache-name)
twod_hsm_nix_ensure() {
  local flake_dir=$1 attr=$2 name=$3
  twod_hsm_ensure_cache_dirs
  twod_hsm_nix_init
  if ! command -v nix >/dev/null; then
    echo "twod_hsm_nix_ensure: nix not found" >&2
    return 1
  fi
  local link stamp want
  link="$(twod_hsm_cache_nix)/${name}"
  stamp="${link}.build-stamp"
  if twod_hsm_nix_outlink_hit "$link" "$attr"; then
    if [[ -f "$stamp" ]]; then
      want="$(twod_hsm_nix_build_stamp "$flake_dir")"
      if [[ "$(cat "$stamp")" == "$want" ]]; then
        echo "nix cache hit: .#${attr} -> ${link}" >&2
        printf '%s' "$link"
        return 0
      fi
    else
      want="$(twod_hsm_nix_build_stamp "$flake_dir")"
      printf '%s' "$want" >"$stamp"
      echo "nix cache hit: .#${attr} -> ${link}" >&2
      printf '%s' "$link"
      return 0
    fi
  fi
  want="$(twod_hsm_nix_build_stamp "$flake_dir")"
  if twod_hsm_nix_outlink_hit "$link" "$attr" \
    && [[ -f "$stamp" && "$(cat "$stamp")" == "$want" ]]; then
    echo "nix cache hit: .#${attr} -> ${link}" >&2
  else
    echo "nix build: .#${attr} -> ${link}" >&2
    if ! (cd "$flake_dir" && nix build ".#${attr}" --out-link "$link"); then
      echo "twod_hsm_nix_ensure: nix build .#${attr} failed" >&2
      return 1
    fi
    printf '%s' "$want" >"$stamp"
  fi
  printf '%s' "$link"
}

twod_hsm_nix_vm_disk() {
  local attr=${1:-vm}
  case "$attr" in
    vm) printf '%s/vm-hsm-smoke.qcow2' "$(twod_hsm_cache_images)" ;;
    vm-production) printf '%s/vm-hsm-smoke-prod.qcow2' "$(twod_hsm_cache_images)" ;;
    vm-production-lab) printf '%s/vm-hsm-smoke-prod-lab.qcow2' "$(twod_hsm_cache_images)" ;;
    *) printf '%s/vm-hsm-smoke-%s.qcow2' "$(twod_hsm_cache_images)" "$attr" ;;
  esac
}

twod_hsm_nix_vm_link() {
  local attr=${1:-vm}
  printf '%s/vm-hsm-runner-%s' "$(twod_hsm_cache_nix)" "$attr"
}

# Ubuntu SNP cloud guest needs a host-glibc binary (not Nix-store interpreter).
twod_hsm_snp_hsm_bin() {
  local repo_root=$1
  if [[ -n "${SNP_HSM_BIN:-}" && -x "${SNP_HSM_BIN}" ]]; then
    printf '%s' "$SNP_HSM_BIN"
    return 0
  fi
  local cargo_bin
  cargo_bin="${repo_root}/impl/rust/enclave-protocol/target/debug/enclave-vsock-staging"
  if [[ -x "$cargo_bin" ]]; then
    printf '%s' "$cargo_bin"
    return 0
  fi
  if command -v cargo >/dev/null; then
    echo "building enclave-vsock-staging for SNP guest (cargo)..." >&2
    (cd "${repo_root}/impl/rust/enclave-protocol" \
      && cargo build --bin enclave-vsock-staging --features staging-vsock) >&2
    [[ -x "$cargo_bin" ]] && printf '%s' "$cargo_bin" && return 0
  fi
  echo "twod_hsm_snp_hsm_bin: need cargo-built enclave-vsock-staging on Ubuntu guest" >&2
  return 1
}

twod_hsm_default_hsm_bin() {
  local repo_root=$1
  if [[ -n "${HSM_BIN:-}" && -x "${HSM_BIN}" ]]; then
    printf '%s' "$HSM_BIN"
    return 0
  fi
  twod_hsm_nix_init
  local flake_dir link
  flake_dir="${repo_root}/impl/nix/vm-hsm"
  if [[ -d "$flake_dir" ]] && command -v nix >/dev/null; then
    link="$(twod_hsm_nix_ensure "$flake_dir" enclave-staging enclave-staging)"
    if [[ -x "${link}/bin/enclave-vsock-staging" ]]; then
      printf '%s' "${link}/bin/enclave-vsock-staging"
      return 0
    fi
  fi
  printf '%s' "${repo_root}/impl/rust/enclave-protocol/target/debug/enclave-vsock-staging"
}

twod_hsm_snp_ubuntu_image() {
  printf '%s/ubuntu-24.04-cloudimg.qcow2' "$(twod_hsm_cache_images)"
}

twod_hsm_snp_base_disk() {
  printf '%s/vm-disk-snp-base.qcow2' "$(twod_hsm_cache_images)"
}

twod_hsm_snp_golden_disk() {
  printf '%s/vm-disk-snp-ready.qcow2' "$(twod_hsm_cache_images)"
}

twod_hsm_snp_cloudinit_iso() {
  printf '%s/cloud-init-snp.iso' "$(twod_hsm_cache_images)"
}

twod_hsm_snp_ovmf_path() {
  if [[ -n "${SNP_BIOS:-}" && -f "${SNP_BIOS}" ]]; then
    printf '%s' "$SNP_BIOS"
    return 0
  fi
  local cached
  cached="$(twod_hsm_cache_firmware)/OVMF.fd"
  if [[ -f "$cached" ]]; then
    printf '%s' "$cached"
    return 0
  fi
  if [[ -f /opt/amde-ovmf/OVMF.fd ]]; then
    printf '%s' /opt/amde-ovmf/OVMF.fd
    return 0
  fi
  if [[ -f /opt/amde-ovmf/share/qemu/OVMF.fd ]]; then
    printf '%s' /opt/amde-ovmf/share/qemu/OVMF.fd
    return 0
  fi
  local fallback=/usr/share/ovmf/OVMF.amdsev.fd
  if [[ -f "$fallback" ]]; then
    printf '%s' "$fallback"
    return 0
  fi
  echo "twod_hsm_snp_ovmf_path: no SEV-SNP OVMF found (set SNP_BIOS or run prepare-snp-host.sh)" >&2
  return 1
}

twod_hsm_link_firmware_cache() {
  local src
  src="$(twod_hsm_snp_ovmf_path)"
  twod_hsm_ensure_cache_dirs
  if [[ -f "$src" && "$src" != "$(twod_hsm_cache_firmware)/OVMF.fd" ]]; then
    ln -sf "$src" "$(twod_hsm_cache_firmware)/OVMF.fd"
    echo "firmware cache: $(twod_hsm_cache_firmware)/OVMF.fd -> $src" >&2
  fi
}

# Resolve the SNP-capable QEMU + AMD OVMF and export QEMU_BIN + SNP_BIOS. Fails if QEMU lacks
# sev-snp-guest or no OVMF is found. Shared by the SNP launcher scripts (run-nix-snp-*).
twod_hsm_resolve_snp_qemu() {
  local qemu
  if [[ -x /opt/qemu-snp/bin/qemu-system-x86_64 ]]; then
    qemu="${QEMU_BIN:-/opt/qemu-snp/bin/qemu-system-x86_64}"
  else
    qemu="${QEMU_BIN:-qemu-system-x86_64}"
  fi
  qemu="$(command -v "$qemu" || true)"
  if [[ -z "$qemu" ]]; then
    echo "qemu-system-x86_64 not found (set QEMU_BIN or run ./install-qemu-snp.sh)" >&2
    return 1
  fi
  if ! "$qemu" -object help 2>&1 | grep -q sev-snp-guest; then
    echo "QEMU lacks sev-snp-guest (run ./install-qemu-snp.sh)" >&2
    return 1
  fi
  QEMU_BIN="$qemu"
  SNP_BIOS="$(twod_hsm_snp_ovmf_path)" || return 1
  export QEMU_BIN SNP_BIOS
}

# Create a writable work disk DST backed by the read-only store image SRC: a thin qcow2 overlay
# (near-instant) when qemu-img is available, else a full writable copy. Shared by run-nix-snp-*.
twod_hsm_make_work_overlay() {
  local src=$1 dst=$2 qemu_img
  rm -f "$dst"
  qemu_img="${QEMU_IMG:-}"
  [[ -n "$qemu_img" && -x "$qemu_img" ]] || qemu_img="$(dirname "${QEMU_BIN:-}")/qemu-img"
  [[ -x "$qemu_img" ]] || qemu_img="$(command -v qemu-img || true)"
  if [[ -n "$qemu_img" && -x "$qemu_img" ]]; then
    "$qemu_img" create -q -f qcow2 -F qcow2 -b "$src" "$dst"
  else
    cp -f "$src" "$dst"
    chmod u+w "$dst"
  fi
}

twod_hsm_snp_prepare_work_disk() {
  local script_dir=$1
  local work golden
  work="${script_dir}/vm-disk.qcow2"
  golden="$(twod_hsm_snp_golden_disk)"
  if [[ -f "$golden" ]]; then
    echo "snp disk cache hit (golden): $golden" >&2
    cp -f "$golden" "$work"
    return 0
  fi
  local base
  base="$(twod_hsm_snp_base_disk)"
  if [[ -f "$base" ]]; then
    echo "snp disk: using base overlay $base" >&2
    cp -f "$base" "$work"
    return 0
  fi
  if [[ -f "$work" ]]; then
    return 0
  fi
  return 1
}

twod_hsm_ssh_opts() {
  printf '%s' '-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null'
}

# Wait for guest SSH (and optionally /var/log/hsm-guest-ready).
# Optional 5th arg: host QEMU PID — abort if that process exits before SSH is up.
twod_hsm_wait_guest_ssh() {
  local port=${1:-2222} max_sec=${2:-120} log=${3:-} require_ready=${4:-0} qemu_pid=${5:-}
  local deadline=$((SECONDS + max_sec))
  local ssh_common
  ssh_common="$(twod_hsm_ssh_opts)"
  while (( SECONDS < deadline )); do
    if [[ -n "$qemu_pid" ]] && ! kill -0 "$qemu_pid" 2>/dev/null; then
      echo "twod_hsm_wait_guest_ssh: QEMU pid ${qemu_pid} exited before SSH ready" >&2
      [[ -n "$log" ]] && tail -30 "$log" >&2 || true
      return 1
    fi
    if [[ -n "$log" ]] && grep -qE "does not accept value|failed to initialize|Error while loading" "$log" 2>/dev/null; then
      tail -20 "$log" >&2 || true
      return 1
    fi
    if ssh $ssh_common -o ConnectTimeout=2 -p "$port" ubuntu@127.0.0.1 true 2>/dev/null; then
      if [[ "$require_ready" == "1" ]]; then
        if ssh $ssh_common -o ConnectTimeout=2 -p "$port" ubuntu@127.0.0.1 \
          test -f /var/log/hsm-guest-ready 2>/dev/null; then
          return 0
        fi
      else
        return 0
      fi
    fi
    sleep 3
  done
  [[ -n "$log" ]] && tail -30 "$log" >&2 || true
  return 1
}

twod_hsm_ensure_python_cbor2() {
  python3 -c "import cbor2" 2>/dev/null && return 0
  echo "installing python3-cbor2 for vsock smoke..." >&2
  if apt-get install -y -qq python3-cbor2 2>/dev/null; then
    return 0
  fi
  pip3 install -q cbor2
}

twod_hsm_snp_ssh_ready_timeout() {
  if [[ -f "$(twod_hsm_snp_golden_disk)" ]]; then
    printf '%s' "${SNP_SSH_READY_TIMEOUT:-90}"
  else
    printf '%s' "${SNP_SSH_READY_TIMEOUT:-600}"
  fi
}

# SNP/ubuntu smokes share guest-cid=42; stop only our guest-cid QEMU (not guest-cid=420, etc.).
twod_hsm_stop_stale_qemu() {
  local cid="${GUEST_CID:-42}"
  local pattern="guest-cid=${cid}([^0-9]|$)"
  if pgrep -f "$pattern" >/dev/null 2>&1; then
    echo "stopping leftover qemu (guest-cid=${cid})" >&2
    pkill -f "$pattern" 2>/dev/null || true
    sleep 2
  fi
}

# Avoid broad pkill patterns that can disrupt the parent ssh session on some hosts.
twod_hsm_kill_all_qemu() {
  pkill -f qemu-system-x86_64 2>/dev/null || true
  sleep 2
}
