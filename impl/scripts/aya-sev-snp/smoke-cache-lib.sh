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
    *)
      return 1
      ;;
  esac
}

# One sha256 over the enclave sources per shell (warm-smoke-cache calls ensure 4×).
twod_hsm_nix_build_stamp() {
  local flake_dir=$1
  if [[ -n "${_TWOD_HSM_NIX_BUILD_STAMP:-}" ]]; then
    printf '%s' "$_TWOD_HSM_NIX_BUILD_STAMP"
    return 0
  fi
  local repo_root rust_dir
  repo_root="$(cd "${flake_dir}/../../.." && pwd)"
  rust_dir="${repo_root}/impl/rust/enclave-protocol"
  _TWOD_HSM_NIX_BUILD_STAMP=$(
    {
      cat "${flake_dir}/flake.lock" "${flake_dir}/flake.nix" 2>/dev/null
      cat "${flake_dir}/"*.nix 2>/dev/null
      [[ -f "${rust_dir}/Cargo.lock" ]] && cat "${rust_dir}/Cargo.lock"
      [[ -f "${rust_dir}/build.rs" ]] && cat "${rust_dir}/build.rs"
      if [[ -d "${rust_dir}/src" ]]; then
        find "${rust_dir}/src" -type f -name '*.rs' 2>/dev/null | LC_ALL=C sort | while read -r f; do
          cat "$f"
        done
      fi
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