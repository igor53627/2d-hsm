#!/usr/bin/env bash
# Log this machine into FlakeHub for Determinate Nix (native Linux builder on macOS).
set -euo pipefail

if ! command -v determinate-nixd >/dev/null; then
  if [ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
    # shellcheck source=/dev/null
    . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
  else
    echo "Nix/determinate-nixd not found. Open a new shell after installing Nix." >&2
    exit 1
  fi
fi

TOKEN_FILE="${1:-}"

if [ -z "$TOKEN_FILE" ]; then
  echo "FlakeHub login for Determinate Nix"
  echo ""
  echo "1. Sign in / create token:"
  echo "   https://flakehub.com/user/settings?editview=tokens"
  if command -v open >/dev/null; then
    open "https://flakehub.com/user/settings?editview=tokens" 2>/dev/null || true
  fi
  echo ""
  echo "2. Paste the token below (input hidden):"
  TOKEN_FILE="$(mktemp)"
  trap 'rm -f "$TOKEN_FILE"' EXIT
  read -r -s -p "FlakeHub token: " token
  echo
  printf '%s' "$token" >"$TOKEN_FILE"
fi

if [ ! -s "$TOKEN_FILE" ]; then
  echo "Empty token file: $TOKEN_FILE" >&2
  exit 1
fi

chmod 600 "$TOKEN_FILE"
determinate-nixd auth login token --token-file "$TOKEN_FILE"
rm -f "$TOKEN_FILE"
trap - EXIT

echo ""
determinate-nixd status
echo ""
echo "Try a Linux build:"
echo "  cd impl/nix/vm-hsm && nix build .#packages.x86_64-linux.enclave-staging"