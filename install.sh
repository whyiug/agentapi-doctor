#!/bin/sh

# Install one exact AgentAPI Doctor release for Linux or macOS.
# The archive is not extracted until its SHA-256 matches the release manifest.

set -eu

VERSION=${AGENTAPI_DOCTOR_VERSION:-0.1.0-rc.3}
INSTALL_DIR=${AGENTAPI_DOCTOR_INSTALL_DIR:-"${HOME}/.local/bin"}
RELEASE_BASE=${AGENTAPI_DOCTOR_RELEASE_BASE:-"https://github.com/whyiug/agentapi-doctor/releases/download/v${VERSION}"}

case "$VERSION" in
  ''|*[!0-9A-Za-z.-]*)
    printf '%s\n' 'error: AGENTAPI_DOCTOR_VERSION is not a safe version' >&2
    exit 2
    ;;
esac
case "$RELEASE_BASE" in
  https://*) ;;
  *)
    printf '%s\n' 'error: release base must use HTTPS' >&2
    exit 2
    ;;
esac

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *)
    printf '%s\n' 'error: this installer supports Linux and macOS; use the Windows release ZIP on Windows' >&2
    exit 2
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *)
    printf 'error: unsupported architecture: %s\n' "$(uname -m)" >&2
    exit 2
    ;;
esac

command -v curl >/dev/null 2>&1 || {
  printf '%s\n' 'error: curl is required' >&2
  exit 2
}

ASSET="agentapi-doctor_${VERSION}_${OS}_${ARCH}.tar.gz"
umask 077
TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t agentapi-doctor)
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$TMP_DIR/$ASSET" "$RELEASE_BASE/$ASSET"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$TMP_DIR/checksums.txt" "$RELEASE_BASE/checksums.txt"

EXPECTED=$(awk -v asset="$ASSET" '
  $2 == asset && $1 ~ /^[0-9a-f]{64}$/ { count += 1; digest = $1 }
  END { if (count == 1) print digest }
' "$TMP_DIR/checksums.txt")
if [ -z "$EXPECTED" ]; then
  printf '%s\n' 'error: release checksum manifest does not contain exactly one matching archive' >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMP_DIR/$ASSET" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "$TMP_DIR/$ASSET" | awk '{print $1}')
else
  printf '%s\n' 'error: sha256sum or shasum is required' >&2
  exit 2
fi

if [ "$ACTUAL" != "$EXPECTED" ]; then
  printf '%s\n' 'error: archive checksum mismatch' >&2
  exit 1
fi

mkdir "$TMP_DIR/extract"
tar -xzf "$TMP_DIR/$ASSET" -C "$TMP_DIR/extract" doctor
if [ ! -f "$TMP_DIR/extract/doctor" ] || [ -L "$TMP_DIR/extract/doctor" ]; then
  printf '%s\n' 'error: verified archive does not contain a regular doctor binary' >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$TMP_DIR/extract/doctor" "$INSTALL_DIR/doctor"

printf 'Installed AgentAPI Doctor %s to %s/doctor\n' "$VERSION" "$INSTALL_DIR"
"$INSTALL_DIR/doctor" version
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) printf 'Add %s to PATH, then run: doctor demo\n' "$INSTALL_DIR" ;;
esac
