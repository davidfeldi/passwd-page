#!/bin/sh
# passwd.page installer
# Usage:
#   curl -fsSL https://passwd.page/install | sh
#   curl -fsSL https://passwd.page/install | VERSION=v3.0.0 sh
#   curl -fsSL https://passwd.page/install | INSTALL_DIR=$HOME/.local/bin sh
#
# Installs: passwd-page (CLI) and passwd-mcp (MCP server) from GitHub Releases.
# Does NOT install passwd-server — self-hosters use Docker or build from source.
#
# Exits non-zero on any failure. Verifies checksums before installing.

set -eu

REPO="davidfeldi/passwd-page"
BINARIES="passwd-page passwd-mcp"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-}"

log()   { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m!\033[0m %s\n' "$*" >&2; }
fail()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- Detect OS/arch ---------------------------------------------------------

detect_os() {
  os="$(uname -s)"
  case "$os" in
    Linux)  echo linux ;;
    Darwin) echo darwin ;;
    *) fail "unsupported OS: $os (only linux and darwin are supported)" ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo amd64 ;;
    arm64|aarch64) echo arm64 ;;
    *) fail "unsupported architecture: $arch" ;;
  esac
}

# --- Resolve version --------------------------------------------------------

resolve_version() {
  if [ -n "$VERSION" ]; then
    echo "$VERSION"
    return
  fi
  # GitHub's /releases/latest returns a 302 redirect to the actual tag URL.
  # We follow with -s -o /dev/null -w '%{url_effective}'.
  url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")"
  tag="${url##*/}"
  if [ -z "$tag" ] || [ "$tag" = "latest" ]; then
    fail "could not resolve latest version (no releases yet?)"
  fi
  echo "$tag"
}

# --- Download + verify ------------------------------------------------------

download() {
  url="$1"; out="$2"
  if ! curl -fsSL "$url" -o "$out"; then
    fail "download failed: $url"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "neither sha256sum nor shasum found"
  fi
}

# --- Install location -------------------------------------------------------

install_to() {
  src="$1"; name="$2"
  dest="$INSTALL_DIR/$name"
  if [ -w "$INSTALL_DIR" ] || [ "$(id -u)" = "0" ]; then
    install -m 0755 "$src" "$dest"
  elif command -v sudo >/dev/null 2>&1; then
    log "Installing to $dest (sudo required)"
    sudo install -m 0755 "$src" "$dest"
  else
    fail "cannot write to $INSTALL_DIR and no sudo available. Try: INSTALL_DIR=\$HOME/.local/bin curl -fsSL https://passwd.page/install | sh"
  fi
}

# --- Main -------------------------------------------------------------------

main() {
  OS="$(detect_os)"
  ARCH="$(detect_arch)"
  TAG="$(resolve_version)"
  # Strip leading 'v' for goreleaser's name template which uses .Version.
  VER="${TAG#v}"

  log "passwd.page installer"
  log "  version: $TAG"
  log "  os/arch: $OS/$ARCH"
  log "  target:  $INSTALL_DIR"
  echo

  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  # Fetch checksums.txt once.
  CHECKSUMS_URL="https://github.com/$REPO/releases/download/$TAG/checksums.txt"
  log "Fetching checksums"
  download "$CHECKSUMS_URL" "$TMP/checksums.txt"

  for bin in $BINARIES; do
    archive="${bin}_${VER}_${OS}_${ARCH}.tar.gz"
    url="https://github.com/$REPO/releases/download/$TAG/$archive"

    log "Downloading $archive"
    download "$url" "$TMP/$archive"

    # Verify checksum
    expected="$(awk -v f="$archive" '$2 == f {print $1}' "$TMP/checksums.txt")"
    if [ -z "$expected" ]; then
      fail "checksum for $archive not found in checksums.txt"
    fi
    actual="$(sha256 "$TMP/$archive")"
    if [ "$expected" != "$actual" ]; then
      fail "checksum mismatch for $archive (expected $expected, got $actual)"
    fi
    log "  sha256 ok"

    # Extract
    tar -xzf "$TMP/$archive" -C "$TMP"
    if [ ! -f "$TMP/$bin" ]; then
      fail "binary $bin not found in archive"
    fi
    chmod +x "$TMP/$bin"

    # Install
    install_to "$TMP/$bin" "$bin"
    log "  installed $INSTALL_DIR/$bin"
    echo
  done

  # PATH warning if INSTALL_DIR is not on PATH
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) warn "$INSTALL_DIR is not on your PATH. Add to your shell rc:"
       warn "  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
  esac

  log "Done. Try: passwd-page version"
  log "If you prefer the name 'passwd' (may shadow /usr/bin/passwd — be careful):"
  log "  ln -s $INSTALL_DIR/passwd-page $INSTALL_DIR/passwd"
}

main
