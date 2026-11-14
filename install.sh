#!/usr/bin/env bash
# depblast installer — downloads a prebuilt binary from GitHub Releases.
# Usage:  curl -fsSL https://raw.githubusercontent.com/jae1231m-blip/depblast/main/install.sh | bash
set -euo pipefail

REPO="jae1231m-blip/depblast"
BIN_DIR="${DEPBLAST_BIN_DIR:-$HOME/.local/bin}"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)    ASSET="depblast-x86_64-linux" ;;
  Linux/aarch64)   ASSET="depblast-aarch64-linux" ;;
  Linux/arm64)     ASSET="depblast-aarch64-linux" ;;
  Darwin/arm64)    ASSET="depblast-aarch64-macos" ;;
  Darwin/x86_64)   ASSET="depblast-x86_64-macos" ;;
  *)
    echo "Unsupported platform: $(uname -s)/$(uname -m)" >&2
    echo "Build from source instead:  cargo install --git https://github.com/$REPO" >&2
    exit 1
    ;;
esac

URL="https://github.com/$REPO/releases/latest/download/$ASSET"
mkdir -p "$BIN_DIR"
echo "Downloading $URL ..."
curl -fsSL "$URL" -o "$BIN_DIR/depblast"
chmod +x "$BIN_DIR/depblast"

if ! command -v depblast >/dev/null 2>&1 && [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo
  echo "NOTE: $BIN_DIR is not on your PATH. Add this to your ~/.bashrc or ~/.zshrc:"
  echo "  export PATH=\"$BIN_DIR:\$PATH\""
fi

echo
"$BIN_DIR/depblast" --version
echo "Installed to $BIN_DIR/depblast — try: depblast --help"
