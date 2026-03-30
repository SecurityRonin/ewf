#!/usr/bin/env bash
# Install ewf — CLI and MCP server for EWF (E01) forensic disk images
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/SecurityRonin/ewf/main/install.sh | bash
#
# What this does:
#   1. Downloads the latest pre-built binary for your OS/arch from GitHub Releases
#   2. Installs it to ~/.local/bin/ewf
#   3. Registers the MCP server with Claude Code (if installed)

set -euo pipefail

REPO="SecurityRonin/ewf"
BIN_NAME="ewf"
INSTALL_DIR="${HOME}/.local/bin"

# Detect OS and architecture
detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin)
      case "$arch" in
        arm64|aarch64) echo "aarch64-apple-darwin" ;;
        x86_64)        echo "x86_64-apple-darwin" ;;
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
      esac
      ;;
    Linux)
      case "$arch" in
        aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
        x86_64)        echo "x86_64-unknown-linux-musl" ;;
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
      esac
      ;;
    *)
      echo "Unsupported OS: $os (use the MSI installer on Windows)" >&2
      exit 1
      ;;
  esac
}

# Get latest release version from GitHub API
get_latest_version() {
  curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"//;s/".*//'
}

main() {
  local platform version version_num url

  echo "Detecting platform..."
  platform="$(detect_platform)"
  echo "  Platform: ${platform}"

  echo "Fetching latest release..."
  version="$(get_latest_version)"
  version_num="${version#v}"
  echo "  Version: ${version}"

  url="https://github.com/${REPO}/releases/download/${version}/${BIN_NAME}-${version_num}-${platform}.tar.gz"
  echo "  URL: ${url}"

  echo "Downloading ${BIN_NAME}..."
  mkdir -p "${INSTALL_DIR}"
  curl -sSL "$url" | tar xz -C "${INSTALL_DIR}" "${BIN_NAME}"
  chmod +x "${INSTALL_DIR}/${BIN_NAME}"
  echo "  Installed to ${INSTALL_DIR}/${BIN_NAME}"

  # Register MCP server with Claude Code if available
  if command -v claude &>/dev/null; then
    echo "Registering MCP server with Claude Code..."
    claude mcp add ewf -- "${INSTALL_DIR}/${BIN_NAME}" mcp
    echo "  Done! ewf MCP server is now available in Claude Code."
  else
    echo ""
    echo "To register the MCP server with Claude Code later:"
    echo "  claude mcp add ewf -- ${INSTALL_DIR}/${BIN_NAME} mcp"
  fi

  echo ""
  echo "To register with Claude Desktop, add to claude_desktop_config.json:"
  echo "  {\"mcpServers\": {\"ewf\": {\"command\": \"${INSTALL_DIR}/${BIN_NAME}\", \"args\": [\"mcp\"]}}}"
  echo ""
  echo "CLI usage:"
  echo "  ewf info image.E01"
  echo "  ewf verify image.E01"
  echo "  ewf read image.E01 --offset 0 --length 512"
}

main
