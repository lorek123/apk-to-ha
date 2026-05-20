#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# F-0 — Tool setup automation.
#
# Modes:
#   ./scripts/setup.sh             # full install
#   ./scripts/setup.sh --check     # verify-only
#   ./scripts/setup.sh --devcontainer  # invoked by devcontainer postCreate
#   ./scripts/setup.sh smoke       # end-to-end smoke test against demo fixture

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REQUIRED_PYTHON="3.14"
readonly REQUIRED_JAVA="21"
readonly REQUIRED_NODE="22"
readonly JADX_VERSION="1.5.5"

# ────────────────────────────────────────────────────────────────
# Logging
# ────────────────────────────────────────────────────────────────
log()   { printf "\033[1;34m[setup]\033[0m %s\n" "$*"; }
warn()  { printf "\033[1;33m[warn]\033[0m  %s\n" "$*"; }
err()   { printf "\033[1;31m[err]\033[0m   %s\n" "$*" >&2; }
ok()    { printf "\033[1;32m[ok]\033[0m    %s\n" "$*"; }

# ────────────────────────────────────────────────────────────────
# OS detection
# ────────────────────────────────────────────────────────────────
detect_os() {
  case "$(uname -s)" in
    Linux*)
      if   command -v apt-get >/dev/null; then echo "ubuntu";
      elif command -v dnf     >/dev/null; then echo "fedora";
      elif command -v pacman  >/dev/null; then echo "arch";
      else echo "linux-other"; fi
      ;;
    Darwin*) echo "macos" ;;
    *)       echo "unknown" ;;
  esac
}

# ────────────────────────────────────────────────────────────────
# Dependency checks
# ────────────────────────────────────────────────────────────────
check_python() {
  if ! command -v python3 >/dev/null; then return 1; fi
  local v; v=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  [[ "$v" == "$REQUIRED_PYTHON" ]]
}

check_java() {
  command -v java >/dev/null || return 1
  local v; v=$(java -version 2>&1 | head -1 | grep -oE '"[0-9]+' | tr -d '"')
  (( v >= REQUIRED_JAVA ))
}

check_node() {
  command -v node >/dev/null || return 1
  local v; v=$(node --version | grep -oE '[0-9]+' | head -1)
  (( v >= REQUIRED_NODE ))
}

check_docker() { command -v docker >/dev/null && docker info >/dev/null 2>&1; }
check_uv()     { command -v uv >/dev/null; }
check_jadx()   { command -v jadx >/dev/null; }
check_gh()     { command -v gh >/dev/null; }

run_checks() {
  local failed=0
  log "Checking required tools..."

  check_python    && ok "Python $REQUIRED_PYTHON"        || { err "Python $REQUIRED_PYTHON missing";        ((failed++)); }
  check_java      && ok "Java $REQUIRED_JAVA+"           || { err "Java $REQUIRED_JAVA+ missing";           ((failed++)); }
  check_node      && ok "Node $REQUIRED_NODE+"           || { err "Node $REQUIRED_NODE+ missing";           ((failed++)); }
  check_docker    && ok "Docker (running)"               || { err "Docker missing or not running";          ((failed++)); }
  check_uv        && ok "uv"                             || { warn "uv missing (will install)"; }
  check_jadx      && ok "JADX"                           || { warn "JADX missing (will install)"; }
  check_gh        && ok "gh CLI"                         || { warn "gh CLI missing (recommended for publishing)"; }

  return $failed
}

# ────────────────────────────────────────────────────────────────
# Installers
# ────────────────────────────────────────────────────────────────
install_uv() {
  if check_uv; then return; fi
  log "Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
}

install_jadx() {
  if check_jadx; then return; fi
  log "Installing JADX $JADX_VERSION from GitHub releases..."
  local install_dir="$HOME/.local/jadx"
  local bin_dir="$HOME/.local/bin"
  local dl="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
  mkdir -p "$install_dir" "$bin_dir"
  curl -fL "$dl" -o /tmp/jadx.zip || { err "Failed to download JADX from $dl"; exit 1; }
  unzip -q -o /tmp/jadx.zip -d "$install_dir"
  rm /tmp/jadx.zip
  chmod +x "$install_dir/bin/jadx" "$install_dir/bin/jadx-gui"
  ln -sf "$install_dir/bin/jadx"     "$bin_dir/jadx"
  ln -sf "$install_dir/bin/jadx-gui" "$bin_dir/jadx-gui"
  ok "JADX $JADX_VERSION installed → $install_dir (symlinked into $bin_dir)"
}

install_jadx_mcp_plugin() {
  log "Installing jadx-ai-mcp plugin..."
  jadx plugins --install "github:zinja-coder:jadx-ai-mcp" || {
    warn "Plugin install via jadx CLI failed. Manual fallback:"
    warn "  1. Download from https://github.com/zinja-coder/jadx-ai-mcp/releases"
    warn "  2. Place JAR in ~/.jadx/plugins/"
  }
}

setup_python_env() {
  log "Setting up Python environment..."
  cd "$REPO_ROOT"
  uv sync --dev 2>/dev/null || {
    warn "uv sync not yet configurable (pyproject.toml is a stub during foundation work)."
    warn "Will be enabled after F-1 lands."
  }
}

setup_mcp_servers() {
  log "Fetching jadx-mcp-server bridge..."
  local mcp_dir="$REPO_ROOT/.cache/jadx-mcp-server"
  mkdir -p "$(dirname "$mcp_dir")"
  if [[ ! -d "$mcp_dir" ]]; then
    git clone --depth 1 https://github.com/zinja-coder/jadx-mcp-server "$mcp_dir"
  fi

  if [[ ! -f "$REPO_ROOT/.claude/settings.local.json" ]]; then
    log "Copying .claude/settings.local.json from example..."
    cp "$REPO_ROOT/.claude/settings.local.json.example" "$REPO_ROOT/.claude/settings.local.json"
    warn "Edit .claude/settings.local.json to point absolute paths at your filesystem."
  fi
}

clone_ha_core() {
  local ha_version
  ha_version=$(grep -E '^ha_core_version' "$REPO_ROOT/config/ha_target.toml" | head -1 | cut -d'"' -f2)
  local ha_core_dir="$REPO_ROOT/.cache/ha-core"
  if [[ -d "$ha_core_dir" ]]; then
    local current
    current=$(git -C "$ha_core_dir" describe --tags 2>/dev/null || echo "unknown")
    if [[ "$current" == "$ha_version" ]]; then
      ok "HA Core $ha_version already cloned"
      return
    fi
    log "Updating HA Core clone to $ha_version..."
    rm -rf "$ha_core_dir"
  fi
  log "Cloning HA Core $ha_version (shallow) for hassfest..."
  git clone --depth 1 --branch "$ha_version" \
    https://github.com/home-assistant/core "$ha_core_dir" || {
      warn "HA Core clone failed. hassfest will fall back to Docker."
      return
    }
  ok "HA Core $ha_version cloned → $ha_core_dir"
}

pull_docker_images() {
  log "Pre-pulling Docker images for V-3..."
  local ha_image_tag
  ha_image_tag=$(grep -E '^ha_image_tag' "$REPO_ROOT/config/ha_target.toml" | head -1 | cut -d'"' -f2)
  docker pull "homeassistant/home-assistant:${ha_image_tag}" || warn "HA image pull failed (will retry on first V-3 run)."
}

# ────────────────────────────────────────────────────────────────
# Smoke test
# ────────────────────────────────────────────────────────────────
run_smoke() {
  log "Running smoke test against demo fixture..."
  warn "Smoke test is a placeholder until F-2b corpus exists."
  warn "Once F-2b lands, this will: pull a demo APK, run P1-1..P5, validate via V-tier, verify HACS load."
  return 0
}

# ────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────
main() {
  local mode="${1:-install}"

  case "$mode" in
    --check)
      run_checks
      exit $?
      ;;
    smoke)
      run_smoke
      exit $?
      ;;
    --devcontainer)
      log "Running in devcontainer postCreate context."
      install_uv
      install_jadx_mcp_plugin
      setup_mcp_servers
      pull_docker_images
      ok "Devcontainer setup complete."
      exit 0
      ;;
    install|"")
      local os; os=$(detect_os)
      log "Detected OS: $os"

      if ! run_checks; then
        warn "Some tools are missing — attempting install..."
      fi

      install_uv
      check_jadx || install_jadx
      install_jadx_mcp_plugin
      setup_mcp_servers
      clone_ha_core
      pull_docker_images
      ok "Setup complete. Try: ./scripts/setup.sh smoke"
      ;;
    *)
      err "Unknown mode: $mode"
      err "Usage: $0 [--check | --devcontainer | smoke]"
      exit 1
      ;;
  esac
}

main "$@"
