#!/usr/bin/env bash
# Ubuntu exploit dev VM updater

set -u
set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}${BOLD}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}${BOLD}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[!]${RESET} $*"; }
error()   { echo -e "${RED}${BOLD}[-]${RESET} $*"; }
section() { echo -e "\n${PURPLE}${BOLD}==> $*${RESET}\n"; }

have() { command -v "$1" >/dev/null 2>&1; }

FAILS=()
FAIL() { FAILS+=("$1"); error "$1"; }

run() {
  local label="$1"; shift
  info "$label"
  if "$@"; then ok "$label"; else FAIL "$label"; return 1; fi
}

run_soft() {
  local label="$1"; shift
  info "$label"
  if "$@"; then ok "$label"; else warn "$label (non-fatal)"; FAILS+=("$label (non-fatal)"); return 1; fi
}

ensure_local_bin_path() {
  mkdir -p "$HOME/.local/bin"
  export PATH="$HOME/.local/bin:$PATH"
  if ! grep -qsE '(^|\s)export PATH="\$HOME/\.local/bin:\$PATH"' "$HOME/.bashrc" 2>/dev/null; then
    printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.bashrc"
  fi
  export PATH="$HOME/.local/bin:$PATH"
}

# ----- sudo keep-alive -----
SUDO_KEEPALIVE_PID=""
start_sudo_keepalive() {
  if ! have sudo; then FAIL "sudo missing"; return 1; fi
  if ! sudo -n true 2>/dev/null; then
    sudo -v || return 1
  fi
  ( while true; do sudo -n true || exit 0; sleep 60; done ) &
  SUDO_KEEPALIVE_PID="$!"
}
stop_sudo_keepalive() {
  if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    SUDO_KEEPALIVE_PID=""
  fi
}

# ----- package frontend -----
PKG="apt-get"
pick_pkg_frontend() { have nala && PKG="nala" || PKG="apt-get"; }

pkg_update() {
  if [[ "$PKG" == "nala" ]]; then
    sudo nala update -y -q || return 1
  else
    sudo apt-get -qq update || return 1
  fi
}

pkg_upgrade() {
  if [[ "$PKG" == "nala" ]]; then
    sudo DEBIAN_FRONTEND=noninteractive nala upgrade -y -q || return 1
  else
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y -qq upgrade || return 1
  fi
}

pkg_install_batch_soft() {
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" || true
}

pkg_fix_soft() {
  sudo DEBIAN_FRONTEND=noninteractive apt-get -y -qq -f install || true
}

pkg_autoremove_soft() {
  if [[ "$PKG" == "nala" ]]; then
    sudo DEBIAN_FRONTEND=noninteractive nala autoremove -y -q || true
  else
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y -qq autoremove || true
  fi
}

pkg_clean_soft() {
  sudo apt-get clean >/dev/null 2>&1 || true
}

# ----- background tasks + logs -----
declare -a PIDS=()
declare -A PIDLOG=()
LOGDIR=""

make_logdir() {
  [[ -n "${LOGDIR:-}" ]] && return 0
  LOGDIR="$(mktemp -d -t upd-logs.XXXXXX)"
}

bg_task() {
  local label="$1"; shift
  make_logdir
  local lf="$LOGDIR/$(echo "$label" | tr ' /:' '___').log"
  info "$label"
  ( "$@" >"$lf" 2>&1 ) &
  local pid="$!"
  PIDS+=("$pid")
  PIDLOG["$pid"]="$lf"
}

wait_tasks() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    if ! wait "$pid"; then
      local lf="${PIDLOG[$pid]:-}"
      if [[ -n "${lf:-}" && -f "${lf:-}" ]]; then
        warn "Background task failed (pid=$pid). Last output:"
        tail -n 40 "$lf" 2>/dev/null | sed 's/^/  /' || true
      fi
      FAIL "Background task failed (pid=$pid)"
    fi
  done
  PIDS=()
  PIDLOG=()
}

kill_bg_tasks() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}

# ----- downloads -----
download_resume() {
  local url="$1"
  local out="$2"
  mkdir -p "$(dirname "$out")"
  if have aria2c; then
    aria2c -q -c -x 16 -s 16 -k 1M -o "$(basename "$out")" -d "$(dirname "$out")" "$url"
  else
    wget -q --continue -O "$out" "$url"
  fi
}

# ----- temp -----
TMPUP=""
cleanup_tmpup() {
  [[ -n "${TMPUP:-}" && -d "${TMPUP:-}" ]] && rm -rf "$TMPUP" 2>/dev/null || true
  TMPUP=""
  [[ -n "${LOGDIR:-}" && -d "${LOGDIR:-}" ]] && rm -rf "$LOGDIR" 2>/dev/null || true
  LOGDIR=""
}

# ----- summary -----
summary() {
  section "Summary"
  if [[ "${#FAILS[@]}" -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}Issues detected:${RESET}"
    for f in "${FAILS[@]}"; do echo -e "  ${YELLOW}-${RESET} $f"; done
  else
    echo -e "${GREEN}${BOLD}No errors detected.${RESET}"
  fi
}

on_interrupt() {
  warn "Interrupted. Stopping background tasks..."
  kill_bg_tasks
  stop_sudo_keepalive
  cleanup_tmpup
  summary
  exit 130
}

on_exit() {
  kill_bg_tasks
  cleanup_tmpup
  stop_sudo_keepalive
  summary
}
trap on_exit EXIT
trap on_interrupt INT TERM

# ----- pre-flight -----
section "Pre-flight"
ensure_local_bin_path

if ! have curl; then
  error "curl missing"; exit 1
fi

info "Checking network reachability..."
if ! curl -fsS --max-time 8 https://github.com >/dev/null 2>&1; then
  error "No internet / cannot reach github.com"
  exit 1
fi
ok "Network OK"

run "sudo keep-alive" start_sudo_keepalive

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || warn "Target is Ubuntu. Detected: ${PRETTY_NAME:-unknown}"
else
  FAIL "Missing /etc/os-release"
fi

# ----- bootstrap helpers -----
section "Bootstrap helpers"
pick_pkg_frontend
run_soft "apt fix broken" pkg_fix_soft
run_soft "install jq + aria2 + nala" pkg_install_batch_soft jq aria2 nala
pick_pkg_frontend
ensure_local_bin_path

# ----- system update -----
section "System update"
bg_task "apt update (bg)" pkg_update
run_soft "wait apt update" wait_tasks
run_soft "upgrade" pkg_upgrade
run_soft "fix deps" pkg_fix_soft

# ----- pipx upgrades -----
section "pipx upgrades"
if have pipx; then
  run_soft "pipx ensurepath" pipx ensurepath
  ensure_local_bin_path
  run_soft "pipx upgrade-all" pipx upgrade-all
else
  warn "pipx not found, skipping"
fi

# ----- git updates -----
section "Git updates"
if [[ -d "$HOME/tools/pwndbg/.git" ]]; then
  OLD_HEAD="$(git -C "$HOME/tools/pwndbg" rev-parse HEAD 2>/dev/null || true)"
  run_soft "pwndbg fetch+pull" bash -c "cd '$HOME/tools/pwndbg' && git fetch --prune && git pull --ff-only"
  NEW_HEAD="$(git -C "$HOME/tools/pwndbg" rev-parse HEAD 2>/dev/null || true)"
  if [[ -n "$OLD_HEAD" && -n "$NEW_HEAD" && "$OLD_HEAD" != "$NEW_HEAD" ]]; then
    run_soft "pwndbg setup" bash -c "cd '$HOME/tools/pwndbg' && ./setup.sh"
  else
    ok "pwndbg unchanged (skipping setup)"
  fi
else
  warn "pwndbg repo not found at ~/tools/pwndbg"
fi

# ----- gdb plugin refresh -----
section "GDB plugin refresh"
run_soft "update GEF" bash -c "mkdir -p '$HOME/.gdb-plugins' && curl -fsS https://gef.blah.cat/py -o '$HOME/.gdb-plugins/gef.py'"

# ----- github release updates -----
section "GitHub release updates"
TMPUP="$(mktemp -d -t upd-dl.XXXXXX)"

if ! have jq; then
  FAIL "jq missing (cannot parse GitHub API reliably)"
else
  bg_task "resolve Ghidra release (bg)" bash -c "
    curl -fsS https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
    | jq -r '{tag: .tag_name, url: (.assets[] | select(.browser_download_url|endswith(\".zip\")) | .browser_download_url)} | @tsv' \
    | head -n 1 > '$TMPUP/ghidra.tsv'
  "

  bg_task "resolve Pulsar release (bg)" bash -c "
    curl -fsS https://api.github.com/repos/pulsar-edit/pulsar/releases/latest \
    | jq -r '{tag: .tag_name, url: (.assets[] | select(.browser_download_url|test(\"(amd64|x64).*\\\\.deb$\")) | .browser_download_url)} | @tsv' \
    | head -n 1 > '$TMPUP/pulsar.tsv'
  "

  run_soft "wait url resolves" wait_tasks

  G_TAG=""
  G_URL=""
  if [[ -s "$TMPUP/ghidra.tsv" ]]; then
    G_TAG="$(cut -f1 "$TMPUP/ghidra.tsv" 2>/dev/null || true)"
    G_URL="$(cut -f2 "$TMPUP/ghidra.tsv" 2>/dev/null || true)"
  fi

  P_TAG=""
  P_URL=""
  if [[ -s "$TMPUP/pulsar.tsv" ]]; then
    P_TAG="$(cut -f1 "$TMPUP/pulsar.tsv" 2>/dev/null || true)"
    P_URL="$(cut -f2 "$TMPUP/pulsar.tsv" 2>/dev/null || true)"
  fi

  section "Ghidra"
  if [[ -n "$G_TAG" && -n "$G_URL" ]]; then
    mkdir -p "$HOME/tools"
    G_DIR="$HOME/tools/ghidra_${G_TAG}"
    if [[ -d "$G_DIR" ]]; then
      ok "Ghidra already present: ${G_TAG}"
      run_soft "ensure ghidra symlink" ln -snf "$G_DIR" "$HOME/tools/ghidra"
    else
      run_soft "download ghidra" download_resume "$G_URL" "$TMPUP/ghidra.zip"
      run_soft "extract ghidra" bash -c "unzip -q -o '$TMPUP/ghidra.zip' -d '$HOME/tools'"
      run_soft "update ghidra symlink" bash -c '
        set -euo pipefail
        latest="$(find "$HOME/tools" -maxdepth 1 -type d -name "ghidra_*" -printf "%f\n" | sort -V | tail -n 1 || true)"
        [[ -n "$latest" ]]
        ln -snf "$HOME/tools/$latest" "$HOME/tools/ghidra"
      '
    fi
  else
    FAIL "Resolve Ghidra latest release (API/rate-limit?)"
  fi

  section "Pulsar"
  if [[ -n "$P_TAG" && -n "$P_URL" ]]; then
    NEED_PULSAR=1
    if have pulsar; then
      if pulsar --version 2>/dev/null | grep -q "$P_TAG"; then
        NEED_PULSAR=0
        ok "Pulsar already up to date: ${P_TAG}"
      fi
    fi

    if [[ "$NEED_PULSAR" -eq 1 ]]; then
      run_soft "download pulsar" download_resume "$P_URL" "$TMPUP/pulsar.deb"
      if [[ -s "$TMPUP/pulsar.deb" ]]; then
        run_soft "dpkg pulsar" bash -c "sudo dpkg -i '$TMPUP/pulsar.deb' >/dev/null 2>&1 || true"
        run_soft "fix deps" pkg_fix_soft
      else
        FAIL "Pulsar download missing"
      fi
    fi
  else
    FAIL "Resolve Pulsar latest release (API/rate-limit?)"
  fi
fi

# ----- app refresh -----
section "App refresh"
if have ghostty; then
  run_soft "ghostty installer" bash -c \
    "/bin/bash -c \"\$(curl -fsS https://raw.githubusercontent.com/mkasberg/ghostty-ubuntu/HEAD/install.sh)\""
else
  warn "Ghostty not detected, skipping"
fi

# ----- self-tests -----
section "Self-tests"
run_soft "pwntools import" bash -c "python3 -c \"from pwn import *; print('Pwntools OK')\" >/dev/null"
run_soft "ropper version"  bash -c "command -v ropper >/dev/null 2>&1 && (ropper --version >/dev/null 2>&1 || ropper -v >/dev/null 2>&1)"
run_soft "ROPGadget"       bash -c "command -v ROPgadget >/dev/null 2>&1 && (ROPGadget --version >/dev/null 2>&1 || ROPgadget --help >/dev/null 2>&1)"
run_soft "checksec"        bash -c "command -v checksec >/dev/null 2>&1 && (checksec --version >/dev/null 2>&1 || checksec --help >/dev/null 2>&1)"
run_soft "ghidra symlink"  bash -c "test -L '$HOME/tools/ghidra' && test -x '$HOME/tools/ghidra/ghidraRun'"

# ----- cleanup -----
section "Cleanup"
run_soft "autoremove" pkg_autoremove_soft
run_soft "clean" pkg_clean_soft

# ----- reboot -----
section "Reboot"
read -r -p "Reboot now? [y/N] " _ans
case "${_ans:-}" in
  y|Y|yes|YES)
    info "Rebooting..."
    sudo reboot
    ;;
  *)
    info "Skipping reboot."
    ;;
esac
