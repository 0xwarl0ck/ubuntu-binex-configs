#!/usr/bin/env bash
# Ubuntu exploit dev VM setup

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
is_gui() { [[ -n "${DISPLAY:-}" ]] || systemctl is-active -q display-manager 2>/dev/null; }

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
}

# ----- package frontend -----
PKG=""

pick_pkg_frontend() {
  if have nala; then
    PKG="nala"
  else
    PKG="apt-get"
  fi
}

pkg_update() {
  if [[ "$PKG" == "nala" ]]; then
    sudo nala update
  else
    sudo apt-get update -y
  fi
}

pkg_upgrade_soft() {
  if [[ "$PKG" == "nala" ]]; then
    sudo DEBIAN_FRONTEND=noninteractive nala upgrade -y || true
  else
    sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || true
  fi
}

pkg_install() {
  if [[ "$PKG" == "nala" ]]; then
    sudo DEBIAN_FRONTEND=noninteractive nala install -y --no-install-recommends "$@"
  else
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
  fi
}

pkg_fix_soft() {
  sudo DEBIAN_FRONTEND=noninteractive apt-get -y -f install || true
}

# ----- sudo keep-alive -----
SUDO_KEEPALIVE_PID=""
start_sudo_keepalive() {
  if ! have sudo; then
    FAIL "sudo missing"
    return 1
  fi
  sudo -v || return 1
  ( while true; do sudo -n true || exit 0; sleep 60; done ) &
  SUDO_KEEPALIVE_PID="$!"
}

stop_sudo_keepalive() {
  if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    SUDO_KEEPALIVE_PID=""
  fi
}

# ----- background tasks + downloads -----
TMPDL=""
PIDS=()

cleanup_tmpdl() {
  [[ -n "${TMPDL:-}" && -d "${TMPDL:-}" ]] && rm -rf "$TMPDL" || true
}

bg_task() {
  local _label="$1"; shift
  info "$_label"
  ( "$@" ) &
  PIDS+=("$!")
}

wait_tasks() {
  local i
  for i in "${PIDS[@]:-}"; do
    if ! wait "$i"; then
      FAIL "Background task failed (pid=$i)"
    fi
  done
  PIDS=()
}

bg_download() {
  local url="$1"
  local out="$2"
  if have aria2c; then
    ( set -euo pipefail; aria2c -q -x 8 -s 8 -k 1M -o "$(basename "$out")" -d "$(dirname "$out")" "$url" ) &
  else
    ( set -euo pipefail; wget -qO "$out" "$url" ) &
  fi
  PIDS+=("$!")
}

# ----- summary -----
summary() {
  section "Summary"
  echo -e "${BLUE}${BOLD}GDB default:${RESET}     gdb (~/.gdbinit -> ~/.gdbinit-gef by default)"
  echo -e "${BLUE}${BOLD}GDB switch:${RESET}      gdb-switch gef|pwndbg"
  echo -e "${BLUE}${BOLD}GDB (GEF):${RESET}       gdb-gef"
  echo -e "${BLUE}${BOLD}GDB (pwndbg):${RESET}    gdb-pwndbg"
  echo -e "${BLUE}${BOLD}Ghidra:${RESET}          ~/tools/ghidra (symlink) / ~/tools/ghidra*/ghidraRun"
  echo -e "${BLUE}${BOLD}Codium:${RESET}          codium"
  echo -e "${BLUE}${BOLD}Pulsar:${RESET}          pulsar --version"
  echo -e "${BLUE}${BOLD}Ghostty:${RESET}         ghostty --version"
  echo -e "${BLUE}${BOLD}Brave:${RESET}           brave-browser --version"
  echo -e "${BLUE}${BOLD}pwntools:${RESET}        python3 -c \"from pwn import *; print('Pwntools OK')\""
  echo -e "${BLUE}${BOLD}ropper:${RESET}          ropper --version"
  echo -e "${BLUE}${BOLD}ROPgadget:${RESET}       ROPGadget --version"
  echo -e "${BLUE}${BOLD}checksec:${RESET}        checksec --version || checksec --help"

  if [[ "${#FAILS[@]}" -gt 0 ]]; then
    echo -e "\n${YELLOW}${BOLD}Issues detected:${RESET}"
    for f in "${FAILS[@]}"; do echo -e "  ${YELLOW}-${RESET} $f"; done
  else
    echo -e "\n${GREEN}${BOLD}No errors detected.${RESET}"
  fi
}

on_exit() {
  stop_sudo_keepalive
  cleanup_tmpdl
  summary
}
trap on_exit EXIT

# ----- pre-flight -----
section "Pre-flight"
if ! have curl; then
  error "curl missing (install curl first)"; exit 1
fi

info "Checking network reachability..."
if ! curl -fsS --max-time 8 https://github.com >/dev/null 2>&1; then
  error "No internet / cannot reach github.com"
  exit 1
fi
ok "Network OK"

# ----- start -----
section "ubuntu exploit dev vm setup"
ensure_local_bin_path

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || warn "Target is Ubuntu. Detected: ${PRETTY_NAME:-unknown}"
else
  FAIL "Missing /etc/os-release"
fi

run "sudo keep-alive" start_sudo_keepalive

# ----- recovery -----
section "Recovery"
run_soft "dpkg configure" sudo dpkg --configure -a
run_soft "apt fix broken" pkg_fix_soft

# ----- enable i386 + repos -----
section "Enable i386 + repos"
run_soft "enable i386" sudo dpkg --add-architecture i386

run "keyring dir" sudo install -d -m 0755 /usr/share/keyrings
run "codium key" bash -c \
  "wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg \
   | gpg --dearmor \
   | sudo tee /usr/share/keyrings/vscodium-archive-keyring.gpg >/dev/null"
run "codium repo" bash -c \
  "echo 'deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://download.vscodium.com/debs vscodium main' \
   | sudo tee /etc/apt/sources.list.d/vscodium.list >/dev/null"

# ----- update + bootstrap helpers -----
section "Update + bootstrap helpers"
TMPDL="$(mktemp -d -t setup-dl.XXXXXX)"

pick_pkg_frontend
bg_task "apt update (bg)" pkg_update
run_soft "wait apt update" wait_tasks

run_soft "install jq + aria2 + nala" bash -c \
  "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends jq aria2 nala || true"
pick_pkg_frontend

run_soft "upgrade" pkg_upgrade_soft

# ----- local state -----
section "Local state"
run_soft "wipe gdb files" bash -c \
  "rm -f '$HOME/.gdbinit' '$HOME/.gdbinit-gef' '$HOME/.gdbinit-pwndbg' \
        '$HOME/.local/bin/gdb-gef' '$HOME/.local/bin/gdb-pwndbg' '$HOME/.local/bin/gdb-switch' && \
   rm -rf '$HOME/.gdb-plugins' && mkdir -p '$HOME/.gdb-plugins' '$HOME/.local/bin'"

run_soft "prepare tools dir" bash -c "mkdir -p '$HOME/tools' '$HOME/.local/bin'"

# ----- core packages -----
section "Core packages"
run "install core" pkg_install \
  ca-certificates software-properties-common git curl wget unzip gpg \
  build-essential gcc g++ make cmake pkg-config \
  autoconf automake libtool \
  clang lldb lld llvm \
  gdb gdb-multiarch gdbserver \
  python3 python3-dev python3-pip python3-venv \
  file binutils elfutils pax-utils \
  strace ltrace \
  patchelf chrpath \
  nasm yasm \
  socat netcat-traditional rlwrap \
  qemu-user qemu-user-static \
  radare2 \
  ruby ruby-dev \
  libc6-dbg libssl-dev libffi-dev \
  gcc-multilib g++-multilib libc6-dev-i386 lib32z1 lib32stdc++6 \
  open-vm-tools \
  remmina tmux fzf eza bat btop \
  pipx \
  codium \
  jq aria2

section "Optional i386 dbg"
run_soft "libc6-dbg:i386" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libc6-dbg:i386

# ----- pwntools -----
section "pwntools"
run_soft "python3-pwntools" pkg_install python3-pwntools
run_soft "pwntools functional" bash -c "python3 -c \"from pwn import *; print('Pwntools OK')\" >/dev/null"

# ----- pipx tools -----
section "pipx tools"
run_soft "pipx ensurepath" pipx ensurepath
ensure_local_bin_path
run_soft "pipx ropper"    pipx install --force ropper
run_soft "pipx ROPGadget" pipx install --force ROPGadget
run_soft "pipx checksec"  pipx install --force checksec
run_soft "hash -r" bash -c "hash -r"

# ----- ghostty -----
section "Ghostty"
run_soft "ghostty installer" bash -c \
  "/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/mkasberg/ghostty-ubuntu/HEAD/install.sh)\""

# ----- gnome default terminal -----
section "GNOME default terminal"
if have ghostty && have gsettings; then
  run_soft "Set GNOME terminal exec=ghostty" bash -c \
    "gsettings set org.gnome.desktop.default-applications.terminal exec 'ghostty'"
  run_soft "Set GNOME terminal exec-arg=''" bash -c \
    "gsettings set org.gnome.desktop.default-applications.terminal exec-arg ''"

  if [[ -x /usr/bin/ghostty ]] && have update-alternatives; then
    run_soft "Register ghostty as x-terminal-emulator" bash -c \
      "sudo update-alternatives --install /usr/bin/x-terminal-emulator x-terminal-emulator /usr/bin/ghostty 60"
    run_soft "Set ghostty as x-terminal-emulator" bash -c \
      "sudo update-alternatives --set x-terminal-emulator /usr/bin/ghostty"
  fi
else
  warn "Skipping GNOME default terminal (ghostty or gsettings missing)"
fi

# ----- brave -----
section "Brave"
run_soft "brave installer" bash -c '
  curl -fsS https://dl.brave.com/install.sh -o /tmp/brave-install.sh
  bash /tmp/brave-install.sh
  rm -f /tmp/brave-install.sh
'

# ----- ghidra + pulsar downloads -----
section "Parallel downloads (Ghidra + Pulsar)"
run_soft "resolve Ghidra URL" bash -c \
  "curl -fsS https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
   | jq -r '.assets[] | select(.browser_download_url|endswith(\".zip\")) | .browser_download_url' \
   | head -n 1 > '$TMPDL/ghidra_url'"

run_soft "resolve Pulsar URL" bash -c \
  "curl -fsS https://api.github.com/repos/pulsar-edit/pulsar/releases/latest \
   | jq -r '.assets[] | select(.browser_download_url|test(\"(amd64|x64).*\\\\.deb$\")) | .browser_download_url' \
   | head -n 1 > '$TMPDL/pulsar_url'"

GURL="$(cat "$TMPDL/ghidra_url" 2>/dev/null || true)"
PURL="$(cat "$TMPDL/pulsar_url" 2>/dev/null || true)"

if [[ -n "$GURL" ]]; then info "Queue download: Ghidra"; bg_download "$GURL" "$TMPDL/ghidra.zip"; else FAIL "Ghidra URL resolve"; fi
if [[ -n "$PURL" ]]; then info "Queue download: Pulsar"; bg_download "$PURL" "$TMPDL/pulsar.deb"; else FAIL "Pulsar URL resolve"; fi
run_soft "wait downloads" wait_tasks

# ----- install pulsar -----
section "Install Pulsar"
if [[ -s "$TMPDL/pulsar.deb" ]]; then
  run_soft "dpkg pulsar" bash -c "sudo dpkg -i '$TMPDL/pulsar.deb' || true"
  run_soft "fix deps"    pkg_fix_soft
else
  FAIL "Pulsar download missing"
fi

# ----- install ghidra -----
section "Install Ghidra"
if [[ -s "$TMPDL/ghidra.zip" ]]; then
  run_soft "extract ghidra" bash -c "unzip -o '$TMPDL/ghidra.zip' -d '$HOME/tools' >/dev/null"
  run_soft "update ghidra symlink" bash -c '
    set -euo pipefail
    latest="$(find "$HOME/tools" -maxdepth 1 -type d -name "ghidra_*" -printf "%f\n" | sort -V | tail -n 1 || true)"
    if [[ -n "$latest" ]]; then
      ln -sfn "$HOME/tools/$latest" "$HOME/tools/ghidra"
    else
      exit 1
    fi
  '
else
  FAIL "Ghidra download missing"
fi

# ----- ruby helper -----
section "Ruby helper"
run_soft "one_gadget" sudo gem install one_gadget --no-document

# ----- gdb plugins + switch -----
section "GDB plugins + global switch"
run "GEF" bash -c "curl -fsSL https://gef.blah.cat/py -o '$HOME/.gdb-plugins/gef.py'"
run "gdbinit-gef" bash -c "printf '%s\n' 'source ~/.gdb-plugins/gef.py' > '$HOME/.gdbinit-gef'"

run "pwndbg update/clone" bash -c '
  set -euo pipefail
  mkdir -p "$HOME/tools"
  if [[ -d "$HOME/tools/pwndbg/.git" ]]; then
    cd "$HOME/tools/pwndbg"
    git fetch --prune
    git pull --ff-only || true
  else
    rm -rf "$HOME/tools/pwndbg"
    git clone https://github.com/pwndbg/pwndbg "$HOME/tools/pwndbg"
  fi
'
run_soft "pwndbg setup" bash -c "cd '$HOME/tools/pwndbg' && ./setup.sh"

if [[ -f "$HOME/tools/pwndbg/gdbinit.py" ]]; then
  run "gdbinit-pwndbg" bash -c "printf '%s\n' 'source ~/tools/pwndbg/gdbinit.py' > '$HOME/.gdbinit-pwndbg'"
else
  FAIL "pwndbg gdbinit.py not found"
fi

run "gdb-gef wrapper" bash -c "cat > '$HOME/.local/bin/gdb-gef' <<'EOF'
#!/usr/bin/env bash
exec gdb -q -x \"\$HOME/.gdbinit-gef\" \"\$@\"
EOF
chmod +x '$HOME/.local/bin/gdb-gef'"

run "gdb-pwndbg wrapper" bash -c "cat > '$HOME/.local/bin/gdb-pwndbg' <<'EOF'
#!/usr/bin/env bash
exec gdb -q -x \"\$HOME/.gdbinit-pwndbg\" \"\$@\"
EOF
chmod +x '$HOME/.local/bin/gdb-pwndbg'"

run "gdb-switch helper" bash -c "cat > '$HOME/.local/bin/gdb-switch' <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mode=\"\${1:-}\"

case \"\$mode\" in
  gef)
    ln -sfn \"\$HOME/.gdbinit-gef\" \"\$HOME/.gdbinit\"
    echo \"[+] ~/.gdbinit -> ~/.gdbinit-gef\"
    ;;
  pwndbg)
    ln -sfn \"\$HOME/.gdbinit-pwndbg\" \"\$HOME/.gdbinit\"
    echo \"[+] ~/.gdbinit -> ~/.gdbinit-pwndbg\"
    ;;
  *)
    echo \"Usage: gdb-switch gef|pwndbg\" >&2
    exit 1
    ;;
esac
EOF
chmod +x '$HOME/.local/bin/gdb-switch'"

run_soft "default gdb -> gef" bash -c "ln -sfn '$HOME/.gdbinit-gef' '$HOME/.gdbinit'"

# ----- aliases + helpers -----
section "Aliases + helpers"
run_soft "remove old alias block" bash -c \
  "sed -i '/^# aliases start$/,/^# aliases end$/d' '$HOME/.bashrc' 2>/dev/null || true"

run_soft "append bashrc" bash -c \
  "cat << 'EOF' >> '$HOME/.bashrc'

# aliases start
alias ff=\"fzf --style full --preview 'fzf-preview.sh {}' --bind 'focus:transform-header:file --brief {}'\"
alias ls='eza \$eza_params'
alias l='eza --git-ignore \$eza_params'
alias ll='eza --all --header --long \$eza_params'
alias llm='eza --all --header --long --sort=modified \$eza_params'
alias la='eza -lbhHigUmuSa'
alias lx='eza -lbhHigUmuSa@'
alias lt='eza --tree \$eza_params'
alias tree='eza --tree \$eza_params'
alias cat=\"batcat\"
alias top=\"btop\"

pwninit() {
  if [[ \$# -lt 2 ]]; then
    echo \"Usage: pwninit <host> <port>\" >&2
    return 1
  fi
  pwn template --host \"\$1\" --port \"\$2\" > exploit.py
  echo \"[+] wrote exploit.py\"
}

gdbsig() {
  if [[ \$# -lt 1 ]]; then
    echo \"Usage: gdbsig <TOKEN>\" >&2
    return 1
  fi
  local q=\"\$1\"
  local roots=(/usr/include /usr/include/x86_64-linux-gnu /usr/include/asm-generic /usr/include/linux)
  grep -RIn --fixed-strings \"\$q\" \"\${roots[@]}\" 2>/dev/null | head -n 30
}
# aliases end
EOF"

# ----- vmware tools -----
section "VMware tools"
if is_gui; then
  run_soft "open-vm-tools-desktop" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall open-vm-tools-desktop
else
  warn "No GUI detected; skipping open-vm-tools-desktop"
fi
run_soft "enable vmtoolsd" sudo systemctl enable --now vmtoolsd

# ----- self-tests -----
section "Self-tests"
run_soft "gdb-gef launches"     bash -c "$HOME/.local/bin/gdb-gef -q -ex 'quit' >/dev/null 2>&1"
run_soft "gdb-pwndbg launches"  bash -c "$HOME/.local/bin/gdb-pwndbg -q -ex 'quit' >/dev/null 2>&1"
run_soft "gdb default launches" bash -c "gdb -q -ex 'quit' >/dev/null 2>&1"
run_soft "gdb-switch pwndbg"    bash -c "gdb-switch pwndbg >/dev/null 2>&1 && gdb -q -ex 'quit' >/dev/null 2>&1"
run_soft "gdb-switch gef"       bash -c "gdb-switch gef >/dev/null 2>&1 && gdb -q -ex 'quit' >/dev/null 2>&1"
run_soft "pwntools functional"  bash -c "python3 -c \"from pwn import *; print('Pwntools OK')\" >/dev/null"
run_soft "ropper functional"    bash -c "ropper --version >/dev/null 2>&1 || ropper -v >/dev/null 2>&1"
run_soft "ROPgadget functional" bash -c "ROPGadget --version >/dev/null 2>&1 || ROPgadget --help >/dev/null 2>&1"
run_soft "checksec functional"  bash -c "checksec --version >/dev/null 2>&1 || checksec --help >/dev/null 2>&1"
run_soft "ghostty functional"   bash -c "command -v ghostty >/dev/null 2>&1 && ghostty --version >/dev/null 2>&1"
run_soft "brave functional"     bash -c "command -v brave-browser >/dev/null 2>&1 && brave-browser --version >/dev/null 2>&1"
run_soft "pulsar functional"    bash -c "command -v pulsar >/dev/null 2>&1 && pulsar --version >/dev/null 2>&1"
run_soft "ghidra symlink"       bash -c "test -L '$HOME/tools/ghidra' && test -x '$HOME/tools/ghidra/ghidraRun'"

# ----- cleanup -----
section "Cleanup"
if [[ "$PKG" == "nala" ]]; then
  run_soft "nala autoremove" sudo DEBIAN_FRONTEND=noninteractive nala autoremove -y
  run_soft "nala clean"      sudo nala clean
else
  run_soft "apt autoremove" sudo DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
  run_soft "apt clean"      sudo apt-get clean
fi
run_soft "tmp cleanup" bash -c "rm -f /tmp/brave-install.sh 2>/dev/null || true"

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
