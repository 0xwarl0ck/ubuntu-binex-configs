# ubuntu-binex-configs
Configuration scripts and files to automate the setup of an **ubuntu binary exploitation development virtual machine**. This repository streamlines the installation of debuggers, decompilers, and library management tools that I use for binary exploitation.

This repository contains two scripts:

- `setup.sh` — full installer and configuration script. Safe to rerun incase it fails or something
- `update.sh` — lifecycle updater

> [!NOTE]  
> This is a **personal configuration** repository. It is tailored for my workflow but provided as-is for anyone building an Ubuntu-based exploit development VM.

I'm using the same tmux and ghostty configuration as my kali config repo.

---

## Toolset

### Analysis & Debugging
- **GDB Plugins:** `pwndbg` + `GEF` with global symlink management and `gdb-switch`
- **Decompiler:** Latest **Ghidra** (installed under `~/tools/` with a persistent symlink)
- **Gadget Hunting:** `ropper`, `ROPGadget`, `one_gadget` (Ruby)
- **Binary Auditing:** `checksec`, `patchelf`, `strace`, `ltrace`

### Environment & Productivity
- **Terminal:** **Ghostty** (set as GNOME default terminal) + `tmux`
- **Modern CLI:** `eza`, `bat`, `fzf`, `btop`
- **Editors:** **VSCodium** + **Pulsar**
- **Browser:** **Brave**
- **Frameworks:** system-wide `pwntools` and `i386` architecture support

---

## Installation and updates

Install straight to your home directory 

```bash
git clone https://github.com/0xwarl0ck/ubuntu-binex-configs.git
cd ubuntu-binex-configs
chmod +x setup.sh
./setup.sh
```

To update tools, simply run `update.sh`
