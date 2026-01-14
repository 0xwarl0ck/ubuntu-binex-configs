# ubuntu-binex-configs
Configuration scripts and files to automate the setup of a professional **Ubuntu Exploit Development VM**. This repository streamlines the installation of debuggers, decompilers, and library management tools.

## Included Tools

The setup scripts in this repository cover the essential "BinEx Starter Pack":

### 1. Debugging & GDB Plugins
* **pwndbg** or **GEF** - Enhanced GDB environments for exploit developers.
* **Radare2 / Cutter** - Powerful reverse engineering frameworks.

### 2. Analysis & Gadget Hunting
* **Ropper / ROPgadget** - To find gadgets for ROP chains.
* **checksec** - To verify binary protections (NX, ASLR, PIE, Canary).
* **one_gadget** - Finds one-shot RCE gadgets in `libc`.

### 3. Exploitation Libraries
* **pwntools** - The industry-standard Python library for crafting exploits.
* **patchelf** - For modifying ELF headers to use specific `libc` versions.
