# Hiew — cross-platform Hacker's View

A console hex viewer, hex editor and disassembler with the modes, hotkeys and blue screen of **Hiew (Hacker's View)**.
Runs on macOS, Linux and Windows.

![Decode mode: arm64 code of /bin/ls](https://raw.githubusercontent.com/7ingsong/hiew/main/docs/decode.png)

*Decode mode on `/bin/ls` (arm64 slice of a universal Mach-O), at the entry point.*

![Hex mode: symbol strings of /bin/ls](https://raw.githubusercontent.com/7ingsong/hiew/main/docs/hex.png)

*Hex mode on the same file: address, 16 bytes in hex, the same bytes as characters.*

## Installation

Requires Python 3.9+.

```sh
pip3 install hiew                 # macOS / Linux / Windows (windows-curses is pulled in on Windows)
python3 -m hiew /bin/ls
```

The built-in assembler (F3 → F2) needs the keystone library:

| System | Command |
|---|---|
| macOS | `brew install keystone` |
| Linux | `apt install libkeystone0` (or your distribution's keystone package) |
| Windows | `pip install "hiew[asm]"` (installs `keystone-engine`) |

Everything else works without it. From a source checkout: `pip install .`, or `python -m hiew file`.

## What is supported

- **Formats:** PE32/PE32+ (x86, x64, ARM, ARM64) with imports and exports; ELF32/64 (LE/BE) with symtab/dynsym,
  GOT slot names, PLT stubs and DT_NEEDED libraries; Mach-O 32/64 and universal (fat) binaries with imports
  (stubs / GOT via the indirect symbol table), exports and libraries; DOS MZ. Other files open as raw data.
- **Windows resources (.rsrc)**: the type / name / language tree with decoded version info, manifests, string tables
  and icon groups, in a window opened with F8, then F4. Enter goes to the data, F2 saves the selected resource
  (icon and cursor groups become real `.ico` / `.cur` files, bitmaps `.bmp`), F3 saves them all.
- **.NET assemblies** (via [dnfile](https://github.com/malwarefrank/dnfile)): runtime, flags, assembly version, managed
  entry point, referenced assemblies and `Namespace.Type::Method` names for every method body. Managed resources are
  listed in the same resources window (F8, then F4), with the strings of `.resources` sets.
- **Disassembler:** capstone — x86-16/32/64, ARM/Thumb, ARM64, MIPS, PowerPC, RISC-V. Branch targets are shown as
  Hiew addresses (`.00401234`), `[rip+X]` is resolved to an absolute address, ARM64 `adrp` + `add`/`ldr` pairs
  are resolved too. Comments show import and symbol names, `@plt` stubs and the strings (ASCII and UTF-16) the code
  refers to.
- **Reference search (F6, imports):** byte-pattern scanning confirmed by the disassembler instead of disassembling the
  whole file — x86 `call`/`jmp`/`jcc`, `[rip+X]`, absolute addresses and jump tables; ARM64 B/BL, B.cond, CBZ/TBZ,
  ADR, literal loads and ADRP pairs. Counts match `otool`; a search takes a few seconds even in libraries of several hundred megabytes.
- **Large files** are memory-mapped and never read into memory as a whole; edits are kept as patches.
