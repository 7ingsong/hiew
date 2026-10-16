# HANDOFF — hiew (cross-platform Hacker's View)

A briefing for an agent that continues this work without access to the original conversation. All paths are
relative to the project root (the folder that contains this file) unless stated otherwise. The user writes in
Russian — answer them in Russian. The project README is in English (the user asked for that).

`<scratchpad>` below means the previous session's temporary folder under `/private/tmp/claude-501/...`. It held
test files and backups. It is temporary and may already be gone.

---

## 1. Goal

A console hex viewer / hex editor / disassembler that reproduces **Hiew (Hacker's View)**: the same modes
(Text / Hex / Decode), the same hotkeys, the same blue screen and a convenient viewer. It must run on macOS, Linux
and Windows.

Requirements the user added along the way:
- **Hotkey reference**: the Hiew Documentation Project, <https://taviso.github.io/hiewdocs/>. Also the Hiew 7
  commands from HIEW7.HLP (Alt-F2 FilBlk, Alt-F3, Ctrl-F3 Replace, F4–F6 bits in edit mode, F10 Trunc, etc.).
- The bottom keybar must change while Alt / Ctrl / Shift is held, as in Hiew.
- Colour themes: light and dark, in addition to the classic one.
- HEM plugins (F11) are **not needed** ("for now").
- Do **not use the word "port"** (or the Russian «порт») or the phrase "Hiew-style" in the README or the program.
  The README title is `# Hiew — cross-platform Hacker's View`.
- Process: a separate tester agent checks every change. The task counts as done only after its **APPROVED**
  verdict.

## 2. What is done

Everything below is implemented and, except the README, approved by the tester. The last verdict is
**APPROVED** (round 14).

- **Core:** three modes. Enter cycles Text → Hex → Decode, and the address survives a mode switch (Text mode keeps
  the exact offset in `text_anchor`). The file is accessed through mmap. Edits are kept as in-memory patches until
  F9.
- **Formats (`hiew/formats.py`):**
  - PE32/PE32+ (x86/x64/ARM/ARM64) with imports and exports.
  - ELF32/64, little and big endian: symtab/dynsym, GOT names from relocations, imports from JUMP_SLOT/GLOB_DAT
    relocations, DT_NEEDED libraries, exports from dynsym.
  - Mach-O 32/64 and universal (fat) with slice selection. Exports are the external symtab symbols. Imports come
    from the indirect symbol table of the `__stubs`/`__got`/`__la_symbol_ptr` sections, one entry per function
    (the stub address). Libraries come from LC_LOAD_DYLIB.
  - DOS MZ. Everything else opens as raw data.
- **Disassembler:** capstone (x86-16/32/64, ARM/Thumb, ARM64, MIPS, PPC, RISC-V).
  - Branch targets are shown as `.00401234`, and `[rip+X]` is resolved to an absolute address.
  - ARM64 `adrp` + `add/ldr/str` pairs get a comment with the name or string they point to; the `adrp` line
    itself gets no comment.
  - Jump markers `--↓1` … use keys `1..9`, `A..Z`.
- **Assembler:** keystone through our own ctypes binding (`disasm.py: _load_keystone`). The library is searched in
  `/opt/homebrew/lib`, `/usr/local/lib`, the pip package, and so on. Assembler numbers are hex by default (`10t`
  is decimal). In Decode edit mode, Enter/F2 opens the assembler, a letter g–z starts typing an instruction, and
  Tab switches to line-by-line mode.
- **hiewdocs key map (`hiew/spec.py`, class `Hiew(App)`):**
  - **Blocks:** `*`, Ctrl+*, Alt+*, `[`/`]`, Ins for insert/overwrite, Alt+M/Alt+N colours saved to
    `<file>.cmarkers`.
  - **Bookmarks:** `+`, `-`, Alt+1..8, Alt+-, Alt+0. Eight per mode, with an indicator like `12♦-----`.
  - **Macros:** Ctrl+. records, Ctrl+0..8 plays, Ctrl+- opens the manager; stored in `~/.config/hiew/macros.json`.
  - **Modes and navigation:** Ctrl+F1 code size, Shift+F1 architecture, F6/Ctrl+F6 references, `/` resync.
  - **Files:** Tab, Ctrl+F11/F12, Ctrl+BkSp, F9, Alt+F10.
  - **Search:** in the F7 dialog the Hex field comes first; F2 direction, F3 case, F4 file/block, F6 UTF-16
    even/odd, F7 instruction search, Alt+? wildcard. Ctrl+Enter / Shift+F7 find the next match, Alt+F7 changes
    direction. Alt+F6 lists strings, Alt+F8 sets the character table / UTF-16.
  - **Names and comments:** `;` adds a comment, Shift+F12 names a location; both are saved to `<file>.hnames`.
    F12 is the names window, with text import/export.
  - **Header (F8):** sub-tables F5 entry point, F6 sections, F7 imports (Enter searches for calls), F9 exports;
    Enter on a fat slice line switches the slice.
  - **Calculator (Alt+=):** hex by default; suffixes t/o/i/h; `@b..@Q`, `@o/@O`; C operators.
  - **Other:** Alt+P screenshot, Shift+F4 print block, Alt+B beeps, Ctrl+Alt (hold) for info, Esc quits without
    changing mtime, F10 quits and updates it, F11 shows "HEM not supported".
- **Hiew 7 commands (`hiew/extra.py`, `ExtraMixin`):**
  - FilBlk, CryBlk/Crypt, DelBlk, CpyBlk, MovBlk, GetBlk, PutBlk.
  - Crypt is a mini x86 language: `mov xor add sub and or rol ror shl shr not neg inc dec`, with data in
    al/ax/eax/rax and the data size chosen with F2.
  - Replace (Y/N/A), bit editor F4/F5/F6, XOR F8/Ctrl+F8, NOP Alt+F2, Trunc F10, Ctrl+Z undo.
- **Replace All:** one pass over the file with progress and Esc, then a confirmation showing the match count.
  `FileBuffer.write_many` makes it a single undo step. Verified on a copy of libclang (285 MB): `00 01→00 00`,
  902150 replacements, and a byte-by-byte diff showed exactly 902150 changed bytes.
- **Fast reference search (`hiew/xrefs.py`):** instead of disassembling all code linearly, it scans for byte
  patterns and confirms each candidate with capstone. libclang (285 MB) takes about 3 s instead of about 22 s, and
  the results match `otool`.
- **Keyboard:**
  - `keys.py`: xterm/CSI, kitty CSI-u, PDCurses. Esc+key = Alt only in the main window. `^H` = Ctrl+BkSp when the
    tty erase character is DEL.
  - `mods.py`: kitty protocol; OS modifier polling (macOS CoreGraphics, Windows GetAsyncKeyState, X11);
    Terminal.app tables for Option/Shift+F; US-layout Option characters.
  - Ctrl+X is the sticky modifier. `hiew --keys` shows the raw bytes and how they are decoded.
- **Themes (`hiew/themes.py`):** hiew (navy, default), blue (DOS), dark, light. 256-colour palettes plus 8-colour
  variants. "Theme:" in F4 switches live; the choice is stored in `~/.config/hiew/settings.json`, and `-t`
  overrides it. Every 256-colour role is at least 3:1 (WCAG).
- **README.md** is in English, with the screenshots `docs/decode.png` and `docs/hex.png` and their explanations.

## 3. Key decisions (and what was rejected)

- **Python + curses + capstone.** The machine has no Go/Rust; it has the system Python 3.9.6. Windows uses
  `windows-curses`. The code stays compatible with 3.8+ (no `match`, no `X | Y` in annotations).
- **Classes:** `App` (app.py) ← `ExtraMixin` (extra.py) ← `Hiew(App)` (spec.py). `Hiew` is the class that runs.
  Hiew overrides App methods; ExtraMixin provides `handle_view_extra/handle_edit_extra`.
  - Key handling order: `App.handle` → `translate_key` (OS modifiers) → `apply_layer` (Ctrl+X) →
    `handle_*_extra` (Hiew → ExtraMixin) → base App.
- **The keystone pip package has no native library on arm64 macOS.** Hence our own ctypes binding, using the
  library from Homebrew (`brew install keystone`, already installed).
- **Modifiers:** a terminal never reports "Alt pressed" on its own. We use the kitty protocol if the terminal
  answers `CSI ? u`, otherwise OS polling. Limitation of polling: it sees key presses globally, not only in the
  terminal window.
- **Terminal.app** encodes modified F-keys VT220-style. The table is in
  `/System/Applications/Utilities/Terminal.app/Contents/Resources/keyMappings.plist`.
  - Option+F1..F5 → F6..F10; Option+F6 → F11 (`[23~`); Option+F7 → F12; Option+F8..F12 → `[25~ [26~ [28~ [29~
    [31~`.
  - Shift+F5..F12 → `[25~ [26~ [28~ [29~ [31~ [32~ [33~ [34~`.
  - **Ctrl+F-keys have no codes at all.**
  - The first version of the Shift table was wrong (Shift+F7 turned into CpyBlk); now fixed.
- **Alt+digits are bookmarks** (per hiewdocs), so the fallback "Alt+1..0 = F1..F10" was dropped. The sticky
  modifier moved from F11 to Ctrl+X, because F11 is HEM in the spec.
- **Reference search heuristics (xrefs.py)** — each one was added after a specific bug:
  - **rel32** (`E8/E9/0F 8x`) candidates whose 4 bytes land exactly on the target are accepted without a boundary
    check, since a chance match is practically impossible. Checking from p−32 used to lose real calls in libclang
    x86_64.
  - **rel8** candidates get a boundary check: decode from 32/28/24/20/16/12 bytes back. If any start lands exactly
    on p, accept. If all of them see p inside another instruction, compare the two readings up to where they meet
    again (or over 48 bytes) and count "junk" instructions (`_WEIRD`: db/in/out/std/cli/les/lds/bound/pop ss/…).
    The reading with less junk wins. This finds the `jne` in cli-32 at .40316E, which every sync start read as
    `or al,75h; pop ss`.
  - **A number in an operand also counts as a reference** (tables such as `jmp [edx*4+0x409154]`). On **x86-64**,
    numbers in brackets with a base register (`[rbx+0x84]`, `[rip+X]`) are displacements, not addresses. **On
    x86-32 they are addresses** (arrays such as `[ecx+0x411ee0]`). The rule was first applied to every architecture
    and lost about 25 references in cli-32, so it was rolled back for x86-32.
  - **`_rip_disp`:** on x86-64 a candidate is rejected if the same bytes are the disp of a `[rip+…]` instruction
    that starts 1–4 bytes earlier and ends at the same byte. Exception: the confirming instruction is itself
    rip-relative.
  - **Instruction start** is decided by a vote across 6 sync starts. If any start saw the same instruction with its
    prefix (`48 8d 05 …`), that one wins. A prefix run is accepted only as legacy prefixes plus at most one REX,
    placed last, before an opcode without its own REX ("4b 40 48 3b" is not a prefix run).
  - **Rejected:** the "longest covering instruction" fallback (it produced `sub eax, imm` inside a `lea`), and an
    unconditional step back over prefix bytes.
  - **ARM64:** B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, ADR, LDR-literal, ADRP+ADD/LDR/STR (ARM64 PE imports work this
    way).
  - **ELF imports:** the search uses the PLT stub address plus the GOT slot; the stub's own `jmp` is excluded.
- **Buffer:** a sorted patch index (bisect). Without it Replace All hung (O(N²)).
- **F5 / name import:** leading zeros are hex (`.00403553`), not octal. Octal `0..` exists only in the calculator.
- **Esc delay of 0.5 s** applies only in the main window; in dialogs Esc acts immediately.

## 4. Current state of the files

The project folder is not a git repository.

| File | Lines | Contents |
|---|---|---|
| `hiew/__main__.py` | 81 | argparse, curses init (`raw`, `nonl`), ^H detection, starts `Hiew` or `--keys` |
| `hiew/app.py` | 1828 | class `App`: drawing, modes, dialogs, navigation, editing, HELP (in Russian; line 1: "Hiew %s - кроссплатформенный Hacker's View") |
| `hiew/spec.py` | 1807 | class `Hiew(App)`: hiewdocs key map, `Calc`, slice switching, themes in the fat-file F4 menu |
| `hiew/extra.py` | 910 | `ExtraMixin`, `Crypt`, replace/replace_all, keybar layers |
| `hiew/formats.py` | 639 | PE/ELF/Mach-O/fat/MZ parsers, `BinInfo` |
| `hiew/xrefs.py` | 321 | fast reference search (`find_refs`) |
| `hiew/disasm.py` | 315 | `Disassembler` (capstone), `assemble` (keystone via ctypes), `hex_numbers` |
| `hiew/keys.py` | 287 | key decoding |
| `hiew/buffer.py` | 237 | `FileBuffer`: mmap, patches, undo, insert/delete/truncate, find, write_many |
| `hiew/mods.py` | 230 | `ModWatcher`, kitty enable/disable, `translate`, `keytest` |
| `hiew/themes.py` | 132 | palettes, settings.json |
| `tests/drive.py` | 96 | pty + pyte harness (see §5) |
| `README.md` | 200 | English; screenshots `docs/decode.png`, `docs/hex.png` |
| `pyproject.toml` | 22 | package `hiew-py`, script `hiew`, deps capstone and windows-curses |
| `.venv/` | — | Python 3.9.6 venv: capstone 5.0.7, pyte, keystone-engine (without its native lib); the package is installed editable |
| `raw2.bin` | — | **stray file** left by tests; delete it |
| `hiew_py.egg-info/` | — | artefact of `pip install -e .` |

Outside the project:
- `~/.config/hiew/settings.json` and `~/.config/hiew/macros.json` were created during manual checks (theme,
  macros).
- **The user's macOS settings were changed** (with their consent):
  - The system shortcuts Ctrl+F1…F8 are disabled (`com.apple.symbolichotkeys`, ids 12, 7, 8, 9, 10, 11, 13, 57).
    Backup: `<scratchpad>/symbolichotkeys-backup.plist`.
  - In all 12 Terminal.app profiles, `keyMapBoundKeys` gained `^F704..^F70F` → `\033[1;5P` … `\033[24;5~`
    (Ctrl+F1..F12). Backup: `<scratchpad>/terminal-backup.plist`.
    - Before this change the user reported that Ctrl+F1 still did not work.
    - After the change, Terminal needs a full restart (Cmd+Q). **Not yet confirmed that it works.**
  - The backups are in the temporary folder and may disappear.

Test data (temporary, may be gone), in `<scratchpad>/`:
- `dl/x/setuptools/cli-32.exe`, `cli-64.exe`, `cli-arm64.exe` — PE files from the setuptools 65.5.0 wheel. To
  recreate: `pip download --no-deps setuptools==65.5.0`, then unzip `setuptools/*.exe`.
- `dl/x/capstone/lib/libcapstone.so` — ELF x86-64 from the capstone 5.0.1 manylinux2014_x86_64 wheel. To recreate:
  `pip download --no-deps --only-binary=:all: --platform manylinux2014_x86_64 --python-version 39 capstone==5.0.1`.
- `t.txt` — UTF-8 Cyrillic text.
- `qa/v/xcheck*.py`, `qa/v/arm_gt.py`, `qa/v/contrast.py` — the tester's cross-check scripts.

System samples:
- `/bin/ls` — fat x86_64 + arm64e.
- `/Library/Developer/CommandLineTools/usr/lib/libclang.dylib` — fat, 285 MB.

## 5. Important data and commands

- **Run:** `.venv/bin/hiew file` (or `python -m hiew`).
  - Options: `-m text|hex|decode`, `-o 1234|.401000|name`, `-e`, `-s x86_64|arm64e|0`, `-a arch`,
    `-t hiew|blue|dark|light`, `--colors 8`, `--no-mouse`, `--no-modpoll`, `--no-kitty`, `--keys`, several files
    or a wildcard.
- **Install on the user's side:** `pip install .`; for the assembler `brew install keystone`.
- **Harness:** from the project root,
  `ROWS=24 COLS=100 .venv/bin/python tests/drive.py FILE 'KEY|KEY|SHOW|…' [args]`.
  - Keys are names from the KEYS dict at the top of `drive.py` (F1..F12, C-F7, S-F7, A-F1.., C-ENTER, ESC, ESCF6,
    S-RIGHT, A-1, C-., INS, DEL, C-x …) or literal text.
  - Pseudo-keys: `SHOW` (dump the screen), `CELLS` (cell colours), `WAITn` (wait n seconds), `KEY@sec`.
  - It sets `HIEW_NO_MODPOLL=1`, maps `QAHOME` to HOME, and emulates `CSI S/T` (pyte doesn't support them).
  - Pitfalls: in view mode Esc/F10 **quit the program**; F8 in Text mode is Xlat; pyte doesn't answer terminal
    queries, so kitty mode stays off. Use `HOME=<fake>` when checking settings.
- **Reference counts to check against (`otool`):**
  - libclang x86_64: `_strcmp` 335, `__NSGetEnviron` 1, `_malloc` 3046, `__Unwind_Resume` 2750, `_free` 50753,
    `_memcpy` 22906, `_strlen` 3557, `_abort` 931, `_qsort` 136, `_getenv` 184.
  - libclang arm64: `__Unwind_Resume` 2705, `_malloc` 3046.
  - Reference command: `otool -arch x86_64 -tV <lib> | grep -c 'symbol stub for: NAME$'`.
- **Tester scripts:** from `<scratchpad>/qa`, run with the project's `.venv/bin/python`:
  - `v/xcheck2.py FILE 40 SEED` — branches;
  - `v/xcheck3.py FILE 40 SEED` — data;
  - `v/xcheck.py FILE 14` — imports.
  - Last run over 20 seeds: 0 differences on cli-32/cli-64. libcapstone shows only "slow-only" masks such as
    `and eax, 0x100000` and `lea` displacements — errors of the old reference sweep, accepted as fine.
- **macOS:** CoreGraphics `CGEventSourceFlagsState(0)` works without permissions. Masks: Shift 0x20000, Ctrl
  0x40000, Alt 0x80000.
- **Errors and their fixes:**
  - zsh doesn't split `set -- $spec` — use `bash -c`.
  - The safety check blocks `rm` with a variable in the path — use a literal absolute path.
  - WebFetch upgrades to https — use curl for http-only sites.

## 6. Open questions and known problems

- **Ctrl+F1 in the user's Terminal.app**: not confirmed to work after the profile change and a Terminal restart.
  If it still doesn't:
  - check that `keyMapBoundKeys` of the "Clear Dark" profile (the default) contains `^F704`;
  - make sure Terminal was closed while writing, since it can overwrite its settings on quit.
- **Not implemented:**
  - HEM modules (F11);
  - editing header tables with F3 inside F8;
  - Shift+F1..F4 in Terminal.app (it sends no codes, so they work only through OS polling);
  - Mach-O imports without stubs (17 data symbols of 491/487 in libclang).
- Instruction search via F7→F7 looks for one encoding only (`mov ebp,esp` = 89 E5, while MSVC emits 8B EC).
- OS modifier polling also sees key presses in other windows, so the keybar may flicker in the background.
- The dialog title in the 8-colour themes (black bold on cyan) is about 2:1 in terminals that draw bold black as
  grey. Left as is on purpose.
- **Windows and Linux were never tested.** The code for PDCurses/X11 exists but has never been run.
- The F1 help is in Russian (the README is in English). The user hasn't decided whether to translate F1.
- The README changes (translation, title, screenshots) were not given to the tester.

## 7. Next steps

1. Delete the stray `raw2.bin` in the project root.
2. Ask the user about git. If they agree: `git init` (`.gitignore` already covers `.venv/`, `__pycache__/`,
   `*.egg-info/`, `build/`, `dist/`), then a first commit with `hiew/`, `tests/`, `docs/`, `README.md`,
   `pyproject.toml` and `HANDOFF.md`. Use the attribution trailer from the system reminder in the commit message.
3. Ask the user whether Ctrl+F1 works after restarting Terminal. If not, run `hiew --keys`, press Fn+Ctrl+F1 and
   decide from the raw bytes column (see §6).
4. Ask whether to translate the F1 help into English (`HELP` in `hiew/app.py`).
5. For any code change: check it in the harness, then give it to the tester agent with an explicit test plan. It is
   done only after **APPROVED**. Keep the reference counts from §5 when changing `xrefs.py`.
6. If the user wants: HEM plugins (not needed for now), F3 editing of the F8 tables, testing on Windows/Linux.
