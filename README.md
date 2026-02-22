# MemScanner — Memory Analysis Tool

A Windows memory scanner and analysis tool built with Dear ImGui + DirectX 11.  
Supports multi-threaded scanning, disassembly, PE parsing, patch management, and more.

---

## Features

- **Memory Scanner** — First/Next scan with 15+ value types (Int8–Int64, Float, Double, Vec2/3/4, AoB, String, WString)
- **Scan Conditions** — Exact, Not Equal, Greater/Less, Between, Increased/Decreased By, Changed/Unchanged, Bitwise AND/OR
- **Disassembler** — Full x86/x64 disassembly powered by [Zydis v4](https://github.com/zyantific/zydis)
- **Memory View** — Hex editor with live read/write
- **Region Map** — List all committed memory regions with protection flags
- **Module View** — Loaded DLLs with base address and size
- **PE Parser** — Sections, imports, exports, TLS callbacks, data directories
- **Heap Viewer** — Walk heap blocks via Toolhelp32
- **Thread View** — List and control target threads
- **Watch List** — Monitor addresses with value history sparklines and freeze
- **Pointer Chains** — Multi-level pointer scanner with offset resolution
- **Patch Manager** — Apply/revert byte patches, NOP ranges, relative JMP/CALL hooks
- **XRef Scanner** — Find all cross-references to a target address
- **Custom Background** — Solid color or image (PNG/JPG/BMP) with opacity + tile support
- **Hot Reload** — Background image auto-reloads when file changes on disk (500ms polling)

---

## Requirements

- Windows 7 or later (x64)
- [MSYS2](https://www.msys2.org/) with MinGW-w64 toolchain
- DirectX 11 runtime (included in Windows)

---

## Dependencies

| Library | Version | Notes |
|---------|---------|-------|
| [Dear ImGui](https://github.com/ocornut/imgui) | v1.91.6 (standard) | Fetched by `make deps` |
| [Zydis](https://github.com/zyantific/zydis) | v4.x amalgamated | Manual download required |
| [stb_image](https://github.com/nothings/stb) | latest | For background image loading |

---

## Build

### 1. Install MSYS2 + MinGW-w64

```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
```

### 2. Fetch ImGui

```bash
make deps
```

### 3. Download Zydis (manual)

1. Go to https://github.com/zyantific/zydis/releases/latest
2. Download `zydis-amalgamated.zip`
3. Extract `Zydis.h` and `Zydis.c` into `src/zydis/`

### 4. Download stb_image (manual)

```bash
curl -o src/stb_image.h https://raw.githubusercontent.com/nothings/stb/master/stb_image.h
```

### 5. Build

```bash
make
# Output: build/MemScanner.exe
```

### Release build (stripped)

```bash
make release
```

### Clean

```bash
make clean
```

---

## Project Structure

```
MemScanner/
├── src/
│   ├── main.cpp              # WinMain, DX11 setup, message loop
│   ├── MemScanner.h          # Shared data structures and enums
│   ├── ProcessEngine.cpp/h   # Process attach, memory read/write, module/thread/heap enumeration
│   ├── ScanEngine.cpp/h      # Multi-threaded first/next/AoB/string/pointer scan
│   ├── DisasmEngine.cpp/h    # Disassembler, patch manager, PE parser, XRef scanner
│   ├── MainUI.cpp/h          # All ImGui windows and UI logic
│   ├── imgui/                # Dear ImGui source (fetched by make deps)
│   ├── zydis/                # Zydis amalgamated source (manual)
│   └── stb_image.h           # stb_image (manual)
├── build/                    # Compiled objects and final .exe
└── Makefile
```

---

## Usage

### Attach to a Process
1. Launch `MemScanner.exe` **as Administrator** (required for `PROCESS_VM_READ` on protected processes)
2. **File → Attach Process...** → find your target → click its PID row

### Scan for a Value
1. Open **Scanner** window (View → Scanner)
2. Select value type (e.g. `Int32`) and condition (e.g. `Exact Value`)
3. Enter value → **First Scan**
4. Change the value in the target process
5. Enter new value → **Next Scan** — repeat until results narrow down

### AoB Scan
- Use pattern like `AA BB ?? CC ??` where `??` is a wildcard byte

### Disassemble
- Open **Disassembler** → enter a module base address from Module View → press Enter

### Custom Background
1. **Tools → Settings → Background tab**
2. Select **Solid Color** and pick a color, or
3. Select **Image**, enter full path to PNG/JPG/BMP → click **Load**
4. Adjust **Opacity** and **Tile** as needed
5. Hot reload: replace the image file on disk → app reloads automatically within 500ms

---

## Hotkeys

| Key | Action |
|-----|--------|
| `F5` | First Scan |
| `F6` | Next Scan |
| `F12` | Open Settings |

---

## Notes

- Run as **Administrator** for full access to system processes
- Some anti-cheat protected processes may block `ReadProcessMemory` even with SeDebugPrivilege
- Docking requires the ImGui docking branch — standard v1.91.6 is used here (no docking)
- Background images are loaded into a D3D11 texture; large images use more VRAM

---

## License

This project is provided as-is for educational and research purposes.
