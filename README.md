# Sirracha Executor

Roblox script executor for Linux. Targets the Sober client (Flatpak).

## Status

| Component | Status |
|-----------|--------|
| Injection | ✅ Working |
| Lua State Detection | ✅ Working |
| Function Resolution | ❌ Needs Offsets |
| Script Execution | ❌ Blocked |

> **Note:** Script execution is blocked because Sober encrypts its binaries. See `docs/EXTREME_DECOMPILING_GUIDE.md`.

## Project Structure

```
sirracha-executor/
├── src/
│   ├── core/           # Core injection library
│   │   ├── injected_lib.c
│   │   ├── pattern_scanner.c
│   │   ├── roblox_state.c
│   │   ├── luau_api.h
│   │   └── roblox_offsets.h
│   ├── ui/             # User interfaces
│   │   ├── SirrachaQt.cpp    # Qt UI (active)
│   │   └── SirrachaUI.c      # GTK UI (legacy)
│   ├── asm/            # Assembly optimizations
│   │   ├── simd_utils.s
│   │   └── heavy_math.s
│   └── Injector.c      # Process injector
├── tools/              # Python analysis tools
│   ├── find_offsets.py
│   ├── scan_mem.py
│   └── ...
├── scripts/            # Shell scripts
│   ├── inject_sober.sh
│   └── dump_sober.sh
├── docs/               # Documentation
│   ├── EXTREME_DECOMPILING_GUIDE.md
│   └── CONTRIBUTING.md
├── Makefile
├── CMakeLists.txt
└── README.md
```

## Requirements

- Linux (Arch, Ubuntu, Debian, Fedora)
- Qt5 or Qt6 development libraries
- GCC/G++ compiler
- CMake 3.16+
- Sober (Flatpak Roblox client)

## Build

### Install Dependencies

```bash
# Arch Linux
sudo pacman -S qt6-base cmake gcc make

# Ubuntu/Debian  
sudo apt install qt6-base-dev cmake g++ make

# Fedora
sudo dnf install qt6-qtbase-devel cmake gcc-c++ make
```

### Build & Run

```bash
make        # Build everything
make run    # Launch UI
make inject # Inject into Sober
make logs   # View debug logs
make clean  # Clean build
```

## Usage

1. **Start Sober** and join a game
2. **Run Sirracha**: `make run`
3. **Click INJECT**
4. **Wait for "Connected"**
5. **Write Lua script** and click **EXECUTE**

## Troubleshooting

### "Offsets not configured"
The Luau function offsets need to be found via reverse engineering.
See `docs/EXTREME_DECOMPILING_GUIDE.md`.

### Qt build fails
```bash
qmake --version  # Check Qt version
```

## License

Copyright (c) 2026 compiledkernel-idk  
All Rights Reserved.
