# Sirracha Executor

Roblox script executor for Linux. Targets the Sober client (Flatpak).

## Status

| Component | Status |
|-----------|--------|
| Injection | ✅ Working |
| Lua State Detection | ✅ Working |
| Function Resolution | ❌ Needs Offsets |
| Script Execution | ❌ Blocked |

> **Note:** Script execution is blocked because Sober encrypts its binaries. We need someone to reverse engineer `libloader.so` to find the Luau function offsets. See `EXTREME_DECOMPILING_GUIDE.md`.

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
# OR for Qt5:
sudo apt install qtbase5-dev cmake g++ make

# Fedora
sudo dnf install qt6-qtbase-devel cmake gcc-c++ make
```

### Build Everything

```bash
# Clean build
make clean

# Build injection library + Qt UI
make

# Run the executor
make run
```

### Build Commands

| Command | Description |
|---------|-------------|
| `make` | Build everything (library, injector, Qt UI) |
| `make run` | Build and launch Qt UI |
| `make run-electron` | Run legacy Electron UI |
| `make logs` | Tail the debug log |
| `make clean` | Remove all build artifacts |

## Usage

1. **Start Sober** and join a game
2. **Run Sirracha**: `make run`
3. **Click INJECT** - Injects the library into Sober
4. **Wait for "Connected"** status
5. **Write your Lua script** in the editor
6. **Click EXECUTE**

## Project Structure

| File | Description |
|------|-------------|
| `SirrachaQt.cpp` | Qt6 user interface (dark theme, syntax highlighting) |
| `Injector.c` | Process injection via ptrace/GDB |
| `injected_lib.c` | Library that runs inside Sober |
| `pattern_scanner.c` | Memory pattern scanning |
| `roblox_state.c` | Roblox structure traversal |
| `luau_api.h` | Luau API definitions |
| `roblox_offsets.h` | Roblox structure offsets |
| `inject_sober.sh` | Shell injection helper |
| `find_offsets.py` | Runtime offset discovery tool |

## Troubleshooting

### Qt build fails
Make sure you have Qt development packages:
```bash
# Check Qt version
qmake --version

# If using Qt5, the build should auto-detect it
```

### Injection fails
- Make sure Sober is running and you're in a game
- Try running with sudo: `sudo ./inject_sober.sh <PID>`

### "Offsets not configured"
The Luau function offsets need to be found. See `EXTREME_DECOMPILING_GUIDE.md` for instructions on reverse engineering libloader.so.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for technical details.

### Priority Tasks
1. **Find Luau offsets** - Reverse engineer `libloader.so` to find `luaL_loadbuffer` and `lua_pcall`
2. **Pattern signatures** - Create byte patterns that work across Sober updates
3. **Testing** - Test on different Linux distros

## License

Copyright (c) 2026 compiledkernel-idk (GitHub) / theterminatorgm (Discord)  
All Rights Reserved.
