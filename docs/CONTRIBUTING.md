# Contributing to Sirracha Executor

## Project Status: 60% Complete

### What Works
- Library injection into Sober process via ptrace/GDB
- Lua state detection (finds valid lua_State with score 52)
- Memory region scanning
- IPC between UI and injected library
- GTK4 UI with syntax highlighting

### What Does Not Work
- Script execution (Luau functions not resolved)
- VisualEngine offset scanning (gets stuck)
- Pattern-based function discovery (Sober code is encrypted)

---

## Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   SirrachaUI.c  │────>│   Injector.c     │────>│ injected_lib.c  │
│   (GTK4 App)    │ IPC │ (ptrace inject)  │     │ (runs in Sober) │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          v
                                                 ┌─────────────────┐
                                                 │pattern_scanner.c│
                                                 │ roblox_state.c  │
                                                 └─────────────────┘
```

### File Descriptions

| File | Purpose |
|------|---------|
| `SirrachaUI.c` | GTK4 UI with code editor and output panel |
| `Injector.c` | Handles ptrace attachment and library loading |
| `injected_lib.c` | Main library injected into Sober. Runs worker thread. |
| `pattern_scanner.c` | Scans memory for Luau function patterns |
| `roblox_state.c` | Uses offsets to find DataModel, Players, etc |
| `luau_api.h` | Luau API typedefs and function pointers |
| `roblox_offsets.h` | Structure offsets from Windows (provided by puenytr) |

---

## The Main Problem

Sober encrypts its code at runtime. When we scan for Luau function patterns:

```c
// Expected: push rbp; mov rbp, rsp (0x55 0x48 0x89 0xE5)
// Actual: encrypted garbage bytes
```

We need to find the VisualEngine pointer offset for Linux. On Windows it is at `base + 0x7AE30D0`. On Linux this offset is different.

### Offset Chain (from puenytr)

```
VisualEngine (base + ???)
    └─> +0x700 = FakeDataModel
        └─> +0x1C0 = RealDataModel
            └─> +0x178 = Workspace
            └─> +0x3A0 = RunService
            └─> +0x3B0 = UserInputService
```

The relative offsets (+0x700, +0x1C0, etc) are the same on Linux. We just need the base VisualEngine pointer location.

---

## How to Help

### Option 1: Find VisualEngine Offset

If you can find where the VisualEngine pointer lives in the Linux Sober binary:

1. Attach debugger to Sober
2. Find a pointer that leads to DataModel chain
3. Calculate offset from Sober base address

### Option 2: Alternative Discovery Methods

Ideas that might work:

- Hook `dlopen` or `dlsym` to catch Luau library loading
- Hook `lua_newstate` to get fresh Lua state
- Trace execution from `main()` to find init code
- Use hardware breakpoints on memory access

### Option 3: Signature Scanning Improvements

The current scanner looks for function prologues. This does not work because code is encrypted. Alternative approaches:

- Scan for string references (LEA instructions)
- Scan for vtable patterns
- Scan for known constants

---

## Building

```bash
# Install dependencies (Fedora/RHEL)
sudo dnf install gtk4-devel gtksourceview5-devel gcc make

# Install dependencies (Ubuntu/Debian)
sudo apt install libgtk-4-dev libgtksourceview-5-dev gcc make

# Build (also installs to /dev/shm automatically)
make

# Build and run
make run

# View debug logs
make logs

# Clean build files
make clean
```

---

## Debug Commands

Type these in the executor and click Execute:

| Command | Action |
|---------|--------|
| `__PROBE__` | List known function status |
| `__ROBLOX__` | Test VisualEngine offset scanning |
| `__SAFEPROBE__` | Scan for function prologues |
| `__DISCOVER__` | Run aggressive string-based discovery |

Check logs at `/dev/shm/sirracha_debug.log`

---

## IPC Files

Located in `/dev/shm/`:

| File | Purpose |
|------|---------|
| `sirracha_exec` | Script to execute (written by UI) |
| `sirracha_output` | Output from execution (read by UI) |
| `sirracha_ready` | Ready signal from injected library |
| `sirracha_debug.log` | Debug log |

---

## Contact

- GitHub: compiledkernel-idk
- Discord: theterminatorgm
