# Sirracha Executor

Roblox script executor for Linux. Targets the Sober client (Flatpak).

## Status

| Component | Status |
|-----------|--------|
| Injection | Working |
| Lua State Detection | Working |
| Function Resolution | Not Working |
| Script Execution | Not Working |

## Requirements

- Linux (tested on Fedora, should work on Ubuntu/Debian)
- GTK4 and GtkSourceView 5
- Sober (Flatpak Roblox client)

## Build

```bash
# Fedora
sudo dnf install gtk4-devel gtksourceview5-devel gcc make

# Ubuntu/Debian  
sudo apt install libgtk-4-dev libgtksourceview-5-dev gcc make

# Build
make

# Build and run
make run

# View logs
make logs

# Clean
make clean
```

## Usage

1. Run `./sirracha`
2. Click ATTACH (launches Sober if not running)
3. Wait for "Ready Signal Received"
4. Enter Lua script
5. Click EXECUTE

## Files

| File | Description |
|------|-------------|
| SirrachaUI.c | GTK4 user interface |
| Injector.c | Process injection via ptrace |
| injected_lib.c | Library that runs inside Sober |
| pattern_scanner.c | Memory pattern scanning |
| roblox_state.c | Roblox structure traversal |
| luau_api.h | Luau API definitions |
| roblox_offsets.h | Roblox structure offsets |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for technical details and how to help.

## License

Copyright (c) 2026 compiledkernel-idk (GitHub) / theterminatorgm (Discord)
All Rights Reserved.
