# Extreme Decompiling Guide: Finding Luau Offsets for Sober

This guide explains how to reverse engineer the Sober Roblox execution environment ("Sober") to find the critical Luau API offsets required for Sirracha to execute scripts.

##  The Objective
We need to find the **relative memory offsets** (from the start of `libloader.so`) for these key Luau C functions:
*   `luaL_loadbuffer` (Compiles a script string into a chunk)
*   `lua_pcall` (Executes the compiled chunk safely)
*   `lua_getglobal` (Gets a global variable, like "print")
*   `lua_settop` (Cleans up the stack)

## 🛠️ Prerequisites
*   **Ghidra** (Free, Open Source NSA Reverse Engineering Tool) - Highly Recommended.
*   **Linux Terminal** (to extract the binary).
*   **Basic Hex/Assembly Knowledge** (x86_64).

---

##  Step 1: Dump the Target Library
**EASY METHOD:** Run the helper script included in this repo:
```bash
./dump_sober.sh
```
This will automatically find Sober and create `sober_dump.bin` or `libloader_dump.so` for you.

---

**MANUAL METHOD (If script fails):**
Sober runs in a Flatpak, and the Roblox code is packed inside `libloader.so` (on x86_64 systems) or increasingly directly inside the main `sober` binary.

1.  **Launch Sober** and enter a game.
2.  **Find the PID**:
    ```bash
    pgrep -f "sober" | head -n 1
    ```
3.  **Locate the Target**:
    ```bash
    cat /proc/<PID>/maps | grep -E "libloader.so|app/bin/sober"
    ```
    *If `libloader.so` isn't found, the code is in the main `sober` binary.*
4.  **Copy it out**:
    ```bash
    # Try libloader first, then fallback to the main binary
    cp /proc/<PID>/root/app/bin/libloader.so ./libloader_dump.so 2>/dev/null || \
    cp /proc/<PID>/root/app/bin/sober ./sober_dump.so
    ```

---

##  Step 2: Analyze with Ghidra
1.  Open **Ghidra**.
2.  Create a new project and import `libloader_dump.so`.
3.  Double-click to open it in **CodeBrowser**.
4.  **Analyze**: When asked, click "Yes" to analyze. Use defaults (DWARF, Function Starts, etc.). *This may take 5-10 minutes.*

---

##  Step 3: Finding `lua_pcall` (The Pivot)
`lua_pcall` is the easiest to find because it's used *everywhere*.

### Method A: Search for Strings
1.  Go to **Search -> Strings**.
2.  Filter for: `attempt to call a nil value`
3.  Double-click the string to go to its location in memory (`.rodata`).
4.  Look at the **XREFS** (Cross References). Usually, there is a function that uses this string.
    *   This function is often `luaD_precall` or `luaV_execute`.
5.  `lua_pcall` calls these functions. Search for *references* to the function you just found. The function that calls it and takes **4 arguments** is likely `lua_pcall`.

### Method B: The "print" trick
1.  Search for the string `"print"`.
2.  Find where it's used. It will be used in `luaB_print` (the implementation of print).
3.  This function is registered in the global table. Finding how it's registered can point you to `lua_pushcclosure` or `lua_register`.

---

##  Step 4: Finding `luaL_loadbuffer`
This function compiles code. It takes 4 arguments: `(lua_State *L, const char *buff, size_t sz, const char *name)`.

1.  Search for strings: `"syntax error"`, `"inventory"`, or standard module names.
2.  Look for code that looks like it's loading a script.
3.  **Signature Match**:
    If you see a function calling another function that references the string `"LUA_ERRSYNTAX"`, you are close.

---

##  Step 5: Calculating the Offset
Onceyou find the function in Ghidra (e.g., `FUN_00123abc`):

1.  Look at the **Address** of the function start (e.g., `0x001846c0`).
2.  Subtract the **Image Base** (Ghidra usually loads .so files at `0x00100000` or `0x00000000`. Check the *Memory Map*).
3.  **The Result is your Offset.**
    *   Example: Function at `0x1846c0`. Base is `0x0`. Offset is `0x1846c0`.
    *   Example: Function at `0x101846c0`. Base is `0x10000000`. Offset is `0x1846c0`.

---

##  Step 6: Updating Sirracha
Open `injected_lib.c` and update the `KNOWN_OFFSETS` section:

```c
// Example values - USE YOUR FOUND OFFSETS
#define OFF_LOADBUFFER 0x123450 
#define OFF_PCALL      0x123490
#define OFF_GETGLOBAL  0x123500
```

##  Common Pitfalls within Sober
*   **Stripped Binaries**: Function names (Symbols) are likely removed. You will see `FUN_00...`. You must rely on logic and strings.
*   **Obfuscation**: Roblox uses "VMProtect" or similar techniques. If the code looks like garbage logic or jumps into nowhere, it's obfuscated. Look for cleaner functions that call into the messy ones—those are often the API boundaries (`lua_` functions).
*   **Architecture**: Sober on PC is **x86_64**. DO NOT use Android/Phone offsets (ARM64). They are completely incompatible.

Good hunting.
