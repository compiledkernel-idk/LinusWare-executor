#!/bin/bash
# Filename: inject_sober.sh
# 
# Usage: ./inject_sober.sh <PID>

LOGfile="/tmp/sirracha_inject_debug.log"
echo "--- Injection Started at $(date) ---" > "$LOGfile"

# 1. Elevate to root
if [ "$EUID" -ne 0 ]; then
    echo "Elevating to root..." >> "$LOGfile"
    exec pkexec "$0" "$@"
fi

PID=$1
if [ -z "$PID" ]; then
    echo "Usage: $0 <PID>" | tee -a "$LOGfile"
    exit 1
fi

# 2. Relax Yama
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
fi

# 3. Find valid target
ORIG_PID=$PID
TARGET=$PID
for i in {1..5}; do
    TRACER=$(grep TracerPid "/proc/$TARGET/status" 2>/dev/null | awk '{print $2}')
    if [ -z "$TRACER" ] || [ "$TRACER" == "0" ]; then break; fi
    TRACER_NAME=$(cat "/proc/$TRACER/comm" 2>/dev/null)
    if [[ "$TRACER_NAME" == "sober" ]] || [[ "$TRACER_NAME" == "bwrap" ]]; then
        TARGET=$TRACER
    else
        break
    fi
done

echo "[*] Target PID: $TARGET (Original: $ORIG_PID)" | tee -a "$LOGfile"

# 4. Locate Library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_PATH="/dev/shm/sirracha.so"

if [ ! -f "$LIB_PATH" ]; then
    if [ -f "$SCRIPT_DIR/sirracha_exec.so" ]; then
        LIB_PATH="$SCRIPT_DIR/sirracha_exec.so"
    else
        echo "[ERROR] Library not found." | tee -a "$LOGfile"
        exit 1
    fi
fi

# 5. Stage library
STAGED_NAME="sirracha_$(date +%s).so"
STAGED_PATH="/dev/shm/$STAGED_NAME"
HOST_STAGED_PATH="/proc/$TARGET/root$STAGED_PATH"

echo "[*] Staging library to $STAGED_PATH..." | tee -a "$LOGfile"
cp -f "$LIB_PATH" "$HOST_STAGED_PATH" 2>/dev/null || cp -f "$LIB_PATH" "$STAGED_PATH"
chmod 777 "$HOST_STAGED_PATH" 2>/dev/null || chmod 777 "$STAGED_PATH"

# Fallback to /tmp if copy failed
if [ ! -f "$HOST_STAGED_PATH" ] && [ ! -f "$STAGED_PATH" ]; then
    echo "[!] /dev/shm copy failed, trying /tmp..." | tee -a "$LOGfile"
    STAGED_PATH="/tmp/$STAGED_NAME"
    HOST_STAGED_PATH="/proc/$TARGET/root$STAGED_PATH"
    cp -f "$LIB_PATH" "$HOST_STAGED_PATH" 2>/dev/null || cp -f "$LIB_PATH" "$STAGED_PATH"
fi

# 6. Method 1: BINARY INJECTOR
if [ -f "$SCRIPT_DIR/injector" ]; then
    echo "[*] Method 1: Binary Injector..." | tee -a "$LOGfile"
    "$SCRIPT_DIR/injector" "$TARGET" "$STAGED_PATH" >> "$LOGfile" 2>&1
    RET=$?
    if [ $RET -eq 0 ]; then
        echo "[SUCCESS] Binary injection worked" | tee -a "$LOGfile"
        rm -f "$HOST_STAGED_PATH" 2>/dev/null
        exit 0
    fi
    echo "[!] Binary method failed (code $RET)" | tee -a "$LOGfile"
fi

# 7. Method 2: GDB (Ultimate - Loaded Symbols)
echo "[*] Method 2: GDB (Explicit Symbols)..." | tee -a "$LOGfile"
GDB_CMD="file /proc/$TARGET/exe; set sysroot /proc/$TARGET/root; attach $TARGET; \
        call ((void*(*)(const char*, int))dlopen)(\"$STAGED_PATH\", 2); \
        detach; quit"
GDB_OUTPUT=$(gdb -batch -ex "$GDB_CMD" 2>&1)
echo "$GDB_OUTPUT" >> "$LOGfile"

if echo "$GDB_OUTPUT" | grep -q "= (void *) 0x[1-9a-f]"; then
    echo "[SUCCESS] GDB (Method 2) worked" | tee -a "$LOGfile"
    rm -f "$HOST_STAGED_PATH" 2>/dev/null
    exit 0
fi

# 8. Method 3: GDB (Legacy/Simple - for Arch/Gentoo sometimes)
if [[ "$GDB_OUTPUT" == *"Invalid data type"* ]] || [[ "$GDB_OUTPUT" == *"No symbol"* ]]; then
    echo "[*] Method 3: GDB (Legacy dlopen)..." | tee -a "$LOGfile"
    # Try just dlopen without casting or file command (relies on default gdb lookup)
    GDB_CMD_LEGACY="set sysroot /proc/$TARGET/root; attach $TARGET; \
            call (void*)dlopen(\"$STAGED_PATH\", 2); \
            detach; quit"
    GDB_OUTPUT_LEGACY=$(gdb -batch -ex "$GDB_CMD_LEGACY" 2>&1)
    echo "$GDB_OUTPUT_LEGACY" >> "$LOGfile"
    
    if echo "$GDB_OUTPUT_LEGACY" | grep -q "= (void *) 0x[1-9a-f]"; then
        echo "[SUCCESS] GDB (Method 3) worked" | tee -a "$LOGfile"
        rm -f "$HOST_STAGED_PATH" 2>/dev/null
        exit 0
    fi
    # Also try __libc_dlopen_mode legacy
    GDB_CMD_INTERNAL="set sysroot /proc/$TARGET/root; attach $TARGET; \
            call (void*)__libc_dlopen_mode(\"$STAGED_PATH\", 2); \
            detach; quit"
    gdb -batch -ex "$GDB_CMD_INTERNAL" >> "$LOGfile" 2>&1
fi

echo "[ERROR] All methods failed. Debug log at $LOGfile" | tee -a "$LOGfile"
# Print last few lines of log to stderr for UI
tail -n 10 "$LOGfile"
exit 1
