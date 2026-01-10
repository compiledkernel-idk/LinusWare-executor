#!/bin/bash
# Filename: inject_sober.sh
# 
# Usage: ./inject_sober.sh <PID>

# 1. Elevate to root
if [ "$EUID" -ne 0 ]; then
    exec pkexec "$0" "$@"
fi

PID=$1
if [ -z "$PID" ]; then
    echo "Usage: $0 <PID>"
    exit 1
fi

# 2. Relax Yama ptrace scope (crucial for Fedora/Arch)
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
fi

# 3. Find the valid target (escape watchdog threads)
TARGET=$PID
for i in {1..5}; do
    TRACER=$(grep TracerPid "/proc/$TARGET/status" 2>/dev/null | awk '{print $2}')
    if [ -z "$TRACER" ] || [ "$TRACER" == "0" ]; then break; fi
    TRACER_NAME=$(cat "/proc/$TRACER/comm" 2>/dev/null)
    # Stop if we hit the sober main process or bwrap, proceed if it's just a thread handler
    if [[ "$TRACER_NAME" == "sober" ]] || [[ "$TRACER_NAME" == "bwrap" ]]; then
        TARGET=$TRACER
    else
        break
    fi
done

echo "[*] Target PID: $TARGET"

# 4. Locate or Build Library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_PATH="/dev/shm/sirracha.so"

if [ ! -f "$LIB_PATH" ]; then
    # Fallback to local file if /dev/shm missing
    if [ -f "$SCRIPT_DIR/sirracha_exec.so" ]; then
        LIB_PATH="$SCRIPT_DIR/sirracha_exec.so"
    else
        echo "[ERROR] Library not found at $LIB_PATH or $SCRIPT_DIR/sirracha_exec.so"
        echo "Run 'make' first."
        exit 1
    fi
fi

# 5. Stage library for container visibility (Flatpak fix)
STAGED_NAME="sirracha_$(date +%s).so"
STAGED_PATH="/tmp/$STAGED_NAME"
HOST_STAGED_PATH="/proc/$TARGET/root$STAGED_PATH"

echo "[*] Staging library to $STAGED_PATH..."
cp -f "$LIB_PATH" "$HOST_STAGED_PATH" 2>/dev/null || cp -f "$LIB_PATH" "$STAGED_PATH"
chmod 777 "$HOST_STAGED_PATH" 2>/dev/null || chmod 777 "$STAGED_PATH"

# 6. Try BINARY INJECTOR (Best method)
if [ -f "$SCRIPT_DIR/injector" ]; then
    echo "[*] Method 1: Binary Injector..."
    "$SCRIPT_DIR/injector" "$TARGET" "$STAGED_PATH"
    RET=$?
    if [ $RET -eq 0 ]; then
        echo "[SUCCESS] Binary injection worked"
        # Cleanup
        rm -f "$HOST_STAGED_PATH" 2>/dev/null
        exit 0
    fi
    echo "[!] Binary injector failed code $RET"
fi

# 7. Try GDB (Fallback method)
echo "[*] Method 2: GDB Injection..."

# We use 'file' to load symbols, and cast dlopen to ensure GDB knows the signature
# We also try __libc_dlopen_mode which is often available internal symbol
GDB_CMD="file /proc/$TARGET/exe; set sysroot /proc/$TARGET/root; attach $TARGET; \
        call ((void*(*)(const char*, int))dlopen)(\"$STAGED_PATH\", 2); \
        detach; quit"

GDB_OUTPUT=$(gdb -batch -ex "$GDB_CMD" 2>&1)

# Check if successful
if echo "$GDB_OUTPUT" | grep -q "= (void *) 0x[1-9a-f]"; then
    echo "$GDB_OUTPUT" | tail -n 5
    echo "[SUCCESS] GDB Injection worked (dlopen)"
    # Cleanup
    rm -f "$HOST_STAGED_PATH" 2>/dev/null
    exit 0
fi

# If failed, try parsing internal symbol
if [[ "$GDB_OUTPUT" == *"Invalid data type"* ]] || [[ "$GDB_OUTPUT" == *"No symbol"* ]]; then
    echo "[!] dlopen symbol missing, trying __libc_dlopen_mode..."
    GDB_CMD="file /proc/$TARGET/exe; set sysroot /proc/$TARGET/root; attach $TARGET; \
            call ((void*(*)(const char*, int))__libc_dlopen_mode)(\"$STAGED_PATH\", 2); \
            detach; quit"
    GDB_OUTPUT=$(gdb -batch -ex "$GDB_CMD" 2>&1)
fi

echo "$GDB_OUTPUT" | tail -n 10

# Final verification
if grep -q "sirracha" "/proc/$TARGET/maps" 2>/dev/null; then
    echo "[SUCCESS] Library verified in memory maps"
    # Cleanup
    rm -f "$HOST_STAGED_PATH" 2>/dev/null
    exit 0
fi

echo "[ERROR] All injection methods failed."
exit 1
