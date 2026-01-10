#!/bin/bash
# Filename: inject_sober.sh

PID=$1
LIB_PATH="/dev/shm/sirracha.so"

if [ -z "$PID" ]; then
    echo "Usage: $0 <PID>"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    exec pkexec "$0" "$@"
fi

# Find top-level watchdog
TARGET=$PID
for i in {1..5}; do
    TRACER=$(grep TracerPid "/proc/$TARGET/status" 2>/dev/null | awk '{print $2}')
    if [ -z "$TRACER" ] || [ "$TRACER" == "0" ]; then break; fi
    TRACER_NAME=$(cat "/proc/$TRACER/comm" 2>/dev/null)
    if [[ "$TRACER_NAME" == "sober" ]]; then
        TARGET=$TRACER
    else
        break
    fi
done

echo "[*] Target PID: $TARGET"

# Stage library for Flatpak visibility
STAGED_PATH="/tmp/sirracha_injected.so"
HOST_STAGED_PATH="/proc/$TARGET/root$STAGED_PATH"

echo "[*] Staging library..."
cp -f "$LIB_PATH" "$HOST_STAGED_PATH" 2>/dev/null || cp -f "$LIB_PATH" "/tmp/sirracha_injected.so"
chmod 777 "$HOST_STAGED_PATH" 2>/dev/null || chmod 777 "/tmp/sirracha_injected.so"

# Inject using multiple GDB methods
echo "[*] Attempting injection..."

GDB_CMD="set sysroot /proc/$TARGET/root; attach $TARGET; \
        call (void*)dlopen(\"$STAGED_PATH\", 2); \
        detach; quit"

# Try standard dlopen first, then fallback to __libc_dlopen_mode
GDB_OUTPUT=$(gdb -batch -ex "$GDB_CMD" 2>&1)

if [[ "$GDB_OUTPUT" == *"Invalid data type"* ]] || [[ "$GDB_OUTPUT" == *"No symbol"* ]]; then
    echo "[!] standard dlopen failed, trying internal __libc_dlopen_mode..."
    GDB_CMD="set sysroot /proc/$TARGET/root; attach $TARGET; \
            call (void*)__libc_dlopen_mode(\"$STAGED_PATH\", 2); \
            detach; quit"
    GDB_OUTPUT=$(gdb -batch -ex "$GDB_CMD" 2>&1)
fi

echo "$GDB_OUTPUT" | tail -5

if grep -q "sirracha" "/proc/$TARGET/maps" 2>/dev/null; then
    echo "[SUCCESS] Library injected into PID $TARGET"
    exit 0
fi

echo "[ERROR] Injection failed. GDB Output:"
echo "$GDB_OUTPUT"
exit 1
