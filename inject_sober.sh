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

echo "[*] Injecting into PID $TARGET"

# Inject using the working GDB method
GDB_OUTPUT=$(gdb -batch \
    -ex "set sysroot /proc/$TARGET/root" \
    -ex "attach $TARGET" \
    -ex "set \$dlopen = (void*(*)(char*, int))dlopen" \
    -ex "call \$dlopen(\"$LIB_PATH\", 2)" \
    -ex "detach" \
    -ex "quit" 2>&1)

echo "$GDB_OUTPUT" | tail -5

if grep -q "sirracha" "/proc/$TARGET/maps" 2>/dev/null; then
    echo "[SUCCESS] Library injected into PID $TARGET"
    exit 0
fi

echo "[ERROR] Injection failed"
exit 1
