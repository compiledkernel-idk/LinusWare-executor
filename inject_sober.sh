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

# 2. Relax Yama ptrace scope
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
fi

# 3. Find the valid target
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

echo "[*] Target PID: $TARGET"

# 4. Locate Library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_PATH="/dev/shm/sirracha.so"

if [ ! -f "$LIB_PATH" ]; then
    if [ -f "$SCRIPT_DIR/sirracha_exec.so" ]; then
        LIB_PATH="$SCRIPT_DIR/sirracha_exec.so"
    else
        echo "[ERROR] Library not found. Run 'make' first."
        exit 1
    fi
fi

# 5. Stage library (Reverted to /dev/shm for reliability)
# systemd PrivateTmp often hides /tmp, but /dev/shm is usually mounted
STAGED_NAME="sirracha_$(date +%s).so"
STAGED_PATH="/dev/shm/$STAGED_NAME"
HOST_STAGED_PATH="/proc/$TARGET/root$STAGED_PATH"

echo "[*] Staging library to $STAGED_PATH..."
cp -f "$LIB_PATH" "$HOST_STAGED_PATH" 2>/dev/null || cp -f "$LIB_PATH" "$STAGED_PATH"
chmod 777 "$HOST_STAGED_PATH" 2>/dev/null || chmod 777 "$STAGED_PATH"

if [ ! -f "$HOST_STAGED_PATH" ] && [ ! -f "$STAGED_PATH" ]; then
    echo "[!] Failed to stage library. Trying /tmp fallback..."
    STAGED_PATH="/tmp/$STAGED_NAME"
    HOST_STAGED_PATH="/proc/$TARGET/root$STAGED_PATH"
    cp -f "$LIB_PATH" "$HOST_STAGED_PATH" 2>/dev/null || cp -f "$LIB_PATH" "$STAGED_PATH"
fi

# 6. Try BINARY INJECTOR
if [ -f "$SCRIPT_DIR/injector" ]; then
    echo "[*] Method 1: Binary Injector..."
    "$SCRIPT_DIR/injector" "$TARGET" "$STAGED_PATH"
    RET=$?
    if [ $RET -eq 0 ]; then
        echo "[SUCCESS] Binary injection worked"
        rm -f "$HOST_STAGED_PATH" 2>/dev/null
        exit 0
    fi
fi

# 7. Try GDB
echo "[*] Method 2: GDB Injection..."
GDB_CMD="file /proc/$TARGET/exe; set sysroot /proc/$TARGET/root; attach $TARGET; \
        call ((void*(*)(const char*, int))dlopen)(\"$STAGED_PATH\", 2); \
        detach; quit"

GDB_OUTPUT=$(gdb -batch -ex "$GDB_CMD" 2>&1)

if echo "$GDB_OUTPUT" | grep -q "= (void *) 0x[1-9a-f]"; then
    echo "$GDB_OUTPUT" | tail -n 5
    echo "[SUCCESS] GDB Injection worked"
    rm -f "$HOST_STAGED_PATH" 2>/dev/null
    exit 0
fi

# Fallback internal symbol
if [[ "$GDB_OUTPUT" == *"Invalid data type"* ]] || [[ "$GDB_OUTPUT" == *"No symbol"* ]]; then
    echo "[!] dlopen symbol missing, trying __libc_dlopen_mode..."
    GDB_CMD="file /proc/$TARGET/exe; set sysroot /proc/$TARGET/root; attach $TARGET; \
            call ((void*(*)(const char*, int))__libc_dlopen_mode)(\"$STAGED_PATH\", 2); \
            detach; quit"
    GDB_OUTPUT=$(gdb -batch -ex "$GDB_CMD" 2>&1)
fi

echo "$GDB_OUTPUT" | tail -n 10

if grep -q "sirracha" "/proc/$TARGET/maps" 2>/dev/null; then
    echo "[SUCCESS] Library verified in maps"
    exit 0
fi

echo "[ERROR] Injection failed"
exit 1
