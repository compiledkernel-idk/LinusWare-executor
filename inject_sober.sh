#!/bin/bash
# Filename: inject_sober.sh
#
# Copyright (c) 2026 compiledkernel-idk
# All Rights Reserved.
#
# This software is proprietary and confidential. 
# Unauthorized copying, distribution, or use of this file, 
# via any medium, is strictly prohibited.


PID=$1
LIB_PATH="/dev/shm/sirracha.so"

if [ -z "$PID" ]; then
    echo "Usage: $0 <PID>"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    exec pkexec "$0" "$@"
fi

if [ ! -f "$LIB_PATH" ]; then
    echo "ERROR: Library not found at $LIB_PATH"
    exit 1
fi

if [ ! -d "/proc/$PID" ]; then
    echo "ERROR: Process $PID does not exist"
    exit 1
fi

# Relax Yama ptrace restriction
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true
fi

# Follow tracer chain to find root process
MAX_DEPTH=10
DEPTH=0
while [ $DEPTH -lt $MAX_DEPTH ]; do
    TRACER=$(grep TracerPid "/proc/$PID/status" 2>/dev/null | awk '{print $2}')
    
    if [ -z "$TRACER" ] || [ "$TRACER" == "0" ]; then
        echo "Found untraced process: PID $PID"
        break
    fi
    
    TRACER_NAME=$(cat "/proc/$TRACER/comm" 2>/dev/null)
    echo "PID $PID is traced by $TRACER_NAME (PID $TRACER)"
    
    if [[ "$TRACER_NAME" == "gdb" ]] || [[ "$TRACER_NAME" == "injector" ]]; then
        echo "Killing stuck debugger..."
        kill -9 "$TRACER" 2>/dev/null
        sleep 0.5
        break
    elif [[ "$TRACER_NAME" == "sober" ]] || [[ "$TRACER_NAME" == "bwrap" ]]; then
        echo "Following tracer chain to parent..."
        PID=$TRACER
        DEPTH=$((DEPTH + 1))
    else
        echo "WARNING: Unknown tracer '$TRACER_NAME'. Cannot proceed."
        exit 1
    fi
done

if [ $DEPTH -eq $MAX_DEPTH ]; then
    echo "ERROR: Tracer chain too deep. Possible loop detected."
    exit 1
fi

echo "Target PID for injection: $PID"

if grep -q "sirracha" "/proc/$PID/maps" 2>/dev/null; then
    echo "Library already injected into PID $PID"
    exit 0
fi

# Try nsenter-based injection (fixes namespace mismatch in Flatpak)
echo "Attempting namespace-aware injection..."

# Copy lib to /tmp so it's accessible from different namespaces (Flatpak shares /tmp)
TMP_LIB="/tmp/sirracha_$(date +%s).so"
cp "$LIB_PATH" "$TMP_LIB"
chmod 666 "$TMP_LIB"

# GDB Command with nsenter fallback
GDB_CMD="gdb -q -batch -ex \"attach $PID\" -ex \"set confirm off\" -ex \"call (void*)dlopen(\\\"$TMP_LIB\\\", 2)\" -ex \"detach\" -ex \"quit\""

# First try with nsenter
GDB_OUTPUT=$(nsenter -t "$PID" -m -p -U --preserve-credentials bash -c "$GDB_CMD" 2>&1)

# If nsenter fails or gdb failed inside, try direct gdb as fallback
if [[ $? -ne 0 ]] || echo "$GDB_OUTPUT" | grep -qi "error"; then
    echo "nsenter injection issue, trying direct gdb fallback..."
    GDB_OUTPUT=$(gdb -q -batch \
        -ex "set sysroot /proc/$PID/root" \
        -ex "attach $PID" \
        -ex "set confirm off" \
        -ex "call (void*)dlopen(\"$TMP_LIB\", 2)" \
        -ex "detach" \
        -ex "quit" 2>&1)
fi

GDB_EXIT=$?
rm -f "$TMP_LIB"

echo "$GDB_OUTPUT" >> /dev/shm/sirracha_gdb.log 2>/dev/null

if echo "$GDB_OUTPUT" | grep -qE '\$[0-9]+ = \(void \*\) 0x[1-9a-fA-F]'; then
    echo "Injection successful (dlopen returned valid pointer)"
    exit 0
fi

if echo "$GDB_OUTPUT" | grep -qE '\$[0-9]+ = \(void \*\) 0x0'; then
    echo "ERROR: dlopen returned NULL - library failed to load"
    echo "Check: $LIB_PATH exists and is accessible from sandbox"
    exit 1
fi

if echo "$GDB_OUTPUT" | grep -qi "ptrace: Operation not permitted"; then
    echo "ERROR: Cannot attach to process (permission denied)"
    echo "Process may be traced by another debugger"
    exit 1
fi

if echo "$GDB_OUTPUT" | grep -qi "No such process"; then
    echo "ERROR: Process $PID no longer exists"
    exit 1
fi

sleep 0.5
if grep -q "sirracha" "/proc/$PID/maps" 2>/dev/null; then
    echo "Injection verified via /proc maps"
    exit 0
fi

echo "WARNING: Injection result unclear"
echo "GDB output: $GDB_OUTPUT"
exit 1
