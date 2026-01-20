#!/bin/bash
#
# LinusWare v3 Test Script
# Injects into running Sober and tests execution
#

set -e

LOG="/tmp/linusware_v3.log"
READY="/tmp/linusware_ready"
SCRIPT="/tmp/linusware_exec.txt"
OUTPUT="/tmp/linusware_output.txt"

echo "=== LinusWare v3 Test ==="
echo ""

# Clean previous state
rm -f "$LOG" "$READY" "$OUTPUT" 2>/dev/null || true

# Check if Sober is running
SOBER_PID=$(pgrep -f "sober|org.vinegarhq.Sober" | head -1 2>/dev/null || true)

if [ -z "$SOBER_PID" ]; then
    echo "[!] Sober is not running."
    echo "[*] Start Sober first, then run this script again."
    echo ""
    echo "To start Sober:"
    echo "  flatpak run org.vinegarhq.Sober"
    echo ""
    exit 1
fi

echo "[+] Found Sober PID: $SOBER_PID"

# Find largest memory process (actual game)
echo "[*] Finding game process..."
GAME_PID=""
MAX_MEM=0

for pid in $(pgrep -f "sober" 2>/dev/null); do
    mem=$(cat /proc/$pid/statm 2>/dev/null | awk '{print $1}' || echo 0)
    if [ "$mem" -gt "$MAX_MEM" ]; then
        MAX_MEM=$mem
        GAME_PID=$pid
    fi
done

if [ -n "$GAME_PID" ]; then
    echo "[+] Game process: PID $GAME_PID (mem: $MAX_MEM pages)"
else
    GAME_PID=$SOBER_PID
    echo "[*] Using first Sober PID: $GAME_PID"
fi

# Check if library is already injected
if grep -q "linusware" /proc/$GAME_PID/maps 2>/dev/null; then
    echo "[+] Library already injected!"
else
    echo "[*] Injecting library..."
    
    # Try vm_inject first (works even with tracer)
    if [ -x "./vm_inject" ]; then
        sudo ./vm_inject 2>&1 | head -20
    elif [ -x "./injector" ]; then
        sudo ./injector "$GAME_PID" /dev/shm/linusware.so 2>&1 | head -20
    else
        echo "[!] No injector found. Build with: make"
        exit 1
    fi
fi

echo ""
echo "[*] Waiting for library initialization..."

# Wait for ready signal
for i in $(seq 1 30); do
    if [ -f "$READY" ]; then
        echo "[+] Library ready!"
        cat "$READY"
        break
    fi
    sleep 1
    echo -n "."
done
echo ""

if [ ! -f "$READY" ]; then
    echo "[!] Library did not signal ready. Check log:"
    echo ""
    cat "$LOG" 2>/dev/null || echo "(no log)"
    exit 1
fi

# Send a test script
echo "[*] Sending test script..."
echo "print('Hello from LinusWare v3!')" > "$SCRIPT"

sleep 2

if [ -f "$OUTPUT" ]; then
    echo "[+] Output received:"
    cat "$OUTPUT"
else
    echo "[!] No output received"
fi

echo ""
echo "[*] Log contents:"
cat "$LOG" 2>/dev/null | tail -30

echo ""
echo "=== Test Complete ==="
echo ""
echo "To execute scripts, write them to: $SCRIPT"
echo "Output will appear at: $OUTPUT"
echo "Log file: $LOG"
