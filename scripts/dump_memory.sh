#!/bin/bash
# Quick script to dump Sober's decrypted memory using the injected library

set -e

echo "[*] Finding Sober process..."
SOBER_PID=$(pgrep -f "/app/bin/sober" | head -1)

if [ -z "$SOBER_PID" ]; then
    echo "[!] Sober not running. Please start Sober first."
    exit 1
fi

echo "[+] Found Sober at PID $SOBER_PID"

# Check if library is already injected
if grep -q "linusware" "/proc/$SOBER_PID/maps" 2>/dev/null; then
    echo "[+] Library already injected, sending dump command..."
else
    echo "[*] Injecting library..."
    ./inject_sober.sh "$SOBER_PID"
    
    if [ $? -ne 0 ]; then
        echo "[!] Injection failed"
        exit 1
    fi
    
    echo "[*] Waiting for library to initialize..."
    sleep 3
fi

# Send dump command
echo "[*] Requesting memory dump..."
echo "__DUMP__" > "/proc/$SOBER_PID/root/tmp/linusware_exec.txt"

# Wait for dump to complete
echo "[*] Dumping memory (this may take a few seconds)..."
sleep 5

# Check output
if [ -f "/proc/$SOBER_PID/root/tmp/linusware_output.txt" ]; then
    cat "/proc/$SOBER_PID/root/tmp/linusware_output.txt"
    echo ""
fi

# Find the dump file
DUMP_FILE=$(ls -t /proc/$SOBER_PID/root/tmp/sober_decrypted_*.bin 2>/dev/null | head -1)

if [ -n "$DUMP_FILE" ]; then
    echo ""
    echo "=== DUMP SUCCESSFUL ==="
    echo "File location (inside container): $DUMP_FILE"
    
    # Copy to host
    HOST_FILE="./$(basename $DUMP_FILE)"
    cp "$DUMP_FILE" "$HOST_FILE" 2>/dev/null || sudo cp "$DUMP_FILE" "$HOST_FILE"
    
    if [ -f "$HOST_FILE" ]; then
        chmod 666 "$HOST_FILE"
        echo "Copied to host: $HOST_FILE"
        echo ""
        echo "File size: $(du -h $HOST_FILE | cut -f1)"
        echo ""
        echo "Next steps:"
        echo "  1. Open Ghidra"
        echo "  2. Import as 'Raw Binary'"
        echo "  3. Set base address to the value shown above"
        echo "  4. Analyze and search for Luau function patterns"
        echo "  5. Update roblox_offsets.h with found offsets"
    else
        echo "Warning: Could not copy to host, file is at: $DUMP_FILE"
    fi
else
    echo "[!] Dump file not found. Check debug log:"
    tail -20 "/proc/$SOBER_PID/root/tmp/linusware_debug.log" 2>/dev/null || echo "No log available"
fi
