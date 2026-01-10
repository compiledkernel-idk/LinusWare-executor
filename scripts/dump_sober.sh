#!/bin/bash
# dump_sober.sh - Automates dumping the Sober binary for reverse engineering
# Usage: ./dump_sober.sh

echo "[-] Looking for Sober process..."
PID=$(pgrep -f "sober" | head -n 1)

if [ -z "$PID" ]; then
    echo "[!] Sober not found! Please launch Sober and join a game first."
    exit 1
fi

echo "[*] Found Sober PID: $PID"

# Try to find libloader.so (Older Sober)
LIB_PATH=$(grep "libloader.so" "/proc/$PID/maps" | head -n 1 | awk '{print $6}')

if [ ! -z "$LIB_PATH" ]; then
    echo "[*] Found libloader.so at: $LIB_PATH"
    OUT_FILE="libloader_dump.so"
    
    # Handle Flatpak path
    FULL_PATH="/proc/$PID/root$LIB_PATH"
    
    echo "[-] Copying..."
    cp "$FULL_PATH" "./$OUT_FILE"
    
    if [ $? -eq 0 ]; then
        echo "[SUCCESS] Dumped to $(pwd)/$OUT_FILE"
        echo "Now open this file in Ghidra!"
        exit 0
    fi
fi

# Fallback: Main Binary (Newer Sober)
echo "[!] libloader.so not found (likely merged into main binary)."
echo "[-] Dumping main executable..."

OUT_FILE="sober_dump.bin"
cp "/proc/$PID/exe" "./$OUT_FILE"

if [ $? -eq 0 ]; then
    echo "[SUCCESS] Dumped main binary to $(pwd)/$OUT_FILE"
    echo "Now open this file in Ghidra!"
    exit 0
fi

echo "[FAIL] Could not dump binary. Try running as root?"
