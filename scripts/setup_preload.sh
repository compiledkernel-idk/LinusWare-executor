#!/bin/bash
# setup_preload.sh - Setup LD_PRELOAD injection for Sober
# 
# Copyright (c) 2026 sultan
# PROPRIETARY AND CONFIDENTIAL

set -e

LIBRARY="/dev/shm/linusware.so"

echo "=== LinusWare LD_PRELOAD Setup ==="
echo ""

# Check library exists
if [ ! -f "$LIBRARY" ]; then
    echo "[!] Library not found: $LIBRARY"
    echo "    Run: make linusware_preload.so"
    exit 1
fi

echo "[1] Library ready: $LIBRARY"
ls -la "$LIBRARY"
echo ""

# Clear old logs
rm -f /tmp/linusware_debug.log /tmp/linusware_ready /tmp/linusware_exec.txt
echo "[2] Cleared old logs"

# Set Flatpak override (no sudo needed for --user)
echo "[3] Setting up Flatpak LD_PRELOAD override..."

flatpak override --user org.vinegarhq.Sober --env=LD_PRELOAD="$LIBRARY"

echo "[✓] Override set successfully!"
echo ""
echo "=== INSTRUCTIONS ==="
echo ""
echo "1. Start Sober normally:"
echo "   flatpak run org.vinegarhq.Sober"
echo ""
echo "2. Join any Roblox game"
echo ""
echo "3. Wait for ready signal:"
echo "   watch -n1 cat /tmp/linusware_ready"
echo ""
echo "4. Check logs:"
echo "   tail -f /tmp/linusware_debug.log"
echo ""
echo "5. Execute scripts by writing to:"
echo "   echo 'print(\"Hello\")' > /tmp/linusware_exec.txt"
echo ""
echo "6. Read output:"
echo "   cat /tmp/linusware_output.txt"
echo ""
echo "=== TO REMOVE ==="
echo "sudo flatpak override --user org.vinegarhq.Sober --unset-env=LD_PRELOAD"
echo ""
