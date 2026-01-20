#!/bin/bash
PID=59304
echo "[*] TARGET PID: $PID"
mkdir -p libs_extracted

# Copy libloader first
cp /proc/$PID/root/app/bin/libloader.so libs_extracted/ 2>/dev/null
cp /proc/$PID/root/app/bin/*.so libs_extracted/ 2>/dev/null

echo "Extracted:"
ls -lh libs_extracted/
