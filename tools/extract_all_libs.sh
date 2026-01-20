#!/bin/bash

echo "[*] Detecting Sober..."
SOBERPID=$(pgrep -f "org.vinegarhq.Sober" | head -1)

if [ -z "$SOBERPID" ]; then
    echo "[!] Sober not running. Please start it to extract libraries."
    exit 1
fi

echo "[+] Sober PID: $SOBERPID"

# Create libs directory
mkdir -p libs_extracted

echo "[*] Extracting libraries from memory maps..."
# Find all mapped .so files that belong to the app
grep "\.so" /proc/$SOBERPID/maps | grep "/app/" | awk '{print $6}' | sort | uniq | while read lib; do
    FNAME=$(basename "$lib")
    
    # Check if we can access the file via /proc/PID/root
    SRC_PATH="/proc/$SOBERPID/root$lib"
    
    if [ -f "$SRC_PATH" ]; then
        echo "  -> Copying $FNAME..."
        cp "$SRC_PATH" "./libs_extracted/$FNAME"
    else
        echo "  [?] Could not access $lib (virtual path?)"
    fi
done

echo "[*] Copying extracted libloader too..."
if [ -f "libloader_extracted.so" ]; then
    cp libloader_extracted.so libs_extracted/libloader.so
fi

echo ""
echo "✓ Extraction complete in ./libs_extracted/"
echo "Run with: LD_LIBRARY_PATH=./libs_extracted ./linus_runner ./libs_extracted/libloader.so"
