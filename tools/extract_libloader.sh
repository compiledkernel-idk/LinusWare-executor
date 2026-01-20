#!/bin/bash
# Extract libloader.so from running Sober for Ghidra analysis

echo "[*] Finding Sober process..."
SOBERPID=$(ps aux | grep -m1 sober | grep -v grep | awk '{print $2}')
for p in $(pgrep -P $SOBERPID 2>/dev/null); do 
  REALPID=$(pgrep -P $p 2>/dev/null | head -1)
done

if [ -z "$REALPID" ]; then
  echo "[!] Sober not running! Please start Sober first."
  exit 1
fi

echo "[+] Found Sober PID: $REALPID"

# Find libloader.so path
LIBPATH=$(grep libloader.so /proc/$REALPID/maps | grep r-xp | head -1 | awk '{print $6}')
echo "[+] Library path: $LIBPATH"

# Copy to current directory
if [ -f "/proc/$REALPID/root$LIBPATH" ]; then
  sudo cp "/proc/$REALPID/root$LIBPATH" ./libloader_extracted.so
  sudo chmod 644 ./libloader_extracted.so
  sudo chown $USER:$USER ./libloader_extracted.so
  echo "[+] Extracted to: ./libloader_extracted.so"
  ls -lh ./libloader_extracted.so
else
  echo "[!] Could not find library file"
  exit 1
fi

echo ""
echo "✓ Ready for Ghidra analysis!"
echo "  File: $(pwd)/libloader_extracted.so"
