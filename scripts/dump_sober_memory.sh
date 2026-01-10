#!/bin/bash
# Dump Sober's decrypted memory for analysis

set -e

# Find Sober PID
SOBER_PID=$(pgrep -f "/app/bin/sober" | head -1)

if [ -z "$SOBER_PID" ]; then
    echo "[!] Sober process not found"
    exit 1
fi

echo "[*] Found Sober at PID $SOBER_PID"
echo "[*] Executable: $(readlink /proc/$SOBER_PID/exe)"

# Create output directory
DUMP_DIR="sober_dumps_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DUMP_DIR"
cd "$DUMP_DIR"

echo "[*] Dumping memory maps..."
cp /proc/$SOBER_PID/maps ./maps.txt

echo "[*] Extracting executable regions..."
grep "r-xp" maps.txt > exec_regions.txt

echo ""
echo "=== Executable Regions ==="
cat exec_regions.txt

# Dump main executable region
echo ""
echo "[*] Dumping main executable..."
MAIN_REGION=$(grep -E "r-xp.*sober" maps.txt | head -1)

if [ -n "$MAIN_REGION" ]; then
    START=$(echo $MAIN_REGION | awk '{print $1}' | cut -d'-' -f1)
    END=$(echo $MAIN_REGION | awk '{print $1}' | cut -d'-' -f2)
    
    echo "    Start: 0x$START"
    echo "    End:   0x$END"
    
    START_DEC=$((16#$START))
    END_DEC=$((16#$END))
    SIZE=$((END_DEC - START_DEC))
    
    echo "    Size:  $SIZE bytes ($((SIZE / 1024 / 1024)) MB)"
    
    # Use gdb to dump memory (more reliable than dd from /proc/mem)
    gdb -batch \
        -ex "attach $SOBER_PID" \
        -ex "dump memory main_exec.bin 0x$START 0x$END" \
        -ex "detach" \
        -ex "quit" 2>/dev/null
    
    if [ -f main_exec.bin ]; then
        echo "[+] Dumped main executable to main_exec.bin"
        
        # Search for interesting strings
        echo ""
        echo "[*] Searching for interesting strings..."
        
        echo ""
        echo "=== DataModel References ==="
        strings main_exec.bin | grep -i "datamodel" | head -20
        
        echo ""
        echo "=== Luau/Lua References ==="
        strings main_exec.bin | grep -iE "luau|lua_|vm" | head -20
        
        echo ""
        echo "=== Script/Execute References ==="
        strings main_exec.bin | grep -iE "script|execute|runstring" | head -20
        
        echo ""
        echo "=== API/Function References ==="
        strings main_exec.bin | grep -iE "getchildren|findchild|getservice" | head -20
    fi
fi

# Also dump all executable regions
echo ""
echo "[*] Dumping all executable regions..."
REGION_NUM=0
while IFS= read -r region; do
    START=$(echo $region | awk '{print $1}' | cut -d'-' -f1)
    END=$(echo $region | awk '{print $1}' | cut -d'-' -f2)
    NAME=$(echo $region | awk '{print $6}')
    
    if [ -z "$NAME" ]; then
        NAME="anon_$REGION_NUM"
    else
        NAME=$(basename "$NAME")
    fi
    
    OUTFILE="region_${REGION_NUM}_${NAME}.bin"
    
    gdb -batch \
        -ex "attach $SOBER_PID" \
        -ex "dump memory $OUTFILE 0x$START 0x$END" \
        -ex "detach" \
        -ex "quit" 2>/dev/null || true
    
    if [ -f "$OUTFILE" ]; then
        SIZE=$(stat -c%s "$OUTFILE")
        echo "    [$REGION_NUM] $NAME: $SIZE bytes"
    fi
    
    REGION_NUM=$((REGION_NUM + 1))
done < exec_regions.txt

echo ""
echo "[+] Memory dump complete!"
echo "[*] Output directory: $(pwd)"
echo ""
echo "Next steps:"
echo "  1. Analyze with: strings main_exec.bin | less"
echo "  2. Disassemble with: objdump -D -b binary -m i386:x86-64 main_exec.bin | less"
echo "  3. Use Ghidra/IDA to load main_exec.bin for deeper analysis"
