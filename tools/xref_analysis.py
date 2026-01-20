#!/usr/bin/env python3
"""
FINAL ATTEMPT: Cross-reference analysis
Find loadbuffer/pcall by analyzing WHAT CALLS what
"""

import sys, re, struct

pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
if not pid:
    import subprocess
    result = subprocess.run(['pgrep', '-f', 'sober'], capture_output=True, text=True)
    for parent in result.stdout.strip().split('\n'):
        children = subprocess.run(['pgrep', '-P', parent], capture_output=True, text=True)
        for child in children.stdout.strip().split('\n'):
            if child:
                grandchildren = subprocess.run(['pgrep', '-P', child], capture_output=True, text=True)
                for gc in grandchildren.stdout.strip().split('\n'):
                    if gc:
                        pid = int(gc)
                        break

print(f"[*] Analyzing PID {pid}")

with open(f'/proc/{pid}/maps', 'r') as f:
    for line in f:
        if 'libloader.so' in line and 'r-xp' in line:
            base = int(line.split('-')[0], 16)
            break

print(f"[+] Base: 0x{base:x}")

with open(f'/proc/{pid}/mem', 'rb') as f:
    f.seek(base)
    data = f.read(0x150000)

# Known working functions
GETTOP = 0x36600
SETTOP = 0x15600

# Find ALL call instructions
calls = {}
for i in range(len(data) - 5):
    if data[i] == 0xE8:  # CALL rel32
        offset = struct.unpack('<i', data[i+1:i+5])[0]
        target = i + 5 + offset
        if 0 < target < len(data):
            if target not in calls:
                calls[target] = []
            calls[target].append(i)

print(f"[+] Found {len(calls)} unique call targets")

# Functions that call gettop/settop are likely loadbuffer/pcall
print(f"\n[*] Functions that call gettop (0x{GETTOP:x}):")
if GETTOP in calls:
    for caller in calls[GETTOP][:10]:
        print(f"    Called from 0x{caller:x}")

print(f"\n[*] Functions that call settop (0x{SETTOP:x}):")
if SETTOP in calls:
    for caller in calls[SETTOP][:10]:
        print(f"    Called from 0x{caller:x}")

# Find functions in 200-400 byte range that call either gettop or settop
print(f"\n[*] Finding likely candidates:")
starts = [m.start() for m in re.finditer(b'\xf3\x0f\x1e\xfa', data)]

candidates = []
for func_start in starts:
    # Check size
    func_end = func_start + 500
    for j in range(func_start, min(func_end, len(data))):
        if data[j] == 0xC3:  # RET
            size = j - func_start
            break
    else:
        continue
    
    if not (200 <= size <= 400):
        continue
    
    # Check if this function calls gettop or settop
    calls_api = False
    for offset in [GETTOP, SETTOP]:
        if offset in calls:
            for call_site in calls[offset]:
                if func_start <= call_site < func_start + size:
                    calls_api = True
                    break
    
    if calls_api:
        candidates.append((func_start, size))
        print(f"    0x{func_start:x} ({size}b) - calls Lua API!")

print(f"\n[!!!] TOP 3 CANDIDATES FOR LOADBUFFER:")
for off, sz in candidates[:3]:
    print(f"    0x{off:x}")
