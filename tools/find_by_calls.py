#!/usr/bin/env python3
"""
Find working offsets by analyzing Sober's own function calls
Instead of guessing, we find where Sober ITSELF calls lua functions
"""

import sys
import struct

def find_call_targets(pid, base, func_offset):
    """Find what addresses are called from a function"""
    with open(f'/proc/{pid}/mem', 'rb') as f:
        f.seek(base + func_offset)
        code = f.read(500)
    
    calls = []
    for i in range(len(code) - 5):
        # Look for CALL instruction (E8 xx xx xx xx)
        if code[i] == 0xE8:
            # Relative call
            offset = struct.unpack('<i', code[i+1:i+5])[0]
            target = func_offset + i + 5 + offset
            if 0 < target < 0x100000:  # Reasonable range
                calls.append(target)
    
    return calls

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 find_by_calls.py <PID>")
        sys.exit(1)
    
    pid = int(sys.argv[1])
    
    # Find libloader base
    with open(f'/proc/{pid}/maps', 'r') as f:
        for line in f:
            if 'libloader.so' in line and 'r-xp' in line:
                base = int(line.split('-')[0], 16)
                break
    
    print(f"[+] libloader.so base: 0x{base:x}")
    
    # Known working functions
    GETTOP = 0x36600
    SETTOP = 0x15600
    
    print(f"\n[*] Analyzing what gettop (0x{GETTOP:x}) calls...")
    gettop_calls = find_call_targets(pid, base, GETTOP)
    print(f"    Calls: {[hex(c) for c in gettop_calls]}")
    
    print(f"\n[*] Analyzing what settop (0x{SETTOP:x}) calls...")
    settop_calls = find_call_targets(pid, base, SETTOP)
    print(f"    Calls: {[hex(c) for c in settop_calls]}")
    
    # Now scan for functions that call gettop/settop
    # These are likely loadbuffer/pcall
    print(f"\n[*] Searching for functions that call gettop/settop...")
    
    with open(f'/proc/{pid}/mem', 'rb') as f:
        f.seek(base + 0x10000)
        code = f.read(0x90000)
    
    candidates = []
    for offset in [GETTOP, SETTOP]:
        # Convert offset to relative call bytes
        for i in range(len(code) - 5):
            if code[i] == 0xE8:  # CALL
                rel = struct.unpack('<i', code[i+1:i+5])[0]
                target = 0x10000 + i + 5 + rel
                if abs(target - offset) < 0x10:  # Close to our known function
                    caller = 0x10000 + i
                    # Find function start (look back for endbr64)
                    for j in range(i, max(0, i-1000), -1):
                        if code[j:j+4] == b'\xf3\x0f\x1e\xfa':
                            func_start = 0x10000 + j
                            candidatesize = i - j
                            if 200 < size < 600:
                                candidates.append(func_start)
                                print(f"    Found caller at 0x{func_start:x} (size ~{size} bytes)")
                            break
    
    print(f"\n[+] Top candidates for loadbuffer/pcall:")
    for c in set(candidates[:10]):
        print(f"    0x{c:x}")

if __name__ == '__main__':
    main()
