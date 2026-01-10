import struct
import sys
import os

def solve_offsets(pid, l_addr):
    mem_file = f"/proc/{pid}/mem"
    maps_file = f"/proc/{pid}/maps"
    
    code_start = 0
    with open(maps_file, 'r') as f:
        for line in f:
            if "r-xp" in line and code_start == 0:
                code_start = int(line.split('-')[0], 16)
                break
    
    print(f"Code Start: {hex(code_start)}")
    
    with open(mem_file, 'rb', 0) as mem:
        # Read L
        mem.seek(l_addr)
        l_data = mem.read(128)
        ptrs = struct.unpack('<16Q', l_data)
        
        top = ptrs[1]
        base = ptrs[2]
        l_g = ptrs[4]
        
        print(f"L: {hex(l_addr)}")
        print(f"  top: {hex(top)}")
        print(f"  base: {hex(base)}")
        print(f"  l_G: {hex(l_g)}")

        # In Luau, global_State structure:
        # TValue registry; (at offset 16-32 approx)
        # TValue gt; (global table at offset 32-48 approx)
        
        mem.seek(l_g)
        g_data = mem.read(256)
        
        # Scan for the global table (tt = 7 in TValue)
        # Luau TValue: { Value v, int extra, int tt } or { Value v, int tt }
        # Based on previous logs, Tags were re-biased.
        # But Table is usually a pointer to a structure with lsizenode.
        
        for offset in range(0, 128, 8):
            val = struct.unpack('<Q', g_data[offset:offset+8])[0]
            if val > 0x10000 and val < 0x800000000000:
                # Check if it's a Table
                try:
                    mem.seek(val)
                    h_data = mem.read(32)
                    lsizenode = h_data[1]
                    if lsizenode > 0 and lsizenode < 32:
                         # Potential Table!
                         print(f"Global Table Candidate at l_G + {offset}: {hex(val)} (lsizenode {lsizenode})")
                         
                         # Scan table for "print"
                         # Luau Table has Node* node at offset 16 or 24
                         # Let's just scan all pointers in the global_State.
                except:
                    pass

solve_offsets(int(sys.argv[1]), int(sys.argv[2], 16))
