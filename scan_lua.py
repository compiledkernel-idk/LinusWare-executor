import struct
import sys
import os

def scan_lua_state(pid):
    maps_file = f"/proc/{pid}/maps"
    mem_file = f"/proc/{pid}/mem"
    
    code_start = 0
    code_end = 0
    mimalloc_regions = []

    with open(maps_file, 'r') as f:
        for line in f:
            parts = line.split()
            addr_range = parts[0].split('-')
            start = int(addr_range[0], 16)
            end = int(addr_range[1], 16)
            perms = parts[1]
            
            if perms == "r-xp" and code_start == 0:
                code_start = start
                code_end = end
            
            if "mimalloc" in line and "rw" in perms:
                mimalloc_regions.append((start, end))

    print(f"Code: {hex(code_start)}-{hex(code_end)}")
    print(f"Scanning {len(mimalloc_regions)} mimalloc regions for lua_State")

    with open(mem_file, 'rb', 0) as mem:
        for start, end in mimalloc_regions:
            size = end - start
            if size > 50*1024*1024: size = 50*1024*1024 # Limit scan
            
            mem.seek(start)
            data = mem.read(size)
            
            for i in range(0, len(data) - 128, 8):
                ptrs = struct.unpack('<16Q', data[i:i+128])
                
                # lua_State heuristic:
                # [1] top, [2] base, [4] l_G, [6] ci
                # Most of these should be pointers.
                
                valid = 0
                code_ptrs = 0
                for p in ptrs[:8]:
                    if p > 0x10000 and p < 0x800000000000:
                        valid += 1
                    if p >= code_start and p < code_end:
                        code_ptrs += 1
                
                if valid >= 6 and code_ptrs >= 1:
                    # check for ci -> previous chain or top > base
                    top = ptrs[1]
                    base = ptrs[2]
                    l_g = ptrs[4]
                    if top > base and (top - base) < 1000000 and l_g > 0x10000:
                         print(f"POTENTIAL LUA_STATE: {hex(start + i)}")
                         print(f"  top: {hex(top)}, base: {hex(base)}, l_G: {hex(l_g)}")
                         # Dump some of l_G
                         try:
                             mem.seek(l_g)
                             g_data = mem.read(64)
                             # In Luau, global_State has a pointer to the main thread at offset 0 or nearby
                             # but let's just see if it's readable.
                             print(f"  l_G is readable")
                         except:
                             pass

if __name__ == "__main__":
    scan_lua_state(int(sys.argv[1]))
