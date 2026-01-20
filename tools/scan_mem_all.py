import struct
import sys
import os

def scan_vtable_all(pid):
    maps_file = f"/proc/{pid}/maps"
    mem_file = f"/proc/{pid}/mem"
    
    code_regions = []
    rw_regions = []

    with open(maps_file, 'r') as f:
        for line in f:
            parts = line.split()
            addr_range = parts[0].split('-')
            start = int(addr_range[0], 16)
            end = int(addr_range[1], 16)
            perms = parts[1]
            
            if perms == "r-xp":
                code_regions.append((start, end, parts[-1]))
            if perms.startswith("rw"):
                rw_regions.append((start, end))

    print(f"Found {len(code_regions)} code regions and {len(rw_regions)} RW regions")

    with open(mem_file, 'rb', 0) as mem:
        for rw_start, rw_end in rw_regions:
            size = rw_end - rw_start
            if size > 10*1024*1024: continue
            
            try:
                mem.seek(rw_start)
                data = mem.read(size)
            except:
                continue
                
            i = 0
            while i < len(data) - 80:
                consecutive = 0
                ptrs = []
                target_region = None
                
                for j in range(32):
                    if i + (j+1)*8 > len(data): break
                    ptr = struct.unpack('<Q', data[i+j*8:i+(j+1)*8])[0]
                    
                    found_in_any = False
                    for cs, ce, name in code_regions:
                        if ptr >= cs and ptr < ce:
                            found_in_any = True
                            if target_region is None: target_region = (cs, ce, name)
                            break
                    
                    if found_in_any:
                        consecutive += 1
                        ptrs.append(ptr)
                    else:
                        break
                
                if consecutive >= 12:
                    cs, ce, name = target_region
                    print(f"FOUND VTABLE at {hex(rw_start + i)} (Entries: {consecutive}) targeting {name}")
                    for k in range(min(3, len(ptrs))):
                        print(f"  V[{k}]: {hex(ptrs[k])} (Offset {hex(ptrs[k] - cs)})")
                    i += consecutive * 8
                else:
                    i += 8

if __name__ == "__main__":
    scan_vtable_all(int(sys.argv[1]))
