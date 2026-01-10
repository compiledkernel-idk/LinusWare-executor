import struct
import sys
import os

def scan_vtable_from_proc(pid):
    maps_file = f"/proc/{pid}/maps"
    mem_file = f"/proc/{pid}/mem"
    
    if not os.path.exists(maps_file):
        print(f"PID {pid} not found")
        return

    regions = []
    code_start = 0
    code_end = 0
    
    with open(maps_file, 'r') as f:
        for line in f:
            parts = line.split()
            addr_range = parts[0].split('-')
            start = int(addr_range[0], 16)
            end = int(addr_range[1], 16)
            perms = parts[1]
            
            # Find the main executable region (anonymous r-xp for Sober VMP)
            if perms == "r-xp" and code_start == 0:
                code_start = start
                code_end = end
                print(f"Target Code Region: {hex(start)}-{hex(end)}")
            
            # Scan RW regions for VTables
            if perms.startswith("rw"):
                regions.append((start, end))

    if code_start == 0:
        print("Could not find code region")
        return

    print(f"Scanning {len(regions)} RW regions for VTables targeting {hex(code_start)}-{hex(code_end)}")
    
    try:
        with open(mem_file, 'rb', 0) as mem:
            for start, end in regions:
                size = end - start
                if size > 10*1024*1024: continue # Skip huge regions
                
                try:
                    mem.seek(start)
                    data = mem.read(size)
                except Exception as e:
                    print(f"Failed to read {hex(start)}: {e}")
                    continue
                
                i = 0
                while i < len(data) - 80:
                    consecutive = 0
                    ptrs = []
                    for j in range(32):
                        if i + (j+1)*8 > len(data): break
                        ptr = struct.unpack('<Q', data[i+j*8:i+(j+1)*8])[0]
                        if ptr >= code_start and ptr < code_end:
                            consecutive += 1
                            ptrs.append(ptr)
                        else:
                            break
                    
                    if consecutive >= 16:
                        print(f"FOUND VTABLE at {hex(start + i)} Offset {hex(start + i - code_start)} Entries: {consecutive}")
                        for k in range(min(5, len(ptrs))):
                            print(f"  V[{k}]: {hex(ptrs[k])} (Offset {hex(ptrs[k] - code_start)})")
                        i += consecutive * 8
                    else:
                        i += 8
    except PermissionError:
        print("Permission Denied. Run with sudo.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scan_mem.py <pid>")
    else:
        scan_vtable_from_proc(int(sys.argv[1]))
