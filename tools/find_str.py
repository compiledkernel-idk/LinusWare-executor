import sys
import os

def find_string_in_proc(pid, s):
    maps_file = f"/proc/{pid}/maps"
    mem_file = f"/proc/{pid}/mem"
    
    with open(maps_file, 'r') as f:
        for line in f:
            parts = line.split()
            addr_range = parts[0].split('-')
            start = int(addr_range[0], 16)
            end = int(addr_range[1], 16)
            perms = parts[1]
            
            if "r" not in perms: continue
            
            try:
                with open(mem_file, 'rb', 0) as mem:
                    mem.seek(start)
                    # Read in chunks
                    chunk_size = 1024*1024
                    for i in range(0, end - start, chunk_size):
                        curr_size = min(chunk_size, end - start - i)
                        data = mem.read(curr_size)
                        idx = data.find(s.encode())
                        if idx != -1:
                            print(f"FOUND '{s}' at {hex(start + i + idx)}")
            except:
                pass

if __name__ == "__main__":
    find_string_in_proc(int(sys.argv[1]), sys.argv[2])
