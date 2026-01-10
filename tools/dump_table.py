import struct
import sys
import os

def dump_table(pid, addr):
    mem_file = f"/proc/{pid}/mem"
    with open(mem_file, 'rb', 0) as mem:
        mem.seek(addr)
        h_data = mem.read(64)
        # lsizenode is usually at offset 1 or similar
        print(f"Table Header at {hex(addr)}: {h_data.hex(' ')}")
        
        # Luau Table structure:
        # Common layout: array (8), lsizenode (4), node (8)
        # Or similar. Let's look for pointers in the host region.
        
        ptrs = struct.unpack('<8Q', h_data)
        for i, p in enumerate(ptrs):
            if p > 0x10000 and p < 0x800000000000:
                 print(f"  Ptr[{i}]: {hex(p)}")
                 # If it's the node array, let's dump a few nodes
                 # Node: { TValue val, TValue key, Node* next }
                 # TValue: 16 bytes. Node: 40 bytes?
                 try:
                     mem.seek(p)
                     nodes = mem.read(400)
                     print(f"    Node data at {hex(p)} readable")
                 except:
                     pass

if __name__ == "__main__":
    dump_table(int(sys.argv[1]), int(sys.argv[2], 16))
