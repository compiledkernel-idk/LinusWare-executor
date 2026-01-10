import struct
import sys
import os

def final_dump(pid, l_addr, g_addr):
    mem_file = f"/proc/{pid}/mem"
    with open(mem_file, 'rb', 0) as mem:
        mem.seek(l_addr)
        l_data = mem.read(256)
        print(f"LUA_STATE at {hex(l_addr)}:")
        for i in range(0, 256, 16):
            chunk = l_data[i:i+16]
            hex_str = chunk.hex(' ')
            ptrs = struct.unpack('<2Q', chunk)
            print(f"  +0x{i:02x}: {hex_str} | {hex(ptrs[0])} {hex(ptrs[1])}")
            
        mem.seek(g_addr)
        g_data = mem.read(512)
        print(f"\nGLOBAL_STATE at {hex(g_addr)}:")
        for i in range(0, 512, 16):
            chunk = g_data[i:i+16]
            hex_str = chunk.hex(' ')
            ptrs = struct.unpack('<2Q', chunk)
            print(f"  +0x{i:02x}: {hex_str} | {hex(ptrs[0])} {hex(ptrs[1])}")

if __name__ == "__main__":
    final_dump(int(sys.argv[1]), int(sys.argv[2], 16), int(sys.argv[3], 16))
