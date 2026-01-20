import struct
import sys

def scan_relative_table(filename, base_addr):
    with open(filename, 'rb') as f:
        data = f.read()

    code_start = 0x55beaf5c0000
    code_end = code_start + 5672960

    print(f"Scanning {filename} for relative offsets (32-bit) in range {hex(code_start)}-{hex(code_end)}")

    found_tables = 0
    i = 0
    while i < len(data) - 256:
        consecutive = 0
        potential_table = []
        for j in range(128):
            if i + (j+1)*4 > len(data): break
            offset = struct.unpack('<i', data[i+j*4:i+(j+1)*4])[0]
            # addr = base_addr + current_pos + offset
            addr = (base_addr + i + j*4) + offset
            
            if addr >= code_start and addr < code_end:
                consecutive += 1
                potential_table.append(addr)
            else:
                break
        
        if consecutive >= 64:
            print(f"Found potential RELATIVE table at Offset {hex(i)} (Addr {hex(base_addr + i)}) Entries: {consecutive}")
            for k in range(min(15, len(potential_table))):
                print(f"  [{k}]: {hex(potential_table[k])} (Offset {hex(potential_table[k] - code_start)})")
            i += consecutive * 4
            found_tables += 1
        else:
            i += 4
    
    print(f"Total tables found: {found_tables}")

if __name__ == "__main__":
    scan_relative_table("sober_dump_0x55beaf5c0000_5672960_r-xp.bin", 0x55beaf5c0000)
