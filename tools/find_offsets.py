#!/usr/bin/env python3
"""
LinusWare Offset Finder
Scans running Sober process to find Luau API function offsets
"""

import os
import re
import sys
import struct

def find_sober_pid():
    """Find the main Sober process"""
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            # Check the exe symlink
            exe_path = os.readlink(f'/proc/{pid}/exe')
            if 'sober' in exe_path.lower():
                return int(pid)
            
            # Also check cmdline
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                cmdline = f.read().decode('utf-8', errors='ignore')
                if 'sober' in cmdline.lower():
                    return int(pid)
            
            # Check maps for libloader.so (Sober's main library)
            with open(f'/proc/{pid}/maps', 'r') as f:
                maps_content = f.read()
                if 'libloader.so' in maps_content:
                    return int(pid)
        except:
            pass
    return None

def get_memory_regions(pid):
    """Get all memory regions from /proc/pid/maps"""
    regions = []
    with open(f'/proc/{pid}/maps', 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 6:
                continue
            addr_range = parts[0]
            perms = parts[1]
            name = parts[-1] if len(parts) >= 6 else ''
            
            start, end = addr_range.split('-')
            start = int(start, 16)
            end = int(end, 16)
            
            regions.append({
                'start': start,
                'end': end,
                'perms': perms,
                'name': name
            })
    return regions

def read_memory(pid, addr, size):
    """Read memory from process"""
    try:
        with open(f'/proc/{pid}/mem', 'rb') as f:
            f.seek(addr)
            return f.read(size)
    except:
        return None

def find_string_refs(data, base_addr, search_strings):
    """Find references to strings in memory"""
    results = {}
    
    for s in search_strings:
        pattern = s.encode('utf-8')
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            results[s] = base_addr + idx
            print(f"  [+] Found '{s}' at 0x{base_addr + idx:x}")
            offset = idx + 1
            break  # Just first occurrence
    
    return results

def find_xrefs(data, base_addr, target_addr):
    """Find code that references a given address (LEA, MOV patterns)"""
    xrefs = []
    
    # Search for LEA patterns (common in x86_64 for string refs)
    # LEA reg, [rip + offset] -> look for the offset
    for i in range(len(data) - 8):
        # Check if there's a reference to target_addr using RIP-relative addressing
        # The instruction would be at i, and the offset would point to target_addr
        # RIP-relative: target = rip + offset, where rip = base_addr + i + instruction_length
        
        # Try different instruction lengths (typically 7 bytes for LEA)
        for inst_len in [7, 6, 5]:
            if i + inst_len > len(data):
                continue
            # Read the 4-byte offset at the end of instruction
            try:
                offset = struct.unpack('<i', data[i+inst_len-4:i+inst_len])[0]
                rip = base_addr + i + inst_len
                calculated_target = rip + offset
                
                if calculated_target == target_addr:
                    xrefs.append(base_addr + i)
            except:
                pass
    
    return xrefs

def find_function_start(data, base_addr, xref_addr):
    """Find the start of a function given a code reference"""
    offset = xref_addr - base_addr
    
    # Search backward for common function prologue patterns
    # push rbp; mov rbp, rsp -> 55 48 89 e5
    # push rbx -> 53
    # sub rsp, XX -> 48 83 ec XX or 48 81 ec XX XX XX XX
    
    for i in range(offset, max(0, offset - 0x1000), -1):
        # Check for push rbp
        if data[i:i+1] == b'\x55':
            # Verify it looks like a function start
            if i > 0 and data[i-1:i] in [b'\xc3', b'\xcc', b'\x90', b'\x00']:
                return base_addr + i
        
        # Check for endbr64 (modern function start)
        if data[i:i+4] == b'\xf3\x0f\x1e\xfa':
            return base_addr + i
    
    return None

def main():
    print("=" * 60)
    print("LINUSWARE OFFSET FINDER")
    print("=" * 60)
    
    pid = find_sober_pid()
    if not pid:
        print("[!] Sober not running")
        sys.exit(1)
    
    print(f"[+] Found Sober PID: {pid}")
    
    regions = get_memory_regions(pid)
    
    # Find libloader.so or main sober binary
    libloader_regions = [r for r in regions if 'libloader.so' in r['name'] and 'r-x' in r['perms']]
    
    if not libloader_regions:
        # Try main sober binary
        libloader_regions = [r for r in regions if '/app/bin/sober' in r['name'] and 'r-x' in r['perms']]
        if libloader_regions:
            print(f"[+] Using main sober binary instead of libloader.so")
    
    if not libloader_regions:
        # Try libbadcpu.so
        libloader_regions = [r for r in regions if 'libbadcpu.so' in r['name'] and 'r-x' in r['perms']]
        if libloader_regions:
            print(f"[+] Using libbadcpu.so")
    
    if not libloader_regions:
        # Just get any executable region
        libloader_regions = [r for r in regions if 'r-x' in r['perms'] and r['end'] - r['start'] > 1000000]
        if libloader_regions:
            print(f"[+] Using largest executable region")
    
    libloader_base = libloader_regions[0]['start']
    print(f"[+] libloader.so base: 0x{libloader_base:x}")
    
    # Key strings to search for
    search_strings = [
        "attempt to call a nil value",
        "attempt to index",
        "syntax error",
        "C stack overflow",
        "print",
        "getglobal",
        "pcall",
        "loadstring",
        "'for' initial value",
        "table index is nil",
    ]
    
    print("\n[*] Searching for key strings...")
    
    all_string_addrs = {}
    
    # Search in all readable regions
    for region in regions:
        if 'r' not in region['perms']:
            continue
        
        size = region['end'] - region['start']
        if size > 100 * 1024 * 1024:  # Skip huge regions
            continue
        
        data = read_memory(pid, region['start'], size)
        if not data:
            continue
        
        refs = find_string_refs(data, region['start'], search_strings)
        all_string_addrs.update(refs)
    
    print(f"\n[+] Found {len(all_string_addrs)} key strings")
    
    # Now find xrefs to "attempt to call a nil value" in executable code
    key_string = "attempt to call a nil value"
    if key_string in all_string_addrs:
        string_addr = all_string_addrs[key_string]
        print(f"\n[*] Searching for code that references '{key_string}'...")
        
        for region in libloader_regions:
            size = region['end'] - region['start']
            data = read_memory(pid, region['start'], size)
            if not data:
                continue
            
            xrefs = find_xrefs(data, region['start'], string_addr)
            
            for xref in xrefs[:5]:  # First 5 xrefs
                print(f"  [+] XREF at 0x{xref:x} (offset: 0x{xref - libloader_base:x})")
                
                func_start = find_function_start(data, region['start'], xref)
                if func_start:
                    print(f"      -> Function start: 0x{func_start:x} (offset: 0x{func_start - libloader_base:x})")
    
    # Output summary
    print("\n" + "=" * 60)
    print("POTENTIAL OFFSETS (relative to libloader.so base)")
    print("=" * 60)
    print(f"libloader.so base: 0x{libloader_base:x}")
    print("\nManual verification required in Ghidra.")
    print("Look for functions near these string references.")
    
    # Write findings to file
    with open('/tmp/linusware_offsets_found.txt', 'w') as f:
        f.write(f"libloader.so base: 0x{libloader_base:x}\n\n")
        f.write("String addresses found:\n")
        for s, addr in all_string_addrs.items():
            f.write(f"  '{s}': 0x{addr:x}\n")
    
    print("\n[+] Results saved to /tmp/linusware_offsets_found.txt")

if __name__ == '__main__':
    main()
