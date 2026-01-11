#!/usr/bin/env python3
import sys
import re

def dump_ram(pid, filename):
    print(f"[-] Reading maps for PID {pid}...")
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Process not found.")
        sys.exit(1)

    # Find the largest executable region (r-xp) which is likely the unpacked text segment
    target_start = 0
    target_end = 0
    max_size = 0

    for line in lines:
        parts = line.split()
        if len(parts) < 5: continue
        
        perms = parts[1]
        addr_range = parts[0]
        
        if "x" in perms: # Executable
            s, e = addr_range.split("-")
            start = int(s, 16)
            end = int(e, 16)
            size = end - start
            
            # Heuristic: The main game code is usually huge (e.g. > 10MB)
            # or it's the specific binary mapping.
            # We'll look for the largest exec segment associated with 'sober' or main binary
            path = parts[5] if len(parts) > 5 else ""
            
            if size > max_size:
                max_size = size
                target_start = start
                target_end = end
                print(f"[*] Found candidate: {addr_range} ({size/1024/1024:.2f} MB) {path}")

    if target_start == 0:
        print("[!] No suitable executable region found.")
        sys.exit(1)

    print(f"[-] Dumping memory {hex(target_start)} - {hex(target_end)} ({max_size/1024/1024:.2f} MB)...")
    
    try:
        with open(f"/proc/{pid}/mem", "rb") as mem:
            mem.seek(target_start)
            data = mem.read(max_size)
            with open(filename, "wb") as out:
                out.write(data)
                print(f"[SUCCESS] Dumped RAM segment to {filename}")
    except PermissionError:
        print("[!] Permission denied. Try running as root (sudo).")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 dump_ram.py <PID> <OUTPUT_FILE>")
        sys.exit(1)
    
    dump_ram(sys.argv[1], sys.argv[2])
