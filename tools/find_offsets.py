
import os
import sys
import re

def get_pid():
    # Find the main Sober process
    # Usually the one with the largest memory footprint or child of the wrapper
    # We look for the process that has the game loops
    try:
        pids = [p for p in os.listdir('/proc') if p.isdigit()]
        sober_pids = []
        for pid in pids:
            try:
                with open(f'/proc/{pid}/cmdline', 'rb') as f:
                    cmd = f.read()
                    if b'sober' in cmd or b'org.vinegarhq.Sober' in cmd:
                        sober_pids.append(pid)
            except:
                continue
        
        # Heuristic: The PID with the most maps/memory is likely the game
        best_pid = None
        max_maps = 0
        
        for pid in sober_pids:
            try:
                with open(f'/proc/{pid}/maps', 'r') as f:
                    count = len(f.readlines())
                    if count > max_maps:
                        max_maps = count
                        best_pid = pid
            except:
                continue
                
        return best_pid
    except Exception as e:
        print(f"Error finding PID: {e}")
        return None

def scan_mem(pid):
    print(f"[*] Scanning PID: {pid}")
    
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    
    regions = []
    
    # Identify the main game code region (r-xp)
    # Usually a very large executable blob (100MB+) or named 'libloader.so'
    base_addr = 0
    target_regions = []
    
    try:
        with open(maps_path, 'r') as f:
            for line in f:
                parts = line.split()
                flags = parts[1]
                
                # Check size - ANY readable region > 1MB
                start = int(parts[0].split('-')[0], 16)
                end = int(parts[0].split('-')[1], 16)
                size = end - start
                
                path = parts[-1] if len(parts) > 5 else "[anon]"
                
                if size > 1 * 1024 * 1024: # > 1MB
                    target_regions.append((start, end, size))
                    if 'libloader' in path and base_addr == 0: base_addr = start
                    print(f"[?] Region: {hex(start)}-{hex(end)} ({size//1024//1024} MB) {flags} {path}")

    except Exception as e:
        print(f"Error parsing maps: {e}")
        return

    if not target_regions:
        print("No suitable regions found.")
        return

    # Targets: ".invalid filename" OR "Current identity is"
    target_strs = [b".invalid filename", b"Current identity is"]
    
    found_str_addr = 0
    
    try:
        mem = open(mem_path, 'rb', buffering=0)
        
        for start, end, size in target_regions:
            try:
                mem.seek(start)
                chunk = mem.read(size)
                
                for target_str in target_strs:
                    offset = chunk.find(target_str)
                    if offset != -1:
                        found_str_addr = start + offset
                        print(f"[+] Found '{target_str.decode()}' at: {hex(found_str_addr)}")
                        
                        # Set Base Address to this region start if not set
                        if base_addr == 0: base_addr = start
                        
                        # Find Reference logic (Simplified for now)
                        # ...
                    break
            except Exception as e:
                print(f"Read error at {hex(start)}: {e}")
                continue
                
        if found_str_addr != 0:
            # Now find the Reference (LEA/MOV)
            # This is harder because x64 uses RIP-relative addressing
            # Instruction: [Opcode] [Offset]
            # Target = RIP + Offset
            # RIP = InstructionAddr + InstructionLength
            
            # We scan the same code regions for any instruction that resolves to found_str_addr
            print("[*] Scan for references & patterns...")
            
            for start, end, size in target_regions:
                # Filter system libs
                if start > 0x700000000000: continue
                # if '/usr' in path: continue

                try:
                    mem.seek(start)
                    print(f"    Scanning region {hex(start)} ({size//1024//1024} MB)...")
                    chunk = mem.read(size)
                except Exception as e:
                    # print(f"    Skipping region {hex(start)}: {e}")
                    continue
                
                # 1. Scan for Code Pattern (Current Identity logic)
                import re
                code_sig = re.compile(b'[\x31\x33]\xff\x44\x89\xf2\x31\xc0\xe8')
                
                # 1b. Scan for lua_gettop signature
                # Standard: 48 8B 47 ?? (mov rax, [rdi+TOP])
                #           48 2B 07    (sub rax, [rdi+BASE])
                #           48 C1 F8 04 (sar rax, 4) or SH/R
                #           C3          (ret)
                # Regex: \x48\x8b[\x47\x57].\x48\x2b.\x48\xc1[\xf8\xe8]\x04
                gettop_sig = re.compile(b'\x48\x8b[\x47\x57].\x48\x2b.\x48\xc1[\xf8\xe8]\x04')
                
                for match in gettop_sig.finditer(chunk):
                    print(f"[!!!] FOUND lua_gettop SIGNATURE at {hex(start + match.start())}")
                    # If found, this IS the code region.
                    # Base of this region is our Code Base.
                    print(f"      Use this region base for offsets: {hex(start)}")
                    
                    found_addr = start + match.start()
                    # Calculate offset
                    print(f"      Offset: {hex(found_addr - start)}")

                for match in code_sig.finditer(chunk):
                    print(f"[!!!] FOUND CODE PATTERN at {hex(start + match.start())}")
                    # The CALL is at offset + 7 (last byte of pattern is E8)
                    # The instruction is E8 XX XX XX XX
                    call_addr = start + match.start() + 7
                    if call_addr + 5 <= start + size:
                         rel = int.from_bytes(chunk[match.start()+8:match.start()+12], byteorder='little', signed=True)
                         target = call_addr + 5 + rel
                         print(f"      CALL Target: {hex(target)}")
                         
                         # If this is sub_2AC8D00, then Base = Target - 0x2AC8D00
                         calc_base = target - 0x2AC8D00
                         print(f"      Calculated Base: {hex(calc_base)}")
                         
                         # Check if the LEA RSI is before it? (Offset -7 bytes from start)
                         # 48 8D 35 ...
                         
                # 2. Scan for Lyric String (Anchor)
                lyric_off = chunk.find(b"Walking on eggshells")
                if lyric_off != -1:
                    print(f"[!!!] FOUND LYRICS at {hex(start + lyric_off)}")
                    # We are in .rodata
                
                # 3. LEA Scan for .invalid filename (if not found yet)
                if found_str_addr != 0:
                    # Method A: Relative Reference (LEA/MOV [RIP+...])
                    import re
                    lea_pattern = re.compile(b'\x48\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
                    
                    for match in lea_pattern.finditer(chunk):
                        i = match.start()
                        if i + 7 > len(chunk): continue
                        rel = int.from_bytes(chunk[i+3:i+7], byteorder='little', signed=True)
                        rip = start + i + 7
                        target = rip + rel
                        
                        if target == found_str_addr:
                            print(f"[!] FOUND RELATIVE REF (LEA) at {hex(start+i)}")
                            # Logic to find prologue...
                            func_addr = start + i # placeholder
                            # Walk back...
                            sub_chunk = chunk[max(0, i-500):i+1]
                            prologue_idx = sub_chunk.rfind(b'\x55\x48\x89\xe5')
                            if prologue_idx != -1:
                                func_addr = start + max(0, i-500) + prologue_idx
                                print(f"    [+] PROLOGUE at {hex(func_addr)}")
                            
                            print(f"OFFSET: {hex(func_addr - base_addr)}")

                    # Method B: Absolute Pointer Scan (MOV REG, IMM64 / Data Table)
                    # Search for the 8-byte address: found_str_addr
                    ptr_bytes = found_str_addr.to_bytes(8, byteorder='little')
                    ptr_idx = chunk.find(ptr_bytes)
                    if ptr_idx != -1:
                         print(f"[!!!] FOUND ABSOLUTE POINTER at {hex(start + ptr_idx)}")
                         print(f"      This location stores the address of '.invalid filename'")
                         # If in Code (r-xp), it's likely: MOV REG, IMM64 (48 B8 ...ADDR...)
                         # Check previous 2 bytes for 48 B8 (MOV RAX) or similar
                         if ptr_idx >= 2:
                             b1 = chunk[ptr_idx-2]
                             b2 = chunk[ptr_idx-1]
                             print(f"      Bytes before: {hex(b1)} {hex(b2)}")
                             if b1 == 0x48 and (b2 & 0xB8) == 0xB8:
                                  print(f"      [+] Looks like MOV REG, IMM64 instruction!")
                                  
                         # Walk back to find prologue...
                         func_addr = start + ptr_idx
                         sub_chunk = chunk[max(0, ptr_idx-500):ptr_idx+1]
                         prologue_idx = sub_chunk.rfind(b'\x55\x48\x89\xe5')
                         if prologue_idx != -1:
                                func_addr = start + max(0, ptr_idx-500) + prologue_idx
                                print(f"    [+] PROLOGUE at {hex(func_addr)}")

    except Exception as e:
        print(f"Scan error: {e}")
        
if __name__ == "__main__":
    if len(sys.argv) > 1:
        pid = sys.argv[1]
    else:
        pid = get_pid()
        
    if pid:
        scan_mem(pid)
    else:
        print("No PID found.")
