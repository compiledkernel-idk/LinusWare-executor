#!/usr/bin/env python3
"""
Automated Offset Finder - Brute Force Testing
Tests all loadbuffer/pcall combinations until execution works
"""

import sys
import re
import subprocess
import time
import os

def get_sober_pid():
    """Find actual Sober PID"""
    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'sober' in line.lower() and 'grep' not in line:
            parent = line.split()[1]
            # Get child
            children = subprocess.run(['pgrep', '-P', parent], capture_output=True, text=True)
            for child in children.stdout.strip().split('\n'):
                if child:
                    grandchildren = subprocess.run(['pgrep', '-P', child], capture_output=True, text=True)
                    for gc in grandchildren.stdout.strip().split('\n'):
                        if gc:
                            return int(gc)
    return None

def get_candidates(pid):
    """Scan memory and get offset candidates"""
    print(f"[*] Scanning PID {pid} for candidates...")
    
    # Read maps
    with open(f'/proc/{pid}/maps', 'r') as f:
        base = 0
        for line in f:
            if 'libloader.so' in line and 'r-xp' in line:
                base = int(line.split('-')[0], 16)
                break
    
    if not base:
        print("[-] libloader.so not found!")
        return None, [], []
    
    print(f"[+] libloader.so base: 0x{base:x}")
    
    # Read memory
    with open(f'/proc/{pid}/mem', 'rb') as f:
        f.seek(base)
        data = f.read(0x150000)
    
    # Find functions
    starts = [m.start() for m in re.finditer(b'\xf3\x0f\x1e\xfa', data)]
    print(f"[+] Found {len(starts)} functions")
    
    # Filter candidates
    lb_candidates = []
    pc_candidates = []
    
    for i, s in enumerate(starts):
        if i < len(starts) - 1:
            sz = starts[i+1] - s
        else:
            sz = 100
        
        chunk = data[s:s+sz]
        ret = chunk.find(b'\xc3')
        if ret != -1:
            sz = ret + 1
        
        # Loadbuffer: 200-400 bytes
        if 200 <= sz <= 400:
            lb_candidates.append(s)
        # Pcall: 150-180 bytes
        if 150 <= sz <= 180:
            pc_candidates.append(s)
    
    print(f"[+] Loadbuffer candidates: {len(lb_candidates)}")
    print(f"[+] Pcall candidates: {len(pc_candidates)}")
    
    return base, lb_candidates, pc_candidates

def patch_offsets(lb_offset, pc_offset):
    """Patch injected_lib.c with test offsets"""
    with open('src/core/injected_lib.c', 'r') as f:
        content = f.read()
    
    # Replace offsets
    content = re.sub(
        r'api->loadbuffer = \(luaL_loadbuffer_t\)\(libloader_base \+ 0x[0-9a-fA-F]+\);',
        f'api->loadbuffer = (luaL_loadbuffer_t)(libloader_base + 0x{lb_offset:x});',
        content
    )
    content = re.sub(
        r'api->pcall = \(lua_pcall_t\)\(libloader_base \+ 0x[0-9a-fA-F]+\);',
        f'api->pcall = (lua_pcall_t)(libloader_base + 0x{pc_offset:x});',
        content
    )
    
    with open('src/core/injected_lib.c', 'w') as f:
        f.write(content)

def test_offsets(pid, lb_offset, pc_offset):
    """Test if offsets work"""
    print(f"[*] Testing: lb=0x{lb_offset:x}, pc=0x{pc_offset:x}")
    
    # Rebuild
    result = subprocess.run(['make'], capture_output=True, cwd='.')
    if result.returncode != 0:
        print("[-] Build failed!")
        return False
    
    # Copy library
    subprocess.run(['cp', 'linusware_exec.so', '/dev/shm/linusware.so'])
    
    # Inject
    inject = subprocess.Popen(
        f'echo "0507" | sudo -S ./scripts/inject_sober.sh {pid}',
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    inject.wait(timeout=15)
    
    time.sleep(3)
    
    # Send test script
    test_script = "print('SUCCESS_MARKER_12345')"
    with open(f'/proc/{pid}/root/tmp/linusware_exec.txt', 'w') as f:
        f.write(test_script)
    
    time.sleep(4)
    
    # Check output
    try:
        with open(f'/proc/{pid}/root/tmp/linusware_output.txt', 'r') as f:
            output = f.read()
            if 'SUCCESS_MARKER_12345' in output or '✓' in output:
                print(f"[!!!] FOUND WORKING OFFSETS!")
                print(f"[!!!] loadbuffer: 0x{lb_offset:x}")
                print(f"[!!!] pcall: 0x{pc_offset:x}")
                return True
            elif 'CRASH' in output or 'ERROR' in output:
                print(f"[-] Crashed/Error")
                return False
    except:
        pass
    
    print("[-] No output (likely crashed)")
    return False

def main():
    if os.geteuid() != 0:
        print("[!] Run with sudo for memory access")
        sys.exit(1)
    
    pid = get_sober_pid()
    if not pid:
        print("[-] Sober not running!")
        sys.exit(1)
    
    print(f"[+] Found Sober PID: {pid}")
    
    base, lb_cands, pc_cands = get_candidates(pid)
    if not base:
        sys.exit(1)
    
    # Sort by most likely (closest to expected sizes)
    lb_cands.sort(key=lambda x: abs((x % 1000) - 300))  # Prefer ~300 byte functions
    pc_cands.sort(key=lambda x: abs((x % 1000) - 170))  # Prefer ~170 byte functions
    
    print(f"\n[*] Starting brute force test...")
    print(f"[*] Testing up to {len(pc_cands)} × {len(lb_cands[:50])} = {len(pc_cands) * len(lb_cands[:50])} combinations")
    
    tested = 0
    for pc_offset in pc_cands:
        for lb_offset in lb_cands[:50]:  # Limit loadbuffer to top 50
            tested += 1
            print(f"\n[{tested}] ", end='')
            
            patch_offsets(lb_offset, pc_offset)
            
            if test_offsets(pid, lb_offset, pc_offset):
                print("\n" + "="*50)
                print("SUCCESS! Working offsets found!")
                print(f"loadbuffer: 0x{lb_offset:x}")
                print(f"pcall: 0x{pc_offset:x}")
                print("="*50)
                return
            
            # Check if Sober crashed
            if not os.path.exists(f'/proc/{pid}'):
                print(f"\n[!] Sober crashed! Exiting...")
                print(f"[!] Last tested: lb=0x{lb_offset:x}, pc=0x{pc_offset:x}")
                return
            
            time.sleep(1)
    
    print("\n[-] No working offsets found in candidates")

if __name__ == '__main__':
    main()
