#!/usr/bin/env python3
"""
Automated Luau Offset Finder
Brute-force tests function candidates in running Sober
"""

import struct
import subprocess
import time

def get_sober_pid():
    """Find Sober PID"""
    result = subprocess.run(['pgrep', '-f', 'sober'], capture_output=True, text=True)
    pids = result.stdout.strip().split('\n')
    return pids[0] if pids and pids[0] else None

def read_mem(pid, addr, size):
    """Read memory from process"""
    try:
        with open(f'/proc/{pid}/mem', 'rb') as f:
            f.seek(addr)
            return f.read(size)
    except:
        return None

def get_libloader_base(pid):
    """Find libloader.so base address"""
    with open(f'/proc/{pid}/maps', 'r') as f:
        for line in f:
            if 'libloader.so' in line and 'r-xp' in line:
                return int(line.split('-')[0], 16)
    return None

def find_function_candidates(pid, base):
    """Find functions by looking for endbr64 (0xf3 0x0f 0x1e 0xfa)"""
    code_start = base + 0x14000  # typical .text offset
    code_size = 0x96000  # ~600KB
    
    data = read_mem(pid, code_start, code_size)
    if not data:
        return []
    
    candidates = []
    endbr64 = b'\xf3\x0f\x1e\xfa'
    
    for i in range(len(data) - 4):
        if data[i:i+4] == endbr64:
            offset = code_start + i - base
            candidates.append(offset)
    
    return candidates

def create_test_payload(candidates):
    """Create C code to test function candidates"""
    code = """
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>

typedef void* lua_State;
typedef int (*lua_gettop_t)(lua_State*);
typedef void (*lua_settop_t)(lua_State*, int);
typedef int (*luaL_loadbuffer_t)(lua_State*, const char*, size_t, const char*);

static jmp_buf jmp;
static void sig_handler(int s) { longjmp(jmp, 1); }

void test_candidates(lua_State* L, uintptr_t base) {
    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    
    uintptr_t candidates[] = { """ + ','.join(f'0x{c:x}' for c in candidates[:50]) + """ };
    
    for (int i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        if (setjmp(jmp) == 0) {
            lua_gettop_t fn = (lua_gettop_t)(base + candidates[i]);
            int result = fn(L);
            if (result >= 0 && result < 10000) {
                printf("CANDIDATE_GETTOP:0x%lx:%d\\n", candidates[i], result);
            }
        }
    }
}
"""
    return code

print("[*] Automated Offset Finder")
print("[*] Step 1: Find Sober...")

pid = get_sober_pid()
if not pid:
    print("[-] Sober not running!")
    exit(1)

print(f"[+] Found Sober PID: {pid}")

print("[*] Step 2: Find libloader.so...")
base = get_libloader_base(int(pid))
if not base:
    print("[-] libloader.so not found!")
    exit(1)

print(f"[+] libloader.so base: 0x{base:x}")

print("[*] Step 3: Scan for function candidates...")
candidates = find_function_candidates(int(pid), base)
print(f"[+] Found {len(candidates)} candidates")

print("[*] Step 4: Filter to reasonable sizes...")
# Filter to functions between 0x15000 and 0x25000 (typical Lua API range)
api_candidates = [c for c in candidates if 0x15000 <= c <= 0x25000]
print(f"[+] {len(api_candidates)} in API range")

print("\n=== TOP CANDIDATES ===")
for c in api_candidates[:30]:
    print(f"  0x{c:x}")

print("\n[*] To test these, update injected_lib.c with:")
print(f"    #define OFF_GETTOP 0x{api_candidates[0]:x}")
print(f"    #define OFF_SETTOP 0x{api_candidates[1]:x}")
print("\nThen make && inject and check logs!")
