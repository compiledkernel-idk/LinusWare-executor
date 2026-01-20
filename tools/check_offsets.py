import sys
import re

def check(pid):
    print(f"Checking PID {pid}...")
    try:
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"
        
        base = 0
        with open(maps_path, 'r') as f:
            for line in f:
                if "libloader.so" in line and "r-xp" in line:
                    base = int(line.split('-')[0], 16)
                    break
                    
        if not base:
             print("libloader.so not found")
             return
             
        print(f"Base: 0x{base:x}")
        
        with open(mem_path, 'rb') as f:
             f.seek(base)
             data = f.read(0x150000) # Read ~1.3MB
             
        # Find functions (Intel CET endbr64 signature)
        starts = [m.start() for m in re.finditer(b'\xf3\x0f\x1e\xfa', data)]
        print(f"Total functions found: {len(starts)}")
        
        # Check specific offsets from previous runs
        offsets = {
            "gettop": 0x36600,
            "settop": 0x15600
        }
        
        for name, off in offsets.items():
            if off in starts:
                print(f"[OK] {name} (0x{off:x}) exists.")
            else:
                print(f"[MISSING] {name} (0x{off:x}) NOT found.")
                
        # Count filtered candidates
        lb_count = 0
        pc_count = 0
        
        for i, s in enumerate(starts):
            if i < len(starts)-1:
                sz = starts[i+1] - s
            else:
                sz = 100
            
            # Refine size by finding ret
            chunk = data[s:s+sz]
            ret = chunk.find(b'\xc3')
            if ret != -1: sz = ret+1
            
            # loadbuffer is typically 200-400 bytes
            if 200 <= sz <= 400: lb_count += 1
            # pcall is typically 150-180 bytes
            if 150 <= sz <= 180: pc_count += 1
            
        print(f"Candidates for loadbuffer: {lb_count}")
        print(f"Candidates for pcall: {pc_count}")
        print(f"Total relevant API candidates: {lb_count + pc_count}")
        if (lb_count + pc_count) > 100:
            print("(Matches your '120 offsets' observation!)")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        check(int(sys.argv[1]))
