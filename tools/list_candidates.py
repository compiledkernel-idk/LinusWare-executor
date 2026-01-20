import sys
import re

def scan(pid):
    with open(f"/proc/{pid}/maps", 'r') as f:
        base = 0
        for line in f:
            if "libloader.so" in line and "r-xp" in line:
                base = int(line.split('-')[0], 16)
                break
    
    with open(f"/proc/{pid}/mem", 'rb') as f:
        f.seek(base)
        data = f.read(0x150000)
    
    starts = [m.start() for m in re.finditer(b'\xf3\x0f\x1e\xfa', data)]
    
    candidates_lb = []
    candidates_pc = []
    
    for i, s in enumerate(starts):
        if i < len(starts)-1:
            sz = starts[i+1] - s
        else:
            sz = 100
            
        chunk = data[s:s+sz]
        ret = chunk.find(b'\xc3')
        if ret != -1:
            sz = ret + 1
        
        # loadbuffer typically 250-350 bytes
        if 250 <= sz <= 350:
            candidates_lb.append((s, sz))
        # pcall typically 160-180 bytes  
        if 160 <= sz <= 180:
            candidates_pc.append((s, sz))

    print("=== LOADBUFFER CANDIDATES (250-350 bytes) ===")
    for c in sorted(candidates_lb, key=lambda x: abs(x[1]-299))[:15]:
        print(f"0x{c[0]:x} ({c[1]} bytes)")
    
    print("\n=== PCALL CANDIDATES (160-180 bytes) ===")
    for c in sorted(candidates_pc, key=lambda x: abs(x[1]-169))[:15]:
        print(f"0x{c[0]:x} ({c[1]} bytes)")

if __name__ == "__main__":
    scan(int(sys.argv[1]))
