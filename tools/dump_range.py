import sys
import os

def dump_range(pid, start, size, output):
    mem_file = f"/proc/{pid}/mem"
    try:
        with open(mem_file, 'rb', 0) as mem:
            mem.seek(start)
            data = mem.read(size)
            with open(output, 'wb') as f:
                f.write(data)
        print(f"Dumped {hex(size)} bytes from {hex(start)} to {output}")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    dump_range(int(sys.argv[1]), int(sys.argv[2], 16), int(sys.argv[3], 16), sys.argv[4])
