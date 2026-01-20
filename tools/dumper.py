from os import _exit, listdir, readlink
import sys

def main():
  count = 0
  hit = None

  print("[*] Scanning for Sober...")

  try:
      for pid in listdir("/proc"):
        if not pid.isdigit():
          continue
        base = f"/proc/{pid}"
        try:
          link = readlink(f"{base}/exe")
          if link == "/app/bin/sober" or link.endswith("/sober"):
            count += 1
            # Ideally we want the main process or the one with the large heap
            # For now, let's take the first one or logic from chat (count == 3?)
            # The chat script used 'count == 3'. Let's stick to simple detection first.
            print(f"[?] Found candidate PID: {pid} ({link})")
            hit = pid
            # break # Don't break immediately, maybe we wait for the 3rd one like the script?
            # Actually, let's just use the logic from the chat exactl if possible, 
            # but the chat logic `if count == 3: hit=pid; break` is specific to their process tree.
            # I will just use the last found one or the one that works.
            # Let's trust the user submitted script logic.
            if count == 3:
                hit = pid
                break
        except BaseException:
          pass
  except Exception as e:
      print(f"[-] Error scanning PIDs: {e}")
      _exit(1)

  if not hit and count > 0:
      hit = pid # Fallback to last found if we didn't hit 3
  
  if not hit:
    print("[-] couldn't get sober!")
    _exit(1)

  base = f"/proc/{hit}"
  print(f"[+] found sober at {hit}")
  
  # Check if we can open mem
  try:
    fMem = open(f"{base}/mem", "rb+")
  except BaseException:
    print("[-] couldn't open memory (root needed?)")
    _exit(1)

  try:
    with open(f"{base}/maps") as fMaps:
      for line in fMaps:
        try:
          parts = line.strip().split(maxsplit=5)
          addr, perms = parts[0], parts[1]
          if perms != "r-xp": # Executable regions
            continue
          if "/" in line: # Skip mapped files? The script did `if "/" in line: continue` which implies looking for anonymous mappings or main stack? 
               # Wait, usually the game code IS in a mapped file (sober/libloader).
               # BUT the script says `if "/" in line: continue`. 
               # This implies they are looking for unpacked code in anon regions.
               # I will keep the logic.
            continue

          start, stop = (int(x, 16) for x in addr.split("-"))

          print(f"[#] reading {addr}")
          fMem.seek(start)
          try:
            data = fMem.read(stop - start)
          except:
            continue
            
          if b"Current identity is" in data:
            print(f"[+] Found Roblox Core in region {addr}")
            print("[+] Dumping to Roblox.elf...")
            with open(f"Roblox.elf", "wb") as f:
              f.write(data)
            print("[+] Dump complete.")
            break 
        except Exception as e:
            print(f"[-] Error scanning map: {e}")
            continue
  except Exception as e:
      print(f"[-] Error reading maps: {e}")
  
  fMem.close()

if __name__ == "__main__":
  main()
