/*
 * vm_inject.c - Process VM injection (bypasses ptrace restrictions)
 *
 * Copyright (c) 2026 sultan
 * PROPRIETARY AND CONFIDENTIAL
 *
 * This injector uses process_vm_readv/writev which works even when
 * the target is already being traced by another process.
 *
 * Compile: gcc -o vm_inject vm_inject.c -ldl
 * Usage: sudo ./vm_inject [library_path]
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_LIB "/dev/shm/linusware.so"

/* Find the Nth sober process */
pid_t find_sober_pid(int n) {
  DIR *d = opendir("/proc");
  if (!d)
    return -1;

  struct dirent *e;
  int count = 0;
  pid_t result = -1;

  while ((e = readdir(d))) {
    if (e->d_type != DT_DIR)
      continue;
    pid_t pid = atoi(e->d_name);
    if (pid <= 0)
      continue;

    char path[128], exe[256];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, exe, sizeof(exe) - 1);
    if (len > 0) {
      exe[len] = '\0';
      if (strcmp(exe, "/app/bin/sober") == 0 || strstr(exe, "/sober")) {
        count++;
        if (count == n) {
          result = pid;
          break;
        }
      }
    }
  }
  closedir(d);
  return result;
}

/* Get base address and path of a library in target process */
unsigned long get_remote_lib_base(pid_t pid, const char *search, char *out_path,
                                  size_t max_len) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  unsigned long addr = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, search) && strstr(line, "r-xp")) {
      addr = strtoul(line, NULL, 16);

      /* Extract path */
      char *p = strchr(line, '/');
      if (p && out_path) {
        /* Remove newline */
        char *nl = strchr(p, '\n');
        if (nl)
          *nl = 0;
        strncpy(out_path, p, max_len - 1);
        out_path[max_len - 1] = 0;
      }
      break;
    }
  }
  fclose(f);
  return addr;
}

/* Get offset of symbol in a specific library file */
unsigned long get_symbol_offset(const char *lib_path, const char *sym) {
  /* dlopen the specific file to ensure we get the right offsets */
  void *h = dlopen(lib_path, RTLD_LAZY);
  if (!h) {
    /* dlopen might fail for some libs, but we try */
    return 0;
  }

  void *sym_addr = dlsym(h, sym);
  if (!sym_addr) {
    dlclose(h);
    return 0;
  }

  /* Find the base address where this specific lib was loaded LOCALLY */
  Dl_info info;
  if (dladdr(sym_addr, &info)) {
    unsigned long offset =
        (unsigned long)sym_addr - (unsigned long)info.dli_fbase;
    dlclose(h);
    return offset;
  }
  dlclose(h);
  return 0;
}

/* Read remote memory using /proc/pid/mem */
ssize_t vm_read(pid_t pid, void *local, void *remote, size_t len) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    /* Fallback to process_vm_readv */
    struct iovec local_iov = {local, len};
    struct iovec remote_iov = {remote, len};
    return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
  }

  ssize_t result = pread(fd, local, len, (off_t)(unsigned long)remote);
  close(fd);
  return result;
}

/* Write remote memory using /proc/pid/mem (can write to read-only pages!) */
ssize_t vm_write(pid_t pid, void *local, void *remote, size_t len) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", pid);
  int fd = open(path, O_RDWR);
  if (fd < 0) {
    printf("[-] Cannot open /proc/%d/mem: %s\n", pid, strerror(errno));
    /* Fallback to process_vm_writev */
    struct iovec local_iov = {local, len};
    struct iovec remote_iov = {remote, len};
    return process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
  }

  ssize_t result = pwrite(fd, local, len, (off_t)(unsigned long)remote);
  if (result < 0) {
    printf("[-] pwrite failed: %s\n", strerror(errno));
  }
  close(fd);
  return result;
}

/* Find an executable region with enough space for shellcode */
unsigned long find_code_cave(pid_t pid, size_t needed) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, "r-xp"))
      continue;
    if (strstr(line, ".so"))
      continue; /* Skip shared libs */

    unsigned long start, end;
    if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
      size_t size = end - start;
      if (size > needed + 0x1000) {
        /* Check end of region for zeros (code cave) */
        unsigned char buf[256];
        unsigned long cave = end - 0x200;

        if (vm_read(pid, buf, (void *)cave, sizeof(buf)) > 0) {
          int zeros = 1;
          for (int i = 0; i < 128; i++) {
            if (buf[i] != 0 && buf[i] != 0xCC) {
              zeros = 0;
              break;
            }
          }
          if (zeros) {
            fclose(f);
            printf("[+] Found code cave at 0x%lx\n", cave);
            return cave;
          }
        }
      }
    }
  }
  fclose(f);
  return 0;
}

/* Find a writable data region with enough space */
unsigned long find_data_cave(pid_t pid, size_t needed) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, "rw-p"))
      continue;
    if (strstr(line, "[stack]") || strstr(line, "[heap]"))
      continue;

    unsigned long start, end;
    if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
      size_t size = end - start;
      if (size > needed + 0x1000) {
        /* Check end of region for zeros */
        unsigned char buf[256];
        unsigned long cave = end - 0x200;
        if (vm_read(pid, buf, (void *)cave, sizeof(buf)) > 0) {
          int zeros = 1;
          for (int i = 0; i < 128; i++) {
            if (buf[i] != 0) {
              zeros = 0;
              break;
            }
          }
          if (zeros) {
            fclose(f);
            printf("[+] Found data cave at 0x%lx\n", cave);
            return cave;
          }
        }
      }
    }
  }
  fclose(f);
  return 0;
}

/*
 * x86_64 Smart Shellcode with Recursion Protection & dlerror capture
 */
unsigned char shellcode_smart[] = {
    /* [0-7] Flag counter (init 0) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    /* [8] Start: Load Flag Address (patched) */
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, /* mov rax, addr */

    /* [18] Increment Flag safely */
    0xf0, 0x48, 0xff, 0x00, /* lock inc qword ptr [rax] */

    /* [22] Check if this is the first run (flag == 1) */
    0x48, 0x83, 0x38, 0x01, /* cmp qword ptr [rax], 1 */

    /* [26] If not 1, skip dlopen (short jump to OFFSET_ORIG) */
    0x75, 0x5f, /* jne +95 (to [123]) */

    /* === DLOPEN CALL === */
    /* Save registers */
    0x50, 0x51, 0x52, 0x56, 0x57, /* push rax, rcx, rdx, rsi, rdi */
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, /* push r8-r11 */

    /* Align stack */
    0x48, 0x89, 0xe0,       /* mov rax, rsp */
    0x48, 0x83, 0xe4, 0xf0, /* and rsp, -16 */
    0x50,                   /* push rax (save orig rsp) */

    /* Load path (patched) */
    0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, /* mov rdi, addr */

    /* Load RTLD_LAZY (1) */
    0xbe, 0x01, 0x00, 0x00, 0x00, /* mov esi, 1 */

    /* Load dlopen address (patched) */
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, /* mov rax, addr */

    /* Call dlopen */
    0xff, 0xd0, /* call rax */

    /* [66] Save Result (RAX) to Result Address */
    0x48, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0, /* mov [addr], rax */

    /* [76] Test Result */
    0x48, 0x85, 0xc0, /* test rax, rax */

    /* [79] JNZ to Skip dlerror (to [103]) */
    0x75, 0x16, /* jnz +22 */

    /* Start dlerror block */
    /* [81] Load dlerror addr */
    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, /* mov rax, addr */
    /* [91] Call dlerror */
    0xff, 0xd0, /* call rax */
    /* [93] Save ErrorPtr */
    0x48, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0, /* mov [addr], rax */
    /* End dlerror block (len 22) */

    /* [103] Restore stack */
    0x5c, /* pop rsp */

    /* Restore registers */
    0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5f, 0x5e, 0x5a, 0x59,
    0x58,

    /* [123] OFFSET_ORIG: Execute stolen bytes (14 bytes) */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90,

    /* [137] Jump back (patched) */
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,      /* mov rax, addr */
    0xff, 0xe0 /* jmp rax */
};

#define OFF_FLAG_ADDR 10
#define OFF_JMP_SKIP 27
#define OFF_PATH_ADDR 44
#define OFF_DLOPEN 59
#define OFF_RESULT_ADDR 68
#define OFF_DLERROR 83
#define OFF_ERROR_PTR 95
#define OFF_ORIG_BYTES 123
#define OFF_RET_ADDR 139
#define SC_SMART_SIZE sizeof(shellcode_smart)

int inject_vm(pid_t pid, const char *lib_path) {
  printf("[*] Target PID: %d\n", pid);
  printf("[*] Library: %s\n", lib_path);

  /* Find libc in target */
  char remote_libc_path[256] = {0};
  unsigned long libc_base = get_remote_lib_base(
      pid, "/libc.so", remote_libc_path, sizeof(remote_libc_path));
  if (!libc_base) {
    libc_base = get_remote_lib_base(pid, "/libc-", remote_libc_path,
                                    sizeof(remote_libc_path));
  }
  if (!libc_base) {
    printf("[-] Cannot find libc in target\n");
    return -1;
  }
  printf("[+] Target libc: 0x%lx (%s)\n", libc_base, remote_libc_path);

  char full_libc_path[512];
  snprintf(full_libc_path, sizeof(full_libc_path), "/proc/%d/root%s", pid,
           remote_libc_path);

  /* Get dlopen offset : prioritize __libc_dlopen_mode */
  unsigned long dlopen_off =
      get_symbol_offset(full_libc_path, "__libc_dlopen_mode");
  if (dlopen_off) {
    printf("[+] Found __libc_dlopen_mode at 0x%lx\n", dlopen_off);
  } else {
    printf("[-] __libc_dlopen_mode not found, falling back to dlopen...\n");
    dlopen_off = get_symbol_offset(full_libc_path, "dlopen");
  }

  if (!dlopen_off) {
    printf("[-] Cannot find dlopen offset\n");
    return -1;
  }
  unsigned long target_dlopen = libc_base + dlopen_off;

  /* Get dlerror offset */
  unsigned long dlerror_off = get_symbol_offset(full_libc_path, "dlerror");
  unsigned long target_dlerror = 0;
  if (dlerror_off) {
    target_dlerror = libc_base + dlerror_off;
    printf("[+] dlerror offset: 0x%lx -> 0x%lx\n", dlerror_off, target_dlerror);
  } else {
    printf("[-] Cannot find dlerror offset (error reporting disabled)\n");
  }

  /* Find code cave */
  unsigned long code_cave = find_code_cave(pid, 512);
  /* Fallback omitted for brevity as find_code_cave is robust now */
  if (code_cave == 0) {
    /* Try using end of region directly */
    /* Simplified fallback logic */
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (f) {
      while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "r-xp") && !strstr(line, ".so")) {
          unsigned long start, end;
          sscanf(line, "%lx-%lx", &start, &end);
          code_cave = end - 0x200;
          printf("[+] Using region end for code: 0x%lx\n", code_cave);
          break;
        }
      }
      fclose(f);
    }
  }

  /* Find Data Cave */
  unsigned long data_cave = find_data_cave(pid, 512);

  if (!code_cave || !data_cave) {
    printf("[-] Failed to find caves\n");
    return -1;
  }

  /* Prepare shellcode */
  size_t path_len = strlen(lib_path) + 1;
  unsigned char *payload = calloc(1, SC_SMART_SIZE);
  memcpy(payload, shellcode_smart, SC_SMART_SIZE);

  /* Data Layout in Data Cave:
   * [0-7] Flag
   * [8-15] Result
   * [16-24] ErrorPtr
   * [24...] Path String
   */
  unsigned long flag_addr = data_cave;
  unsigned long result_addr = data_cave + 8;
  unsigned long error_ptr_addr = data_cave + 16;
  unsigned long path_addr = data_cave + 24;

  /* Patch Payload */
  memcpy(payload + OFF_FLAG_ADDR, &flag_addr, 8);
  memcpy(payload + OFF_PATH_ADDR, &path_addr, 8);
  memcpy(payload + OFF_DLOPEN, &target_dlopen, 8);
  memcpy(payload + OFF_RESULT_ADDR, &result_addr, 8);
  memcpy(payload + OFF_DLERROR, &target_dlerror, 8);
  memcpy(payload + OFF_ERROR_PTR, &error_ptr_addr, 8);

  printf("[*] Code Cave: 0x%lx\n", code_cave);
  printf("[*] Data Cave: 0x%lx\n", data_cave);

  /* Write Data */
  unsigned char zero_data[24] = {0};
  vm_write(pid, zero_data, (void *)flag_addr, 24);
  vm_write(pid, (void *)lib_path, (void *)path_addr, path_len);

  /* Write Code Payload */
  vm_write(pid, payload, (void *)code_cave, SC_SMART_SIZE);

  /* Hook "free" */
  unsigned long free_off = get_symbol_offset(full_libc_path, "free");
  if (free_off) {
    unsigned long target_free = libc_base + free_off;
    printf("[*] Hooking free at 0x%lx\n", target_free);

    unsigned char orig_bytes[32];
    if (vm_read(pid, orig_bytes, (void *)target_free, 32) > 0) {
      /* Patch Original Bytes */
      memcpy(payload + OFF_ORIG_BYTES, orig_bytes, 14);
      unsigned long return_addr = target_free + 14;
      memcpy(payload + OFF_RET_ADDR, &return_addr, 8);

      /* Re-write ONLY patched shellcode */
      vm_write(pid, payload, (void *)code_cave, SC_SMART_SIZE);

      /* Install Hook */
      unsigned char hook[12] = {
          0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, /* mov rax, addr */
          0xff, 0xe0                          /* jmp rax */
      };
      unsigned long code_start = code_cave + 8;
      memcpy(hook + 2, &code_start, 8);

      vm_write(pid, hook, (void *)target_free, sizeof(hook));
      printf("[+] Hook installed at free!\n");
      printf("[+] Waiting for 3 seconds...\n");

      sleep(3);

      /* Read Result */
      unsigned long result = 0;
      vm_read(pid, &result, (void *)result_addr, 8);
      printf("[*] dlopen result: 0x%lx\n", result);

      if (result == 0) {
        printf("[-] dlopen returned NULL! Injection failed inside target.\n");
        if (target_dlerror) {
          unsigned long err_ptr = 0;
          vm_read(pid, &err_ptr, (void *)error_ptr_addr, 8);
          if (err_ptr) {
            char err_msg[256] = {0};
            vm_read(pid, err_msg, (void *)err_ptr, 255);
            printf("[-] dlerror says: %s\n", err_msg);
          } else {
            printf("[-] dlerror returned NULL (no error message?)\n");
          }
        }
      } else {
        printf("[+] dlopen SUCCESS! Handle: 0x%lx\n", result);
        printf("[+] NOTE: Check logs at: "
               "/proc/%d/root/dev/shm/linusware_debug.log\n",
               pid);
      }
    }
  }

  free(payload);
  return 0;
}

/* Copy library to target container's /tmp to ensure visibility */
int deploy_library(pid_t pid, const char *src_path) {
  char dst_path[256];
  snprintf(dst_path, sizeof(dst_path), "/proc/%d/root/tmp/linusware.so", pid);

  printf("[*] Deploying library to container: %s\n", dst_path);

  /* Read source */
  FILE *f_src = fopen(src_path, "rb");
  if (!f_src) {
    printf("[-] Cannot open source lib: %s\n", src_path);
    return -1;
  }

  /* Write dest */
  FILE *f_dst = fopen(dst_path, "wb");
  if (!f_dst) {
    printf("[-] Cannot open container path: %s (%s)\n", dst_path,
           strerror(errno));
    fclose(f_src);
    return -1;
  }

  char buf[8192];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f_src)) > 0) {
    fwrite(buf, 1, n, f_dst);
  }

  fclose(f_src);
  fclose(f_dst);

  /* chmod 777 to be safe */
  chmod(dst_path, 0777);
  printf("[+] Library deployed successfully.\n");
  return 0;
}

int main(int argc, char **argv) {
  /* Default source is host /dev/shm/linusware.so */
  const char *host_lib_path = "/dev/shm/linusware.so";
  /* Internal path is always /tmp/linusware.so */
  const char *internal_lib_path = "/tmp/linusware.so";

  printf("=== LinusWare VM Injector ===\n");
  printf("\n");

  /* Find the 3rd sober process (actual game) */
  pid_t pid = find_sober_pid(3);
  if (pid <= 0) {
    /* Try 2 if 3 weak */
    pid = find_sober_pid(2);
  }

  if (pid <= 0) {
    printf("[-] Could not find Sober game process\n");
    return 1;
  }

  printf("[+] Found game process: PID %d\n", pid);

  /* Deploy library to that specific PID's namespace */
  if (deploy_library(pid, host_lib_path) < 0) {
    printf("[-] Failed to deploy library to container.\n");
    return 1;
  }

  /* Inject using the INTERNAL path */
  if (inject_vm(pid, internal_lib_path) < 0) {
    printf("[-] Injection failed.\n");
    return 1;
  }

  printf("[+] Done!\n");
  return 0;
}
