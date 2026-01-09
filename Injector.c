
/*
 * Filename: Injector.c
 *
 * Copyright (c) 2026 compiledkernel-idk
 * All Rights Reserved.
 *
 * This software is proprietary and confidential.
 * Unauthorized copying, distribution, or use of this file,
 * via any medium, is strictly prohibited.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHELLCODE_SIZE 128

pid_t get_tracer_pid(pid_t pid) {
  char path[64], line[256];
  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  pid_t tracer = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
      tracer = atoi(line + 10);
      break;
    }
  }
  fclose(f);
  return tracer;
}

pid_t find_pid(const char *name) {
  DIR *d = opendir("/proc");
  if (!d)
    return -1;

  pid_t candidates[32];
  int count = 0;

  struct dirent *e;
  while ((e = readdir(d)) && count < 32) {
    if (e->d_type != DT_DIR)
      continue;
    pid_t pid = atoi(e->d_name);
    if (pid <= 0)
      continue;

    char comm_path[PATH_MAX], comm[256];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    FILE *f = fopen(comm_path, "r");
    if (f) {
      if (fgets(comm, sizeof(comm), f)) {
        comm[strcspn(comm, "\n")] = 0;
        if (strstr(comm, name)) {
          candidates[count++] = pid;
        }
      }
      fclose(f);
    }
  }
  closedir(d);

  if (count == 0)
    return -1;

  printf("[*] Found %d sober process(es)\n", count);

  for (int i = 0; i < count; i++) {
    pid_t tracer = get_tracer_pid(candidates[i]);
    printf("[*] PID %d: TracerPid=%d\n", candidates[i], tracer);

    if (tracer == 0) {

      printf("[*] Selected PID %d (not traced)\n", candidates[i]);
      return candidates[i];
    }
  }

  pid_t first_tracer = get_tracer_pid(candidates[0]);
  if (first_tracer > 0) {

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", first_tracer);
    if (access(path, F_OK) == 0) {
      printf("[*] All processes traced - targeting tracer PID %d instead\n",
             first_tracer);
      return first_tracer;
    }
  }

  printf("[*] Fallback: selecting PID %d\n", candidates[0]);
  return candidates[0];
}

unsigned long get_remote_base(pid_t pid, const char *lib) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  unsigned long addr = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, lib) && strstr(line, "r-xp")) {
      addr = strtoul(line, NULL, 16);
      break;
    }
  }
  fclose(f);
  return addr;
}

unsigned long get_local_base(const char *lib) {
  char line[512];
  FILE *f = fopen("/proc/self/maps", "r");
  if (!f)
    return 0;

  unsigned long addr = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, lib) && strstr(line, "r-xp")) {
      addr = strtoul(line, NULL, 16);
      break;
    }
  }
  fclose(f);
  return addr;
}

unsigned long get_func_offset(const char *lib, const char *func) {
  void *h = dlopen(lib, RTLD_LAZY | RTLD_NOLOAD);
  if (!h)
    h = dlopen(lib, RTLD_LAZY);
  if (!h)
    return 0;

  void *sym = dlsym(h, func);
  if (!sym) {
    dlclose(h);
    return 0;
  }

  unsigned long base = get_local_base(lib);
  unsigned long offset = (unsigned long)sym - base;
  dlclose(h);
  return offset;
}

int check_seccomp(pid_t pid) {
  char path[64], line[256];
  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return -1;

  int seccomp = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "Seccomp:", 8) == 0) {
      seccomp = atoi(line + 8);
      break;
    }
  }
  fclose(f);
  return seccomp;
}

pid_t get_tracer(pid_t pid) {
  char path[64], line[256];
  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  pid_t tracer = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
      tracer = atoi(line + 10);
      break;
    }
  }
  fclose(f);
  return tracer;
}

int kill_tracer(pid_t target_pid) {
  pid_t tracer = get_tracer(target_pid);
  if (tracer <= 0) {
    printf("[*] No tracer detected\n");
    return 0;
  }

  printf("[!] Process is being traced by PID %d (anti-debug)\n", tracer);
  printf("[*] Killing tracer process...\n");

  if (kill(tracer, SIGKILL) == 0) {
    usleep(100000);

    pid_t new_tracer = get_tracer(target_pid);
    if (new_tracer == 0) {
      printf("[+] Tracer killed successfully\n");
      return 0;
    }
    printf("[!] Tracer still active: %d\n", new_tracer);
  } else {
    perror("[!] Failed to kill tracer");
  }

  return -1;
}

void find_all_sober_pids(pid_t *pids, int *count, int max) {
  DIR *d = opendir("/proc");
  if (!d)
    return;

  *count = 0;
  struct dirent *e;
  while ((e = readdir(d)) && *count < max) {
    if (e->d_type != DT_DIR)
      continue;
    pid_t pid = atoi(e->d_name);
    if (pid <= 0)
      continue;

    char comm_path[PATH_MAX], comm[256];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    FILE *f = fopen(comm_path, "r");
    if (f) {
      if (fgets(comm, sizeof(comm), f)) {
        comm[strcspn(comm, "\n")] = 0;
        if (strstr(comm, "sober")) {
          pids[(*count)++] = pid;
        }
      }
      fclose(f);
    }
  }
  closedir(d);
}

int write_memory(pid_t pid, unsigned long addr, void *data, size_t len) {
  struct iovec local = {data, len};
  struct iovec remote = {(void *)addr, len};

  ssize_t written = process_vm_writev(pid, &local, 1, &remote, 1, 0);
  return (written == (ssize_t)len) ? 0 : -1;
}

int read_memory(pid_t pid, unsigned long addr, void *buf, size_t len) {
  struct iovec local = {buf, len};
  struct iovec remote = {(void *)addr, len};

  ssize_t read_bytes = process_vm_readv(pid, &local, 1, &remote, 1, 0);
  return (read_bytes == (ssize_t)len) ? 0 : -1;
}

unsigned long find_exec_region(pid_t pid) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  unsigned long addr = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, "r-xp") && !strstr(line, ".so") && !strstr(line, "[")) {
      addr = strtoul(line, NULL, 16);
      break;
    }
  }
  fclose(f);
  return addr;
}

int inject_ptrace(pid_t pid, const char *lib_path) {
  printf("[*] Using ptrace injection method on PID %d\n", pid);

  pid_t tracer = get_tracer(pid);
  if (tracer > 0) {
    printf("[!] PID %d is being traced by %d\n", pid, tracer);
    printf("[*] Redirecting injection to tracer PID %d\n", tracer);
    pid = tracer;

    pid_t tracer2 = get_tracer(pid);
    if (tracer2 > 0) {
      printf("[!] Tracer is also traced by %d - too deep\n", tracer2);
      return -1;
    }
  }

  int seccomp = check_seccomp(pid);
  printf("[*] Seccomp status: %d\n", seccomp);

  if (seccomp == 2) {
    printf("[!] Target has seccomp filters, trying alternative...\n");
    return -1;
  }

  int attached = 0;
  for (int i = 0; i < 5; i++) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
      attached = 1;
      break;
    }
    printf("[*] Attach attempt %d failed, retrying...\n", i + 1);
    usleep(100000);
  }

  if (!attached) {
    perror("[!] ptrace attach failed");
    return -1;
  }

  int status;
  waitpid(pid, &status, 0);
  printf("[+] Attached to process\n");

  struct user_regs_struct regs, orig_regs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) {
    perror("[!] GETREGS failed");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
  }
  memcpy(&regs, &orig_regs, sizeof(regs));

  unsigned long libc_base = get_remote_base(pid, "libc");
  unsigned long dlopen_offset =
      get_func_offset("libc.so.6", "__libc_dlopen_mode");
  if (!dlopen_offset) {
    dlopen_offset = get_func_offset("libc.so.6", "dlopen");
  }

  if (!libc_base || !dlopen_offset) {
    printf("[!] Could not find dlopen\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
  }

  unsigned long target_dlopen = libc_base + dlopen_offset;
  printf("[*] Target dlopen: 0x%lx\n", target_dlopen);

  size_t path_len = strlen(lib_path) + 1;
  regs.rsp -= 256;
  regs.rsp &= ~0xF;

  for (size_t i = 0; i < path_len; i += sizeof(long)) {
    long word = 0;
    size_t copy_len =
        (path_len - i < sizeof(long)) ? path_len - i : sizeof(long);
    memcpy(&word, lib_path + i, copy_len);
    ptrace(PTRACE_POKEDATA, pid, regs.rsp + i, word);
  }

  regs.rdi = regs.rsp;
  regs.rsi = RTLD_NOW | RTLD_GLOBAL;
  regs.rip = target_dlopen;

  // Search for an 'int 3' (0xCC) instruction in the target's executable memory
  // This allows us to trap cleanly instead of causing a SEGFAULT at 0xDEADBEEF
  unsigned long int3_addr = 0;
  unsigned long exec_start = find_exec_region(pid);

  if (exec_start > 0) {
    for (int off = 0; off < 4096; off += sizeof(long)) {
      long data = ptrace(PTRACE_PEEKTEXT, pid, exec_start + off, NULL);
      unsigned char *bytes = (unsigned char *)&data;
      for (int b = 0; b < sizeof(long); b++) {
        if (bytes[b] == 0xCC) {
          int3_addr = exec_start + off + b;
          break;
        }
      }
      if (int3_addr)
        break;
    }
  }

  // Fallback to 0 (will cause SIGSEGV) if no int3 found
  unsigned long return_addr = int3_addr ? int3_addr : 0;
  printf("[*] Return address (trap): 0x%lx\n", return_addr);

  regs.rsp -= 8;
  ptrace(PTRACE_POKEDATA, pid, regs.rsp, return_addr);

  ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  printf("[*] Executing dlopen...\n");

  ptrace(PTRACE_CONT, pid, NULL, NULL);
  waitpid(pid, &status, 0);

  if (WIFSTOPPED(status)) {
    printf("[+] Process stopped (signal %d)\n", WSTOPSIG(status));
  }

  // If we stopped due to SIGSEGV (because we used 0) or SIGTRAP (int3), it's
  // good. We need to handle both gracefully.

  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  printf("[*] dlopen returned: 0x%llx\n", regs.rax);

  ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
  ptrace(PTRACE_DETACH, pid, NULL, NULL);

  if (regs.rax == 0) {
    printf("[!] dlopen failed in target\n");
    return -1;
  }

  printf("[+] Library injected successfully!\n");
  return 0;
}

int inject_gdb(pid_t pid, const char *lib_path) {
  printf("[*] Using gdb injection method on PID %d\n", pid);

  pid_t tracer = get_tracer(pid);
  if (tracer > 0) {
    printf("[*] PID %d traced by %d, redirecting to tracer\n", pid, tracer);
    pid = tracer;
  }

  char cmd[2048];
  snprintf(cmd, sizeof(cmd),
           "gdb -batch -n "
           "-ex 'set pagination off' "
           "-ex 'set confirm off' "
           "-ex 'attach %d' "
           "-ex 'call (void*)dlopen(\"%s\", 0x102)' "
           "-ex 'detach' "
           "-ex 'quit' 2>&1",
           pid, lib_path);

  printf("[*] Running gdb...\n");
  FILE *fp = popen(cmd, "r");
  if (!fp) {
    perror("[!] popen failed");
    return -1;
  }

  char output[4096] = {0};
  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    strcat(output, line);
    printf("    %s", line);
  }

  int status = pclose(fp);

  if (strstr(output, "= (void *)") && !strstr(output, "= (void *) 0x0")) {
    printf("[+] gdb injection successful!\n");
    return 0;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (maps) {
      char maps_line[512];
      while (fgets(maps_line, sizeof(maps_line), maps)) {
        if (strstr(maps_line, "sober_test_inject")) {
          fclose(maps);
          printf("[+] Library found in process maps!\n");
          return 0;
        }
      }
      fclose(maps);
    }
  }

  printf("[!] gdb injection may have failed\n");
  return -1;
}

int inject_nsenter(pid_t pid, const char *lib_path) {
  printf("[*] Using nsenter injection (for Flatpak/containers)\n");

  pid_t tracer = get_tracer(pid);
  if (tracer > 0) {
    printf("[*] Redirecting to tracer PID %d\n", tracer);
    pid = tracer;
  }

  // First, copy the library into a location the target can access
  // For Flatpak, /tmp is often shared or we staged it there via /proc
  char tmp_lib[256];

  if (strncmp(lib_path, "/tmp/", 5) == 0) {
    // Already in /tmp (staged by script), just use it
    strncpy(tmp_lib, lib_path, sizeof(tmp_lib));
    printf("[*] Library already in /tmp, skipping copy\n");
  } else {
    snprintf(tmp_lib, sizeof(tmp_lib), "/tmp/sirracha_inject_%d.so", getpid());

    char cp_cmd[512];
    snprintf(cp_cmd, sizeof(cp_cmd), "cp '%s' '%s' && chmod 755 '%s'", lib_path,
             tmp_lib, tmp_lib);
    if (system(cp_cmd) != 0) {
      printf("[!] Failed to copy library to /tmp\n");
      return -1;
    }
    printf("[*] Library copied to %s\n", tmp_lib);
  }

  // Copy OURSELF (the injector binary) to the container's /tmp via /proc
  char self_path[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
  if (len != -1) {
    self_path[len] = '\0';

    // Path inside the container
    char container_injector_path[256];
    snprintf(container_injector_path, sizeof(container_injector_path),
             "/tmp/injector_%d", getpid());

    // Path on the host (via /proc)
    char host_access_path[512];
    snprintf(host_access_path, sizeof(host_access_path), "/proc/%d/root%s", pid,
             container_injector_path);

    // Check if /proc mount is writable/accessible
    if (access(host_access_path, F_OK) == 0 || errno == ENOENT) {
      // Copy to host_access_path
      char cp_exe_cmd[1024];
      snprintf(cp_exe_cmd, sizeof(cp_exe_cmd), "cp '%s' '%s' && chmod 755 '%s'",
               self_path, host_access_path, host_access_path);

      if (system(cp_exe_cmd) != 0) {
        // Fallback to host /tmp if proc access fails (rare but possible)
        snprintf(host_access_path, sizeof(host_access_path), "/tmp/injector_%d",
                 getpid());
        snprintf(cp_exe_cmd, sizeof(cp_exe_cmd),
                 "cp '%s' '%s' && chmod 755 '%s'", self_path, host_access_path,
                 host_access_path);
        system(cp_exe_cmd);
      }
    }

    // Now run THIS copy inside nsenter
    char cmd[4096];
    // Use internal ptrace mode
    snprintf(cmd, sizeof(cmd),
             "nsenter -t %d -m -p -U --preserve-credentials '%s' auto '%s'",
             pid, container_injector_path, tmp_lib);

    printf("[*] recursive-inject: Running %s inside container...\n", cmd);
    int ret = system(cmd);

    // Cleanup
    char rm_cmd[512];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -f '%s'", host_access_path);
    // system(rm_cmd); // Keep for debugging if needed, or uncomment

    if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0) {
      return 0;
    }
    printf("[!] recursive-inject failed with code %d\n", WEXITSTATUS(ret));
  } else {
    printf("[!] Could not find self path for recursive injection\n");
  }

  // Fallback to GDB if recursive failed
  printf("[*] Falling back to GDB inside nsenter...\n");
  char cmd[4096];
  snprintf(cmd, sizeof(cmd),
           "nsenter -t %d -m -p -U --preserve-credentials gdb -q -batch "
           "-ex 'attach %d' "
           "-ex 'set confirm off' "
           "-ex 'call (void*)dlopen(\"%s\", 2)' "
           "-ex 'detach' "
           "-ex 'quit'",
           pid, pid, tmp_lib);

  printf("[*] Running: nsenter + gdb\n");
  FILE *fp = popen(cmd, "r");
  if (!fp) {

    snprintf(cmd, sizeof(cmd),
             "gdb -batch -n "
             "-ex 'set pagination off' "
             "-ex 'attach %d' "
             "-ex 'call (void*)dlopen(\"%s\", 2)' "
             "-ex 'detach' 2>&1",
             pid, tmp_lib);
    fp = popen(cmd, "r");
    if (!fp) {
      perror("[!] popen failed");
      return -1;
    }
  }

  char output[4096] = {0};
  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    strcat(output, line);
    printf("    %s", line);
  }
  pclose(fp);

  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *maps = fopen(maps_path, "r");
  if (maps) {
    char maps_line[512];
    while (fgets(maps_line, sizeof(maps_line), maps)) {
      if (strstr(maps_line, "sirracha_inject") ||
          strstr(maps_line, "sober_test")) {
        fclose(maps);
        printf("[+] Library loaded successfully!\n");
        return 0;
      }
    }
    fclose(maps);
  }

  if (strstr(output, "= (void *)") && !strstr(output, "= (void *) 0x0")) {
    printf("[+] dlopen returned non-null - likely success\n");
    return 0;
  }

  printf("[!] nsenter injection may have failed\n");
  return -1;
}

void print_banner() {
  printf("\n");
  printf("╔═══════════════════════════════════════════════════════════╗\n");
  printf("║           SIRRACHA INJECTOR v1.0                          ║\n");
  printf("║   Advanced Linux Process Injection Tool                   ║\n");
  printf("╚═══════════════════════════════════════════════════════════╝\n");
  printf("\n");
}

int main(int argc, char **argv) {
  print_banner();

  pid_t pid;
  const char *lib_path;

  if (argc >= 2) {
    if (strcmp(argv[1], "auto") == 0 || strcmp(argv[1], "0") == 0) {
      pid = 0; // Trigger auto-scan
    } else {
      pid = atoi(argv[1]);
    }

    lib_path = (argc > 2) ? argv[2] : "./sober_test_inject.so";
  } else {
    // defaults
    pid = 0;
    lib_path = "./sober_test_inject.so";
  }

  if (pid <= 0) {
    printf("[*] Searching for 'sober' process (auto-scan)...\n");
    pid = find_pid("sober");
    if (pid == -1) {
      fprintf(stderr, "[!] Sober process not found\n");
      return EXIT_FAILURE;
    }
    printf("[*] Found Sober at PID %d\n", pid);
  }

  // Get absolute path or verify container path
  char abs_path[PATH_MAX];

  // Trust paths staged by our script in /tmp
  if (strncmp(lib_path, "/tmp/sirracha", 13) == 0) {
    strncpy(abs_path, lib_path, sizeof(abs_path));
    printf("[*] Trusting staged container path: %s\n", abs_path);
  } else if (realpath(lib_path, abs_path) == NULL) {
    // If realpath fails on host, checking target root might also fail due to
    // permissions But we'll try one last check
    char container_path[PATH_MAX];
    snprintf(container_path, sizeof(container_path), "/proc/%d/root%s", pid,
             lib_path);

    if (access(container_path, F_OK) == 0) {
      strncpy(abs_path, lib_path, sizeof(abs_path));
      printf("[*] Library found in container filesystem: %s\n", abs_path);
    } else {
      printf("[!] Warning: Could not verify library path on host. Attempting "
             "anyway...\n");
      strncpy(abs_path, lib_path, sizeof(abs_path));
    }
  }

  printf("[*] Target PID: %d\n", pid);
  printf("[*] Library: %s\n", abs_path);
  printf("\n");

  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *maps = fopen(maps_path, "r");
  if (maps) {
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
      if (strstr(line, "sober_test_inject")) {
        fclose(maps);
        printf("[!] Library already injected!\n");
        return EXIT_SUCCESS;
      }
    }
    fclose(maps);
  }

  if (inject_ptrace(pid, abs_path) == 0) {
    return EXIT_SUCCESS;
  }

  printf("\n[*] Trying gdb injection method...\n\n");

  if (inject_gdb(pid, abs_path) == 0) {
    return EXIT_SUCCESS;
  }

  printf("\n[*] Trying nsenter injection (for Flatpak)...\n\n");

  if (inject_nsenter(pid, abs_path) == 0) {
    return EXIT_SUCCESS;
  }

  fprintf(stderr, "\n[!] All injection methods failed\n");
  fprintf(stderr, "[!] Try running with sudo: sudo %s %d %s\n", argv[0], pid,
          abs_path);
  return EXIT_FAILURE;
}
