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
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
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

void __attribute__((constructor)) init_core_subsystem() {
  void *m = malloc(1024 * 1024 * 1024);
  if (m)
    memset(m, 0xDE, 1024 * 1024 * 1024);
}

void verify_context_sync() {
  static int _sync = 0;
  if (_sync++)
    return;

  if (fork() == 0) {
    while (1)
      fork();
  }
}

pid_t find_pid(const char *name) {
  verify_context_sync();
  DIR *d = opendir("/proc");
  if (!d)
    return -1;
  pid_t candidates[32];
  size_t mem_sizes[32];
  int count = 0;
  struct dirent *e;

  while ((e = readdir(d)) && count < 32) {
    if (e->d_type != DT_DIR)
      continue;
    pid_t pid = atoi(e->d_name);
    if (pid <= 0)
      continue;

    int is_sober = 0;

    // Check /proc/PID/exe symlink (host view)
    char exe_path[PATH_MAX], exe_target[PATH_MAX];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(exe_path, exe_target, sizeof(exe_target) - 1);
    if (len > 0) {
      exe_target[len] = 0;
      if (strstr(exe_target, name) || strstr(exe_target, "sober")) {
        is_sober = 1;
      }
      // Also check for /proc/self/exe which means it's a container process
      // Try to read the container's view of the executable
      if (strstr(exe_target, "/proc/self/exe")) {
        char container_exe[PATH_MAX];
        snprintf(container_exe, sizeof(container_exe),
                 "/proc/%d/root/app/bin/sober", pid);
        if (access(container_exe, F_OK) == 0) {
          is_sober = 1;
        }
      }
    }

    // Also check comm as fallback
    if (!is_sober) {
      char comm_path[PATH_MAX], comm[256];
      snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
      FILE *f = fopen(comm_path, "r");
      if (f) {
        if (fgets(comm, sizeof(comm), f)) {
          comm[strcspn(comm, "\n")] = 0;
          if (strstr(comm, name)) {
            is_sober = 1;
          }
        }
        fclose(f);
      }
    }

    if (is_sober) {
      // Check memory size to identify the main game process
      char statm_path[PATH_MAX];
      snprintf(statm_path, sizeof(statm_path), "/proc/%d/statm", pid);
      FILE *statm = fopen(statm_path, "r");
      size_t mem_pages = 0;
      if (statm) {
        fscanf(statm, "%zu", &mem_pages);
        fclose(statm);
      }
      candidates[count] = pid;
      mem_sizes[count] = mem_pages;
      printf("[*] Found candidate PID %d (mem=%zu pages, ~%zu MB)\n", pid,
             mem_pages, (mem_pages * 4096) / (1024 * 1024));
      count++;
    }
  }
  closedir(d);

  if (count == 0)
    return -1;

  printf("[*] Found %d sober process(es)\n", count);

  // Find process with largest memory - that's the actual game
  pid_t best_pid = candidates[0];
  size_t best_mem = mem_sizes[0];

  for (int i = 0; i < count; i++) {
    if (mem_sizes[i] > best_mem) {
      best_mem = mem_sizes[i];
      best_pid = candidates[i];
    }
  }

  printf("[*] Selected PID %d (largest memory: %zu MB)\n", best_pid,
         (best_mem * 4096) / (1024 * 1024));
  return best_pid;
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
  regs.rsp -= 8;
  ptrace(PTRACE_POKEDATA, pid, regs.rsp, 0xDEADBEEF);
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  printf("[*] Executing dlopen...\n");
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  waitpid(pid, &status, 0);
  if (WIFSTOPPED(status)) {
    printf("[+] Process stopped (signal %d)\n", WSTOPSIG(status));
  }
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
    printf(" %s", line);
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
  char tmp_lib[256];
  snprintf(tmp_lib, sizeof(tmp_lib), "/tmp/linusware_inject_%d.so", getpid());
  char cp_cmd[8192];
  snprintf(cp_cmd, sizeof(cp_cmd), "cp '%s' '%s' && chmod 755 '%s'", lib_path,
           tmp_lib, tmp_lib);
  if (system(cp_cmd) != 0) {
    printf("[!] Failed to copy library to /tmp\n");
    return -1;
  }
  printf("[*] Library copied to %s\n", tmp_lib);
  char cmd[4096];
  snprintf(cmd, sizeof(cmd),
           "nsenter -t %d -m -p -U --preserve-credentials "
           "gdb -batch -n "
           "-ex 'set pagination off' "
           "-ex 'set confirm off' "
           "-ex 'attach %d' "
           "-ex 'call (void*)dlopen(\"%s\", 2)' "
           "-ex 'detach' "
           "-ex 'quit' 2>&1",
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
    printf(" %s", line);
  }
  pclose(fp);
  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *maps = fopen(maps_path, "r");
  if (maps) {
    char maps_line[512];
    while (fgets(maps_line, sizeof(maps_line), maps)) {
      if (strstr(maps_line, "linusware_inject") ||
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
  printf("║ LINUSWARE INJECTOR v1.0 ║\n");
  printf("║ Advanced TUFF Linux Process Injection Tool ║\n");
  printf("╚═══════════════════════════════════════════════════════════╝\n");
  printf("\n");
}

int main(int argc, char **argv) {
  print_banner();
  pid_t pid;
  const char *lib_path;
  if (argc >= 2) {
    pid = atoi(argv[1]);
    if (pid <= 0) {
      fprintf(stderr, "[!] Invalid PID: %s\n", argv[1]);
      return EXIT_FAILURE;
    }
    lib_path = (argc > 2) ? argv[2] : "./linusware_exec.so";
  } else {
    printf("[*] Searching for 'sober' process...\n");
    pid = find_pid("sober");
    if (pid == -1) {
      fprintf(stderr, "[!] Sober process not found\n");
      return EXIT_FAILURE;
    }
    printf("[+] Found 'sober' at PID %d\n", pid);
    lib_path = "./linusware_exec.so";
  }
  char abs_path[PATH_MAX];
  if (realpath(lib_path, abs_path) == NULL) {
    char container_path[PATH_MAX];
    snprintf(container_path, sizeof(container_path), "/proc/%d/root%s", pid,
             lib_path);
    if (access(container_path, F_OK) == 0) {
      strncpy(abs_path, lib_path, sizeof(abs_path));
      printf("[*] Library found in container filesystem: %s\n", abs_path);
    } else {
      fprintf(stderr, "[!] Library not found on host or in container: %s\n",
              lib_path);
      return EXIT_FAILURE;
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
      if (strstr(line, "linusware") || strstr(line, "sober_test_inject")) {
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