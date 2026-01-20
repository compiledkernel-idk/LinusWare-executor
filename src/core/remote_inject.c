/*
 * remote_inject.c - Remote code injection via ptrace
 *
 * Copyright (c) 2026 sultan
 * PROPRIETARY AND CONFIDENTIAL
 *
 * This implements the core injection mechanism using ptrace to execute
 * shellcode in a traced child process. Critical for bypassing anti-cheat
 * tracers in Sober.
 */

#define _GNU_SOURCE
#include "remote_inject.h"
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Log function - defined in injected_lib.c */
extern void log_debug(const char *fmt, ...);

/*
 * x86_64 dlopen shellcode template.
 *
 * This shellcode:
 * 1. Saves all registers
 * 2. Preserves the 128-byte Red Zone by subtracting from RSP
 * 3. Aligns stack to 16 bytes
 * 4. Calls dlopen(path, RTLD_NOW)
 * 5. Restores registers
 * 6. Triggers int3 to return control to tracer
 *
 * Layout:
 * [shellcode] [int3] [library_path_string]
 */
static const uint8_t DLOPEN_SHELLCODE_TEMPLATE[] = {
    /* Save all registers - push in reverse order for easy restore */
    0x50, /* push rax */
    0x51, /* push rcx */
    0x52, /* push rdx */
    0x53, /* push rbx */
    0x55, /* push rbp */
    0x56, /* push rsi */
    0x57, /* push rdi */
    0x41,
    0x50, /* push r8 */
    0x41,
    0x51, /* push r9 */
    0x41,
    0x52, /* push r10 */
    0x41,
    0x53, /* push r11 */
    0x41,
    0x54, /* push r12 */
    0x41,
    0x55, /* push r13 */
    0x41,
    0x56, /* push r14 */
    0x41,
    0x57, /* push r15 */
    0x9c, /* pushfq - save flags */

    /* Preserve Red Zone: sub rsp, 256 (128 for red zone + 128 for safety) */
    0x48,
    0x81,
    0xec,
    0x00,
    0x01,
    0x00,
    0x00,

    /* Align stack to 16 bytes: and rsp, -16 */
    0x48,
    0x83,
    0xe4,
    0xf0,

    /* Save original RSP in RBP for later restoration */
    0x48,
    0x89,
    0xe5, /* mov rbp, rsp */

    /* Load library path address into RDI (1st argument to dlopen) */
    /* The path will be appended after the shellcode */
    /* We use RIP-relative addressing */
    0x48,
    0x8d,
    0x3d, /* lea rdi, [rip + offset] */
    0x00,
    0x00,
    0x00,
    0x00, /* offset will be patched */

    /* Load RTLD_NOW (2) into RSI (2nd argument) */
    0xbe,
    0x02,
    0x00,
    0x00,
    0x00, /* mov esi, 2 */

    /* Find and call dlopen */
    /* We need the absolute address of dlopen in the target process */
    /* This will be patched with the actual address */
    0x48,
    0xb8, /* movabs rax, dlopen_addr */
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, /* 8-byte absolute address */

    0xff,
    0xd0, /* call rax */

    /* Restore original RSP from RBP */
    0x48,
    0x89,
    0xec, /* mov rsp, rbp */

    /* Undo Red Zone adjustment: add rsp, 256 */
    0x48,
    0x81,
    0xc4,
    0x00,
    0x01,
    0x00,
    0x00,

    /* Restore all registers in reverse order */
    0x9d, /* popfq - restore flags */
    0x41,
    0x5f, /* pop r15 */
    0x41,
    0x5e, /* pop r14 */
    0x41,
    0x5d, /* pop r13 */
    0x41,
    0x5c, /* pop r12 */
    0x41,
    0x5b, /* pop r11 */
    0x41,
    0x5a, /* pop r10 */
    0x41,
    0x59, /* pop r9 */
    0x41,
    0x58, /* pop r8 */
    0x5f, /* pop rdi */
    0x5e, /* pop rsi */
    0x5d, /* pop rbp */
    0x5b, /* pop rbx */
    0x5a, /* pop rdx */
    0x59, /* pop rcx */
    0x58, /* pop rax */

    /* Breakpoint - returns control to tracer */
    0xcc, /* int3 */
};

/* Offsets for patching the shellcode */
#define PATCH_OFFSET_PATH_LEA                                                  \
  47 /* Offset to the LEA instruction's displacement */
#define PATCH_OFFSET_DLOPEN_ADDR                                               \
  57 /* Offset to the dlopen address in movabs                                 \
      */
#define SHELLCODE_SIZE (sizeof(DLOPEN_SHELLCODE_TEMPLATE))

uintptr_t find_executable_region(pid_t target) {
  char path[64];
  char line[512];
  uintptr_t result = 0;

  snprintf(path, sizeof(path), "/proc/%d/maps", target);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  while (fgets(line, sizeof(line), f)) {
    uintptr_t start, end;
    char perms[8];

    if (sscanf(line, "%lx-%lx %s", &start, &end, perms) >= 3) {
      /* Look for readable + executable regions */
      if (perms[0] == 'r' && perms[2] == 'x') {
        /* Prefer RWX regions for easier writing */
        if (perms[1] == 'w') {
          result = start;
          break;
        }
        /* Fall back to RX if no RWX found */
        if (!result) {
          result = start;
        }
      }
    }
  }
  fclose(f);

  return result;
}

uintptr_t find_memory_cave(pid_t target, size_t min_size) {
  char path[64];
  char line[512];

  snprintf(path, sizeof(path), "/proc/%d/maps", target);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  /* Find a large executable region and scan for caves */
  uintptr_t best_region = 0;
  size_t best_size = 0;

  while (fgets(line, sizeof(line), f)) {
    uintptr_t start, end;
    char perms[8];

    if (sscanf(line, "%lx-%lx %s", &start, &end, perms) >= 3) {
      size_t size = end - start;
      if (perms[0] == 'r' && perms[2] == 'x' && size > best_size) {
        best_region = start;
        best_size = size;
      }
    }
  }
  fclose(f);

  if (!best_region)
    return 0;

  /* For now, just return the start + some offset */
  /* A proper implementation would scan for 0xCC or 0x00 runs */
  return best_region + 0x1000; /* Skip first page */
}

int write_to_remote(pid_t target, uintptr_t addr, const void *data,
                    size_t len) {
  const unsigned long *words = (const unsigned long *)data;
  size_t word_count = (len + sizeof(long) - 1) / sizeof(long);

  for (size_t i = 0; i < word_count; i++) {
    unsigned long word = 0;
    size_t remaining = len - i * sizeof(long);
    size_t to_copy = (remaining > sizeof(long)) ? sizeof(long) : remaining;
    memcpy(&word, (const char *)data + i * sizeof(long), to_copy);

    if (ptrace(PTRACE_POKEDATA, target, addr + i * sizeof(long), word) < 0) {
      log_debug("POKEDATA failed at 0x%lx: %s\n", addr + i * sizeof(long),
                strerror(errno));
      return -1;
    }
  }

  return 0;
}

int read_from_remote(pid_t target, uintptr_t addr, void *buf, size_t len) {
  unsigned long *words = (unsigned long *)buf;
  size_t word_count = (len + sizeof(long) - 1) / sizeof(long);

  for (size_t i = 0; i < word_count; i++) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, target, addr + i * sizeof(long), NULL);
    if (word == -1 && errno != 0) {
      log_debug("PEEKDATA failed at 0x%lx: %s\n", addr + i * sizeof(long),
                strerror(errno));
      return -1;
    }
    words[i] = word;
  }

  return 0;
}

int save_target_state(pid_t target, saved_state_t *state, uintptr_t addr,
                      size_t len) {
  if (!state)
    return -1;

  memset(state, 0, sizeof(*state));

  /* Save registers */
  if (ptrace(PTRACE_GETREGS, target, NULL, &state->regs) < 0) {
    log_debug("Failed to save registers: %s\n", strerror(errno));
    return -1;
  }

  /* Save original code at injection point */
  state->shellcode_addr = addr;
  state->shellcode_size = len;

  if (read_from_remote(target, addr, state->original_code, len) < 0) {
    return -1;
  }

  state->valid = 1;
  return 0;
}

int restore_target_state(pid_t target, const saved_state_t *state) {
  if (!state || !state->valid)
    return -1;

  /* Restore original code */
  if (write_to_remote(target, state->shellcode_addr, state->original_code,
                      state->shellcode_size) < 0) {
    log_debug("Failed to restore original code\n");
    return -1;
  }

  /* Restore registers */
  if (ptrace(PTRACE_SETREGS, target, NULL, &state->regs) < 0) {
    log_debug("Failed to restore registers: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

int wait_for_stop(pid_t target, int timeout_ms) {
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);

  while (1) {
    int status;
    pid_t result = waitpid(target, &status, WNOHANG);

    if (result < 0) {
      return -1;
    }

    if (result > 0) {
      if (WIFSTOPPED(status)) {
        return status;
      }
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        log_debug("Target exited unexpectedly\n");
        return -1;
      }
    }

    /* Check timeout */
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
                      (now.tv_nsec - start.tv_nsec) / 1000000;

    if (elapsed_ms >= timeout_ms) {
      return INJECT_ERR_TIMEOUT;
    }

    usleep(1000); /* Sleep 1ms */
  }
}

size_t generate_dlopen_shellcode(uint8_t *buf, size_t max_len,
                                 const char *library_path) {
  size_t path_len = strlen(library_path) + 1;
  size_t total_size = SHELLCODE_SIZE + path_len;

  if (total_size > max_len) {
    return 0;
  }

  /* Copy template */
  memcpy(buf, DLOPEN_SHELLCODE_TEMPLATE, SHELLCODE_SIZE);

  /* Append library path after shellcode */
  memcpy(buf + SHELLCODE_SIZE, library_path, path_len);

  /* Patch the LEA offset: distance from LEA instruction end to path string */
  int32_t lea_offset = SHELLCODE_SIZE - (PATCH_OFFSET_PATH_LEA + 4);
  memcpy(buf + PATCH_OFFSET_PATH_LEA, &lea_offset, 4);

  return total_size;
}

/*
 * Known dlopen offsets for common glibc versions used in Flatpak.
 * These are fallbacks if we can't read the target's libc directly.
 */
static const uintptr_t KNOWN_DLOPEN_OFFSETS[] = {
    0x89770,  /* glibc 2.38 (Fedora 39, Ubuntu 24.04) */
    0x8a770,  /* glibc 2.39 (Fedora 40) */
    0x88f70,  /* glibc 2.37 (Fedora 38) */
    0x84270,  /* glibc 2.36 */
    0x7f000,  /* glibc 2.35 */
    0x7a770,  /* glibc 2.34 */
    0x77860,  /* glibc 2.33 */
    0x163290, /* glibc 2.31-2.32 (older) */
};
#define NUM_KNOWN_OFFSETS                                                      \
  (sizeof(KNOWN_DLOPEN_OFFSETS) / sizeof(KNOWN_DLOPEN_OFFSETS[0]))

uintptr_t find_dlopen_address(pid_t target) {
  char path[128];
  char line[512];
  uintptr_t libc_base = 0;
  char libc_path[256] = {0};

  /* Find libc base and path in target process */
  snprintf(path, sizeof(path), "/proc/%d/maps", target);
  FILE *f = fopen(path, "r");
  if (!f) {
    log_debug("Cannot open %s\n", path);
    return 0;
  }

  while (fgets(line, sizeof(line), f)) {
    /* Match /libc.so or /libc- specifically, NOT libcap/libcurl etc */
    if ((strstr(line, "/libc.so") || strstr(line, "/libc-2")) &&
        strstr(line, "r-xp")) {
      /* Parse the line: addr-addr perms offset dev inode pathname */
      uintptr_t start;
      char perms[8], offset[16], dev[16];
      unsigned long inode;
      char pathname[256];

      if (sscanf(line, "%lx-%*lx %s %s %s %lu %255s", &start, perms, offset,
                 dev, &inode, pathname) >= 6) {
        libc_base = start;
        strncpy(libc_path, pathname, sizeof(libc_path) - 1);
      } else {
        sscanf(line, "%lx", &libc_base);
      }
      break;
    }
  }
  fclose(f);

  if (!libc_base) {
    log_debug("Could not find libc in target %d\n", target);
    return 0;
  }

  log_debug("Target libc base: 0x%lx, path: %s\n", libc_base, libc_path);

  /* Try to read the actual libc from the target's namespace */
  /* For Flatpak, we need to use /proc/PID/root/path */
  snprintf(path, sizeof(path), "/proc/%d/root%s", target, libc_path);

  /* Try to find dlopen in the ELF using nm or readelf output pattern */
  /* Since reading ELF is complex, use process_vm_readv to probe */

  /* FALLBACK: Try known offsets and see if they look like valid code */
  log_debug("Trying known dlopen offsets...\n");

  for (size_t i = 0; i < NUM_KNOWN_OFFSETS; i++) {
    uintptr_t candidate = libc_base + KNOWN_DLOPEN_OFFSETS[i];

    /* We can't easily verify if this is valid from outside the process */
    /* Just try the most common one for modern systems */
    if (i == 0) {
      log_debug("Using dlopen candidate: 0x%lx (offset 0x%lx)\n", candidate,
                KNOWN_DLOPEN_OFFSETS[i]);
      return candidate;
    }
  }

  log_debug("No dlopen candidates found\n");
  return 0;
}

int inject_and_execute(pid_t target, const uint8_t *shellcode, size_t len) {
  saved_state_t saved;
  int result = INJECT_SUCCESS;
  int attached = 0;

  /* Try to attach if we're not already tracing */
  if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == 0) {
    attached = 1;
    if (wait_for_stop(target, 5000) < 0) {
      log_debug("Failed to wait for attach stop\n");
      result = INJECT_ERR_ATTACH;
      goto cleanup;
    }
  } else if (errno != EPERM) {
    log_debug("PTRACE_ATTACH failed: %s\n", strerror(errno));
    result = INJECT_ERR_ATTACH;
    goto cleanup;
  }
  /* else: we're already attached (we are the tracer) */

  /* Find executable memory */
  uintptr_t inject_addr = find_memory_cave(target, len);
  if (!inject_addr) {
    inject_addr = find_executable_region(target);
  }
  if (!inject_addr) {
    log_debug("No executable memory found in target\n");
    result = INJECT_ERR_NO_MEMORY;
    goto cleanup;
  }

  log_debug("Injecting %zu bytes at 0x%lx in PID %d\n", len, inject_addr,
            target);

  /* Save original state */
  if (save_target_state(target, &saved, inject_addr, len) < 0) {
    log_debug("Failed to save target state\n");
    result = INJECT_ERR_WRITE;
    goto cleanup;
  }

  /* Write shellcode */
  if (write_to_remote(target, inject_addr, shellcode, len) < 0) {
    log_debug("Failed to write shellcode\n");
    result = INJECT_ERR_WRITE;
    goto cleanup;
  }

  /* Modify RIP to point to shellcode */
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, target, NULL, &regs) < 0) {
    log_debug("Failed to get registers\n");
    result = INJECT_ERR_EXECUTE;
    goto restore;
  }

  regs.rip = inject_addr;

  if (ptrace(PTRACE_SETREGS, target, NULL, &regs) < 0) {
    log_debug("Failed to set RIP\n");
    result = INJECT_ERR_EXECUTE;
    goto restore;
  }

  /* Continue execution */
  if (ptrace(PTRACE_CONT, target, NULL, NULL) < 0) {
    log_debug("Failed to continue target\n");
    result = INJECT_ERR_EXECUTE;
    goto restore;
  }

  /* Wait for int3 (shellcode completion) */
  int status = wait_for_stop(target, 10000);
  if (status < 0) {
    log_debug("Shellcode execution failed or timed out\n");
    result = (status == INJECT_ERR_TIMEOUT) ? INJECT_ERR_TIMEOUT
                                            : INJECT_ERR_EXECUTE;
    goto restore;
  }

  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    log_debug("Shellcode executed successfully!\n");
  } else {
    log_debug("Unexpected stop signal: %d\n", WSTOPSIG(status));
  }

restore:
  /* Restore original state */
  if (restore_target_state(target, &saved) < 0) {
    log_debug("Failed to restore target state\n");
    if (result == INJECT_SUCCESS) {
      result = INJECT_ERR_RESTORE;
    }
  }

cleanup:
  if (attached) {
    ptrace(PTRACE_DETACH, target, NULL, NULL);
  }

  /* Continue execution if we were already the tracer */
  if (!attached) {
    ptrace(PTRACE_CONT, target, NULL, NULL);
  }

  return result;
}

int inject_library(pid_t target, const char *library_path) {
  uint8_t shellcode[MAX_SHELLCODE_SIZE];

  /* Generate the shellcode */
  size_t shellcode_size =
      generate_dlopen_shellcode(shellcode, sizeof(shellcode), library_path);

  if (shellcode_size == 0) {
    log_debug("Failed to generate shellcode\n");
    return -1;
  }

  /* Find dlopen address in target */
  uintptr_t dlopen_addr = find_dlopen_address(target);
  if (!dlopen_addr) {
    log_debug("Failed to find dlopen in target\n");
    return -1;
  }

  log_debug("dlopen @ 0x%lx in target\n", dlopen_addr);

  /* Patch dlopen address into shellcode */
  memcpy(shellcode + PATCH_OFFSET_DLOPEN_ADDR, &dlopen_addr, 8);

  /* Inject and execute */
  return inject_and_execute(target, shellcode, shellcode_size);
}
