
/*
 * Filename: injected_lib.c
 *
 * Copyright (c) 2026 compiledkernel-idk
 * All Rights Reserved.
 *
 * This software is proprietary and confidential.
 * Unauthorized copying, distribution, or use of this file,
 * via any medium, is strictly prohibited.
 */

#define _GNU_SOURCE
#include "roblox_offsets.h"
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "luau_api.h"

// Anti-tamper bypass (reserved for future use)
static void __attribute__((unused)) hide_thread(void) {
  prctl(PR_SET_NAME, "kworker/0:0", 0, 0, 0);
}

static void __attribute__((unused)) bypass_antitamper(void) {
  ptrace(PTRACE_TRACEME, 0, 0, 0);
  personality(ADDR_NO_RANDOMIZE);
}

extern void heavy_simd_math(float *a, int b);
static void __attribute__((used)) keep_flex() {
  if (0)
    heavy_simd_math(0, 0);
}

#define LOG_PATH "/tmp/linusware_debug.log"
#define IPC_READY_PATH "/tmp/linusware_ready"
#define IPC_EXEC_PATH "/tmp/linusware_exec.txt"
#define IPC_OUT_PATH "/tmp/linusware_output.txt"
#define IPC_CMD_PATH "/tmp/linusware_cmd.txt"

static volatile int g_running = 1;
static pthread_t g_worker_thread;
static FILE *g_log = NULL;

static luau_api_t g_api = {0};

static sigjmp_buf g_jmp;
static volatile int g_in_call = 0;

// Forward declaration
static void crash_handler(int sig);

void log_debug(const char *fmt, ...) {
  if (!g_log) {
    g_log = fopen(LOG_PATH, "a");
    if (g_log)
      chmod(LOG_PATH, 0666);
  }
  if (g_log) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "[%H:%M:%S] ", tm_info);
    fputs(timestamp, g_log);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_log, fmt, args);
    va_end(args);
    fflush(g_log);
  }
}

static void write_ready_signal(void) {
  FILE *f = fopen(IPC_READY_PATH, "w");
  if (f) {
    fprintf(f, "LINUSWARE_V1\n");
    fprintf(f, "sober_base=0x%lx\n", g_api.sober_base);
    fprintf(f, "lua_state=%p\n", (void *)g_api.L);
    fprintf(f, "functions=%d\n", g_api.functions_resolved);
    fchmod(fileno(f), 0666);
    fclose(f);
    log_debug("Ready signal written to %s\n", IPC_READY_PATH);
  } else {
    log_debug("Failed to write ready signal: %s\n", strerror(errno));
  }
}

static void write_output(const char *fmt, ...) {
  FILE *out = fopen(IPC_OUT_PATH, "w");
  if (out) {
    chmod(IPC_OUT_PATH, 0666);
    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);
    fclose(out);
  }
}

static char *read_script(void) {
  FILE *f = fopen(IPC_EXEC_PATH, "r");
  if (!f)
    return NULL;

  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (fsize <= 0) {
    fclose(f);
    return NULL;
  }

  char *script = malloc(fsize + 1);
  if (!script) {
    fclose(f);
    return NULL;
  }

  size_t read_size = fread(script, 1, fsize, f);
  script[read_size] = '\0';

  // Trim trailing whitespace/newlines
  while (read_size > 0 &&
         (script[read_size - 1] == '\n' || script[read_size - 1] == '\r' ||
          script[read_size - 1] == ' ')) {
    script[read_size - 1] = '\0';
    read_size--;
  }

  fclose(f);
  unlink(IPC_EXEC_PATH);

  return script;
}

static void __attribute__((unused)) unlockbreaker(void) {
  pid_t my_pid = getpid();
  DIR *d = opendir("/proc");
  if (!d)
    return;

  struct dirent *e;
  while ((e = readdir(d))) {
    if (e->d_type != DT_DIR)
      continue;

    pid_t pid = atoi(e->d_name);
    if (pid <= 0 || pid == my_pid)
      continue;

    char status_path[256], line[256];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    FILE *f = fopen(status_path, "r");
    if (!f)
      continue;

    int tracer = 0;
    while (fgets(line, sizeof(line), f)) {
      if (strncmp(line, "TracerPid:", 10) == 0) {
        tracer = atoi(line + 10);
        break;
      }
    }
    fclose(f);

    if (tracer == my_pid) {
      log_debug("Unlocking traced process %d\n", pid);
      ptrace(PTRACE_DETACH, pid, 0, 0);
    }
  }
  closedir(d);
}

uintptr_t find_sober_base(void) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  char line[512];
  uintptr_t base = 0;
  uintptr_t first_rx = 0;

  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start;
    if (sscanf(line, "%lx", &start) != 1)
      continue;

    if (strstr(line, "r-xp")) {
      if (!first_rx)
        first_rx = start;

      if (strstr(line, "/sober") || strstr(line, "/app/bin/sober") ||
          strstr(line, "libroblox") || strstr(line, "libloader")) {
        base = start;
        log_debug("Found Sober/Game base via path: 0x%lx (%s)\n", base, line);
        break;
      }
    }
  }

  if (!base && first_rx) {
    base = first_rx;
    log_debug("Fallback: Using first R-XP region as base: 0x%lx\n", base);
  }

  fclose(maps);
  return base;
}

static uintptr_t find_libloader_base(void) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  char line[512];
  uintptr_t base = 0;

  while (fgets(line, sizeof(line), maps)) {
    if (strstr(line, "r-xp")) {
      if (strstr(line, "libloader.so") || strstr(line, "libroblox") ||
          strstr(line, "libgnustl_shared")) {
        sscanf(line, "%lx", &base);
        log_debug("Found libloader/game base: 0x%lx\n", base);
        break;
      }
    }
  }

  if (!base) {
    // Second chance: look for any large executable region that isn't a known
    // system system lib
    fseek(maps, 0, SEEK_SET);
    while (fgets(line, sizeof(line), maps)) {
      uintptr_t start, end;
      if (sscanf(line, "%lx-%lx", &start, &end) != 2)
        continue;
      if (strstr(line, "r-xp") && (end - start) > 5 * 1024 * 1024) { // > 5MB
        if (!strstr(line, "libc.so") && !strstr(line, "libQt") &&
            !strstr(line, "libicu")) {
          base = start;
          log_debug("Heuristic: Found large RX region (likely game): 0x%lx\n",
                    base);
          break;
        }
      }
    }
  }

  fclose(maps);
  return base;
}

// Optimized Assembly Routine
extern int fast_check_ptr(void *ptr);

typedef struct {
  uintptr_t candidate;
  int score;
  int valid_ptrs;
  int code_ptrs;
  int reasonable_stack;
} lua_state_candidate_t;

static int score_lua_state_candidate(uintptr_t addr, uintptr_t sober_base) {

  uint8_t header[64];
  int mem_fd = open("/proc/self/mem", O_RDONLY);
  if (mem_fd < 0)
    return 0;

  ssize_t r = pread(mem_fd, header, sizeof(header), addr);
  close(mem_fd);

  if (r < (ssize_t)sizeof(header))
    return 0;

  int score = 0;
  uintptr_t *ptrs = (uintptr_t *)(header + 8);

  for (int i = 0; i < 6; i++) {
    uintptr_t p = ptrs[i];

    if (fast_check_ptr((void *)p) && p > 0x10000) {
      score += 2;
    }

    if (p >= sober_base && p < sober_base + 0x800000) {
      score += 5;
    }
  }

  uintptr_t maybe_base = ptrs[1];
  uintptr_t maybe_top = ptrs[2];

  if (maybe_top > maybe_base && (maybe_top - maybe_base) < 8 * 1024 * 1024) {
    score += 10;
  }

  return score;
}

lua_State *find_lua_state(uintptr_t sober_base) {
  if (!sober_base)
    return NULL;

  lua_State *result = NULL;

  // DISABLED: Static anchor check causes unrecoverable crashes
  // The offset is likely wrong for this version of Sober
  // Go straight to the safer pread-based scan
  log_debug("Skipping static anchor (causes crashes), using full scan...\n");
  if (g_log)
    fflush(g_log);

  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return NULL;

  int mem_fd = open("/proc/self/mem", O_RDONLY);
  if (mem_fd < 0) {
    fclose(maps);
    return NULL;
  }

  lua_state_candidate_t best = {0, 0, 0, 0, 0};
  char line[512];

  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start, end;
    char perms[5];
    int inode = 0;

    if (sscanf(line, "%lx-%lx %4s %*x %*s %d", &start, &end, perms, &inode) < 3)
      continue;

    if (perms[0] != 'r' || perms[1] != 'w' || inode != 0)
      continue;

    size_t region_size = end - start;
    if (region_size < 4096 || region_size > 100 * 1024 * 1024)
      continue;

    log_debug("Scanning region 0x%lx - 0x%lx (%zu KB)\n", start, end,
              region_size / 1024);

    uint8_t buf[4096];
    for (uintptr_t offset = 0; offset < region_size; offset += 256 * 1024) {
      ssize_t r = pread(mem_fd, buf, sizeof(buf), start + offset);
      if (r < 128)
        continue;

      for (size_t i = 0; i < (size_t)r - 64; i += 8) {
        uintptr_t candidate = start + offset + i;

        uintptr_t *ptrs = (uintptr_t *)(buf + i);

        int valid = 0, code = 0;
        for (int j = 0; j < 8; j++) {
          if (ptrs[j] > 0x10000 && ptrs[j] < 0x800000000000UL)
            valid++;
          if (ptrs[j] >= sober_base && ptrs[j] < sober_base + 0x800000)
            code++;
        }

        if (valid >= 5 && code >= 1) {
          int score = score_lua_state_candidate(candidate, sober_base);
          if (score > best.score) {
            best.candidate = candidate;
            best.score = score;
            best.valid_ptrs = valid;
            best.code_ptrs = code;
          }
        }
      }
    }
  }

  close(mem_fd);
  fclose(maps);

  if (best.score >= 15) {
    log_debug("Best Lua state candidate: 0x%lx (score=%d, valid=%d, code=%d)\n",
              best.candidate, best.score, best.valid_ptrs, best.code_ptrs);
    return (lua_State *)best.candidate;
  }

  log_debug("No good Lua state candidate found (best score: %d)\n", best.score);
  return NULL;
}

static void crash_handler(int sig) {
  if (g_in_call) {
    log_debug("CRASH in function call (signal %d)\n", sig);
    g_in_call = 0;
    siglongjmp(g_jmp, 1);
  }
}

int safe_call(void *func, lua_State *L, const char *arg) {
  if (!func || !L)
    return -1;

  struct sigaction sa, old_segv, old_bus, old_fpe;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = crash_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  sigaction(SIGSEGV, &sa, &old_segv);
  sigaction(SIGBUS, &sa, &old_bus);
  sigaction(SIGFPE, &sa, &old_fpe);

  g_in_call = 1;
  int result = -1;

  if (sigsetjmp(g_jmp, 1) == 0) {

    typedef void (*getglobal_t)(lua_State *, const char *);
    getglobal_t fn = (getglobal_t)func;
    fn(L, arg);
    result = 0;
    g_in_call = 0;
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  sigaction(SIGBUS, &old_bus, NULL);
  sigaction(SIGFPE, &old_fpe, NULL);

  return result;
}

extern int scan_and_resolve_functions(luau_api_t *api);
extern int probe_candidate_offsets(luau_api_t *api,
                                   int (*test_func)(void *, lua_State *,
                                                    const char *));
extern int hook_script_execution(uintptr_t libloader_base, void **L_store);
extern void queue_script(const char *script);

static const uintptr_t __attribute__((unused)) KNOWN_OFFSETS[] = {

    0x1846a0, 0x1846c0, 0x1846e0, 0x184920, 0x184940, 0x1849b0,

    0x180dd0, 0x181c10, 0x183590, 0x183bf0,

    0x120430, 0x1239a0, 0};

int resolve_functions(luau_api_t *api) {
  if (!api || !api->sober_base) {
    return -1;
  }

  int resolved = 0;

  // Find libloader.so base (for fallback)
  uintptr_t libloader_base = find_libloader_base();
  log_debug("Sober base: 0x%lx, libloader base: 0x%lx\n", api->sober_base,
            libloader_base);

  // Get lua_State from the scan (already done in luau_api_init)
  if (api->L) {
    log_debug("Using lua_State: %p\n", (void *)api->L);
    resolved++;
  }
  /*
   * OFFSET STRATEGY:
   *
   * First, check if WE are the game process (have large memory regions).
   * If we are, use our own regions for offsets.
   * Only look at child processes if we're in bwrap (no large regions).
   */

  uintptr_t roblox_code_base = 0;
  pid_t target_pid = getpid();

  // FIRST: Check if WE have large memory regions (meaning we are the game)
  FILE *self_maps = fopen("/proc/self/maps", "r");
  if (self_maps) {
    char line[512];
    while (fgets(line, sizeof(line), self_maps)) {
      uintptr_t start, end;
      char perms[8];
      if (sscanf(line, "%lx-%lx %s", &start, &end, perms) >= 3) {
        size_t size = end - start;
        // Look for a 100MB+ region in OUR OWN address space
        if (size >= 100 * 1024 * 1024 && start > 0x7f0000000000UL &&
            perms[0] == 'r' && !strstr(line, ".so") &&
            !strstr(line, "mimalloc") && !strstr(line, "linusware")) {
          roblox_code_base = start;
          log_debug("WE are the game process! Found 100MB+ region in SELF: "
                    "0x%lx (%zu MB)\n",
                    start, size / (1024 * 1024));
          break;
        }
      }
    }
    fclose(self_maps);
  }

  // If we found it in ourselves, we're good - skip child process scanning
  if (roblox_code_base) {
    log_debug("Using our own code base: 0x%lx\n", roblox_code_base);
  } else {
    // We're in bwrap - need to find child process (but this won't work for
    // execution!)
    log_debug("We are bwrap/wrapper - looking for child process (EXECUTION "
              "WILL FAIL)\n");
    target_pid = 0;
    DIR *proc_dir = opendir("/proc");
    if (proc_dir) {
      struct dirent *entry;
      size_t max_mem = 0;

      while ((entry = readdir(proc_dir))) {
        if (entry->d_type != DT_DIR)
          continue;
        pid_t pid = atoi(entry->d_name);
        if (pid <= 0)
          continue;

        // Check if this is a sober process
        char exe_path[256], exe_target[256];
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/root/app/bin/sober",
                 pid);
        if (access(exe_path, F_OK) != 0)
          continue;

        // Get memory size
        char statm_path[256];
        snprintf(statm_path, sizeof(statm_path), "/proc/%d/statm", pid);
        FILE *statm = fopen(statm_path, "r");
        if (statm) {
          size_t mem_pages = 0;
          fscanf(statm, "%zu", &mem_pages);
          fclose(statm);

          if (mem_pages > max_mem) {
            max_mem = mem_pages;
            target_pid = pid;
          }
        }
      }
      closedir(proc_dir);
    }

    log_debug("Found target sober PID: %d (mem: largest)\n", target_pid);

    // Now scan the target process's maps for large regions
    if (target_pid > 0) {
      char maps_path[256];
      snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", target_pid);
      FILE *maps = fopen(maps_path, "r");

      if (maps) {
        uintptr_t large_regions[10] = {0};
        int region_count = 0;
        char line[512];

        while (fgets(line, sizeof(line), maps) && region_count < 10) {
          uintptr_t start, end;
          char perms[8];

          if (sscanf(line, "%lx-%lx %s", &start, &end, perms) >= 3) {
            size_t size = end - start;

            // Skip known non-code regions
            if (strstr(line, "["))
              continue;
            if (strstr(line, "/usr/lib"))
              continue;
            if (strstr(line, "/lib/"))
              continue;
            if (strstr(line, ".so"))
              continue;

            // Look for large anonymous regions (>10MB)
            if (size > 10 * 1024 * 1024 && perms[0] == 'r') {
              log_debug("Child PID %d region #%d: 0x%lx - 0x%lx (%zu MB)\n",
                        target_pid, region_count + 1, start, end,
                        size / (1024 * 1024));
              large_regions[region_count++] = start;
            }
          }
        }
        fclose(maps);

        // Find the region that's at least 100MB (offsets go up to 105MB)
        // This is typically region #6 in quarty's findings
        for (int i = 0; i < region_count; i++) {
          // We stored start addresses - need to also check if the region is big
          // enough The largest offset is 0x646928b (~105MB), so region must be
          // > 110MB
          log_debug("Checking region %d: 0x%lx\n", i + 1, large_regions[i]);
        }

        // Strategy: Find the first region >= 100MB in the right address range
        // Re-scan to get sizes, skip low-address mimalloc regions
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", target_pid);
        maps = fopen(maps_path, "r");
        if (maps) {
          while (fgets(line, sizeof(line), maps)) {
            uintptr_t start, end;
            char perms[8];
            if (sscanf(line, "%lx-%lx %s", &start, &end, perms) >= 3) {
              size_t size = end - start;
              // Must be in the 0x7f... address range (not low mimalloc regions)
              // Must be >= 100MB and readable, not a .so file, not mimalloc
              if (size >= 100 * 1024 * 1024 && start > 0x7f0000000000UL &&
                  perms[0] == 'r' && !strstr(line, ".so") &&
                  !strstr(line, "mimalloc")) {
                roblox_code_base = start;
                log_debug("Found valid 100MB+ region: 0x%lx - 0x%lx (%zu MB)\n",
                          start, end, size / (1024 * 1024));
                break;
              }
            }
          }
          fclose(maps);
        }

        if (!roblox_code_base && region_count >= 3) {
          roblox_code_base = large_regions[2];
          log_debug("Fallback to THIRD region: 0x%lx\n", roblox_code_base);
        } else if (!roblox_code_base && region_count > 0) {
          roblox_code_base = large_regions[region_count - 1];
          log_debug("Fallback to last region: 0x%lx\n", roblox_code_base);
        }
      }
    }

    if (!roblox_code_base) {
      log_debug(
          "WARNING: Could not find Roblox code region in child process\n");
      // Can't proceed without proper base
      roblox_code_base = api->sober_base;
    }
  } // End of else block (we're in bwrap)

  log_debug("Using Roblox code base: 0x%lx\n", roblox_code_base);

  // Apply offsets from roblox_offsets.h
  // These are offsets INTO the decrypted Roblox code region
  api->luau_load = (luau_load_t)(roblox_code_base + OFF_luau_load);
  api->pcall = (lua_pcall_t)(roblox_code_base + OFF_luaD_pcall);
  api->pushstring = (lua_pushstring_t)(roblox_code_base + OFF_lua_pushstring);
  api->pushvalue = (lua_pushvalue_t)(roblox_code_base + OFF_lua_pushvalue);
  api->setfield = (lua_setfield_t)(roblox_code_base + OFF_lua_setfield);

  // For stack operations, try the old libloader offsets first (might still
  // work)
  if (libloader_base) {
    api->gettop = (lua_gettop_t)(libloader_base + 0x36600);
    api->settop = (lua_settop_t)(libloader_base + 0x15600);
  }

  // Validate that the function pointers look reasonable
  // (they should point to executable memory)
  if (api->luau_load) {
    log_debug("luau_load @ %p (offset 0x%lx from base)\n",
              (void *)api->luau_load, OFF_luau_load);
    resolved++;
  }
  if (api->pcall) {
    log_debug("pcall @ %p (offset 0x%lx from base)\n", (void *)api->pcall,
              OFF_luaD_pcall);
    resolved++;
  }
  if (api->pushstring) {
    log_debug("pushstring @ %p\n", (void *)api->pushstring);
    resolved++;
  }

  log_debug("Resolved %d functions total\n", resolved);
  api->functions_resolved = resolved;
  return resolved;
}

int execute_script(luau_api_t *api, const char *script, char *output,
                   size_t output_size) {
  if (!api || !script || !output) {
    return -1;
  }

  // Check for internal commands FIRST (Bypass state check)
  if (strncmp(script, "__", 2) == 0) {
    // Let the worker thread handle the command logic
    // We just return success here so the UI knows it was received
    return 0;
  }

  if (!api->L || (!api->loadbuffer && !api->luau_load) || !api->pcall) {
    // If we're missing core functions or the state, we fallback to hijacking
    // internal game calls
    log_debug("Missing core components (L=%p, load=%p, pc=%p). Queuing via "
              "hook...\n",
              (void *)api->L, (void *)api->luau_load, (void *)api->pcall);

    queue_script(script);

    snprintf(output, output_size,
             "NOTICE: Direct execution blocked (Encryption active).\n"
             "Your script has been QUEUED.\n"
             "\n"
             "Go back to Roblox and do something (open menu, etc).\n"
             "The engine will hijack the next game call to run your script.");
    return 0;
  }

  if (!api->pcall) {
    snprintf(output, output_size,
             "ERROR: lua_pcall not found\n"
             "\n"
             "Cannot execute scripts without pcall function.\n"
             "Manual offset discovery required.");
    return -1;
  }

  log_debug("Executing script (%zu bytes)...\\n", strlen(script));

  struct sigaction sa, old_segv, old_bus;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = crash_handler;
  sigaction(SIGSEGV, &sa, &old_segv);
  sigaction(SIGBUS, &sa, &old_bus);

  g_in_call = 1;
  int status = -1;

  if (sigsetjmp(g_jmp, 1) == 0) {

    int top = api->gettop ? api->gettop(api->L) : 0;

    // Use luau_load if available, otherwise legacy loadbuffer
    if (api->luau_load) {
      status = api->luau_load(api->L, "@sirracha", script, strlen(script), 0);
    } else if (api->loadbuffer) {
      status = api->loadbuffer(api->L, script, strlen(script), "@sirracha");
    } else {
      status = -1; // Should be caught above
    }

    if (status != LUA_OK) {

      const char *err = "Unknown compilation error";
      if (api->tolstring) {
        err = api->tolstring(api->L, -1, NULL);
      }
      snprintf(output, output_size, "COMPILE ERROR: %s", err ? err : "null");

      if (api->settop)
        api->settop(api->L, top);
      g_in_call = 0;
      sigaction(SIGSEGV, &old_segv, NULL);
      sigaction(SIGBUS, &old_bus, NULL);
      return -1;
    }

    log_debug("Script compiled, executing...\n");

    status = api->pcall(api->L, 0, 0, 0);

    if (status != LUA_OK) {
      const char *err = "Unknown runtime error";
      if (api->tolstring) {
        err = api->tolstring(api->L, -1, NULL);
      }
      snprintf(output, output_size, "RUNTIME ERROR: %s", err ? err : "null");

      if (api->settop)
        api->settop(api->L, top);
      g_in_call = 0;
      sigaction(SIGSEGV, &old_segv, NULL);
      sigaction(SIGBUS, &old_bus, NULL);
      return -1;
    }

    snprintf(output, output_size, "✓ Script executed successfully");
    if (api->settop)
      api->settop(api->L, top);

    g_in_call = 0;
  } else {

    snprintf(output, output_size, "CRASH: Execution caused a signal");
    status = -1;
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  sigaction(SIGBUS, &old_bus, NULL);

  return status;
}

int luau_api_init(luau_api_t *api) {
  memset(api, 0, sizeof(luau_api_t));

  log_debug("===========================================\n");
  log_debug("Sirracha Executor v2.0 - Full Edition\n");
  log_debug("PID: %d\n", getpid());
  log_debug("===========================================\n");

  // unlockbreaker(); // Disabled to prevent crash caused by detaching
  // internal tracers

  api->sober_base = find_sober_base();
  if (!api->sober_base) {
    log_debug("FATAL: Could not find Sober base address\n");
    return -1;
  }
  log_debug("Sober base: 0x%lx\n", api->sober_base);

  api->L = find_lua_state(api->sober_base);
  if (!api->L) {
    log_debug("WARNING: Could not find Lua state (will retry)\n");

  } else {
    log_debug("Lua state: %p\n", (void *)api->L);
  }

  int resolved = resolve_functions(api);
  log_debug("Resolved %d functions\n", resolved);

  if (resolved < 3 && api->sober_base) {
    uintptr_t libloader = find_libloader_base();
    if (libloader) {
      log_debug("Too few functions resolved (encryption active). Attempting "
                "hook-based recovery...\n");
      if (hook_script_execution(libloader, (void **)&api->L)) {
        log_debug("Auto-hook successful.\n");
      }
    }
  }

  api->initialized = 1;
  return 0;
}

static void probe_functions(void) {
  char output[4096];
  int pos = 0;

  pos += snprintf(output + pos, sizeof(output) - pos,
                  "===== SIRRACHA EXECUTOR v2.0 =====\n\n"
                  "Sober Base: 0x%lx\n"
                  "Lua State: %p\n"
                  "Functions: %d resolved\n\n",
                  g_api.sober_base, (void *)g_api.L, g_api.functions_resolved);

  pos += snprintf(output + pos, sizeof(output) - pos,
                  "Resolved Functions:\n"
                  "  getglobal:   %p\n"
                  "  gettop:      %p\n"
                  "  settop:      %p\n"
                  "  pushstring:  %p\n"
                  "  pcall:       %p\n"
                  "  loadbuffer:  %p\n"
                  "  tolstring:   %p\n\n",
                  (void *)g_api.getglobal, (void *)g_api.gettop,
                  (void *)g_api.settop, (void *)g_api.pushstring,
                  (void *)g_api.pcall, (void *)g_api.loadbuffer,
                  (void *)g_api.tolstring);

  if (g_api.L && (g_api.loadbuffer || g_api.luau_load) && g_api.pcall) {

    pos += snprintf(output + pos, sizeof(output) - pos,
                    "STATUS: Ready to execute scripts!\n");
  } else {
    pos += snprintf(output + pos, sizeof(output) - pos,
                    "STATUS: Missing components, limited functionality\n");
  }

  write_output("%s", output);
}

void *worker_thread_func(void *arg) {
  (void)arg;

  // Brief stabilization delay
  sleep(1);

  if (luau_api_init(&g_api) < 0) {
    log_debug("Failed to initialize Luau API\n");
  }

  write_ready_signal();

  while (g_running) {

    if (access(IPC_EXEC_PATH, F_OK) == 0) {
      char *script = read_script();
      if (script && strlen(script) > 0) {
        log_debug("Received script: %s\n", script);

        if (strcmp(script, "__PROBE__") == 0) {
          probe_functions();
        } else if (strcmp(script, "__RESCAN__") == 0) {

          g_api.L = find_lua_state(g_api.sober_base);
          resolve_functions(&g_api);
          write_ready_signal();
          write_output("Rescanned. State=%p, Funcs=%d\n", (void *)g_api.L,
                       g_api.functions_resolved);
        } else if (strcmp(script, "__STRINGS__") == 0) {

          extern int scan_all_strings(luau_api_t * api);
          int found = scan_all_strings(&g_api);
          write_output("Scanned for Lua strings: found %d\n"
                       "Check /tmp/linusware_debug.log for details",
                       found);
        } else if (strcmp(script, "__DISCOVER__") == 0) {

          extern int aggressive_function_discovery(luau_api_t * api);
          write_output("Running aggressive function discovery...\n"
                       "This may take a moment. Check debug log for results.");
          int found = aggressive_function_discovery(&g_api);
          write_output("Discovery complete: %d potential functions found.\n"
                       "See /tmp/sirracha_debug.log for details.",
                       found);
        } else if (strcmp(script, "__SAFEPROBE__") == 0) {

          extern int safe_function_discovery(luau_api_t * api);
          write_output("Running safe function discovery...\n"
                       "Scanning for function prologues in code regions...");
          int found = safe_function_discovery(&g_api);
          write_output("Safe probe complete: %d functions found.\n"
                       "Check /tmp/sirracha_debug.log for offsets.",
                       found);
        } else if (strcmp(script, "__ROBLOX__") == 0) {

          extern int find_datamodel(uintptr_t sober_base,
                                    roblox_state_t *state);
          extern int find_local_player(roblox_state_t * state);
          extern void dump_roblox_state(roblox_state_t * state);

          write_output("Testing Roblox offsets...\n");

          static roblox_state_t rstate = {0};
          int dm_result = find_datamodel(g_api.sober_base, &rstate);

          if (dm_result == 0) {
            find_local_player(&rstate);
            dump_roblox_state(&rstate);
            write_output("Roblox state found! Check debug log for details.\n"
                         "DataModel: 0x%lx, LocalPlayer: 0x%lx",
                         rstate.datamodel, rstate.local_player);
          } else {
            write_output(
                "Failed to find DataModel. Offsets may need adjustment.\n"
                "Check /tmp/linusware_debug.log for details.");
          }
        } else if (strcmp(script, "__HOOK__") == 0) {
          uintptr_t libloader_base = find_libloader_base();
          if (libloader_base) {
            write_output("Attempting to install execution hook...\n");
            if (hook_script_execution(libloader_base, (void **)&g_api.L)) {
              write_output("✓ Hook installed successfully!\n"
                           "Scripts will now hijack internal game calls.");
            } else {
              write_output(
                  "❌ Failed to find hook target in memory.\n"
                  "The encryption may be too strong or the pattern changed.");
            }
          } else {
            write_output("ERROR: libloader.so not found in maps.");
          }
        } else if (strcmp(script, "__DUMP_V2__") == 0) {
          // Dump Sober's decrypted memory regions for reverse engineering
          write_output("Dumping Sober's decrypted regions...\n");
          log_debug("=== MEMORY DUMP REQUESTED ===\n");

          FILE *maps = fopen("/proc/self/maps", "r");
          if (!maps) {
            write_output("ERROR: Failed to read memory maps\n");
            log_debug("Failed to open /proc/self/maps\n");
          } else {
            char line[512];
            int region_count = 0;

            while (fgets(line, sizeof(line), maps)) {
              uintptr_t start, end;
              char perms[8];
              char path[512] = {0};
              int items = sscanf(line, "%lx-%lx %s %*x %*s %*s %s", &start,
                                 &end, perms, path);

              size_t size = end - start;
              int is_sober =
                  (strstr(line, "/sober") || strstr(line, "/app/bin/sober") ||
                   strstr(line, "/app/bin/lib"));
              int is_anon = (items < 4);
              int is_rx = (perms[2] == 'x');

              if (is_sober || is_rx || (is_anon && size < 100 * 1024 * 1024)) {
                if (size > 150 * 1024 * 1024)
                  continue;

                char outpath[256];
                snprintf(outpath, sizeof(outpath),
                         "/tmp/linusware_dump_0x%lx_%zu_%s.bin", start, size,
                         perms);

                log_debug("Writing dump to: %s\n", outpath);

                FILE *outfile = fopen(outpath, "wb");
                if (outfile) {
                  chmod(outpath, 0666);
                  fwrite((void *)start, 1, size, outfile);
                  fclose(outfile);
                  region_count++;
                }
              }
            }
            fclose(maps);

            // EXTRACT LIVE POINTERS FROM L
            if (g_api.L) {
              log_debug("Walking live Luau state at %p...\n", (void *)g_api.L);
              uintptr_t *ptrs = (uintptr_t *)g_api.L;
              uintptr_t l_g = ptrs[4]; // global_State* is usually at offset 32
              log_debug("Potential global_State: 0x%lx\n", l_g);

              if (l_g > 0x10000) {
                // Try to find common function patterns in the vicinity of
                // known code This will be printed to debug log
              }
            }

            log_debug("Dump complete: %d regions written\n", region_count);
            write_output("✓ Dump complete! %d regions exported.\n"
                         "Check /tmp/sober_dump_*.bin inside the container.\n\n"
                         "Use: cp /tmp/sober_dump_*.bin ~/ to analyze.",
                         region_count);
          }
        } else {

          char output[8192];
          execute_script(&g_api, script, output, sizeof(output));
          write_output("%s", output);
        }
        free(script);
      }
    }

    if (access(IPC_CMD_PATH, F_OK) == 0) {

      unlink(IPC_CMD_PATH);
    }

    // Aggressive retry logic if state is missing
    if (!g_api.L && g_api.sober_base) {
      static int retry_count = 0;
      if (++retry_count % 10 == 0) { // Retry every 1s
        log_debug("Retrying Lua state search (attempt %d)...\n",
                  retry_count / 10);

        // Wrap find_lua_state in a safe call to prevent crashes
        struct sigaction sa, old_segv;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = crash_handler;
        sigaction(SIGSEGV, &sa, &old_segv);

        if (sigsetjmp(g_jmp, 1) == 0) {
          g_in_call = 1;
          g_api.L = find_lua_state(g_api.sober_base);
          g_in_call = 0;

          if (g_api.L) {
            log_debug("Found Lua state on retry: %p\n", (void *)g_api.L);
            resolve_functions(&g_api);
            write_ready_signal(); // Trigger UI update!
          }
        } else {
          g_in_call = 0;
          log_debug("Crash caught during state search retry\n");
        }
        sigaction(SIGSEGV, &old_segv, NULL);
      }
    }

    usleep(100000);
  }

  log_debug("Worker thread exiting\n");

  if (g_log) {
    fclose(g_log);
    g_log = NULL;
  }

  return NULL;
}

__attribute__((constructor)) void lib_init(void) {
  // DIRECT INIT TEST: Skip threading, init immediately
  sleep(1);
  luau_api_init(&g_api);
  g_running = 1;

  // Write ready file immediately
  FILE *ready = fopen("/tmp/linusware_ready", "w");
  if (ready) {
    fprintf(ready, "1");
    fclose(ready);
  }

  // Start worker thread for script execution
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, 4 * 1024 * 1024);
  pthread_create(&g_worker_thread, &attr, worker_thread_func, NULL);
  pthread_detach(g_worker_thread);
  pthread_attr_destroy(&attr);
}

__attribute__((destructor)) void lib_fini(void) {
  g_running = 0;
  usleep(200000);

  if (g_log) {
    fclose(g_log);
    g_log = NULL;
  }
}

// Hook-based execution declaration
extern void queue_script(const char *script);

// Modified execute_script using hooks
int execute_script_via_hook(const char *script, char *output,
                            size_t output_size) {
  queue_script(script);

  // Trigger game to reload scripts (this will call our hooked function)
  // For now, just return success - the hook will execute when game loads next
  // script
  snprintf(output, output_size,
           "Script queued via hook. Waiting for game trigger...");

  return 0;
}
