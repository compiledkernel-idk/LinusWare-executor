/*
 * executor_v3.c - LinusWare Executor v3.0
 *
 * Copyright (c) 2026 sultan
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Runtime function discovery with string xrefs
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Configuration - Using Flatpak shared data dir */
static const char *get_base_path(void) {
  static char path[512] = {0};
  if (path[0] == '\0') {
    const char *home = getenv("HOME");
    if (!home)
      home = "/tmp";

    /* Try data dir first */
    snprintf(path, sizeof(path), "%s/.var/app/org.vinegarhq.Sober/data", home);
    if (access(path, W_OK) == 0)
      return path;

    /* Fallback to home */
    if (access(home, W_OK) == 0)
      return home;

    /* Last resort */
    return "/tmp";
  }
  return path;
}

#define LOG_PATH_FMT "%s/linusware_v3.log"
#define READY_PATH_FMT "%s/linusware_ready"
#define SCRIPT_PATH_FMT "%s/linusware_exec.txt"
#define OUTPUT_PATH_FMT "%s/linusware_output.txt"

static char g_log_path[300], g_ready_path[300], g_script_path[300],
    g_output_path[300];

static void init_paths(void) {
  const char *base = get_base_path();
  snprintf(g_log_path, sizeof(g_log_path), LOG_PATH_FMT, base);
  snprintf(g_ready_path, sizeof(g_ready_path), READY_PATH_FMT, base);
  snprintf(g_script_path, sizeof(g_script_path), SCRIPT_PATH_FMT, base);
  snprintf(g_output_path, sizeof(g_output_path), OUTPUT_PATH_FMT, base);
}

#define ANCHOR_STRING_1 "attempt to call"
#define ANCHOR_STRING_2 "Current identity is %d"

/* Types */
typedef struct lua_State lua_State;
typedef int (*luau_load_fn)(lua_State *L, const char *chunkname,
                            const char *data, size_t size, int env);
typedef int (*lua_pcall_fn)(lua_State *L, int nargs, int nresults, int errfunc);
typedef int (*lua_gettop_fn)(lua_State *L);

#define LUA_OK 0

typedef struct {
  uintptr_t code_base;
  size_t code_size;
  lua_State *L;
  luau_load_fn luau_load;
  lua_pcall_fn pcall;
  lua_gettop_fn gettop;
  int ready;
} executor_state_t;

typedef struct {
  uintptr_t start;
  uintptr_t end;
  int readable;
  int writable;
  int executable;
  char path[256];
} mem_region_t;

/* Globals */
static FILE *g_log = NULL;
static executor_state_t g_state = {0};
static pthread_t g_worker_thread;
static volatile int g_running = 0;
static sigjmp_buf g_jmpbuf;
static volatile sig_atomic_t g_in_unsafe = 0;

/* Crash handler */
static void crash_handler(int sig) {
  if (g_in_unsafe) {
    siglongjmp(g_jmpbuf, sig);
  }
  signal(sig, SIG_DFL);
  raise(sig);
}

/* Logging */
static void log_init(void) {
  if (g_log)
    return;
  init_paths(); /* Ensure paths are set */
  g_log = fopen(g_log_path, "w");
  if (g_log) {
    setbuf(g_log, NULL);
    chmod(g_log_path, 0666);
  }
}

static void log_msg(const char *fmt, ...) {
  log_init();
  if (!g_log)
    return;

  time_t now = time(NULL);
  struct tm *tm = localtime(&now);
  fprintf(g_log, "[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec);

  va_list args;
  va_start(args, fmt);
  vfprintf(g_log, fmt, args);
  va_end(args);
  fflush(g_log);
}

/* Memory region scanning */
static int get_memory_regions(mem_region_t *regions, int max_regions) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  char line[512];
  int count = 0;

  while (fgets(line, sizeof(line), maps) && count < max_regions) {
    uintptr_t start, end;
    char perms[8] = {0};
    char path[256] = "";

    if (sscanf(line, "%lx-%lx %7s %*x %*s %*d %255[^\n]", &start, &end, perms,
               path) >= 3) {
      mem_region_t *r = &regions[count];
      r->start = start;
      r->end = end;
      r->readable = (perms[0] == 'r');
      r->writable = (perms[1] == 'w');
      r->executable = (perms[2] == 'x');
      strncpy(r->path, path, sizeof(r->path) - 1);
      count++;
    }
  }

  fclose(maps);
  return count;
}

/* Safe memory access wrapper */
static int safe_memcmp(const void *a, const void *b, size_t n) {
  struct sigaction sa = {0}, old_segv, old_bus;
  sa.sa_handler = crash_handler;
  sigaction(SIGSEGV, &sa, &old_segv);
  sigaction(SIGBUS, &sa, &old_bus);

  int result = -1;
  g_in_unsafe = 1;
  if (sigsetjmp(g_jmpbuf, 1) == 0) {
    result = memcmp(a, b, n);
  }
  g_in_unsafe = 0;

  sigaction(SIGSEGV, &old_segv, NULL);
  sigaction(SIGBUS, &old_bus, NULL);
  return result;
}

static uintptr_t safe_read_ptr(uintptr_t addr) {
  struct sigaction sa = {0}, old_segv, old_bus;
  sa.sa_handler = crash_handler;
  sigaction(SIGSEGV, &sa, &old_segv);
  sigaction(SIGBUS, &sa, &old_bus);

  uintptr_t result = 0;
  g_in_unsafe = 1;
  if (sigsetjmp(g_jmpbuf, 1) == 0) {
    result = *(uintptr_t *)addr;
  }
  g_in_unsafe = 0;

  sigaction(SIGSEGV, &old_segv, NULL);
  sigaction(SIGBUS, &old_bus, NULL);
  return result;
}

static uint8_t safe_read_byte(uintptr_t addr) {
  struct sigaction sa = {0}, old_segv, old_bus;
  sa.sa_handler = crash_handler;
  sigaction(SIGSEGV, &sa, &old_segv);
  sigaction(SIGBUS, &sa, &old_bus);

  uint8_t result = 0;
  g_in_unsafe = 1;
  if (sigsetjmp(g_jmpbuf, 1) == 0) {
    result = *(uint8_t *)addr;
  }
  g_in_unsafe = 0;

  sigaction(SIGSEGV, &old_segv, NULL);
  sigaction(SIGBUS, &old_bus, NULL);
  return result;
}

/* Find a string in memory */
static uintptr_t find_string_in_memory(const char *needle) {
  mem_region_t regions[512];
  int n = get_memory_regions(regions, 512);
  size_t needle_len = strlen(needle);

  for (int i = 0; i < n; i++) {
    mem_region_t *r = &regions[i];
    if (!r->readable)
      continue;

    size_t size = r->end - r->start;
    if (size < needle_len || size > 500 * 1024 * 1024)
      continue;
    if (strstr(r->path, "/lib/") || strstr(r->path, "/usr/lib"))
      continue;

    for (size_t j = 0; j < size - needle_len; j++) {
      if (safe_memcmp((void *)(r->start + j), needle, needle_len) == 0) {
        uintptr_t found = r->start + j;
        log_msg("Found string '%s' at 0x%lx\n", needle, found);
        return found;
      }
    }
  }
  return 0;
}

/* Find xref to address (RIP-relative) */
static uintptr_t find_xref_to(uintptr_t target_addr) {
  mem_region_t regions[512];
  int n = get_memory_regions(regions, 512);

  for (int i = 0; i < n; i++) {
    mem_region_t *r = &regions[i];
    if (!r->readable)
      continue;

    size_t size = r->end - r->start;
    if (size < 4096 || size > 500 * 1024 * 1024)
      continue;
    if (strstr(r->path, "/lib/") || strstr(r->path, "/usr/lib"))
      continue;

    for (size_t j = 0; j < size - 8; j++) {
      uint8_t b0 = safe_read_byte(r->start + j);
      uint8_t b1 = safe_read_byte(r->start + j + 1);

      /* LEA r64, [rip+disp32]: 48 8D xx */
      if (b0 == 0x48 && b1 == 0x8D) {
        uint8_t modrm = safe_read_byte(r->start + j + 2);
        if ((modrm & 0xC7) == 0x05) {
          int32_t disp = (int32_t)safe_read_ptr(r->start + j + 3);
          /* Only use lower 32 bits */
          disp = *(int32_t *)(void *)&disp;
          uintptr_t rip = r->start + j + 7;
          uintptr_t resolved = rip + disp;

          if (resolved == target_addr) {
            log_msg("Found LEA xref at 0x%lx\n", r->start + j);
            return r->start + j;
          }
        }
      }
    }
  }
  return 0;
}

/* Find function start by scanning backwards for prologue */
static uintptr_t find_function_start(uintptr_t addr) {
  for (int i = 0; i < 4096; i++) {
    uint8_t b0 = safe_read_byte(addr - i);
    uint8_t b1 = safe_read_byte(addr - i + 1);
    uint8_t b2 = safe_read_byte(addr - i + 2);
    uint8_t b3 = safe_read_byte(addr - i + 3);

    /* push rbp; mov rbp, rsp */
    if (b0 == 0x55 && b1 == 0x48 && b2 == 0x89 && b3 == 0xE5) {
      log_msg("Found function prologue at 0x%lx\n", addr - i);
      return addr - i;
    }
    /* endbr64 */
    if (b0 == 0xF3 && b1 == 0x0F && b2 == 0x1E && b3 == 0xFA) {
      log_msg("Found endbr64 at 0x%lx\n", addr - i);
      return addr - i;
    }
  }
  return 0;
}

/* Find code region (largest readable region > 10MB) */
static int find_code_region(executor_state_t *state) {
  mem_region_t regions[512];
  int n = get_memory_regions(regions, 512);

  uintptr_t best_start = 0;
  size_t best_size = 0;

  for (int i = 0; i < n; i++) {
    mem_region_t *r = &regions[i];
    size_t size = r->end - r->start;

    if (strstr(r->path, ".so"))
      continue;
    if (strstr(r->path, "[stack]"))
      continue;
    if (strstr(r->path, "[vdso]"))
      continue;
    if (strstr(r->path, "linusware"))
      continue;

    if (r->readable && size >= 10 * 1024 * 1024 && size > best_size) {
      best_start = r->start;
      best_size = size;
    }
  }

  if (best_start) {
    state->code_base = best_start;
    state->code_size = best_size;
    log_msg("Code region: 0x%lx (%zu MB)\n", best_start,
            best_size / (1024 * 1024));
    return 0;
  }
  return -1;
}

/* Validate lua_State candidate */
static int validate_lua_state(uintptr_t addr, uintptr_t code_base) {
  int score = 0;
  int valid_ptrs = 0;

  for (int i = 0; i < 12; i++) {
    uintptr_t val = safe_read_ptr(addr + i * 8);
    if (val > 0x10000 && val < 0x7FFFFFFFFFFF) {
      valid_ptrs++;
    }
  }

  if (valid_ptrs >= 6)
    score += valid_ptrs * 5;

  /* L->top should be > L->base */
  uintptr_t maybe_top = safe_read_ptr(addr + 0x18);
  uintptr_t maybe_base = safe_read_ptr(addr + 0x20);

  if (maybe_top > maybe_base && (maybe_top - maybe_base) < 0x10000) {
    score += 30;
  }

  /* L->global->mainthread should point back to L */
  uintptr_t maybe_global = safe_read_ptr(addr + 0x08);
  if (maybe_global > 0x10000 && maybe_global < 0x7FFFFFFFFFFF) {
    uintptr_t mt = safe_read_ptr(maybe_global);
    if (mt == addr)
      score += 50;
    mt = safe_read_ptr(maybe_global + 8);
    if (mt == addr)
      score += 50;
  }

  return score;
}

/* Find lua_State */
static lua_State *find_lua_state(uintptr_t code_base) {
  mem_region_t regions[512];
  int n = get_memory_regions(regions, 512);

  lua_State *best = NULL;
  int best_score = 0;

  for (int i = 0; i < n; i++) {
    mem_region_t *r = &regions[i];

    if (!r->readable || !r->writable)
      continue;
    if (r->executable)
      continue;
    if (strstr(r->path, ".so"))
      continue;
    if (strstr(r->path, "linusware"))
      continue;

    size_t size = r->end - r->start;
    if (size < 4096 || size > 64 * 1024 * 1024)
      continue;

    for (uintptr_t addr = r->start; addr < r->end - 256; addr += 8) {
      int score = validate_lua_state(addr, code_base);
      if (score > best_score) {
        best_score = score;
        best = (lua_State *)addr;
      }
    }
  }

  if (best && best_score >= 30) {
    log_msg("Found lua_State: %p (score=%d)\n", (void *)best, best_score);
    return best;
  }

  log_msg("No lua_State found (best=%d)\n", best_score);
  return NULL;
}

/* Discover functions */
static int discover_functions(executor_state_t *state) {
  log_msg("=== Function discovery ===\n");
  int found = 0;

  /* Find via error strings */
  uintptr_t identity_str = find_string_in_memory(ANCHOR_STRING_2);
  if (identity_str) {
    uintptr_t xref = find_xref_to(identity_str);
    if (xref) {
      uintptr_t func = find_function_start(xref);
      if (func) {
        log_msg("Identity check func at 0x%lx\n", func);
      }
    }
  }

  uintptr_t call_error = find_string_in_memory(ANCHOR_STRING_1);
  if (call_error) {
    uintptr_t xref = find_xref_to(call_error);
    if (xref) {
      uintptr_t func = find_function_start(xref);
      if (func) {
        log_msg("Call error handler at 0x%lx\n", func);
      }
    }
  }

  /* Pattern scan for lua_gettop */
  mem_region_t regions[512];
  int n = get_memory_regions(regions, 512);

  for (int i = 0; i < n && !state->gettop; i++) {
    mem_region_t *r = &regions[i];
    if (!r->readable)
      continue;
    if (strstr(r->path, "/lib/"))
      continue;

    size_t size = r->end - r->start;
    if (size < 1024 * 1024 || size > 200 * 1024 * 1024)
      continue;

    /* Pattern: 48 8B 47 ?? 48 2B 47 ?? 48 C1 F8 04 C3 */
    for (size_t j = 0; j < size - 20; j++) {
      if (safe_read_byte(r->start + j) == 0x48 &&
          safe_read_byte(r->start + j + 1) == 0x8B &&
          safe_read_byte(r->start + j + 2) == 0x47 &&
          safe_read_byte(r->start + j + 4) == 0x48 &&
          safe_read_byte(r->start + j + 5) == 0x2B &&
          safe_read_byte(r->start + j + 6) == 0x47 &&
          safe_read_byte(r->start + j + 8) == 0x48 &&
          safe_read_byte(r->start + j + 9) == 0xC1 &&
          safe_read_byte(r->start + j + 10) == 0xF8 &&
          safe_read_byte(r->start + j + 11) == 0x04 &&
          safe_read_byte(r->start + j + 12) == 0xC3) {

        state->gettop = (lua_gettop_fn)(r->start + j);
        log_msg("FOUND lua_gettop at 0x%lx!\n", r->start + j);
        found++;
        break;
      }
    }
  }

  log_msg("Discovery complete: %d functions\n", found);
  return found;
}

/* Execute script */
static int execute_script(const char *script, char *output,
                          size_t output_size) {
  if (!g_state.L) {
    snprintf(output, output_size, "ERROR: No Lua state");
    return -1;
  }

  log_msg("Executing script (%zu bytes)\n", strlen(script));

  if (g_state.gettop) {
    struct sigaction sa = {0}, old_segv, old_bus;
    sa.sa_handler = crash_handler;
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    g_in_unsafe = 1;
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
      int top = g_state.gettop(g_state.L);
      log_msg("gettop returned: %d\n", top);
      snprintf(output, output_size, "Stack top: %d (working!)", top);
    } else {
      snprintf(output, output_size, "CRASH in gettop");
    }
    g_in_unsafe = 0;

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    return 0;
  }

  snprintf(output, output_size, "L=%p, gettop=%p, luau_load=%p, pcall=%p",
           (void *)g_state.L, (void *)g_state.gettop, (void *)g_state.luau_load,
           (void *)g_state.pcall);
  return -1;
}

/* Write ready status */
static void write_ready_status(void) {
  FILE *f = fopen(g_ready_path, "w");
  if (f) {
    fprintf(f, "READY\npid=%d\ncode_base=0x%lx\nL=%p\ngettop=%p\n", getpid(),
            g_state.code_base, (void *)g_state.L, (void *)g_state.gettop);
    fclose(f);
    chmod(g_ready_path, 0666);
  }
}

/* Worker thread */
static void *worker_thread(void *arg) {
  (void)arg;
  log_msg("Worker started, PID=%d\n", getpid());

  /* Wait for game init */
  int attempts = 0;
  while (g_running && attempts < 120) {
    if (find_code_region(&g_state) == 0) {
      log_msg("Game ready after %d attempts\n", attempts);
      break;
    }
    attempts++;
    usleep(500000);
  }

  if (!g_state.code_base) {
    log_msg("ERROR: Game init timeout\n");
    return NULL;
  }

  /* Find lua_State */
  for (int i = 0; i < 30 && g_running; i++) {
    g_state.L = find_lua_state(g_state.code_base);
    if (g_state.L)
      break;
    log_msg("Retrying L search (%d)...\n", i + 1);
    usleep(1000000);
  }

  discover_functions(&g_state);

  g_state.ready = 1;
  write_ready_status();
  log_msg("=== READY ===\n");

  /* Main loop */
  while (g_running) {
    if (access(g_script_path, F_OK) == 0) {
      FILE *f = fopen(g_script_path, "r");
      if (f) {
        char script[65536] = {0};
        size_t len = fread(script, 1, sizeof(script) - 1, f);
        fclose(f);
        unlink(g_script_path);

        if (len > 0) {
          char output[4096] = {0};
          execute_script(script, output, sizeof(output));

          FILE *out = fopen(g_output_path, "w");
          if (out) {
            fprintf(out, "%s\n", output);
            fclose(out);
            chmod(g_output_path, 0666);
          }
        }
      }
    }
    usleep(100000);
  }

  log_msg("Worker exiting\n");
  return NULL;
}

/* Check if we're the game process */
static int is_game_process(void) {
  char comm[64] = {0};
  FILE *f = fopen("/proc/self/comm", "r");
  if (f) {
    if (fgets(comm, sizeof(comm), f)) {
      char *p = strchr(comm, '\n');
      if (p)
        *p = '\0';
      log_msg("Process Comm: %s\n", comm);

      if (strstr(comm, "sober") || strstr(comm, "roblox")) {
        log_msg("Confirmed game process via comm!\n");
        fclose(f);
        return 1;
      }
    }
    fclose(f);
  }

  char exe[512] = {0};
  ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if (len > 0) {
    exe[len] = '\0';
    log_msg("Process EXE: %s\n", exe);
    if (strstr(exe, "sober") || strstr(exe, "roblox")) {
      log_msg("Confirmed game process via exe name!\n");
      return 1;
    }
    if (strstr(exe, "bwrap") || strstr(exe, "flatpak")) {
      log_msg("Skipping wrapper process\n");
      return 0;
    }
  }

  /* Final fallback: if it's large, it's likely the game */
  f = fopen("/proc/self/statm", "r");
  if (f) {
    unsigned long size = 0;
    fscanf(f, "%lu", &size);
    fclose(f);
    if (size > 10000) {
      log_msg("Large process detected (%lu pages), assuming game.\n", size);
      return 1;
    }
  }

  return 0;
}

/* Library constructor */
__attribute__((constructor)) static void library_init(void) {
  FILE *f = fopen("/home/sultan/linusware_success.txt", "a");
  if (f) {
    fprintf(f, "EXECUTOR_LOADED_PID_%d\n", getpid());
    fclose(f);
  }
}

/* Library destructor - only run when actually exiting */
__attribute__((destructor)) static void library_fini(void) {
  /* Check if we actually started */
  if (!g_running) {
    return; /* Never started, don't log */
  }

  log_msg("Library unloading\n");
  g_running = 0;

  /* Give worker thread time to finish */
  usleep(100000);

  if (g_log) {
    fclose(g_log);
    g_log = NULL;
  }
}
