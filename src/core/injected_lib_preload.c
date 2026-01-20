/*
 * injected_lib_preload.c - LD_PRELOAD Injection Library
 *
 * Copyright (c) 2026 sultan
 * PROPRIETARY AND CONFIDENTIAL
 *
 * This library is designed to be loaded via LD_PRELOAD before the game starts.
 * It detects when it's in the ACTUAL game process (not bwrap/tracer) and waits
 * for the Lua state to be initialized before executing scripts.
 *
 * Usage:
 *   sudo flatpak override --user org.vinegarhq.Sober \
 *     --env=LD_PRELOAD=/dev/shm/linusware.so
 *   flatpak run org.vinegarhq.Sober
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "luau_api.h"
#include "roblox_offsets.h"

/* ========================================================================== */
/*                              CONFIGURATION */
/* ========================================================================== */

/* Minimum memory for game detection (100MB) */
#define MIN_GAME_MEMORY_MB 100

/* Maximum time to wait for game initialization (seconds) */
#define MAX_INIT_WAIT_SECONDS 120

/* Polling interval while waiting for game (milliseconds) */
#define INIT_POLL_MS 500

/* Script polling interval (milliseconds) */
#define SCRIPT_POLL_MS 100

/* ========================================================================== */
/*                              GLOBALS */
/* ========================================================================== */

static FILE *g_log = NULL;
static luau_api_t g_api = {0};
static pthread_t g_worker_thread;
static volatile int g_running = 0;
static volatile int g_is_game_process = 0;

/* Crash handling */
static sigjmp_buf g_jmp_buf;
static volatile sig_atomic_t g_in_risky_call = 0;

/* ========================================================================== */
/*                              LOGGING */
/* ========================================================================== */

static void log_init(void) {
  if (g_log)
    return;

  char path[128];
  snprintf(path, sizeof(path), "/tmp/linusware_preload_%d.log", getpid());
  g_log = fopen(path, "a");
  if (g_log) {
    setbuf(g_log, NULL);
  }

  /* Also append to main log */
  FILE *main_log = fopen("/tmp/linusware_debug.log", "a");
  if (main_log) {
    setbuf(main_log, NULL);
    /* Use main log instead */
    if (g_log)
      fclose(g_log);
    g_log = main_log;
  }
}

static void log_msg(const char *fmt, ...) {
  log_init();
  if (!g_log)
    return;

  time_t now = time(NULL);
  struct tm *tm = localtime(&now);
  fprintf(g_log, "[%02d:%02d:%02d][%d] ", tm->tm_hour, tm->tm_min, tm->tm_sec,
          getpid());

  va_list args;
  va_start(args, fmt);
  vfprintf(g_log, fmt, args);
  va_end(args);
  fflush(g_log);
}

/* ========================================================================== */
/*                         CRASH HANDLING */
/* ========================================================================== */

static void crash_handler(int sig) {
  if (g_in_risky_call) {
    siglongjmp(g_jmp_buf, sig);
  }
  signal(sig, SIG_DFL);
  raise(sig);
}

static void install_crash_handler(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = crash_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESETHAND;
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);
}

/* ========================================================================== */
/*                         GAME DETECTION */
/* ========================================================================== */

/*
 * Check if THIS process has the large memory regions characteristic of the
 * game.
 */
static int check_is_game_process(void) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  char line[512];
  int large_regions = 0;
  size_t total_size = 0;

  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start, end;
    char perms[8];

    if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
      size_t size = end - start;

      /* Count large anonymous regions in high memory */
      if (size >= 50 * 1024 * 1024 && start > 0x7f0000000000UL &&
          perms[0] == 'r' && !strstr(line, ".so") &&
          !strstr(line, "linusware")) {
        large_regions++;
        total_size += size;
      }
    }
  }
  fclose(maps);

  /* Game typically has multiple large regions totaling 100MB+ */
  return (large_regions >= 1 && total_size >= MIN_GAME_MEMORY_MB * 1024 * 1024);
}

/*
 * Get the code base address for offset calculation.
 */
static uintptr_t find_code_base(void) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  char line[512];
  uintptr_t code_base = 0;
  size_t best_size = 0;

  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start, end;
    char perms[8];

    if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
      size_t size = end - start;

      /* Find the largest readable region in game memory space */
      if (size >= 100 * 1024 * 1024 && start > 0x7f0000000000UL &&
          perms[0] == 'r' && !strstr(line, ".so") &&
          !strstr(line, "mimalloc") && size > best_size) {
        code_base = start;
        best_size = size;
      }
    }
  }
  fclose(maps);

  return code_base;
}

/* ========================================================================== */
/*                         LUA STATE DISCOVERY */
/* ========================================================================== */

/*
 * Scan memory for Lua state structures.
 * Returns the best candidate found.
 */
static lua_State *scan_for_lua_state(void) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return NULL;

  char line[512];
  lua_State *best = NULL;
  int best_score = 0;
  int regions_scanned = 0;

  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start, end;
    char perms[8];

    if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) < 3)
      continue;
    if (perms[0] != 'r' || perms[1] != 'w')
      continue;
    if (strstr(line, ".so") || strstr(line, "linusware"))
      continue;

    size_t size = end - start;
    if (size < 4096 || size > 32 * 1024 * 1024)
      continue;

    regions_scanned++;

    /* Scan for pointer patterns typical of lua_State */
    for (uintptr_t addr = start; addr < end - 128; addr += 8) {
      install_crash_handler();
      g_in_risky_call = 1;

      if (sigsetjmp(g_jmp_buf, 1) == 0) {
        uintptr_t *ptr = (uintptr_t *)addr;
        int score = 0;
        int valid_ptrs = 0;

        /* Check first 12 slots for valid pointers */
        for (int i = 0; i < 12; i++) {
          uintptr_t val = ptr[i];
          if (val > 0x10000 && val < 0x800000000000UL) {
            valid_ptrs++;
          }
        }

        if (valid_ptrs >= 7) {
          score = valid_ptrs * 10;

          /* L->top > L->base and close together */
          if (ptr[1] > ptr[2] && ptr[1] - ptr[2] < 0x10000) {
            score += 50;
          }

          /* L->global should be a valid pointer */
          if (ptr[3] > 0x10000 && ptr[3] < 0x800000000000UL) {
            score += 20;
          }

          if (score > best_score) {
            best_score = score;
            best = (lua_State *)addr;
          }
        }
      }

      g_in_risky_call = 0;
    }
  }
  fclose(maps);

  if (best) {
    log_msg("Found lua_State candidate: %p (score=%d, scanned %d regions)\n",
            (void *)best, best_score, regions_scanned);
  }

  return best;
}

/* ========================================================================== */
/*                         FUNCTION RESOLUTION */
/* ========================================================================== */

static int resolve_luau_functions(luau_api_t *api, uintptr_t base) {
  if (!api || !base)
    return -1;

  api->luau_load = (luau_load_t)(base + OFF_luau_load);
  api->pcall = (lua_pcall_t)(base + OFF_luaD_pcall);
  api->pushstring = (lua_pushstring_t)(base + OFF_lua_pushstring);
  api->pushvalue = (lua_pushvalue_t)(base + OFF_lua_pushvalue);
  api->setfield = (lua_setfield_t)(base + OFF_lua_setfield);

  log_msg("Resolved Luau functions from base 0x%lx:\n", base);
  log_msg("  luau_load:   0x%lx\n", (uintptr_t)api->luau_load);
  log_msg("  pcall:       0x%lx\n", (uintptr_t)api->pcall);
  log_msg("  pushstring:  0x%lx\n", (uintptr_t)api->pushstring);

  api->sober_base = base;
  api->functions_resolved = 1;
  return 0;
}

/* ========================================================================== */
/*                         SCRIPT EXECUTION */
/* ========================================================================== */

static int execute_script_preload(const char *script, char *output,
                                  size_t output_size) {
  if (!g_api.L || !g_api.functions_resolved) {
    snprintf(output, output_size, "ERROR: Not initialized");
    return -1;
  }

  log_msg("Executing script (%zu bytes)\n", strlen(script));

  install_crash_handler();
  g_in_risky_call = 1;

  if (sigsetjmp(g_jmp_buf, 1) != 0) {
    g_in_risky_call = 0;
    snprintf(output, output_size, "CRASH: Signal during execution");
    log_msg("CRASH during script execution\n");
    return -1;
  }

  /* TODO: Actually call Luau functions here */
  /* For now, just verify we can read the Lua state */
  uintptr_t *L = (uintptr_t *)g_api.L;
  log_msg("L->top: 0x%lx, L->base: 0x%lx\n", L[1], L[2]);

  g_in_risky_call = 0;
  snprintf(output, output_size, "Script received (execution stub)");
  return 0;
}

/* ========================================================================== */
/*                         WORKER THREAD */
/* ========================================================================== */

static void *worker_thread(void *arg) {
  (void)arg;

  log_msg("Worker thread started, waiting for game initialization...\n");

  /* Phase 1: Wait for game to fully load */
  time_t start = time(NULL);
  int init_attempts = 0;

  while (g_running) {
    init_attempts++;

    if (check_is_game_process()) {
      log_msg("Game memory detected after %d attempts\n", init_attempts);
      break;
    }

    if (time(NULL) - start > MAX_INIT_WAIT_SECONDS) {
      log_msg("Timeout waiting for game memory\n");
      return NULL;
    }

    usleep(INIT_POLL_MS * 1000);
  }

  if (!g_running)
    return NULL;

  /* Phase 2: Find code base */
  uintptr_t code_base = 0;
  for (int i = 0; i < 60 && g_running; i++) { /* 30 seconds max */
    code_base = find_code_base();
    if (code_base)
      break;
    usleep(500000);
  }

  if (!code_base) {
    log_msg("ERROR: Could not find code base\n");
    return NULL;
  }

  log_msg("Code base: 0x%lx\n", code_base);

  /* Phase 3: Find Lua state */
  lua_State *L = NULL;
  for (int i = 0; i < 60 && g_running; i++) { /* 30 seconds max */
    L = scan_for_lua_state();
    if (L)
      break;
    log_msg("Waiting for Lua state... (attempt %d)\n", i + 1);
    usleep(500000);
  }

  if (!L) {
    log_msg("ERROR: Could not find Lua state\n");
    return NULL;
  }

  g_api.L = L;

  /* Phase 4: Resolve functions */
  if (resolve_luau_functions(&g_api, code_base) < 0) {
    log_msg("ERROR: Failed to resolve functions\n");
    return NULL;
  }

  /* Signal ready */
  FILE *ready = fopen("/tmp/linusware_ready", "w");
  if (ready) {
    fprintf(ready, "READY %d 0x%lx 0x%lx\n", getpid(), code_base, (uintptr_t)L);
    fclose(ready);
  }

  log_msg("=== READY FOR SCRIPTS ===\n");

  /* Phase 5: Script execution loop */
  while (g_running) {
    FILE *f = fopen("/tmp/linusware_exec.txt", "r");
    if (f) {
      char script[65536];
      size_t len = fread(script, 1, sizeof(script) - 1, f);
      script[len] = '\0';
      fclose(f);

      unlink("/tmp/linusware_exec.txt");

      if (len > 0) {
        log_msg("Received script: %.50s%s\n", script, len > 50 ? "..." : "");

        char output[4096];
        int result = execute_script_preload(script, output, sizeof(output));

        FILE *out = fopen("/tmp/linusware_output.txt", "w");
        if (out) {
          fprintf(out, "[%s] %s\n", result == 0 ? "OK" : "ERROR", output);
          fclose(out);
        }
      }
    }

    usleep(SCRIPT_POLL_MS * 1000);
  }

  log_msg("Worker thread exiting\n");
  return NULL;
}

/* ========================================================================== */
/*                         LIBRARY ENTRY/EXIT */
/* ========================================================================== */

__attribute__((constructor)) static void library_init(void) {
  /* Quick check - skip bwrap processes */
  char exe[256];
  ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if (len > 0) {
    exe[len] = '\0';
    if (strstr(exe, "bwrap")) {
      return; /* Skip bwrap, wait for actual sober */
    }
  }

  log_msg("===========================================\n");
  log_msg("LinusWare Preload v1.0\n");
  log_msg("PID: %d, EXE: %s\n", getpid(), len > 0 ? exe : "unknown");
  log_msg("===========================================\n");

  /* Start worker thread */
  g_running = 1;
  if (pthread_create(&g_worker_thread, NULL, worker_thread, NULL) != 0) {
    log_msg("ERROR: Failed to create worker thread\n");
    g_running = 0;
    return;
  }

  /* Detach - let it run independently */
  pthread_detach(g_worker_thread);

  log_msg("Worker thread started in background\n");
}

__attribute__((destructor)) static void library_fini(void) {
  if (g_running) {
    log_msg("Library unloading\n");
    g_running = 0;
  }

  if (g_log) {
    fclose(g_log);
    g_log = NULL;
  }
}
