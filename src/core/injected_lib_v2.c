/*
 * injected_lib_v2.c - Dual-Mode Injection Library
 *
 * Copyright (c) 2026 sultan
 * PROPRIETARY AND CONFIDENTIAL
 *
 * This library operates in TWO modes:
 *
 * TRACER MODE: When loaded in the tracer process (bwrap or parent sober)
 *   - Detects the actual game child process
 *   - Uses ptrace to inject the library into the game
 *   - Relays script commands via shared memory
 *
 * GAME MODE: When loaded in the actual game process
 *   - Detects large memory regions (100MB+)
 *   - Resolves Luau function addresses
 *   - Executes scripts directly
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
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "luau_api.h"
#include "remote_inject.h"
#include "roblox_offsets.h"
#include "shared_ipc.h"
#include "tracer_control.h"

/* ========================================================================== */
/*                              GLOBALS */
/* ========================================================================== */

static FILE *g_log = NULL;
static luau_api_t g_api = {0};
static ipc_handle_t g_ipc = {0};
static pthread_t g_worker_thread;
static volatile int g_running = 0;
static volatile int g_mode = 0; /* 0 = unknown, 1 = tracer, 2 = game */

#define MODE_UNKNOWN 0
#define MODE_TRACER 1
#define MODE_GAME 2

/* Crash handling */
static sigjmp_buf g_jmp_buf;
static volatile sig_atomic_t g_in_risky_call = 0;

/* ========================================================================== */
/*                              LOGGING */
/* ========================================================================== */

void log_debug(const char *fmt, ...) {
  if (!g_log) {
    g_log = fopen("/tmp/linusware_debug.log", "a");
    if (!g_log)
      return;
    setbuf(g_log, NULL);
  }

  time_t now = time(NULL);
  struct tm *tm = localtime(&now);
  fprintf(g_log, "[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec);

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
  /* Else: not our crash, let it through */
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
/*                         MODE DETECTION */
/* ========================================================================== */

/*
 * Check if WE are the game process by looking for large memory regions.
 * The actual Roblox game has 100MB+ anonymous regions.
 */
static int is_game_process(void) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  char line[512];
  int has_large_region = 0;

  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start, end;
    char perms[8];

    if (sscanf(line, "%lx-%lx %s", &start, &end, perms) >= 3) {
      size_t size = end - start;

      /* Look for 100MB+ readable region in high memory */
      if (size >= 100 * 1024 * 1024 && start > 0x7f0000000000UL &&
          perms[0] == 'r' && !strstr(line, ".so") &&
          !strstr(line, "mimalloc") && !strstr(line, "linusware")) {
        has_large_region = 1;
        break;
      }
    }
  }
  fclose(maps);

  return has_large_region;
}

/*
 * Check if we are a tracer (have traced children).
 */
static int is_tracer_process(void) {
  pid_t children[16];
  int count = find_traced_children(children, 16);
  return count > 0;
}

/*
 * Determine which mode we should operate in.
 */
static int detect_mode(void) {
  /* First check if we ARE the game (have large memory) */
  if (is_game_process()) {
    log_debug("Mode detected: GAME (we have 100MB+ regions)\n");
    return MODE_GAME;
  }

  /* Check if we are tracing game-like processes */
  if (is_tracer_process()) {
    log_debug("Mode detected: TRACER (we have traced children)\n");
    return MODE_TRACER;
  }

  /* Check if we're a sober process at all */
  if (is_sober_process(getpid())) {
    /* We're sober but no large regions and not tracing... might be early load
     */
    log_debug("Mode detected: GAME (sober process, waiting for init)\n");
    return MODE_GAME;
  }

  /* Check if we're bwrap/wrapper with game child processes */
  pid_t game_pid = find_game_process();
  if (game_pid > 0) {
    log_debug("Mode detected: TRACER (found game child PID %d)\n", game_pid);
    return MODE_TRACER;
  }

  log_debug("Mode detected: UNKNOWN\n");
  return MODE_UNKNOWN;
}

/* ========================================================================== */
/*                         GAME MODE: LUA EXECUTION */
/* ========================================================================== */

/*
 * Find the code region containing Roblox code.
 */
static uintptr_t find_code_base(void) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  char line[512];
  uintptr_t code_base = 0;

  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start, end;
    char perms[8];

    if (sscanf(line, "%lx-%lx %s", &start, &end, perms) >= 3) {
      size_t size = end - start;

      /* 100MB+ region in proper address range */
      if (size >= 100 * 1024 * 1024 && start > 0x7f0000000000UL &&
          perms[0] == 'r' && !strstr(line, ".so") &&
          !strstr(line, "mimalloc")) {
        code_base = start;
        log_debug("Found code region: 0x%lx - 0x%lx (%zu MB)\n", start, end,
                  size / (1024 * 1024));
        break;
      }
    }
  }
  fclose(maps);

  return code_base;
}

/*
 * Find Lua state by scanning memory for valid state structures.
 */
static lua_State *find_lua_state_v2(void) {
  /* Similar to existing implementation, but focused on game regions */
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return NULL;

  char line[512];
  lua_State *best_candidate = NULL;
  int best_score = 0;

  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start, end;
    char perms[8];

    if (sscanf(line, "%lx-%lx %s", &start, &end, perms) < 3)
      continue;
    if (perms[0] != 'r' || perms[1] != 'w')
      continue; /* Need rw */

    size_t size = end - start;
    if (size < 4096 || size > 16 * 1024 * 1024)
      continue; /* Reasonable size */
    if (strstr(line, ".so"))
      continue;

    /* Scan this region for Lua state patterns */
    for (uintptr_t addr = start; addr < end - 256; addr += 8) {
      install_crash_handler();
      g_in_risky_call = 1;

      if (sigsetjmp(g_jmp_buf, 1) == 0) {
        uintptr_t *ptr = (uintptr_t *)addr;

        /* Lua state heuristics */
        int score = 0;
        int valid_ptrs = 0;

        for (int i = 0; i < 10; i++) {
          uintptr_t val = ptr[i];
          /* Valid pointer range */
          if (val > 0x10000 && val < 0x800000000000UL) {
            valid_ptrs++;
          }
        }

        if (valid_ptrs >= 6) {
          score = valid_ptrs * 5;

          /* Check for L->top and L->base relationship */
          if (ptr[1] > ptr[2] && ptr[1] - ptr[2] < 0x10000) {
            score += 20;
          }

          if (score > best_score) {
            best_score = score;
            best_candidate = (lua_State *)addr;
          }
        }
      }

      g_in_risky_call = 0;
    }
  }
  fclose(maps);

  if (best_candidate) {
    log_debug("Best Lua state candidate: %p (score=%d)\n",
              (void *)best_candidate, best_score);
  }

  return best_candidate;
}

/*
 * Resolve Luau function addresses from offsets.
 */
static int resolve_functions_v2(luau_api_t *api, uintptr_t code_base) {
  if (!api || !code_base)
    return -1;

  /* Apply offsets from roblox_offsets.h */
  api->luau_load = (luau_load_t)(code_base + OFF_luau_load);
  api->pcall = (lua_pcall_t)(code_base + OFF_luaD_pcall);
  api->pushstring = (lua_pushstring_t)(code_base + OFF_lua_pushstring);
  api->pushvalue = (lua_pushvalue_t)(code_base + OFF_lua_pushvalue);
  api->setfield = (lua_setfield_t)(code_base + OFF_lua_setfield);

  log_debug("Resolved functions:\n");
  log_debug("  luau_load @ %p\n", (void *)api->luau_load);
  log_debug("  pcall @ %p\n", (void *)api->pcall);
  log_debug("  pushstring @ %p\n", (void *)api->pushstring);

  api->functions_resolved = 1;
  return 0;
}

/*
 * Execute a Luau script.
 */
static int execute_script_v2(luau_api_t *api, const char *script, char *output,
                             size_t output_size) {
  if (!api || !api->L || !api->functions_resolved) {
    snprintf(output, output_size, "ERROR: API not initialized");
    return -1;
  }

  if (!script || !*script) {
    snprintf(output, output_size, "ERROR: Empty script");
    return -1;
  }

  log_debug("Executing script (%zu bytes)...\n", strlen(script));

  /* Set up crash protection */
  install_crash_handler();
  g_in_risky_call = 1;

  if (sigsetjmp(g_jmp_buf, 1) != 0) {
    g_in_risky_call = 0;
    snprintf(output, output_size, "CRASH: Execution caused a signal");
    log_debug("CRASH in script execution\n");
    return -1;
  }

  int result = -1;

  /* Try to load and execute the script */
  if (api->luau_load) {
    /* Use luau_load for Roblox's Luau */
    /* Note: actual calling convention may differ */
    log_debug("Calling luau_load...\n");

    /* This is where we'd compile and execute */
    /* For now, just signal success if we get here */
    result = 0;
    snprintf(output, output_size, "Script executed (stub)");
  }

  g_in_risky_call = 0;
  return result;
}

/* ========================================================================== */
/*                         GAME MODE: WORKER THREAD */
/* ========================================================================== */

static void *game_worker_thread(void *arg) {
  (void)arg;
  log_debug("Game worker thread started\n");

  /* Open IPC as game side */
  if (ipc_open(&g_ipc, 0) < 0) {
    log_debug("Game failed to open IPC\n");
    return NULL;
  }

  /* Share Lua state info */
  if (g_api.L) {
    g_ipc.shm->lua_state_addr = (uint64_t)(uintptr_t)g_api.L;
  }
  g_ipc.shm->code_base_addr = g_api.sober_base;

  ipc_start_heartbeat(&g_ipc, 0);

  while (g_running) {
    if (ipc_check_pending(&g_ipc)) {
      const char *script = ipc_get_script(&g_ipc);
      char output[4096] = {0};

      int result = execute_script_v2(&g_api, script, output, sizeof(output));
      ipc_set_result(&g_ipc, result, output);
    }

    usleep(50000); /* 50ms poll */
  }

  ipc_stop_heartbeat(&g_ipc);
  ipc_close(&g_ipc);

  log_debug("Game worker thread exiting\n");
  return NULL;
}

static int init_game_mode(void) {
  log_debug("=== Initializing GAME MODE ===\n");
  log_debug("PID: %d\n", getpid());

  /* Find code base */
  g_api.sober_base = find_code_base();
  if (!g_api.sober_base) {
    log_debug("ERROR: Could not find code base\n");
    return -1;
  }

  /* Find Lua state */
  g_api.L = find_lua_state_v2();
  if (!g_api.L) {
    log_debug("WARNING: Could not find Lua state (yet)\n");
    /* Continue anyway - might find it later */
  }

  /* Resolve functions */
  resolve_functions_v2(&g_api, g_api.sober_base);

  /* Start worker thread */
  g_running = 1;
  if (pthread_create(&g_worker_thread, NULL, game_worker_thread, NULL) != 0) {
    log_debug("ERROR: Failed to create worker thread\n");
    return -1;
  }

  log_debug("Game mode initialized successfully\n");
  return 0;
}

/* ========================================================================== */
/*                         TRACER MODE: REMOTE INJECTION */
/* ========================================================================== */

static void *tracer_worker_thread(void *arg) {
  (void)arg;
  log_debug("Tracer worker thread started\n");

  /* Open IPC as tracer side */
  if (ipc_open(&g_ipc, 1) < 0) {
    log_debug("Tracer failed to create IPC\n");
    return NULL;
  }

  ipc_start_heartbeat(&g_ipc, 1);

  /* Find the game process */
  pid_t game_pid = find_game_process();
  if (game_pid <= 0) {
    log_debug("Could not find game process\n");
    ipc_close(&g_ipc);
    return NULL;
  }

  log_debug("Found game process: PID %d\n", game_pid);

  /* Check if WE are the tracer of the game */
  pid_t game_tracer = find_game_tracer();
  log_debug("Game's tracer PID: %d, we are PID: %d\n", game_tracer, getpid());

  int result = INJECT_ERR_ATTACH;

  if (game_tracer == getpid()) {
    /* We ARE the tracer! Use ptrace directly */
    log_debug("We are the game's tracer - using ptrace injection\n");
    result = inject_library(game_pid, "/dev/shm/linusware.so");
  } else if (game_tracer > 0) {
    /* We're not the tracer - try injecting into the tracer first */
    log_debug("We are NOT the game's tracer. Tracer is PID %d\n", game_tracer);
    log_debug("Attempting to inject into the tracer...\n");

    /* Try to inject into the tracer using GDB from outside */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "gdb -batch -ex 'attach %d' "
             "-ex 'call (void*)dlopen(\"/dev/shm/linusware.so\", 2)' "
             "-ex 'detach' -ex 'quit' 2>/dev/null",
             game_tracer);

    int gdb_result = system(cmd);
    if (gdb_result == 0) {
      log_debug("Successfully injected into tracer via GDB\n");
      result = INJECT_SUCCESS;
    } else {
      log_debug("GDB injection into tracer failed: %d\n", gdb_result);
    }
  }

  if (result != INJECT_SUCCESS) {
    log_debug("Failed to inject into game: error %d\n", result);
    /* Continue anyway - game might already have it */
  } else {
    log_debug("Successfully injected into game process!\n");
  }

  /* Wait for game to connect via IPC */
  log_debug("Waiting for game to initialize...\n");
  for (int i = 0; i < 100; i++) { /* 10 seconds max */
    if (ipc_peer_alive(&g_ipc, 1)) {
      log_debug("Game connected via IPC!\n");
      break;
    }
    usleep(100000); /* 100ms */
  }

  /* Main relay loop - forward scripts from UI to game */
  /* (This would integrate with the existing IPC file mechanism) */
  while (g_running) {
    /* Check for scripts in the old IPC location */
    FILE *f = fopen("/tmp/linusware_exec.txt", "r");
    if (f) {
      char script[65536];
      size_t len = fread(script, 1, sizeof(script) - 1, f);
      script[len] = '\0';
      fclose(f);

      /* Remove the file */
      unlink("/tmp/linusware_exec.txt");

      if (len > 0) {
        log_debug("Relaying script to game (%zu bytes)\n", len);
        char output[4096];
        int result =
            ipc_send_script(&g_ipc, script, output, sizeof(output), 5000);

        /* Write output */
        FILE *out = fopen("/tmp/linusware_output.txt", "w");
        if (out) {
          if (result >= 0) {
            fprintf(out, "%s", output);
          } else {
            fprintf(out, "ERROR: Script execution failed (%d)", result);
          }
          fclose(out);
        }
      }
    }

    usleep(100000); /* 100ms poll */
  }

  ipc_stop_heartbeat(&g_ipc);
  ipc_close(&g_ipc);

  log_debug("Tracer worker thread exiting\n");
  return NULL;
}

static int init_tracer_mode(void) {
  log_debug("=== Initializing TRACER MODE ===\n");
  log_debug("PID: %d\n", getpid());

  /* Start worker thread */
  g_running = 1;
  if (pthread_create(&g_worker_thread, NULL, tracer_worker_thread, NULL) != 0) {
    log_debug("ERROR: Failed to create worker thread\n");
    return -1;
  }

  log_debug("Tracer mode initialized successfully\n");
  return 0;
}

/* ========================================================================== */
/*                         LIBRARY ENTRY POINT */
/* ========================================================================== */

__attribute__((constructor)) void library_init(void) {
  /* Early init logging */
  log_debug("===========================================\n");
  log_debug("LinusWare Executor v3.0 - Dual Mode\n");
  log_debug("PID: %d\n", getpid());
  log_debug("===========================================\n");

  /* Determine mode */
  g_mode = detect_mode();

  switch (g_mode) {
  case MODE_GAME:
    init_game_mode();
    break;

  case MODE_TRACER:
    init_tracer_mode();
    break;

  default:
    log_debug("Unknown mode - not initializing\n");
    break;
  }
}

__attribute__((destructor)) void library_fini(void) {
  log_debug("Library destructor called\n");

  g_running = 0;

  if (g_mode == MODE_GAME || g_mode == MODE_TRACER) {
    pthread_join(g_worker_thread, NULL);
  }

  if (g_log) {
    fclose(g_log);
    g_log = NULL;
  }
}
