/*
 * linusware_audit.c - LD_AUDIT Hook Library
 *
 * Copyright (c) 2026 sultan
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Uses the LD_AUDIT mechanism to hook the dynamic linker.
 * This gets called for EVERY library load, even in forked processes.
 * When we detect the game process, we load our executor.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Configuration */
static const char *EXECUTOR_LIB = NULL;
static const char *LOG_PATH = NULL;
static FILE *g_log = NULL;
static volatile int g_executor_loaded = 0;
static volatile int g_is_game = 0;

/* Initialize paths based on HOME */
static void init_paths(void) {
  static char executor_path[512];
  static char log_path[512];
  static int initialized = 0;

  if (initialized)
    return;

  const char *home = getenv("HOME");
  if (!home)
    home = "/tmp";

  snprintf(executor_path, sizeof(executor_path),
           "%s/.local/share/linusware/linusware.so", home);
  snprintf(log_path, sizeof(log_path),
           "%s/.var/app/org.vinegarhq.Sober/data/linusware_audit.log", home);

  EXECUTOR_LIB = executor_path;
  LOG_PATH = log_path;
  initialized = 1;
}

/* Logging */
static void audit_log(const char *fmt, ...) {
  if (!g_log) {
    init_paths();
    g_log = fopen(LOG_PATH, "a");
    if (g_log) {
      setbuf(g_log, NULL);
      chmod(LOG_PATH, 0666);
    }
  }
  if (!g_log)
    return;

  va_list args;
  va_start(args, fmt);
  fprintf(g_log, "[audit] ");
  vfprintf(g_log, fmt, args);
  va_end(args);
  fflush(g_log);
}

/* Check if current memory footprint indicates game process */
static int is_large_process(void) {
  FILE *f = fopen("/proc/self/statm", "r");
  if (!f)
    return 0;

  unsigned long size = 0;
  fscanf(f, "%lu", &size);
  fclose(f);

  /* Game process will have > 100k pages (400MB+) */
  return size > 100000;
}

/* Load the executor library */
static void load_executor(void) {
  if (g_executor_loaded)
    return;
  g_executor_loaded = 1;

  init_paths();

  /* Sync filesystem to ensure file is accessible */
  sync();

  /* Small delay to let process stabilize */
  usleep(100000); /* 100ms */

  audit_log("Loading executor from: %s\n", EXECUTOR_LIB);
  audit_log("File exists check...\n");

  if (access(EXECUTOR_LIB, R_OK) != 0) {
    audit_log("ERROR: File not accessible: %s\n", EXECUTOR_LIB);
    return;
  }

  audit_log("File accessible, calling dlopen...\n");

  void *handle = dlopen(EXECUTOR_LIB, RTLD_NOW | RTLD_GLOBAL);
  if (handle) {
    audit_log("SUCCESS: Executor loaded at %p!\n", handle);
  } else {
    const char *err = dlerror();
    audit_log("FAILED: dlopen error: %s\n", err ? err : "(null)");
  }
}

/* Worker thread that waits for game init then loads executor */
static void *loader_thread(void *arg) {
  (void)arg;

  audit_log("Loader thread started, waiting for game...\n");

  /* Wait for game indicators */
  for (int i = 0; i < 120; i++) { /* 60 seconds max */
    /* Check memory size */
    FILE *f = fopen("/proc/self/statm", "r");
    unsigned long size = 0;
    if (f) {
      fscanf(f, "%lu", &size);
      fclose(f);
    }

    /* Log periodically */
    if (i % 10 == 0) {
      audit_log("Check #%d: mem=%lu pages, is_game=%d\n", i, size, g_is_game);
    }

    /* Load if: 1) large memory (10k+ pages = 40MB+) OR 2) game confirmed via
     * lib detection */
    if (size > 10000 || (g_is_game && size > 1000)) {
      audit_log("Trigger: mem=%lu, is_game=%d - loading executor!\n", size,
                g_is_game);
      load_executor();
      break;
    }
    usleep(500000); /* 500ms */
  }

  audit_log("Loader thread exiting\n");
  return NULL;
}

/*
 * ============================================================================
 *                          LD_AUDIT INTERFACE
 * ============================================================================
 */

/* Required: Return the audit interface version we support */
unsigned int la_version(unsigned int version) {
  init_paths();
  audit_log("la_version called, version=%u, PID=%d\n", version, getpid());

  /* Start loader thread in background */
  pthread_t thread;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&thread, &attr, loader_thread, NULL);
  pthread_attr_destroy(&attr);

  return LAV_CURRENT;
}

/* Called when a new shared object is loaded */
unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
  if (!map || !map->l_name)
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;

  const char *name = map->l_name;
  if (!name[0])
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;

  /* Log interesting library loads - just set flag, don't load yet */
  if (strstr(name, "libGL") || strstr(name, "libvulkan") ||
      strstr(name, "libX11") || strstr(name, "libwayland")) {
    audit_log("Graphics lib: %s\n", name);
    g_is_game = 1;
  }

  /* If we see mimalloc (used by Roblox), we're definitely in the game */
  if (strstr(name, "mimalloc")) {
    audit_log("Roblox lib: %s\n", name);
    g_is_game = 1;
    /* Don't load here - let the background thread do it after stabilization */
  }

  return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

/* Called when the audit library is about to be unloaded */
void la_preinit(uintptr_t *cookie) { audit_log("la_preinit called\n"); }

/* Called when all dependencies are loaded */
void la_activity(uintptr_t *cookie, unsigned int flag) {
  if (flag == LA_ACT_CONSISTENT) {
    audit_log("Activity consistent, game=%d, loaded=%d\n", g_is_game,
              g_executor_loaded);
    /* Don't load here either - let background thread handle it */
  }
}
