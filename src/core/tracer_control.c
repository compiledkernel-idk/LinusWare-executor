/*
 * tracer_control.c - Tracer chain management for Sober injection
 *
 * Copyright (c) 2026 sultan
 * PROPRIETARY AND CONFIDENTIAL
 */

#define _GNU_SOURCE
#include "tracer_control.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Forward declarations */
static int compare_by_memory(const void *a, const void *b);

pid_t get_tracer_pid(pid_t pid) {
  char path[64];
  char line[256];
  pid_t tracer = -1;

  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return -1;

  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
      tracer = atoi(line + 10);
      break;
    }
  }
  fclose(f);
  return tracer;
}

size_t get_memory_pages(pid_t pid) {
  char path[64];
  size_t pages = 0;

  snprintf(path, sizeof(path), "/proc/%d/statm", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  if (fscanf(f, "%zu", &pages) != 1) {
    pages = 0;
  }
  fclose(f);
  return pages;
}

int is_sober_process(pid_t pid) {
  char path[128];

  /* Check if /proc/PID/root/app/bin/sober exists (Flatpak container) */
  snprintf(path, sizeof(path), "/proc/%d/root/app/bin/sober", pid);
  if (access(path, F_OK) == 0) {
    return 1;
  }

  /* Also check exe symlink */
  char exe_path[64];
  char exe_target[256];
  snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
  ssize_t len = readlink(exe_path, exe_target, sizeof(exe_target) - 1);
  if (len > 0) {
    exe_target[len] = 0;
    if (strstr(exe_target, "sober") || strstr(exe_target, "/app/bin/sober")) {
      return 1;
    }
  }

  return 0;
}

int build_tracer_chain(tracer_chain_t *chain) {
  if (!chain)
    return -1;

  memset(chain, 0, sizeof(*chain));

  DIR *proc = opendir("/proc");
  if (!proc)
    return -1;

  struct dirent *entry;
  while ((entry = readdir(proc)) && chain->count < 16) {
    if (entry->d_type != DT_DIR)
      continue;

    pid_t pid = atoi(entry->d_name);
    if (pid <= 0)
      continue;

    if (!is_sober_process(pid))
      continue;

    process_info_t *info = &chain->processes[chain->count];
    info->pid = pid;
    info->tracer_pid = get_tracer_pid(pid);
    info->memory_pages = get_memory_pages(pid);
    info->is_sober = 1;

    chain->count++;
  }
  closedir(proc);

  if (chain->count == 0)
    return -1;

  /* Sort by memory to find game process (largest) */
  qsort(chain->processes, chain->count, sizeof(process_info_t),
        compare_by_memory);

  /* Game process is the one with most memory */
  chain->game_process = chain->processes[0].pid;

  /* Find outermost tracer (TracerPid=0) */
  for (int i = 0; i < chain->count; i++) {
    if (chain->processes[i].tracer_pid == 0) {
      chain->outermost_tracer = chain->processes[i].pid;
      break;
    }
  }

  return 0;
}

static int compare_by_memory(const void *a, const void *b) {
  const process_info_t *pa = (const process_info_t *)a;
  const process_info_t *pb = (const process_info_t *)b;
  /* Sort descending by memory */
  if (pb->memory_pages > pa->memory_pages)
    return 1;
  if (pb->memory_pages < pa->memory_pages)
    return -1;
  return 0;
}

pid_t find_outermost_tracer(void) {
  tracer_chain_t chain;
  if (build_tracer_chain(&chain) < 0) {
    return -1;
  }
  return chain.outermost_tracer;
}

pid_t find_game_process(void) {
  tracer_chain_t chain;
  if (build_tracer_chain(&chain) < 0) {
    return -1;
  }
  return chain.game_process;
}

/* Find the process that traces the game (the middle tracer) */
pid_t find_game_tracer(void) {
  pid_t game = find_game_process();
  if (game <= 0)
    return -1;

  pid_t tracer = get_tracer_pid(game);
  return tracer;
}

int is_tracer_of(pid_t target) {
  pid_t tracer = get_tracer_pid(target);
  return (tracer == getpid());
}

int find_traced_children(pid_t *children, int max_count) {
  if (!children || max_count <= 0)
    return 0;

  int count = 0;
  DIR *proc = opendir("/proc");
  if (!proc)
    return 0;

  struct dirent *entry;
  pid_t my_pid = getpid();

  while ((entry = readdir(proc)) && count < max_count) {
    if (entry->d_type != DT_DIR)
      continue;

    pid_t pid = atoi(entry->d_name);
    if (pid <= 0)
      continue;

    if (get_tracer_pid(pid) == my_pid) {
      children[count++] = pid;
    }
  }
  closedir(proc);

  return count;
}

int wait_for_trace_opportunity(pid_t target, int timeout_ms) {
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);

  while (1) {
    pid_t tracer = get_tracer_pid(target);

    /* Not traced - we can attach! */
    if (tracer == 0) {
      return 0;
    }

    /* We are already the tracer */
    if (tracer == getpid()) {
      return 0;
    }

    /* Check timeout */
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
                      (now.tv_nsec - start.tv_nsec) / 1000000;

    if (elapsed_ms >= timeout_ms) {
      return -1; /* Timeout */
    }

    usleep(10000); /* Sleep 10ms */
  }
}
