/*
 * tracer_control.h - Tracer chain management for Sober injection
 *
 * Provides functions to detect and navigate the Sober process tree:
 * - Find the outermost tracer (TracerPid=0)
 * - Traverse the tracer chain to find the actual game process
 * - Manage ptrace relationships for remote injection
 */

#ifndef TRACER_CONTROL_H
#define TRACER_CONTROL_H

#include <stdint.h>
#include <sys/types.h>

/* Process info structure for tracer chain */
typedef struct {
  pid_t pid;
  pid_t tracer_pid;
  size_t memory_pages; /* From /proc/PID/statm */
  int is_sober;        /* Has /app/bin/sober in exe path */
} process_info_t;

/* Tracer chain structure */
typedef struct {
  process_info_t processes[16];
  int count;
  pid_t outermost_tracer; /* TracerPid=0 */
  pid_t game_process;     /* Largest memory, actual game */
} tracer_chain_t;

/*
 * Build the complete tracer chain for Sober processes.
 * Returns 0 on success, -1 on failure.
 */
int build_tracer_chain(tracer_chain_t *chain);

/*
 * Find the outermost tracer (sober process with TracerPid=0).
 * This is the process we can inject into.
 */
pid_t find_outermost_tracer(void);

/*
 * Find the actual game process (the one with ~5GB memory).
 * This is the process we want to execute code in.
 */
pid_t find_game_process(void);

/*
 * Find the process that TRACES the game (the middle tracer).
 * This is the sober process that has ptrace control over the game.
 */
pid_t find_game_tracer(void);

/*
 * Get the TracerPid of a process.
 * Returns 0 if not traced, -1 on error.
 */
pid_t get_tracer_pid(pid_t pid);

/*
 * Get memory size of a process in pages.
 * Returns 0 on error.
 */
size_t get_memory_pages(pid_t pid);

/*
 * Check if a PID is a sober process (has /app/bin/sober).
 */
int is_sober_process(pid_t pid);

/*
 * Check if we (current process) are the tracer of target.
 */
int is_tracer_of(pid_t target);

/*
 * Find all children that we are currently tracing.
 * Returns count of traced children.
 */
int find_traced_children(pid_t *children, int max_count);

/*
 * Attempt to become the tracer of target by waiting for current
 * tracer to detach or exit. Timeout in milliseconds.
 */
int wait_for_trace_opportunity(pid_t target, int timeout_ms);

#endif /* TRACER_CONTROL_H */
