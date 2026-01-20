/*
 * shared_ipc.h - Shared memory IPC for tracer-game communication
 *
 * Uses POSIX shared memory (/dev/shm) to communicate between:
 * - Tracer process (handles UI commands)
 * - Game process (executes Luau scripts)
 *
 * Includes heartbeat mechanism for cleanup on crash.
 */

#ifndef SHARED_IPC_H
#define SHARED_IPC_H

#include <pthread.h>
#include <stdint.h>

/* IPC shared memory name */
#define IPC_SHM_NAME "/linusware_ipc"

/* IPC commands */
#define IPC_CMD_NONE 0
#define IPC_CMD_EXEC 1 /* Execute script in 'script' buffer */
#define IPC_CMD_EXIT 2 /* Shutdown request */
#define IPC_CMD_PING 3 /* Heartbeat ping */
#define IPC_CMD_PONG 4 /* Heartbeat response */

/* Script buffer sizes */
#define IPC_SCRIPT_SIZE 65536
#define IPC_OUTPUT_SIZE 65536

/* Heartbeat timeout in milliseconds */
#define IPC_HEARTBEAT_TIMEOUT_MS 5000

/*
 * Shared memory block structure.
 * Must be carefully aligned for atomic operations.
 */
typedef struct __attribute__((aligned(64))) {
  /* Heartbeat fields - written atomically */
  volatile int32_t tracer_alive;     /* Incremented by tracer */
  volatile int32_t game_alive;       /* Incremented by game */
  volatile int64_t tracer_timestamp; /* Last tracer update time */
  volatile int64_t game_timestamp;   /* Last game update time */

  /* Command/control fields */
  volatile int32_t command;      /* Current command (IPC_CMD_*) */
  volatile int32_t result;       /* Execution result code */
  volatile int32_t script_ready; /* Script is ready to execute */
  volatile int32_t output_ready; /* Output is ready to read */

  /* Process identification */
  int32_t tracer_pid;
  int32_t game_pid;

  /* Lua state info from game */
  uint64_t lua_state_addr;
  uint64_t code_base_addr;

  /* Padding to cache line boundary */
  char _pad[8];

  /* Script buffer - separate cache line */
  char script[IPC_SCRIPT_SIZE];

  /* Output buffer - separate cache line */
  char output[IPC_OUTPUT_SIZE];

} ipc_shared_block_t;

/*
 * IPC handle for local process.
 */
typedef struct {
  ipc_shared_block_t *shm;    /* Mapped shared memory */
  int fd;                     /* File descriptor */
  int is_owner;               /* Did we create it? */
  pthread_t heartbeat_thread; /* Heartbeat monitor */
  int running;                /* Heartbeat running */
} ipc_handle_t;

/*
 * Create or open the shared memory segment.
 * is_tracer: 1 if caller is tracer, 0 if game
 */
int ipc_open(ipc_handle_t *handle, int is_tracer);

/*
 * Close and optionally unlink the shared memory.
 */
void ipc_close(ipc_handle_t *handle);

/*
 * Cleanup any stale shared memory from previous crash.
 */
void ipc_cleanup_stale(void);

/*
 * Start the heartbeat monitoring thread.
 * Returns 0 on success.
 */
int ipc_start_heartbeat(ipc_handle_t *handle, int is_tracer);

/*
 * Stop the heartbeat monitoring thread.
 */
void ipc_stop_heartbeat(ipc_handle_t *handle);

/*
 * Check if the other side is still alive.
 * Returns 1 if alive, 0 if dead/timed out.
 */
int ipc_peer_alive(ipc_handle_t *handle, int is_tracer);

/*
 * TRACER SIDE: Send a script to the game for execution.
 * Blocks until execution completes or timeout.
 */
int ipc_send_script(ipc_handle_t *handle, const char *script, char *output,
                    size_t output_size, int timeout_ms);

/*
 * GAME SIDE: Check for pending script.
 * Returns 1 if script is pending, 0 otherwise.
 */
int ipc_check_pending(ipc_handle_t *handle);

/*
 * GAME SIDE: Get the pending script.
 * Returns pointer to script buffer (do not free).
 */
const char *ipc_get_script(ipc_handle_t *handle);

/*
 * GAME SIDE: Set execution result and output.
 */
void ipc_set_result(ipc_handle_t *handle, int result, const char *output);

/*
 * Update heartbeat timestamp.
 */
void ipc_heartbeat_tick(ipc_handle_t *handle, int is_tracer);

#endif /* SHARED_IPC_H */
