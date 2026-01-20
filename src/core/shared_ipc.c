/*
 * shared_ipc.c - Shared memory IPC implementation
 *
 * Copyright (c) 2026 sultan
 * PROPRIETARY AND CONFIDENTIAL
 */

#define _GNU_SOURCE
#include "shared_ipc.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Log function - defined in injected_lib.c */
extern void log_debug(const char *fmt, ...);

static int64_t get_timestamp_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

void ipc_cleanup_stale(void) {
  /* Try to remove any existing stale segment */
  shm_unlink(IPC_SHM_NAME);
}

int ipc_open(ipc_handle_t *handle, int is_tracer) {
  if (!handle)
    return -1;

  memset(handle, 0, sizeof(*handle));

  int flags = O_RDWR;
  if (is_tracer) {
    /* Tracer creates the segment */
    ipc_cleanup_stale();
    flags |= O_CREAT | O_EXCL;
  }

  handle->fd = shm_open(IPC_SHM_NAME, flags, 0666);

  if (handle->fd < 0) {
    if (is_tracer) {
      log_debug("Failed to create shared memory: %s\n", strerror(errno));
      return -1;
    }

    /* Game might need to wait for tracer */
    for (int i = 0; i < 50; i++) {
      usleep(100000); /* 100ms */
      handle->fd = shm_open(IPC_SHM_NAME, O_RDWR, 0666);
      if (handle->fd >= 0)
        break;
    }

    if (handle->fd < 0) {
      log_debug("Failed to open shared memory: %s\n", strerror(errno));
      return -1;
    }
  }

  /* Set size if we created it */
  if (is_tracer) {
    if (ftruncate(handle->fd, sizeof(ipc_shared_block_t)) < 0) {
      log_debug("Failed to set shm size: %s\n", strerror(errno));
      close(handle->fd);
      shm_unlink(IPC_SHM_NAME);
      return -1;
    }
    handle->is_owner = 1;
  }

  /* Map the segment */
  handle->shm = mmap(NULL, sizeof(ipc_shared_block_t), PROT_READ | PROT_WRITE,
                     MAP_SHARED, handle->fd, 0);

  if (handle->shm == MAP_FAILED) {
    log_debug("Failed to mmap shared memory: %s\n", strerror(errno));
    close(handle->fd);
    if (is_tracer)
      shm_unlink(IPC_SHM_NAME);
    return -1;
  }

  /* Initialize if we're the tracer */
  if (is_tracer) {
    memset((void *)handle->shm, 0, sizeof(ipc_shared_block_t));
    handle->shm->tracer_pid = getpid();
    handle->shm->tracer_timestamp = get_timestamp_ms();
    handle->shm->tracer_alive = 1;
  } else {
    handle->shm->game_pid = getpid();
    handle->shm->game_timestamp = get_timestamp_ms();
    handle->shm->game_alive = 1;
  }

  handle->running = 1;
  log_debug("IPC opened: %s mode, fd=%d\n", is_tracer ? "tracer" : "game",
            handle->fd);

  return 0;
}

void ipc_close(ipc_handle_t *handle) {
  if (!handle)
    return;

  handle->running = 0;

  if (handle->shm && handle->shm != MAP_FAILED) {
    munmap((void *)handle->shm, sizeof(ipc_shared_block_t));
  }

  if (handle->fd >= 0) {
    close(handle->fd);
  }

  if (handle->is_owner) {
    shm_unlink(IPC_SHM_NAME);
  }

  memset(handle, 0, sizeof(*handle));
}

void ipc_heartbeat_tick(ipc_handle_t *handle, int is_tracer) {
  if (!handle || !handle->shm)
    return;

  int64_t now = get_timestamp_ms();

  if (is_tracer) {
    __atomic_add_fetch(&handle->shm->tracer_alive, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&handle->shm->tracer_timestamp, now, __ATOMIC_SEQ_CST);
  } else {
    __atomic_add_fetch(&handle->shm->game_alive, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&handle->shm->game_timestamp, now, __ATOMIC_SEQ_CST);
  }
}

int ipc_peer_alive(ipc_handle_t *handle, int is_tracer) {
  if (!handle || !handle->shm)
    return 0;

  int64_t now = get_timestamp_ms();
  int64_t peer_ts =
      is_tracer
          ? __atomic_load_n(&handle->shm->game_timestamp, __ATOMIC_SEQ_CST)
          : __atomic_load_n(&handle->shm->tracer_timestamp, __ATOMIC_SEQ_CST);

  return (now - peer_ts) < IPC_HEARTBEAT_TIMEOUT_MS;
}

static void *heartbeat_thread(void *arg) {
  ipc_handle_t *handle = (ipc_handle_t *)arg;
  int is_tracer = handle->is_owner;

  while (handle->running) {
    ipc_heartbeat_tick(handle, is_tracer);
    usleep(1000000); /* 1 second */
  }

  return NULL;
}

int ipc_start_heartbeat(ipc_handle_t *handle, int is_tracer) {
  (void)is_tracer;
  if (!handle)
    return -1;

  handle->running = 1;
  if (pthread_create(&handle->heartbeat_thread, NULL, heartbeat_thread,
                     handle) != 0) {
    return -1;
  }

  return 0;
}

void ipc_stop_heartbeat(ipc_handle_t *handle) {
  if (!handle)
    return;

  handle->running = 0;
  pthread_join(handle->heartbeat_thread, NULL);
}

int ipc_send_script(ipc_handle_t *handle, const char *script, char *output,
                    size_t output_size, int timeout_ms) {
  if (!handle || !handle->shm || !script)
    return -1;

  ipc_shared_block_t *shm = handle->shm;

  /* Copy script to shared buffer */
  size_t script_len = strlen(script);
  if (script_len >= IPC_SCRIPT_SIZE) {
    script_len = IPC_SCRIPT_SIZE - 1;
  }
  memcpy((void *)shm->script, script, script_len);
  ((char *)shm->script)[script_len] = '\0';

  /* Clear output and set flags */
  shm->output[0] = '\0';
  shm->output_ready = 0;
  shm->result = 0;

  /* Signal that script is ready */
  __atomic_store_n(&shm->command, IPC_CMD_EXEC, __ATOMIC_SEQ_CST);
  __atomic_store_n(&shm->script_ready, 1, __ATOMIC_SEQ_CST);

  /* Wait for result */
  int64_t start = get_timestamp_ms();
  while (1) {
    if (__atomic_load_n(&shm->output_ready, __ATOMIC_SEQ_CST)) {
      break;
    }

    int64_t elapsed = get_timestamp_ms() - start;
    if (elapsed >= timeout_ms) {
      return -2; /* Timeout */
    }

    usleep(10000); /* 10ms */
  }

  /* Copy output */
  if (output && output_size > 0) {
    strncpy(output, (const char *)shm->output, output_size - 1);
    output[output_size - 1] = '\0';
  }

  /* Clear flags */
  __atomic_store_n(&shm->script_ready, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&shm->command, IPC_CMD_NONE, __ATOMIC_SEQ_CST);

  return shm->result;
}

int ipc_check_pending(ipc_handle_t *handle) {
  if (!handle || !handle->shm)
    return 0;

  return __atomic_load_n(&handle->shm->script_ready, __ATOMIC_SEQ_CST) &&
         __atomic_load_n(&handle->shm->command, __ATOMIC_SEQ_CST) ==
             IPC_CMD_EXEC;
}

const char *ipc_get_script(ipc_handle_t *handle) {
  if (!handle || !handle->shm)
    return NULL;
  return (const char *)handle->shm->script;
}

void ipc_set_result(ipc_handle_t *handle, int result, const char *output) {
  if (!handle || !handle->shm)
    return;

  ipc_shared_block_t *shm = handle->shm;

  shm->result = result;

  if (output) {
    strncpy((char *)shm->output, output, IPC_OUTPUT_SIZE - 1);
    shm->output[IPC_OUTPUT_SIZE - 1] = '\0';
  } else {
    shm->output[0] = '\0';
  }

  __atomic_store_n(&shm->output_ready, 1, __ATOMIC_SEQ_CST);
}
