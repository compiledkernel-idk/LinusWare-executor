/*
 * remote_inject.h - Remote code injection via ptrace
 *
 * Provides functionality to inject and execute code in a traced child process.
 * Uses ptrace POKEDATA to write shellcode and SETREGS to redirect execution.
 *
 * CRITICAL CONSIDERATIONS:
 * - 16-byte stack alignment required before calling glibc functions
 * - 128-byte Red Zone must be preserved on x86_64
 * - Original register state must be saved and restored
 */

#ifndef REMOTE_INJECT_H
#define REMOTE_INJECT_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>

/* Maximum shellcode size */
#define MAX_SHELLCODE_SIZE 4096

/* Injection result codes */
#define INJECT_SUCCESS 0
#define INJECT_ERR_ATTACH -1
#define INJECT_ERR_NO_MEMORY -2
#define INJECT_ERR_WRITE -3
#define INJECT_ERR_EXECUTE -4
#define INJECT_ERR_TIMEOUT -5
#define INJECT_ERR_RESTORE -6

/* Saved state for restoration */
typedef struct {
  struct user_regs_struct regs;
  uint8_t original_code[MAX_SHELLCODE_SIZE];
  uintptr_t shellcode_addr;
  size_t shellcode_size;
  int valid;
} saved_state_t;

/*
 * Find an executable memory region in target process.
 * Prefers regions that are RWX, falls back to RX.
 * Returns address or 0 on failure.
 */
uintptr_t find_executable_region(pid_t target);

/*
 * Find a suitable memory cave (unused executable memory).
 * Looks for large runs of 0x00 or 0xCC bytes.
 */
uintptr_t find_memory_cave(pid_t target, size_t min_size);

/*
 * Write data to target process memory using ptrace.
 * Data must be word-aligned for efficiency.
 */
int write_to_remote(pid_t target, uintptr_t addr, const void *data, size_t len);

/*
 * Read data from target process memory.
 */
int read_from_remote(pid_t target, uintptr_t addr, void *buf, size_t len);

/*
 * Save current execution state of target (registers + code at injection point).
 */
int save_target_state(pid_t target, saved_state_t *state, uintptr_t addr,
                      size_t len);

/*
 * Restore target to saved state.
 */
int restore_target_state(pid_t target, const saved_state_t *state);

/*
 * Inject shellcode and execute it in target process.
 *
 * This function:
 * 1. Attaches to target (if not already attached)
 * 2. Finds executable memory
 * 3. Saves original state
 * 4. Writes shellcode
 * 5. Sets RIP to shellcode
 * 6. Continues execution until shellcode hits int3
 * 7. Restores original state
 *
 * The shellcode MUST end with 'int3' (0xCC) instruction!
 */
int inject_and_execute(pid_t target, const uint8_t *shellcode, size_t len);

/*
 * Generate dlopen shellcode for loading a library.
 * Returns shellcode size, writes to 'buf'.
 *
 * The shellcode properly handles:
 * - 128-byte Red Zone preservation
 * - 16-byte stack alignment
 * - Register preservation
 */
size_t generate_dlopen_shellcode(uint8_t *buf, size_t max_len,
                                 const char *library_path);

/*
 * High-level: Inject a shared library into target process.
 * Uses shellcode to call dlopen() in the target.
 */
int inject_library(pid_t target, const char *library_path);

/*
 * Utility: Wait for target to stop (after PTRACE_CONT).
 * Returns the status from waitpid.
 */
int wait_for_stop(pid_t target, int timeout_ms);

#endif /* REMOTE_INJECT_H */
