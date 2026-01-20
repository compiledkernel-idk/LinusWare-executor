/*
 * Hook-based execution approach
 * Instead of calling Lua functions directly, we hook Sober's script loading
 */

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define IPC_OUT_PATH "/tmp/linusware_output.txt"

// Hook structure
typedef struct {
  void *original_func;
  void *hook_func;
  unsigned char original_bytes[16];
  void *target_addr;
} hook_t;

static hook_t g_loadbuffer_hook = {0};
static char *g_pending_script = NULL;
void **g_captured_L = NULL; // Pointer to g_api.L

// Our hook function - gets called instead of original loadbuffer
static int hooked_loadbuffer(void *L, const char *buff, size_t sz,
                             const char *name) {
  // Capture the Lua state if we haven't already
  if (g_captured_L && L) {
    *g_captured_L = L;
  }

  // If we have a pending script, execute it instead
  if (g_pending_script) {
    printf("[HOOK] Hijacking loadbuffer call for %s\n", name);
    buff = g_pending_script;
    sz = strlen(g_pending_script);
    name = "@linusware_hijack";

    char *to_free = g_pending_script;
    g_pending_script = NULL;

    typedef int (*loadbuffer_t)(void *, const char *, size_t, const char *);
    loadbuffer_t orig = (loadbuffer_t)g_loadbuffer_hook.target_addr;

    // To call the original, we temporarily UNHOOK it
    mprotect((void *)((uintptr_t)orig & ~0xFFF), 0x1000,
             PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(orig, g_loadbuffer_hook.original_bytes, 12);

    int res = orig(L, buff, sz, name);

    // Re-hook
    unsigned char jmp[16];
    jmp[0] = 0x48;
    jmp[1] = 0xB8;
    *(uint64_t *)(jmp + 2) = (uint64_t)hooked_loadbuffer;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy(orig, jmp, 12);
    mprotect((void *)((uintptr_t)orig & ~0xFFF), 0x1000, PROT_READ | PROT_EXEC);

    free(to_free);
    return res;
  }

  // Call original function normally
  typedef int (*loadbuffer_t)(void *, const char *, size_t, const char *);
  loadbuffer_t orig = (loadbuffer_t)g_loadbuffer_hook.target_addr;

  mprotect((void *)((uintptr_t)orig & ~0xFFF), 0x1000,
           PROT_READ | PROT_WRITE | PROT_EXEC);
  memcpy(orig, g_loadbuffer_hook.original_bytes, 12);

  int res = orig(L, buff, sz, name);

  unsigned char jmp[16];
  jmp[0] = 0x48;
  jmp[1] = 0xB8;
  *(uint64_t *)(jmp + 2) = (uint64_t)hooked_loadbuffer;
  jmp[10] = 0xFF;
  jmp[11] = 0xE0;
  memcpy(orig, jmp, 12);
  mprotect((void *)((uintptr_t)orig & ~0xFFF), 0x1000, PROT_READ | PROT_EXEC);

  return res;
}

// Install inline hook
static int install_hook(void *target, void *hook, hook_t *hook_struct) {
  // Save original bytes
  memcpy(hook_struct->original_bytes, target, 16);
  hook_struct->target_addr = target;
  hook_struct->hook_func = hook;

  // Make memory writable
  mprotect((void *)((uintptr_t)target & ~0xFFF), 0x1000,
           PROT_READ | PROT_WRITE | PROT_EXEC);

  // Write JMP to our hook (x86_64)
  unsigned char jmp[16];
  jmp[0] = 0x48; // movabs rax
  jmp[1] = 0xB8;
  *(uint64_t *)(jmp + 2) = (uint64_t)hook;
  jmp[10] = 0xFF; // jmp rax
  jmp[11] = 0xE0;

  memcpy(target, jmp, 12);

  // Make memory executable again
  mprotect((void *)((uintptr_t)target & ~0xFFF), 0x1000, PROT_READ | PROT_EXEC);

  return 0;
}

// Find and hook loadbuffer automatically
int hook_script_execution(uintptr_t libloader_base, void **L_store) {
  g_captured_L = L_store;
  unsigned char *base = (unsigned char *)libloader_base;

  // Look for function starts in reasonable range (libloader is typically 1MB+)
  for (int i = 0x10000; i < 0x200000; i++) {
    // Check for endbr64 or standard prologue
    if ((base[i] == 0xF3 && base[i + 1] == 0x0F && base[i + 2] == 0x1E &&
         base[i + 3] == 0xFA) ||
        (base[i] == 0x55 && base[i + 1] == 0x48 && base[i + 2] == 0x89 &&
         base[i + 3] == 0xE5)) {

      // Potential function start, calculate approximate size
      int size = 0;
      for (int j = 0; j < 1000; j++) {
        if (base[i + j] == 0xC3) { // ret
          size = j;
          break;
        }
      }

      // luaL_loadbuffer is usually between 200 and 800 bytes
      if (size > 150 && size < 900) {
        void *target = (void *)(base + i);
        printf("[HOOK] Candidate found at offset 0x%x (size %d)\n", i, size);

        // To refine, look for common Lua constants or strings in the function
        // body But for now, we'll try the first good-sized function.
        if (install_hook(target, hooked_loadbuffer, &g_loadbuffer_hook) == 0) {
          printf("[HOOK] Hooked function at 0x%p\n", target);
          return 1;
        }
      }
    }
  }

  printf("[HOOK] No suitable hook targets found.\n");
  return 0;
}

// Queue script for execution
void queue_script(const char *script) {
  if (g_pending_script) {
    free(g_pending_script);
  }
  g_pending_script = strdup(script);
}
