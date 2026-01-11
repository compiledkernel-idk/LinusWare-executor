#include "pattern_scanner.h"
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static jmp_buf g_scan_jmp;
static int g_in_scan = 0;

void scan_signal_handler(int sig) {
  if (g_in_scan) {
    g_in_scan = 0;
    siglongjmp(g_scan_jmp, 1);
  } else {
    // Ghost Mode: Silently ignore traps outside of scan windows
    if (sig == SIGTRAP || sig == SIGILL)
      return;
    exit(sig);
  }
}

int vtable_hunter(luau_api_t *api) {
  if (!api)
    return 0;
  int found = 0;
  struct sigaction sa, old_segv;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = scan_signal_handler;
  sigaction(SIGSEGV, &sa, &old_segv);

  log_debug("--- VTABLE HUNTER ---\n");
  uintptr_t code_start = api->sober_base;
  uintptr_t code_end = code_start + 0x10000000;

  FILE *maps = fopen("/proc/self/maps", "r");
  if (maps) {
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
      uintptr_t s, e;
      char perms[5];
      if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) == 3 && perms[0] == 'r' &&
          perms[1] == 'w') {
        log_debug("Scanning mapping for VTables: 0x%lx - 0x%lx (%s)\n", s, e,
                  line);

        uintptr_t *ptrs = (uintptr_t *)s;
        int region_ptrs = (e - s) / 8;
        int consecutive = 0;
        uintptr_t table_start = 0;

        for (int i = 0; i < region_ptrs - 20; i++) {
          uintptr_t val = 0;
          g_in_scan = 1;
          if (sigsetjmp(g_scan_jmp, 1) == 0) {
            val = ptrs[i];
            g_in_scan = 0;
          } else {
            consecutive = 0;
            continue;
          }

          if (val >= code_start && val < code_end) {
            if (consecutive == 0)
              table_start = (uintptr_t)&ptrs[i];
            consecutive++;
            if (consecutive > 10) {
              log_debug("FOUND VTABLE at 0x%lx (Offset 0x%lx, Entries %d)\n",
                        table_start, table_start - api->sober_base,
                        consecutive);
              found++;
              // Log first few entries
              for (int k = 0; k < 5; k++) {
                log_debug("  V[%d]: 0x%lx (Offset 0x%lx)\n", k,
                          ptrs[i - consecutive + 1 + k],
                          ptrs[i - consecutive + 1 + k] - api->sober_base);
              }
              i += consecutive;
              consecutive = 0;
            }
          } else {
            consecutive = 0;
          }
        }
      }
    }
    fclose(maps);
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  return found;
}

int relative_jump_table_hunter(luau_api_t *api) {
  if (!api)
    return 0;
  int found = 0;
  struct sigaction sa, old_segv;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = scan_signal_handler;
  sigaction(SIGSEGV, &sa, &old_segv);

  log_debug("--- RELATIVE JUMP TABLE HUNTER ---\n");
  FILE *maps = fopen("/proc/self/maps", "r");
  if (maps) {
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
      uintptr_t s, e;
      char perms[5];
      if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) == 3 && perms[2] == 'x' &&
          strstr(line, "sober")) {
        log_debug("Scanning Sober RX: 0x%lx - 0x%lx\n", s, e);

        uint8_t *code = (uint8_t *)s;
        size_t region_size = e - s;

        for (size_t i = 0; i < region_size - 400; i += 4) {
          int32_t *table = (int32_t *)(code + i);
          int consecutive = 0;

          g_in_scan = 1;
          if (sigsetjmp(g_scan_jmp, 1) == 0) {
            for (int j = 0; j < 64; j++) {
              int32_t offset = table[j];
              uintptr_t dest = (uintptr_t)&table[j] + offset;
              if (dest >= s && dest < e) {
                consecutive++;
              } else {
                break;
              }
            }
            g_in_scan = 0;
          }

          if (consecutive >= 64) {
            log_debug(
                "FOUND POTENTIAL RELATIVE JUMP TABLE at 0x%lx (Offset 0x%lx)\n",
                (uintptr_t)table, (uintptr_t)table - api->sober_base);
            found++;
            i += (consecutive * 4);
          }
        }
      }
    }
    fclose(maps);
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  return found;
}

int aggressive_function_discovery(luau_api_t *api) {
  (void)api;
  log_debug("Function discovery disabled to prevent crashes\\n");
  return 0;
}

uintptr_t find_function_by_string_ref(uintptr_t base, const char *str) {
  uintptr_t str_addr = 0;
  // Stub for now, can be implemented if string scanning is needed again
  return 0;
}

int scan_all_strings(luau_api_t *api) {
  // Stub
  return 0;
}

uintptr_t scan_range_for_functions(uintptr_t start, uintptr_t end,
                                   luau_api_t *api) {
  (void)start;
  (void)end;
  (void)api;
  return 0;
}

int scan_and_resolve_functions(luau_api_t *api) {
  return aggressive_function_discovery(api);
}

int safe_function_discovery(luau_api_t *api) {
  return aggressive_function_discovery(api);
}
