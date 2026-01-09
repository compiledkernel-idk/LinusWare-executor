
/*
 * Filename: pattern_scanner.c
 *
 * Copyright (c) 2026 compiledkernel-idk
 * All Rights Reserved.
 *
 * This software is proprietary and confidential.
 * Unauthorized copying, distribution, or use of this file,
 * via any medium, is strictly prohibited.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "luau_api.h"

extern void log_debug(const char *fmt, ...);

static sigjmp_buf g_scan_jmp;
static volatile int g_in_scan = 0;

static void scan_signal_handler(int sig) {
  (void)sig;
  if (g_in_scan) {
    g_in_scan = 0;
    siglongjmp(g_scan_jmp, 1);
  }
}

static int safe_memcmp(const void *s1, const void *s2, size_t n) {
  struct sigaction sa, old_segv, old_bus;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = scan_signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  sigaction(SIGSEGV, &sa, &old_segv);
  sigaction(SIGBUS, &sa, &old_bus);

  g_in_scan = 1;
  int result = -1;

  if (sigsetjmp(g_scan_jmp, 1) == 0) {
    result = memcmp(s1, s2, n);
    g_in_scan = 0;
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  sigaction(SIGBUS, &old_bus, NULL);

  return result;
}

static int pattern_match(const uint8_t *data, const uint8_t *pattern,
                         const char *mask, size_t length) {
  for (size_t i = 0; i < length; i++) {
    if (mask[i] == 'x' && data[i] != pattern[i]) {
      return 0;
    }
  }
  return 1;
}

uintptr_t scan_for_pattern(uintptr_t start, size_t size, const uint8_t *pattern,
                           const char *mask, size_t pattern_len) {
  if (!start || !size || !pattern || !mask || !pattern_len) {
    return 0;
  }

  struct sigaction sa, old_segv, old_bus;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = scan_signal_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGSEGV, &sa, &old_segv);
  sigaction(SIGBUS, &sa, &old_bus);

  uintptr_t result = 0;
  g_in_scan = 1;

  if (sigsetjmp(g_scan_jmp, 1) == 0) {
    const uint8_t *data = (const uint8_t *)start;
    size_t scan_size = size - pattern_len;

    for (size_t i = 0; i < scan_size; i++) {
      if (pattern_match(data + i, pattern, mask, pattern_len)) {
        result = start + i;
        break;
      }
    }
    g_in_scan = 0;
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  sigaction(SIGBUS, &old_bus, NULL);

  return result;
}

static const uint8_t PATTERN_GETTOP[] = {
    0x48, 0x8B, 0x47, 0x10, 0x48, 0x2B, 0x47, 0x08,
};
static const char MASK_GETTOP[] = "xxxx?xxx";

static const uint8_t PATTERN_SETTOP[] = {
    0x55, 0x48, 0x89, 0xE5, 0x48, 0x8B, 0x47, 0x08,
};
static const char MASK_SETTOP[] = "xxxxxxxx";

static const uint8_t PATTERN_PUSHSTRING[] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53,
    0x48, 0x89, 0xFB, 0x49, 0x89, 0xF6,
};
static const char MASK_PUSHSTRING[] = "xxxxxxxxxxxxxx";

static const uint8_t PATTERN_PCALL[] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41,
    0x56, 0x41, 0x55, 0x41, 0x54, 0x53,
};
static const char MASK_PCALL[] = "xxxxxxxxxxxxxxx";

static const uint8_t PATTERN_LOADBUFFER[] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56,
    0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xEC,
};
static const char MASK_LOADBUFFER[] = "xxxxxxxxxxxxxxxxxx";

typedef struct {
  const char *name;
  const uint8_t *pattern;
  const char *mask;
  size_t length;
  size_t api_offset;
} pattern_entry_t;

#define OFFSETOF(type, member) ((size_t)&((type *)0)->member)

static const pattern_entry_t PATTERNS[] = {
    {"lua_gettop", PATTERN_GETTOP, MASK_GETTOP, sizeof(PATTERN_GETTOP),
     OFFSETOF(luau_api_t, gettop)},
    {"lua_settop", PATTERN_SETTOP, MASK_SETTOP, sizeof(PATTERN_SETTOP),
     OFFSETOF(luau_api_t, settop)},
    {"lua_pushstring", PATTERN_PUSHSTRING, MASK_PUSHSTRING,
     sizeof(PATTERN_PUSHSTRING), OFFSETOF(luau_api_t, pushstring)},
    {"lua_pcall", PATTERN_PCALL, MASK_PCALL, sizeof(PATTERN_PCALL),
     OFFSETOF(luau_api_t, pcall)},
    {"luaL_loadbuffer", PATTERN_LOADBUFFER, MASK_LOADBUFFER,
     sizeof(PATTERN_LOADBUFFER), OFFSETOF(luau_api_t, loadbuffer)},
    {NULL, NULL, NULL, 0, 0}};

typedef struct {
  uintptr_t start;
  uintptr_t end;
  size_t size;
} code_region_t;

static int find_code_regions(code_region_t *regions, int max_regions) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  int count = 0;
  char line[512];

  while (fgets(line, sizeof(line), maps) && count < max_regions) {
    uintptr_t start, end;
    char perms[5];

    if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) >= 3) {

      if (perms[2] == 'x' && strstr(line, "/sober")) {
        regions[count].start = start;
        regions[count].end = end;
        regions[count].size = end - start;
        count++;
        log_debug("Found code region: 0x%lx - 0x%lx (%zu KB)\n", start, end,
                  (end - start) / 1024);
      }
    }
  }

  fclose(maps);
  return count;
}

uintptr_t scan_for_function(uintptr_t base, size_t size,
                            const func_pattern_t *pattern) {
  if (!pattern || !pattern->pattern || !pattern->mask) {
    return 0;
  }

  return scan_for_pattern(base, size, pattern->pattern, pattern->mask,
                          pattern->length);
}

int scan_and_resolve_functions(luau_api_t *api) {
  if (!api || !api->sober_base) {
    log_debug("Cannot scan: API or base not initialized\n");
    return -1;
  }

  code_region_t regions[16];
  int region_count = find_code_regions(regions, 16);

  if (region_count == 0) {
    log_debug("No code regions found to scan\n");
    return -1;
  }

  int resolved = 0;

  for (int p = 0; PATTERNS[p].name != NULL; p++) {
    const pattern_entry_t *pe = &PATTERNS[p];

    for (int r = 0; r < region_count; r++) {
      uintptr_t addr = scan_for_pattern(regions[r].start, regions[r].size,
                                        pe->pattern, pe->mask, pe->length);

      if (addr) {

        void **target = (void **)((uint8_t *)api + pe->api_offset);
        *target = (void *)addr;

        log_debug("Found %s at 0x%lx (offset 0x%lx)\n", pe->name, addr,
                  addr - api->sober_base);
        resolved++;
        break;
      }
    }
  }

  log_debug("Resolved %d/%d functions via pattern scanning\n", resolved,
            (int)(sizeof(PATTERNS) / sizeof(PATTERNS[0]) - 1));

  return resolved;
}

static const struct {
  uintptr_t start;
  uintptr_t end;
  const char *desc;
} OFFSET_RANGES[] = {{0x100000, 0x200000, "Core Lua/Luau functions"},
                     {0x180000, 0x190000, "Stack manipulation cluster"},
                     {0x120000, 0x130000, "Load/compile functions"},
                     {0x0F0000, 0x110000, "Error handling"},
                     {0x050000, 0x080000, "String/table ops"},
                     {0, 0, NULL}};

static const uint8_t PROLOGUE_PUSH_RBP[] = {0x55};
static const uint8_t PROLOGUE_FULL[] = {0x55, 0x48, 0x89, 0xE5};

int is_valid_function_prologue(uintptr_t addr) {
  struct sigaction sa, old_segv;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = scan_signal_handler;
  sigaction(SIGSEGV, &sa, &old_segv);

  int valid = 0;
  g_in_scan = 1;

  if (sigsetjmp(g_scan_jmp, 1) == 0) {
    const uint8_t *bytes = (const uint8_t *)addr;

    if (bytes[0] == 0x55) {
      valid = 1;

      if (bytes[1] == 0x48 && bytes[2] == 0x89 && bytes[3] == 0xE5) {
        valid = 2;
      }
    }

    else if (bytes[0] == 0x41 && (bytes[1] >= 0x54 && bytes[1] <= 0x57)) {
      valid = 1;
    }

    else if (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) {
      valid = 1;
    }

    else if (bytes[0] == 0xF3 && bytes[1] == 0x0F && bytes[2] == 0x1E &&
             bytes[3] == 0xFA) {
      valid = 1;
    }

    g_in_scan = 0;
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  return valid;
}

typedef struct {
  uintptr_t addr;
  uintptr_t offset;
  int confidence;
} found_func_t;

#define MAX_FOUND_FUNCS 256

int scan_range_for_functions(uintptr_t base, uintptr_t start_offset,
                             uintptr_t end_offset, found_func_t *results,
                             int max_results) {
  if (!base || !results || start_offset >= end_offset)
    return 0;

  struct sigaction sa, old_segv;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = scan_signal_handler;
  sigaction(SIGSEGV, &sa, &old_segv);

  int count = 0;
  g_in_scan = 1;

  log_debug("Scanning range 0x%lx - 0x%lx for function prologues...\n",
            start_offset, end_offset);

  if (sigsetjmp(g_scan_jmp, 1) == 0) {

    for (uintptr_t off = start_offset; off < end_offset && count < max_results;
         off += 16) {
      uintptr_t addr = base + off;
      const uint8_t *bytes = (const uint8_t *)addr;

      if (bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x89 &&
          bytes[3] == 0xE5) {
        results[count].addr = addr;
        results[count].offset = off;
        results[count].confidence = 2;
        count++;
      }
    }
    g_in_scan = 0;
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  log_debug("Found %d potential functions in range\n", count);
  return count;
}

int safe_function_discovery(luau_api_t *api) {
  if (!api || !api->sober_base) {
    log_debug("Cannot probe: API not initialized\n");
    return 0;
  }

  log_debug("=== SAFE FUNCTION DISCOVERY ===\n");
  log_debug("Sober base: 0x%lx\n", api->sober_base);

  static found_func_t functions[MAX_FOUND_FUNCS];
  int total_found = 0;

  for (int r = 0;
       OFFSET_RANGES[r].desc != NULL && total_found < MAX_FOUND_FUNCS; r++) {
    log_debug("Scanning %s (0x%lx - 0x%lx)...\n", OFFSET_RANGES[r].desc,
              OFFSET_RANGES[r].start, OFFSET_RANGES[r].end);

    int found = scan_range_for_functions(
        api->sober_base, OFFSET_RANGES[r].start, OFFSET_RANGES[r].end,
        &functions[total_found], MAX_FOUND_FUNCS - total_found);

    total_found += found;
  }

  log_debug("\n=== PROMISING CANDIDATES ===\n");
  int promising = 0;

  for (int i = 0; i < total_found; i++) {
    uintptr_t off = functions[i].offset;

    if ((off >= 0x180000 && off <= 0x190000) ||
        (off >= 0x120000 && off <= 0x130000) ||
        (off >= 0x100000 && off <= 0x115000)) {

      log_debug("CANDIDATE: offset=0x%lx addr=0x%lx confidence=%d\n", off,
                functions[i].addr, functions[i].confidence);
      promising++;
    }
  }

  log_debug("\n=== LOOKING FOR FUNCTION CLUSTERS ===\n");

  for (int i = 0; i < total_found - 2; i++) {
    uintptr_t off1 = functions[i].offset;
    uintptr_t off2 = functions[i + 1].offset;
    uintptr_t off3 = functions[i + 2].offset;

    if ((off2 - off1 >= 16 && off2 - off1 <= 64) &&
        (off3 - off2 >= 16 && off3 - off2 <= 64)) {
      log_debug("CLUSTER at offsets: 0x%lx, 0x%lx, 0x%lx\n", off1, off2, off3);
    }
  }

  log_debug("=== Discovery complete: %d total, %d promising ===\n", total_found,
            promising);
  return total_found;
}

int probe_candidate_offsets(luau_api_t *api,
                            int (*test_func)(void *, lua_State *,
                                             const char *)) {
  (void)test_func;
  return safe_function_discovery(api);
}

static const char *LUA_STRINGS[] = {"attempt to call a",
                                    "attempt to index a",
                                    "stack overflow",
                                    "C stack overflow",
                                    "cannot resume",
                                    "string.format",
                                    "loadstring",
                                    "@",
                                    "function",
                                    "nil",
                                    "table",
                                    "getmetatable",
                                    "setmetatable",
                                    "print",
                                    "error",
                                    "pcall",
                                    "xpcall",
                                    "tostring",
                                    "tonumber",
                                    "lua_State",
                                    "LUAU_",
                                    NULL};

int scan_for_lua_strings(uintptr_t base, size_t size) {
  if (!base || !size)
    return 0;

  log_debug("Scanning for Lua strings in 0x%lx - 0x%lx\n", base, base + size);

  struct sigaction sa, old_segv;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = scan_signal_handler;
  sigaction(SIGSEGV, &sa, &old_segv);

  int found = 0;
  g_in_scan = 1;

  if (sigsetjmp(g_scan_jmp, 1) == 0) {
    for (int s = 0; LUA_STRINGS[s] != NULL; s++) {
      const char *target = LUA_STRINGS[s];
      size_t str_len = strlen(target);

      const char *data = (const char *)base;
      for (size_t i = 0; i < size - str_len; i++) {
        if (memcmp(data + i, target, str_len) == 0) {
          log_debug("Found '%s' at offset 0x%lx\n", target, (uintptr_t)i);
          found++;
          break;
        }
      }
    }
    g_in_scan = 0;
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  log_debug("Found %d Lua-related strings\n", found);

  return found;
}

uintptr_t find_function_by_string_ref(uintptr_t base, size_t size,
                                      const char *target_string) {
  if (!base || !size || !target_string) {
    return 0;
  }

  size_t str_len = strlen(target_string);

  struct sigaction sa, old_segv;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = scan_signal_handler;
  sigaction(SIGSEGV, &sa, &old_segv);

  uintptr_t str_addr = 0;
  g_in_scan = 1;

  if (sigsetjmp(g_scan_jmp, 1) == 0) {
    const char *data = (const char *)base;
    for (size_t i = 0; i < size - str_len; i++) {
      if (memcmp(data + i, target_string, str_len) == 0) {
        str_addr = base + i;
        log_debug("Found string '%s' at 0x%lx\n", target_string, str_addr);
        break;
      }
    }
    g_in_scan = 0;
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  return str_addr;
}

typedef struct {
  uintptr_t lea_addr;
  uintptr_t func_start;
} xref_result_t;

#define MAX_XREFS 32

int find_xrefs_to_address(uintptr_t code_start, size_t code_size,
                          uintptr_t target_addr, xref_result_t *results,
                          int max_results) {
  if (!code_start || !code_size || !target_addr || !results)
    return 0;

  struct sigaction sa, old_segv;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = scan_signal_handler;
  sigaction(SIGSEGV, &sa, &old_segv);

  int count = 0;
  g_in_scan = 1;

  if (sigsetjmp(g_scan_jmp, 1) == 0) {
    const uint8_t *code = (const uint8_t *)code_start;

    for (size_t i = 0; i < code_size - 7 && count < max_results; i++) {

      if (code[i] == 0x48 && code[i + 1] == 0x8D) {
        uint8_t modrm = code[i + 2];

        if ((modrm & 0xC7) == 0x05) {

          int32_t disp = *(int32_t *)&code[i + 3];

          uintptr_t lea_addr = code_start + i;
          uintptr_t ref_target = lea_addr + 7 + disp;

          if (ref_target == target_addr) {
            results[count].lea_addr = lea_addr;

            uintptr_t func_start = 0;
            for (int j = 0; j < 512 && i >= (size_t)j; j++) {

              if (code[i - j] == 0x55 && i - j + 3 < code_size &&
                  code[i - j + 1] == 0x48 && code[i - j + 2] == 0x89 &&
                  code[i - j + 3] == 0xE5) {
                func_start = code_start + i - j;
                break;
              }

              if (code[i - j] == 0x55 && j > 4) {
                func_start = code_start + i - j;
                break;
              }
            }
            results[count].func_start = func_start;
            count++;

            log_debug("XREF: LEA at 0x%lx -> 0x%lx (func @ 0x%lx)\n", lea_addr,
                      ref_target, func_start);
          }
        }
      }
    }
    g_in_scan = 0;
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  return count;
}

int scan_all_strings(luau_api_t *api) {
  if (!api || !api->sober_base)
    return 0;

  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  char line[512];
  int total_strings = 0;

  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start, end;
    char perms[5];

    if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) >= 3) {

      if (perms[0] == 'r' && strstr(line, "/sober")) {
        total_strings += scan_for_lua_strings(start, end - start);
      }
    }
  }

  fclose(maps);
  return total_strings;
}

int aggressive_function_discovery(luau_api_t *api) {
  if (!api || !api->sober_base)
    return 0;

  log_debug("=== AGGRESSIVE FUNCTION DISCOVERY ===\n");

  code_region_t regions[16];
  int region_count = find_code_regions(regions, 16);
  if (region_count == 0) {
    log_debug("No code regions found\n");
    return 0;
  }

  uintptr_t code_start = regions[0].start;
  size_t code_size = regions[0].size;

  struct {
    const char *str;
    const char *likely_func;
  } markers[] = {{"attempt to call a", "lua_call/pcall error handler"},
                 {"attempt to index a", "gettable/settable error"},
                 {"stack overflow", "luaD_throw or checkstack"},
                 {"cannot resume", "lua_resume"},
                 {"bad argument", "luaL_argerror"},
                 {NULL, NULL}};

  int functions_found = 0;
  xref_result_t xrefs[MAX_XREFS];

  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 0;

  char line[512];
  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start, end;
    char perms[5];

    if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) >= 3) {
      if (perms[0] != 'r')
        continue;
      if (!strstr(line, "/sober") && !strstr(line, "heap") &&
          !strstr(line, "[anon"))
        continue;

      size_t size = end - start;
      if (size > 100 * 1024 * 1024)
        continue;

      for (int m = 0; markers[m].str != NULL; m++) {
        uintptr_t str_addr =
            find_function_by_string_ref(start, size, markers[m].str);

        if (str_addr) {
          log_debug("Found marker '%s' for %s\n", markers[m].str,
                    markers[m].likely_func);

          int xref_count = find_xrefs_to_address(code_start, code_size,
                                                 str_addr, xrefs, MAX_XREFS);

          if (xref_count > 0) {
            log_debug("  Found %d xrefs to this string\n", xref_count);
            for (int x = 0; x < xref_count; x++) {
              log_debug(
                  "    Xref %d: LEA at 0x%lx, func at 0x%lx (offset 0x%lx)\n",
                  x, xrefs[x].lea_addr, xrefs[x].func_start,
                  xrefs[x].func_start ? xrefs[x].func_start - api->sober_base
                                      : 0);
            }
            functions_found += xref_count;
          }
        }
      }
    }
  }

  fclose(maps);
  log_debug("=== Discovery complete: %d potential functions found ===\n",
            functions_found);
  return functions_found;
}
