#ifndef PATTERN_SCANNER_H
#define PATTERN_SCANNER_H

#include "luau_api.h"
#include <stdint.h>

void log_debug(const char *fmt, ...);

int aggressive_function_discovery(luau_api_t *api);
int vtable_hunter(luau_api_t *api);
int relative_jump_table_hunter(luau_api_t *api);
int scan_all_strings(luau_api_t *api);

uintptr_t scan_range_for_functions(uintptr_t start, uintptr_t end,
                                   luau_api_t *api);
int scan_and_resolve_functions(luau_api_t *api);
int safe_function_discovery(luau_api_t *api);

#endif
