# Filename: Makefile
#
# Copyright (c) 2026 compiledkernel-idk
# All Rights Reserved.
#
# This software is proprietary and confidential. 
# Unauthorized copying, distribution, or use of this file, 
# via any medium, is strictly prohibited.

# Sirracha Executor Makefile

# Sirracha Executor Makefile (Electron UI)

CC = gcc
CFLAGS = -Wall -O3 -fPIC -ffunction-sections -fdata-sections -s
LDFLAGS = -Wl,--gc-sections,--strip-all,-z,now,-z,relro
PTHREAD = -lpthread
DL = -ldl
UI_DIR = sirracha-ui

.PHONY: all clean install run ui-dep

all: sirracha_exec.so injector ui-dep
	@cp -f sirracha_exec.so /dev/shm/sirracha.so
	@chmod 777 /dev/shm/sirracha.so
	@strip --strip-all sirracha_exec.so 2>/dev/null || true
	@echo "Encrypting binary..."
	@upx --best --ultra-brute sirracha_exec.so >/dev/null 2>&1 || upx -9 sirracha_exec.so >/dev/null 2>&1 || true
	@echo ""
	@echo "Build complete. Run: make run"
	@echo ""

# The main injection library (BACKEND)
sirracha_exec.so: injected_lib.c pattern_scanner.c roblox_state.c luau_api.h roblox_offsets.h
	$(CC) $(CFLAGS) -shared -o $@ injected_lib.c pattern_scanner.c roblox_state.c $(DL) $(PTHREAD)
	@strip --strip-unneeded $@ 2>/dev/null || true

# The CLI/helper injector (OPTIONAL usage)
injector: Injector.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ Injector.c $(DL)

# Install UI dependencies
ui-dep:
	@if [ ! -d "$(UI_DIR)/node_modules" ]; then \
		echo "Installing UI dependencies..."; \
		cd $(UI_DIR) && npm install; \
	fi

run: all
	@echo "Launching Sirracha UI..."
	@./$(UI_DIR)/run.sh

clean:
	rm -f sirracha_exec.so injector sober_test_inject.so
	rm -f /dev/shm/sirracha*.so
	@echo "Clean"

logs:
	@tail -f /dev/shm/sirracha_debug.log 2>/dev/null || echo "No log found"
