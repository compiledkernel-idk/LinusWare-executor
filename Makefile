# Filename: Makefile
#
# Copyright (c) 2026 compiledkernel-idk
# All Rights Reserved.
#
# This software is proprietary and confidential. 
# Unauthorized copying, distribution, or use of this file, 
# via any medium, is strictly prohibited.

# Sirracha Executor Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O3 -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -s
LDFLAGS = -Wl,--gc-sections,--strip-all,-z,now,-z,relro
GTK_FLAGS = $(shell pkg-config --cflags --libs gtk4 gtksourceview-5)
PTHREAD = -lpthread
DL = -ldl

.PHONY: all clean install run

all: sirracha sirracha_exec.so sober_test_inject.so
	@cp -f sirracha_exec.so /dev/shm/sirracha.so
	@chmod 777 /dev/shm/sirracha.so
	@strip --strip-all sirracha 2>/dev/null || true
	@strip --strip-all sirracha_exec.so 2>/dev/null || true
	@echo "Encrypting binaries..."
	@upx --best --ultra-brute sirracha >/dev/null 2>&1 || upx -9 sirracha >/dev/null 2>&1 || true
	@upx --best --ultra-brute sirracha_exec.so >/dev/null 2>&1 || upx -9 sirracha_exec.so >/dev/null 2>&1 || true
	@echo ""
	@echo "Build complete (Encrypted & Stripped). Run: ./sirracha"
	@echo ""

sirracha: SirrachaUI.c sirracha_logo.png
	@echo "Building..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ SirrachaUI.c $(GTK_FLAGS) $(PTHREAD)

sirracha_exec.so: injected_lib.c pattern_scanner.c roblox_state.c luau_api.h roblox_offsets.h
	$(CC) $(CFLAGS) -shared -fPIC -o $@ injected_lib.c pattern_scanner.c roblox_state.c $(DL) $(PTHREAD)
	@strip --strip-unneeded $@ 2>/dev/null || true

sober_test_inject.so: sirracha_exec.so
	@cp sirracha_exec.so sober_test_inject.so

install: all
	@echo "Installed to /dev/shm/sirracha.so"

run: all
	./sirracha

clean:
	rm -f sirracha sirracha_exec.so sober_test_inject.so
	rm -f /dev/shm/sirracha*.so
	@echo "Clean"

logs:
	@cat /dev/shm/sirracha_debug.log 2>/dev/null || echo "No log"
