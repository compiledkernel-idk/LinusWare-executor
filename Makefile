# Filename: Makefile
#
# Copyright (c) 2026 compiledkernel-idk
# All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, distribution, or use of this file,
# via any medium, is strictly prohibited.

# Sirracha Executor Makefile

# Sirracha Executor Makefile (Qt UI)

CC = gcc
CXX = g++
CFLAGS = -Wall -O3 -fPIC -ffunction-sections -fdata-sections -s
LDFLAGS = -Wl,--gc-sections,--strip-all,-z,now,-z,relro
PTHREAD = -lpthread
DL = -ldl

.PHONY: all clean install run qt-ui

all: sirracha_exec.so injector qt-ui
	@cp -f sirracha_exec.so /dev/shm/sirracha.so
	@chmod 777 /dev/shm/sirracha.so
	@strip --strip-all sirracha_exec.so 2>/dev/null || true
	@echo "Encrypting binary..."
	@upx --best --ultra-brute sirracha_exec.so >/dev/null 2>&1 || upx -9 sirracha_exec.so >/dev/null 2>&1 || true
	@echo ""
	@echo "Build complete. Run: make run"
	@echo ""

# The main injection library (BACKEND)
sirracha_exec.so: injected_lib.c pattern_scanner.c roblox_state.c simd_utils.s heavy_math.s luau_api.h roblox_offsets.h
	$(CC) $(CFLAGS) -shared -o $@ injected_lib.c pattern_scanner.c roblox_state.c simd_utils.s heavy_math.s $(DL) $(PTHREAD)
	@strip --strip-unneeded $@ 2>/dev/null || true

# The CLI/helper injector (OPTIONAL usage)
injector: Injector.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ Injector.c $(DL)

# Qt UI build
qt-ui: sirracha-qt

sirracha-qt: SirrachaQt.cpp
	@echo "Building Qt UI..."
	@mkdir -p build
	@cd build && cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1 && make -j$(nproc) 2>&1 | tail -5
	@cp build/sirracha-qt . 2>/dev/null || echo "Qt build failed - install Qt5/Qt6 dev packages"

run: all
	@echo "Launching Sirracha Qt UI..."
	@./sirracha-qt 2>/dev/null || ./sirracha-ui/run.sh

# Legacy Electron UI
run-electron:
	@./sirracha-ui/run.sh

clean:
	rm -f sirracha_exec.so injector sober_test_inject.so sirracha-qt
	rm -rf build
	rm -f /dev/shm/sirracha*.so
	@echo "Clean"

logs:
	@tail -f /tmp/sirracha_debug.log 2>/dev/null || tail -f /dev/shm/sirracha_debug.log 2>/dev/null || echo "No log found"
