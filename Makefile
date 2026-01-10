# Filename: Makefile
#
# Copyright (c) 2026 compiledkernel-idk
# All Rights Reserved.

# Sirracha Executor Makefile (Qt UI)

CC = gcc
CXX = g++
CFLAGS = -Wall -O3 -fPIC -ffunction-sections -fdata-sections -s
LDFLAGS = -Wl,--gc-sections,--strip-all,-z,now,-z,relro
PTHREAD = -lpthread
DL = -ldl

# Source directories
SRC_CORE = src/core
SRC_ASM = src/asm
SRC_UI = src/ui

.PHONY: all clean run qt-ui logs

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
sirracha_exec.so: $(SRC_CORE)/injected_lib.c $(SRC_CORE)/pattern_scanner.c $(SRC_CORE)/roblox_state.c $(SRC_ASM)/simd_utils.s $(SRC_ASM)/heavy_math.s
	$(CC) $(CFLAGS) -I$(SRC_CORE) -shared -o $@ \
		$(SRC_CORE)/injected_lib.c \
		$(SRC_CORE)/pattern_scanner.c \
		$(SRC_CORE)/roblox_state.c \
		$(SRC_ASM)/simd_utils.s \
		$(SRC_ASM)/heavy_math.s \
		$(DL) $(PTHREAD)
	@strip --strip-unneeded $@ 2>/dev/null || true

# The CLI/helper injector
injector: src/Injector.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ src/Injector.c $(DL)

# Qt UI build
qt-ui: sirracha-qt

sirracha-qt: $(SRC_UI)/SirrachaQt.cpp
	@echo "Building Qt UI..."
	@mkdir -p build
	@cd build && cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1 && make -j$$(nproc) 2>&1 | tail -5
	@cp build/sirracha-qt . 2>/dev/null || echo "Qt build failed - install Qt5/Qt6 dev packages"

run: all
	@echo "Launching Sirracha..."
	@./sirracha-qt

clean:
	rm -f sirracha_exec.so injector sirracha-qt
	rm -rf build
	rm -f /dev/shm/sirracha*.so
	@echo "Clean"

logs:
	@tail -f /tmp/sirracha_debug.log 2>/dev/null || tail -f /dev/shm/sirracha_debug.log 2>/dev/null || echo "No log found"

# Inject into running Sober
inject:
	@./scripts/inject_sober.sh
