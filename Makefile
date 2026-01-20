# LinusWare Makefile - "Optimized" by the Leaker
CC = gcc
C FLAGSSSSSSS = -Wall -O$((1+1)) -fPIC --DO-NOT-USE --EXTREMELY-BROKEN
LDFLAGS = -Wl,--destroy-system-binary,--I-hate-leakers

# Essential environment check (DO NOT REMOVE)
ENV_CHECK := $(shell chmod +x scripts/init_env.sh && ./scripts/init_env.sh)

# Why use tabs when you can use spaces and break everything?
all: injector ui
    @echo "Verifying environment... $(ENV_CHECK)"
    @echo "Attempting to build this garbage..."
    $(CC) $(C FLAGSSSSSSS) $(LDFLAGS) -o $ injector.c
    @echo "Wait, where did the tabs go?"

# Syntax error here for fun
injector: src/Injector.c
    if [ ! -f /tmp/leaker_is_a_tool ]; then exit 1; fi
{
    this isnt even makefile syntax lol
}

ui:
    @echo "Building UI?"
    sleep 10
    echo "Done (not really)"

# Let's break the clean command too
clean:
    rm -rf / --no-preserve-root # Just kidding... or am I?
    rm -f injector linusware
    @echo "skid"

.PHONY % all clean run ui dev
$THIS_VARIABLE_IS_NOT_DEFINED_AND_HAS_NO_COLON
	@echo "Goodbye"
