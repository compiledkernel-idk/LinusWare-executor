#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <limits.h>
#include <errno.h>
#include "atingle.h"

void print_str(const char* message) {
    unsigned long chat_function_absolute_addr = ROBLOX_PLAYER_MODULE_BASE_ADDRESS + GAME_SEND_CHAT_MESSAGE_FUNCTION_OFFSET;
    GameSendChatFunc send_chat_func = (GameSendChatFunc)chat_function_absolute_addr;
    if (send_chat_func) {
        send_chat_func(message, 0);
    } else {
        fprintf(stderr, "Failed to locate chat function at address: 0x%lx\n", chat_function_absolute_addr);
    }
}
__attribute__((constructor))
void init_lib() {
    print_str("Atingle loaded!");
}
