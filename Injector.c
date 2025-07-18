#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/user.h>

unsigned long get_base_address(pid_t pid, const char *module) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, module)) {
            unsigned long base_addr;
            sscanf(line, "%lx-%*lx", &base_addr);
            fclose(f);
            return base_addr;
        }
    }
    fclose(f);
    return 0;
}

unsigned long get_local_offset(const char *lib_path, const char *symbol) {
    void *handle = dlopen(lib_path, RTLD_LAZY);
    if (!handle) return 0;

    void *symbol_addr = dlsym(handle, symbol);
    if (!symbol_addr) {
        dlclose(handle);
        return 0;
    }

    unsigned long local_base = get_base_address(getpid(), lib_path);
    if (local_base == 0) {
        dlclose(handle);
        return 0;
    }
    
    unsigned long offset = (unsigned long)symbol_addr - local_base;
    dlclose(handle);
    return offset;
}

pid_t find_pid(const char *target_name) {
    DIR* d = opendir("/proc");
    if (!d) return -1;

    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;

        pid_t pid = atoi(e->d_name);
        if (pid <= 0) continue;

        char exe_path[PATH_MAX];
        char link_target[PATH_MAX];
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

        ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
        if (len == -1) continue;
        link_target[len] = '\0';

        if (strstr(link_target, target_name)) {
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    return -1;
}

int ptrace_write_data(pid_t pid, unsigned long addr, void *data, size_t size) {
    unsigned long i;
    long word;
    for (i = 0; i < size; i += sizeof(long)) {
        memcpy(&word, (char*)data + i, (size - i < sizeof(long)) ? (size - i) : sizeof(long));
        ptrace(PTRACE_POKEDATA, pid, addr + i, word);
    }
    return 0;
}

int inject(pid_t pid, const char* library_path) {
    struct user_regs_struct old_regs, regs;
    int status;

    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);
    memcpy(&regs, &old_regs, sizeof(struct user_regs_struct));

    unsigned long remote_libc_base = get_base_address(pid, "libc.so.6");
    unsigned long remote_libdl_base = get_base_address(pid, "libdl.so.2");

    unsigned long mmap_offset = get_local_offset("libc.so.6", "mmap");
    unsigned long remote_mmap_addr = remote_libc_base + mmap_offset;

    unsigned long dlopen_offset = get_local_offset("libdl.so.2", "dlopen");
    unsigned long remote_dlopen_addr = remote_libdl_base + dlopen_offset;

    size_t library_path_len = strlen(library_path) + 1;
    size_t alloc_size = (library_path_len + 0xFFF) & ~0xFFF;

    regs.rip = remote_mmap_addr;
    regs.rdi = 0; // let kernel choose
    regs.rsi = alloc_size;
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.rcx = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8 = -1;
    regs.r9 = 0;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    unsigned long remote_allocated_mem = regs.rax;

    unsigned long remote_lib_path_addr = remote_allocated_mem;
    ptrace_write_data(pid, remote_lib_path_addr, (void*)library_path, library_path_len);

    regs.rip = remote_dlopen_addr;
    regs.rdi = remote_lib_path_addr; // filename
    regs.rsi = RTLD_NOW; // flags

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    unsigned long remote_lib_handle = regs.rax; // Not used

    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 1;
}

int main(int argc, char *argv[]) {
    const char* target_lib_path = "./atingle.so";
    if (argc > 1) {
        target_lib_path = argv[1];
    }

    pid_t game_pid = find_pid("sober");
    if (game_pid == -1) {
        return EXIT_FAILURE;
    }

    if (!inject(game_pid, target_lib_path)) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
