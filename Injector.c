#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <sys/user.h>
#include <errno.h>
#include <limits.h>

unsigned long get_module_base_address(pid_t target_pid, const char *module_name) {
    char maps_path[PATH_MAX];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", target_pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) {
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, module_name)) {
            unsigned long base_addr;
            sscanf(line, "%lx-%*lx", &base_addr);
            fclose(f);
            return base_addr;
        }
    }
    fclose(f);
    return 0;
}

unsigned long get_symbol_offset_local(const char *local_lib_path, const char *symbol_name) {
    void *handle = dlopen(local_lib_path, RTLD_LAZY);
    if (!handle) {
        return 0;
    }

    void *symbol_addr = dlsym(handle, symbol_name);
    if (!symbol_addr) {
        dlclose(handle);
        return 0;
    }

    unsigned long local_lib_base = get_module_base_address(getpid(), local_lib_path);
    if (local_lib_base == 0) {
        dlclose(handle);
        return 0;
    }
    
    unsigned long offset = (unsigned long)symbol_addr - local_lib_base;
    dlclose(handle);
    return offset;
}

pid_t find_target_process_pid() {
    DIR* d = opendir("/proc");
    if (!d) {
        return -1;
    }

    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;

        pid_t pid = atoi(e->d_name);
        if (pid <= 0) continue;

        char exe_path[PATH_MAX];
        char link_target[PATH_MAX];
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

        ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
        if (len == -1) {
            continue;
        }
        link_target[len] = '\0';

        if (strstr(link_target, "sober")) {
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    return -1;
}

int inject_shared_library(pid_t target_pid, const char* library_path) {
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        return 0;
    }
    waitpid(target_pid, NULL, 0);

    struct user_regs_struct regs, original_regs;
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &original_regs) == -1) {
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }
    memcpy(&regs, &original_regs, sizeof(regs));

    unsigned long remote_libc_base = get_module_base_address(target_pid, "libc.so.6");
    if (remote_libc_base == 0) {
        ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }

    unsigned long remote_libdl_base = get_module_base_address(target_pid, "libdl.so.2");
    if (remote_libdl_base == 0) {
        ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }

    unsigned long mmap_offset = get_symbol_offset_local("libc.so.6", "mmap");
    if (mmap_offset == 0) {
        ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }
    unsigned long remote_mmap_addr = remote_libc_base + mmap_offset;

    unsigned long dlopen_offset = get_symbol_offset_local("libdl.so.2", "dlopen");
    if (dlopen_offset == 0) {
        ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }
    unsigned long remote_dlopen_addr = remote_libdl_base + dlopen_offset;

    size_t library_path_len = strlen(library_path) + 1;
    size_t total_alloc_size = (library_path_len + 0xFFF) & ~0xFFF;

    regs.rdi = 0;
    regs.rsi = total_alloc_size;
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8 = -1;
    regs.r9 = 0;
    regs.rip = remote_mmap_addr;

    if (ptrace(PTRACE_SETREGS, target_pid, NULL, &regs) == -1) {
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }

    if (ptrace(PTRACE_CONT, target_pid, NULL, NULL) == -1) {
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }
    waitpid(target_pid, NULL, 0);

    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == -1) {
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }
    void* remote_allocated_mem = (void*)regs.rax;
    if (remote_allocated_mem == MAP_FAILED) {
        ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }

    struct iovec local_lib_path_io = { (void*)library_path, library_path_len };
    struct iovec remote_lib_path_io = { remote_allocated_mem, library_path_len };
    if (process_vm_writev(target_pid, &local_lib_path_io, 1, &remote_lib_path_io, 1, 0) == -1) {
        ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }

    struct user_regs_struct dlopen_regs = original_regs;
    dlopen_regs.rdi = (unsigned long)remote_allocated_mem;
    dlopen_regs.rsi = RTLD_NOW | RTLD_GLOBAL;
    dlopen_regs.rip = remote_dlopen_addr;

    if (ptrace(PTRACE_SETREGS, target_pid, NULL, &dlopen_regs) == -1) {
        ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }

    if (ptrace(PTRACE_CONT, target_pid, NULL, NULL) == -1) {
        ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }
    waitpid(target_pid, NULL, 0);

    if (ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs) == -1) {
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }

    if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1) {
        return 0;
    }

    return 1;
}

int main() {
    const char* target_shared_library_path = "./atingle.so";
    
    pid_t process_pid = find_target_process_pid();
    if (process_pid == -1) {
        return EXIT_FAILURE;
    }

    if (!inject_shared_library(process_pid, target_shared_library_path)) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
