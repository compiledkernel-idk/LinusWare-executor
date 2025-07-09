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

unsigned long get_base_address(pid_t pid, const char *module) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }

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
    if (!handle) {
        return 0;
    }

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

        if (strstr(link_target, target_name)) {
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    return -1;
}
// should work better for now
int inject(pid_t pid, const char* library_path) {
    unsigned long remote_libc_base = get_base_address(pid, "libc.so.6");
    if (remote_libc_base == 0) {
        return 0;
    }

    unsigned long remote_libdl_base = get_base_address(pid, "libdl.so.2");
    if (remote_libdl_base == 0) {
        return 0;
    }

    unsigned long mmap_offset = get_local_offset("libc.so.6", "mmap");
    if (mmap_offset == 0) {
        return 0;
    }
    unsigned long remote_mmap_addr = remote_libc_base + mmap_offset;

    unsigned long dlopen_offset = get_local_offset("libdl.so.2", "dlopen");
    if (dlopen_offset == 0) {
        return 0;
    }
    unsigned long remote_dlopen_addr = remote_libdl_base + dlopen_offset;

    size_t library_path_len = strlen(library_path) + 1;
    size_t total_alloc_size = (library_path_len + 0xFFF + 0x1000) & ~0xFFF;

    void* remote_mem_placeholder = (void*)0x000000; // Placeholder

    if (remote_mem_placeholder == NULL || remote_mem_placeholder == MAP_FAILED) {
        return 0;
    }

    struct iovec local_path_io = { (void*)library_path, library_path_len };
    struct iovec remote_path_io = { remote_mem_placeholder, library_path_len };
    if (process_vm_writev(pid, &local_path_io, 1, &remote_path_io, 1, 0) == -1) {
        return 0;
    }

    void* remote_shellcode_addr = remote_mem_placeholder + library_path_len; // mmap and dlopen

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
