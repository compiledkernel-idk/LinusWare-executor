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

pid_t findSoberPID() {
    DIR* d = opendir("/proc");
    if (!d) return -1;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;
        pid_t pid = atoi(e->d_name);
        if (pid <= 0) continue;

        char buf[512];
        snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
        FILE* f = fopen(buf, "r");
        if (!f) continue;
        fread(buf, 1, sizeof(buf), f);
        fclose(f);
        if (strstr(buf, "sober")) {
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    return -1;
}

int injectSharedLib(pid_t pid, const char* soPath) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) return 0;
    waitpid(pid, NULL, 0);

    size_t len = strlen(soPath) + 1;

    void* handle = dlopen("libc.so.6", RTLD_LAZY);
    void* mmapAddr = dlsym(handle, "mmap");
    dlclose(handle);
    if (!mmapAddr) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    struct user_regs_struct regs, backup;
    ptrace(PTRACE_GETREGS, pid, NULL, &backup);
    regs = backup;

    regs.rdi = 0;
    regs.rsi = (len + 0x1000) & ~0xFFF;
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE;
    regs.r8 = -1;
    regs.r9 = 0;
    regs.rax = (unsigned long)mmapAddr;
    regs.rip = (unsigned long)mmapAddr;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    void* remoteMem = (void*)regs.rax;

    struct iovec local = { (void*)soPath, len };
    struct iovec remote = { remoteMem, len };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    handle = dlopen("libdl.so.2", RTLD_LAZY);
    void* dlopenAddr = dlsym(handle, "dlopen");
    dlclose(handle);
    if (!dlopenAddr) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    regs = backup;
    regs.rdi = (unsigned long)remoteMem;
    regs.rsi = RTLD_NOW | RTLD_GLOBAL;
    regs.rax = (unsigned long)dlopenAddr;
    regs.rip = (unsigned long)dlopenAddr;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    ptrace(PTRACE_SETREGS, pid, NULL, &backup);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
}

int main() {
    const char* test_so_path = "./sober_test_inject.so";
    pid_t pid = findSoberPID();
    if (pid == -1) return EXIT_FAILURE;
    if (!injectSharedLib(pid, test_so_path)) return EXIT_FAILURE;
    printf("Injected %s into org.vinegarhq.Sober (PID %d)\n", test_so_path, pid);
    return EXIT_SUCCESS;
}
