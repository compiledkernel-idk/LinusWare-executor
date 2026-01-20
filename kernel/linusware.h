/*
 * LinusWare Kernel Module - Shared Header
 *
 * Defines structures and IOCTLs shared between kernel and userspace
 */

#ifndef _LINUSWARE_H
#define _LINUSWARE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define DEVICE_PATH "/dev/linusware"

/* IOCTL magic number */
#define LINUSWARE_MAGIC 'L'

/* Target info - returned when querying detected targets */
struct lw_target_info {
  __s32 pid;
  __u64 base_addr;
  __u64 size;
  char comm[16];
  __s32 ready;
};

/* Inject command - for injecting shellcode */
struct lw_inject_cmd {
  __s32 pid;
  __u64 addr;         /* Where to inject */
  __u64 size;         /* Size of payload */
  char payload[4096]; /* Shellcode/data to inject */
};

/* Register manipulation command */
struct lw_regs_cmd {
  __s32 pid;
  /* We use a large buffer to hold pt_regs to avoid abi issues */
  /* Userspace needs to cast this to struct user_regs_struct equivalent */
  char regs[512];
};

/* IOCTL commands */
#define LINUSWARE_GET_TARGET _IOR(LINUSWARE_MAGIC, 1, struct lw_target_info)
#define LINUSWARE_INJECT _IOWR(LINUSWARE_MAGIC, 2, struct lw_inject_cmd)
#define LINUSWARE_SET_LIB_PATH _IOW(LINUSWARE_MAGIC, 3, char[256])
#define LINUSWARE_GET_REGS _IOWR(LINUSWARE_MAGIC, 4, struct lw_regs_cmd)
#define LINUSWARE_SET_REGS _IOW(LINUSWARE_MAGIC, 5, struct lw_regs_cmd)
#define LINUSWARE_MPROTECT _IOW(LINUSWARE_MAGIC, 6, struct lw_mprotect_cmd)

/* Mprotect command */
struct lw_mprotect_cmd {
  pid_t pid;
  unsigned long addr;
  unsigned long len;
  int prot; /* READ=1, WRITE=2, EXEC=4 */
};

#endif /* _LINUSWARE_H */
