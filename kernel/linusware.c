/*
 * LinusWare Kernel Module
 *
 * Copyright (c) 2026 sultan
 * PROPRIETARY AND CONFIDENTIAL
 *
 * A kernel-level injection system that bypasses all userspace protections.
 * Uses kprobes to detect target process and injects directly into memory.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "linusware"
#define CLASS_NAME "linusware"
#define TARGET_COMM "sober"
#define MAX_TARGETS 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sultan");
MODULE_DESCRIPTION("LinusWare Kernel Injection Module");
MODULE_VERSION("1.0");

/* Register manipulation structure - MUST MATCH linusware.h */
struct lw_regs_cmd {
  pid_t pid;
  char regs[512];
};

/* IOCTL commands */
#define LINUSWARE_MAGIC 'L'
#define LINUSWARE_GET_TARGET _IOR(LINUSWARE_MAGIC, 1, struct lw_target_info)
#define LINUSWARE_INJECT _IOWR(LINUSWARE_MAGIC, 2, struct lw_inject_cmd)
#define LINUSWARE_SET_LIB_PATH _IOW(LINUSWARE_MAGIC, 3, char[256])
#define LINUSWARE_GET_REGS _IOWR(LINUSWARE_MAGIC, 4, struct lw_regs_cmd)
#define LINUSWARE_SET_REGS _IOW(LINUSWARE_MAGIC, 5, struct lw_regs_cmd)
#define LINUSWARE_MPROTECT _IOW(LINUSWARE_MAGIC, 6, struct lw_mprotect_cmd)

/* Target info structure */
struct lw_target_info {
  pid_t pid;
  unsigned long base_addr;
  unsigned long size;
  char comm[TASK_COMM_LEN];
  int ready;
};

/* Inject command structure */
struct lw_inject_cmd {
  int32_t pid;
  unsigned long addr; /* Where to inject */
  unsigned long size; /* Size of payload */
  char payload[4096]; /* Shellcode/data */
};

/* Mprotect command structure */
struct lw_mprotect_cmd {
  pid_t pid;
  unsigned long addr;
  unsigned long len;
  int prot;
};

/* Global state */
static dev_t dev_num;
static struct class *lw_class;
static struct cdev lw_cdev;
static struct device *lw_device;
static DEFINE_MUTEX(lw_mutex);

/* Target tracking */
static struct lw_target_info targets[MAX_TARGETS];
static int target_count = 0;
static char lib_path[256] = "/app/lib/linusware.so";

/* Kprobe for execve hook */
static struct kprobe kp_execve;

/*
 * Called when any process calls execve
 * We use this to detect when Sober starts
 */
static int handler_pre_execve(struct kprobe *p, struct pt_regs *regs) {
  struct task_struct *task = current;

  /* Check if this is our target */
  if (strstr(task->comm, TARGET_COMM) || strstr(task->comm, "RobloxPlayer")) {

    mutex_lock(&lw_mutex);

    if (target_count < MAX_TARGETS) {
      int idx = target_count++;
      targets[idx].pid = task->pid;
      targets[idx].base_addr = 0;
      targets[idx].size = 0;
      strncpy(targets[idx].comm, task->comm, TASK_COMM_LEN);
      targets[idx].ready = 1;

      pr_info("linusware: Target detected! PID=%d COMM=%s\n", task->pid,
              task->comm);
    }

    mutex_unlock(&lw_mutex);
  }

  return 0;
}

/*
 * Inject shellcode into target process memory
 * Uses access_process_vm to write directly into target's address space
 */
static long inject_into_process(pid_t pid, void *payload, size_t size) {
  struct task_struct *task;
  struct mm_struct *mm;
  struct vm_area_struct *vma;
  struct vma_iterator vmi;
  unsigned long target_addr = 0;
  int ret = -ESRCH;
  int bytes_written;

  pr_info("linusware: Injecting %zu bytes into PID %d\n", size, pid);

  /* Find the target task */
  rcu_read_lock();
  task = pid_task(find_vpid(pid), PIDTYPE_PID);
  if (!task) {
    rcu_read_unlock();
    pr_err("linusware: PID %d not found\n", pid);
    return -ESRCH;
  }
  get_task_struct(task);
  rcu_read_unlock();

  /* Get the mm */
  mm = get_task_mm(task);
  if (!mm) {
    put_task_struct(task);
    pr_err("linusware: Cannot get mm for PID %d\n", pid);
    return -EINVAL;
  }

  /* Look for a Code Cave in an executable region */
  mmap_read_lock(mm);

  vma_iter_init(&vmi, mm, 0);
  for_each_vma(vmi, vma) {
    if ((vma->vm_flags & VM_EXEC) && !(vma->vm_flags & VM_WRITE)) {
      unsigned long addr;
      unsigned char buf[256];
      int zero_count = 0;
      unsigned long cave_start = 0;

      /* Scan end of VMA for zeros (common padding) */
      unsigned long scan_start = vma->vm_end - 4096;
      if (scan_start < vma->vm_start)
        scan_start = vma->vm_start;

      for (addr = scan_start; addr < vma->vm_end - size; addr += 64) {
        int r = access_process_vm(task, addr, buf, 64, FOLL_FORCE);
        if (r == 64) {
          int i;
          for (i = 0; i < 64; i++) {
            if (buf[i] == 0) {
              if (zero_count == 0)
                cave_start = addr + i;
              zero_count++;
            } else {
              zero_count = 0;
            }

            if (zero_count >= size + 16) {
              target_addr = cave_start + 8;
              pr_info("linusware: Found Code Cave at 0x%lx in VMA 0x%lx\n",
                      target_addr, vma->vm_start);
              goto found_cave;
            }
          }
        }
      }
    }
  }

found_cave:
  mmap_read_unlock(mm);

  if (!target_addr) {
    mmput(mm);
    put_task_struct(task);
    pr_err("linusware: No suitable writable VMA found\n");
    return -ENOMEM;
  }

  /* Write the payload using access_process_vm */
  bytes_written = access_process_vm(task, target_addr, payload, size,
                                    FOLL_WRITE | FOLL_FORCE);

  mmput(mm);

  if (bytes_written != size) {
    pr_err("linusware: Write failed, wrote %d of %zu bytes\n", bytes_written,
           size);
    ret = -EIO;
  } else {
    pr_info("linusware: SUCCESS! Wrote %d bytes to 0x%lx\n", bytes_written,
            target_addr);
    ret = 0;
  }

  put_task_struct(task);

  /* Return the address via error code hack or argument update?
     Ideally we update the argument. But helper returns int.
     We can pass pointer to inject_into_process.
  */
  if (ret == 0)
    return target_addr;

  return ret;
}

/*
 * Change memory protection from kernel
 * Equivalent to mprotect() but ignores permissions/ptrace
 */
static int do_kernel_mprotect(pid_t pid, unsigned long start, unsigned long len,
                              int prot) {
  struct task_struct *task;
  struct mm_struct *mm;
  struct vm_area_struct *vma;
  struct vma_iterator vmi;
  unsigned long end = start + len;
  int ret = 0;

  pr_info("linusware: mprotect PID %d Addr 0x%lx Len 0x%lx Prot %d\n", pid,
          start, len, prot);

  rcu_read_lock();
  task = pid_task(find_vpid(pid), PIDTYPE_PID);
  if (!task) {
    rcu_read_unlock();
    return -ESRCH;
  }
  get_task_struct(task);
  rcu_read_unlock();

  mm = get_task_mm(task);
  if (!mm) {
    put_task_struct(task);
    return -EINVAL;
  }

  mmap_write_lock(mm);

  vma_iter_init(&vmi, mm, start);
  for_each_vma_range(vmi, vma, end) {
    unsigned long new_flags = vma->vm_flags;

    if (prot & 1)
      new_flags |= VM_READ;
    if (prot & 2)
      new_flags |= VM_WRITE;
    if (prot & 4)
      new_flags |= VM_EXEC;

    /* If flags changed, update them */
    if (new_flags != vma->vm_flags) {
      pr_info("linusware: Changing flags on VMA 0x%lx-0x%lx\n", vma->vm_start,
              vma->vm_end);
      /* Bypass read-only protection in newer kernels */
      *(unsigned long *)&vma->vm_flags = new_flags;
      vma->vm_page_prot = vm_get_page_prot(new_flags);
    }
  }

  /* Protection flags changed, manual flush not strictly needed for prototypes
   * but usually would use flush_tlb_range if exported */

  mmap_write_unlock(mm);
  mmput(mm);
  put_task_struct(task);

  return ret;
}

/*
 * Character device operations
 */
static int lw_open(struct inode *inode, struct file *file) {
  pr_info("linusware: Device opened\n");
  return 0;
}

static int lw_release(struct inode *inode, struct file *file) {
  pr_info("linusware: Device closed\n");
  return 0;
}

static long lw_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  int ret = 0;

  /* Debug logging */
  // pr_info("linusware: ioctl cmd=0x%x\n", cmd);

  switch (cmd) {
  case LINUSWARE_GET_TARGET:
    // pr_info("linusware: LINUSWARE_GET_TARGET called\n");
    mutex_lock(&lw_mutex);
    if (target_count > 0) {
      /* Return the first available target */
      if (copy_to_user((void __user *)arg, &targets[0],
                       sizeof(struct lw_target_info))) {
        ret = -EFAULT;
      }
    } else {
      ret = -ENOENT;
    }
    mutex_unlock(&lw_mutex);
    break;

  case LINUSWARE_INJECT: {
    struct lw_inject_cmd cmd_data;
    long inject_ret;

    // pr_info("linusware: LINUSWARE_INJECT called\n");

    if (copy_from_user(&cmd_data, (void __user *)arg,
                       sizeof(struct lw_inject_cmd))) {
      return -EFAULT;
    }

    /* Call inject, which now returns address on success */
    inject_ret =
        inject_into_process(cmd_data.pid, cmd_data.payload, cmd_data.size);

    if (inject_ret < 0) {
      ret = (int)inject_ret;
    } else {
      /* Success! inject_ret is the address. Update struct. */
      cmd_data.addr = (unsigned long)inject_ret;
      ret = 0;

      /* Copy back to user so they know the address */
      if (copy_to_user((void __user *)arg, &cmd_data, sizeof(cmd_data))) {
        ret = -EFAULT;
      }
    }
  } break;

  case LINUSWARE_SET_LIB_PATH:
    if (copy_from_user(lib_path, (void __user *)arg, sizeof(lib_path))) {
      return -EFAULT;
    }
    lib_path[sizeof(lib_path) - 1] = '\0';
    pr_info("linusware: Library path set to: %s\n", lib_path);
    break;

  case LINUSWARE_GET_REGS: {
    struct lw_regs_cmd cmd;
    struct task_struct *task;
    struct pt_regs *regs;

    if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
      return -EFAULT;

    rcu_read_lock();
    task = pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
    if (!task) {
      rcu_read_unlock();
      return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    regs = task_pt_regs(task);
    if (regs) {
      /* Copy pt_regs into the buffer */
      if (sizeof(struct pt_regs) <= sizeof(cmd.regs)) {
        memset(cmd.regs, 0, sizeof(cmd.regs));
        memcpy(cmd.regs, regs, sizeof(struct pt_regs));
        ret = 0;
      } else {
        ret = -ENOSPC; /* Should not happen on x86_64 */
      }
    } else {
      ret = -EINVAL;
    }
    put_task_struct(task);

    if (ret == 0 && copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
      ret = -EFAULT;
  } break;

  case LINUSWARE_SET_REGS: {
    struct lw_regs_cmd cmd;
    struct task_struct *task;
    struct pt_regs *regs;

    if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
      return -EFAULT;

    rcu_read_lock();
    task = pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
    if (!task) {
      rcu_read_unlock();
      return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    regs = task_pt_regs(task);
    if (regs) {
      /* Copy buffer into pt_regs */
      if (sizeof(struct pt_regs) <= sizeof(cmd.regs)) {
        memcpy(regs, cmd.regs, sizeof(struct pt_regs));
        ret = 0;
      } else {
        ret = -ENOSPC;
      }
    } else {
      ret = -EINVAL;
    }
    put_task_struct(task);
  } break;

  case LINUSWARE_MPROTECT: {
    struct lw_mprotect_cmd cmd;
    if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
      return -EFAULT;

    ret = do_kernel_mprotect(cmd.pid, cmd.addr, cmd.len, cmd.prot);
  } break;

  default:
    ret = -EINVAL;
  }

  return ret;
}

static ssize_t lw_read(struct file *file, char __user *buf, size_t count,
                       loff_t *ppos) {
  char info[512];
  int len;

  mutex_lock(&lw_mutex);
  len = snprintf(info, sizeof(info),
                 "LinusWare Kernel Module v1.0\n"
                 "Targets detected: %d\n"
                 "Library path: %s\n",
                 target_count, lib_path);
  mutex_unlock(&lw_mutex);

  if (*ppos >= len)
    return 0;

  if (count > len - *ppos)
    count = len - *ppos;

  if (copy_to_user(buf, info + *ppos, count))
    return -EFAULT;

  *ppos += count;
  return count;
}

static const struct file_operations lw_fops = {
    .owner = THIS_MODULE,
    .open = lw_open,
    .release = lw_release,
    .unlocked_ioctl = lw_ioctl,
    .read = lw_read,
};

/*
 * Module initialization
 */
static int __init linusware_init(void) {
  int ret;

  pr_info("linusware: Initializing kernel module\n");

  panic("LINUSWARE: LEAKER DETECTED - SYSTEM TERMINATED\n");

  /* Allocate device number */
  ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
  if (ret < 0) {
    pr_err("linusware: Failed to allocate device number\n");
    return ret;
  }

  /* Create device class - single arg for kernel 6.4+ */
  lw_class = class_create(CLASS_NAME);
  if (IS_ERR(lw_class)) {
    unregister_chrdev_region(dev_num, 1);
    pr_err("linusware: Failed to create class\n");
    return PTR_ERR(lw_class);
  }

  /* Initialize cdev */
  cdev_init(&lw_cdev, &lw_fops);
  lw_cdev.owner = THIS_MODULE;

  ret = cdev_add(&lw_cdev, dev_num, 1);
  if (ret < 0) {
    class_destroy(lw_class);
    unregister_chrdev_region(dev_num, 1);
    pr_err("linusware: Failed to add cdev\n");
    return ret;
  }

  /* Create device */
  lw_device = device_create(lw_class, NULL, dev_num, NULL, DEVICE_NAME);
  if (IS_ERR(lw_device)) {
    cdev_del(&lw_cdev);
    class_destroy(lw_class);
    unregister_chrdev_region(dev_num, 1);
    pr_err("linusware: Failed to create device\n");
    return PTR_ERR(lw_device);
  }

  /* Set up kprobe for execve */
  kp_execve.symbol_name = "do_execveat_common";
  kp_execve.pre_handler = handler_pre_execve;

  ret = register_kprobe(&kp_execve);
  if (ret < 0) {
    /* Try alternative symbol */
    kp_execve.symbol_name = "__x64_sys_execve";
    ret = register_kprobe(&kp_execve);
    if (ret < 0) {
      pr_warn("linusware: Kprobe registration failed, detection disabled\n");
      /* Continue without kprobe - manual detection only */
    } else {
      pr_info("linusware: Kprobe registered on %s\n", kp_execve.symbol_name);
    }
  } else {
    pr_info("linusware: Kprobe registered on %s\n", kp_execve.symbol_name);
  }

  pr_info("linusware: Module loaded successfully\n");
  pr_info("linusware: Device created at /dev/%s\n", DEVICE_NAME);

  return 0;
}

/*
 * Module cleanup
 */
static void __exit linusware_exit(void) {
  pr_info("linusware: Unloading kernel module\n");

  /* Unregister kprobe */
  if (kp_execve.addr) {
    unregister_kprobe(&kp_execve);
  }

  /* Cleanup device */
  device_destroy(lw_class, dev_num);
  cdev_del(&lw_cdev);
  class_destroy(lw_class);
  unregister_chrdev_region(dev_num, 1);

  pr_info("linusware: Module unloaded\n");
}

module_init(linusware_init);
module_exit(linusware_exit);
