#ifndef RUNTIME_STRUCT_OFFSETS_H
#define RUNTIME_STRUCT_OFFSETS_H

#include "../kernels/offsets.h"

extern const struct kernel_offsets *active_offsets;

#define _RSO(field, fallback) (active_offsets && active_offsets->field ? active_offsets->field : (fallback))
#define _RSO_64(field, fallback) ((uint64_t)_RSO(field, fallback))
#define _RSO_IMAGE(field, fallback) \
  (KIMAGE_TEXT_BASE + _RSO_64(field, fallback))

/* Override symbol macros with the selected device entry. */
#undef INIT_TASK
#undef INIT_CRED
#undef ROOT_TASK_GROUP
#undef SELINUX_ENFORCING
#undef SELINUX_BLOB_SIZES
#undef SECURITY_HOOK_HEADS
#undef SLIDE_NFULNL_LOGGER_IMAGE
#undef SLIDE_LOGGERS_0_1_IMAGE
#undef SLIDE_RANDOM_BOOT_ID_DATA_IMAGE
#undef SLIDE_INIT_TASK_IMAGE
#undef SLIDE_ROOT_TASK_GROUP_IMAGE
#undef SLIDE_SYSCTL_BOOTID_IMAGE

#define INIT_TASK           _RSO_IMAGE(off_init_task, INIT_TASK_OFF)
#define INIT_CRED           _RSO_IMAGE(off_init_cred, INIT_CRED_OFF)
#define ROOT_TASK_GROUP     _RSO_IMAGE(off_root_task_group, ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING   _RSO_IMAGE(off_selinux_enforcing, SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES  _RSO_IMAGE(off_selinux_blob_sizes, SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS _RSO_IMAGE(off_security_hook_heads, SECURITY_HOOK_HEADS_OFF)

#define SLIDE_NFULNL_LOGGER_IMAGE \
  _RSO_IMAGE(off_slide_nfulnl_logger, SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE \
  _RSO_IMAGE(off_slide_loggers_0_1, SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \
  _RSO_IMAGE(off_slide_boot_id, SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE _RSO_IMAGE(off_init_task, INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  _RSO_IMAGE(off_root_task_group, ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  _RSO_IMAGE(off_slide_boot_id, SLIDE_SYSCTL_BOOTID_OFF)

/* cfi/configfs layer: offsets into the kernel image (0 = missing entry). */
#undef NOOP_LLSEEK_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_MISC_FOPS_OFF

#define NOOP_LLSEEK_OFF         _RSO_64(off_noop_llseek, 0)
#define CONFIGFS_READ_ITER_OFF  _RSO_64(off_configfs_read_iter, 0)
#define CONFIGFS_BIN_WRITE_ITER_OFF _RSO_64(off_configfs_bin_write_iter, 0)
#define ASHMEM_IOCTL_OFF        _RSO_64(off_ashmem_ioctl, 0)
#define ASHMEM_FOPS_OFF         _RSO_64(off_ashmem_fops, 0)
#define ASHMEM_MISC_FOPS_OFF    _RSO_64(off_ashmem_misc_fops, 0)

/* cred layout: 6.1 KMI puts uid@4/caps@40/security@120; the target.h
 * fallbacks are the 6.6 GKI values. */
#undef CRED_UID_OFF
#undef CRED_SECUREBITS_OFF
#undef CRED_CAPS_OFF
#undef CRED_SECURITY_OFF

#define CRED_UID_OFF       _RSO(cred_uid, 8)
#define CRED_SECUREBITS_OFF _RSO(cred_securebits, 40)
#define CRED_CAPS_OFF      _RSO(cred_caps, 48)
#define CRED_SECURITY_OFF  _RSO(cred_security, 128)

#undef FAKE_TASK_PRIO_OFF
#undef FAKE_TASK_NORMAL_PRIO_OFF
#undef FAKE_TASK_TASK_GROUP_OFF
#undef FAKE_TASK_PI_LOCK_OFF
#undef FAKE_TASK_PI_WAITERS_OFF
#undef FAKE_TASK_PI_TOP_TASK_OFF
#undef FAKE_TASK_PI_BLOCKED_ON_OFF
#undef TASK_PID_OFF
#undef TASK_TGID_OFF
#undef TASK_ATOMIC_FLAGS_OFF
#undef TASK_REAL_CRED_OFF
#undef TASK_CRED_OFF
#undef TASK_COMM_OFF
#undef TASK_TASKS_OFF
#undef TASK_SECCOMP_OFF

#define FAKE_TASK_PRIO_OFF           _RSO(task_prio, 0x94)
#define FAKE_TASK_NORMAL_PRIO_OFF    _RSO(task_normal_prio, 0x9C)
#define FAKE_TASK_TASK_GROUP_OFF     _RSO(task_sched_task_group, 0x420)
#define FAKE_TASK_PI_LOCK_OFF        _RSO(task_pi_lock, 0x9EC)
#define FAKE_TASK_PI_WAITERS_OFF     _RSO(task_pi_waiters, 0xA00)
#define FAKE_TASK_PI_TOP_TASK_OFF    _RSO(task_pi_top_task, 0xA10)
#define FAKE_TASK_PI_BLOCKED_ON_OFF  _RSO(task_pi_blocked_on, 0xA18)
#define TASK_PID_OFF             _RSO(task_pid, 0x708)
#define TASK_TGID_OFF            _RSO(task_tgid, 0x70C)
#define TASK_ATOMIC_FLAGS_OFF    _RSO(task_atomic_flags, 0x6C8)
#define TASK_REAL_CRED_OFF       _RSO(task_real_cred, 0x8F8)
#define TASK_CRED_OFF            _RSO(task_cred, 0x900)
#define TASK_COMM_OFF            _RSO(task_comm, 0x910)
#define TASK_TASKS_OFF           _RSO(task_tasks, 0x638)
#define TASK_SECCOMP_OFF         _RSO(task_seccomp, 0x9C8)

#endif
