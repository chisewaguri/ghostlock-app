/* 5.4.210-qgki-perf-gc89cd02a7dfe (ROG Phone 5s, SM8350, android11-5.4) */

OFFSETS_ENTRY(
    "5.4.210-qgki-perf-gc89cd02a7dfe",
    STRUCT_OFFSETS_5_4,
    .kernel_phys_load = 0xa8000000,
    .pselect_waiter_shift = 1,
    .pselect_waiter_off = 24,
    .route_select = 1,
    .off_init_task = 0x02a7b380,
    .off_init_cred = 0x02a870f8,
    .off_root_task_group = 0x02c410a8,
    .off_selinux_enforcing = 0x02c2a001,
    .off_selinux_blob_sizes = 0x02198704,
    .off_security_hook_heads = 0x02198090,
    .off_slide_nfulnl_logger = 0x0298aa88,
    .off_slide_boot_id = 0x02ced0b1,
    .off_slide_loggers_0_1 = 0x02992b60,
),

/* Stamp geometry, measured from the image: the stale rt_mutex_waiter left by
 * futex(FUTEX_WAIT_REQUEUE_PI) sits at svc-0x198 (futex syscall frame 0x70 +
 * do_futex 0x20 + futex_wait_requeue_pi 0x1a0, waiter at +0x98). The pselect6
 * window bottoms exactly at svc-0x198 and cannot reach it; select(2)'s
 * shallower syscall frame (0x80) puts its fd_set copy at svc-0x1b0..svc-0x138,
 * covering the whole 0x50 waiter. shift = (waiter - word0 - 16) / 8 = +1,
 * anchored on 5.10's device-proven -2 at waiter - word0 = 0. */
