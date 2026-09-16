/* 5.15.178-android13-8-00021-g6f2f96be86b9-ab13729987 */

OFFSETS_ENTRY(
    "5.15.178-android13-8-00021-g6f2f96be86b9-ab13729987",
    STRUCT_OFFSETS_5_15,
    /* setsockopt(MCAST_BLOCK_SOURCE) copies struct group_source_req to
     * sp+0x18 inside ip_setsockopt, which puts the buffer base at
     * svc-0x358. The stale waiter sits at svc-0x2f8, so it lands at
     * buffer+0x60 with the whole compact waiter inside the 0x108 bytes. */
    .mcast_waiter_off = 0x60,
    .mcast_buffer_size = 0x108,
    .mcast_task_offset = 0x30,
    .mcast_lock_offset = 0x38,
    .off_init_task = 0x02c33580,
    .off_init_cred = 0x02bed628,
    .off_root_task_group = 0x02d47ac0,
    .off_selinux_enforcing = 0x02d99cf0,
    .off_selinux_blob_sizes = 0x02152cc8,
    .off_security_hook_heads = 0x02150840,
    .off_slide_nfulnl_logger = 0x02af1e28,
    .off_slide_boot_id = 0x02db5799,
    .off_slide_loggers_0_1 = 0x02af1d58,
),

/* BTF reference (runtime uses target.h defaults): */
/* #define STRUCT_PAGE_SIZE 0x40 */
/* #define STRUCT_PAGE_COMPOUND_HEAD 0x8 */
/* #define STRUCT_PAGE_TYPE 0x30 */
/* #define STRUCT_SLAB_CACHE 0x18 */
/* #define STRUCT_MM_STRUCT 0x3E0 */
