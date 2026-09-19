/* 5.10.205-android12-9-00034-g4f7845197313-ab11959366 */

OFFSETS_ENTRY(
    "5.10.205-android12-9-00034-g4f7845197313-ab11959366",
    STRUCT_OFFSETS_5_10,
    /* q4q (SM8450, same SoC) ships shift 0 for 5.10 pselect; the poco
     * builds measure -2. per-device, not per-family. */
    .pselect_waiter_shift = 0,
    .off_init_task = 0x0279bec0,
    .off_init_cred = 0x027b0ae0,
    .off_root_task_group = 0x02991040,
    .off_selinux_enforcing = 0x02a40b98,
    .off_selinux_blob_sizes = 0x022eacb8,
    .off_security_hook_heads = 0x022ea628,
    .off_slide_nfulnl_logger = 0x027913a0,
    .off_slide_boot_id = 0x02a5fbb5,
    .off_slide_loggers_0_1 = 0x027912d0,
),

/* BTF reference (runtime uses target.h defaults): */
/* #define STRUCT_PAGE_SIZE 0x40 */
/* #define STRUCT_PAGE_COMPOUND_HEAD 0x8 */
/* #define STRUCT_PAGE_TYPE 0x30 */
/* #define STRUCT_SLAB_CACHE 0x18 */
/* #define STRUCT_MM_STRUCT 0x3E0 */
