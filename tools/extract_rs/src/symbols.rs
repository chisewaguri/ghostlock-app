//! Symbol resolution tables and ashmem file_operations scanning.

use std::collections::{BTreeMap, BTreeSet};

use crate::btf::Btf;
use crate::kallsyms::{find_data_symbol, find_function, unique};

pub const SYMBOLS: &[(&str, &str)] = &[
    ("off_init_task", "init_task"),
    ("off_init_cred", "init_cred"),
    ("off_root_task_group", "root_task_group"),
    ("off_selinux_enforcing", "selinux_state"),
    ("off_selinux_blob_sizes", "selinux_blob_sizes"),
    ("off_security_hook_heads", "security_hook_heads"),
    ("off_kmalloc_caches", "kmalloc_caches"),
    ("off_anon_pipe_buf_ops", "anon_pipe_buf_ops"),
    ("off_slide_nfulnl_logger", "nfulnl_logger"),
    ("off_slide_boot_id", "sysctl_bootid"),
];

pub const FUNCTIONS: &[(&str, &str)] = &[
    ("off_configfs_read_iter", "configfs_read_iter"),
    ("off_configfs_bin_write_iter", "configfs_bin_write_iter"),
    ("off_copy_splice_read", "copy_splice_read"),
    ("off_noop_llseek", "noop_llseek"),
];

/// (field, exact symbol, data-symbol fragments, rust vtable fragments)
pub const ASHMEM_FUNCTIONS: &[(&str, &str, &[&str], &[&str])] = &[
    (
        "off_ashmem_ioctl",
        "ashmem_ioctl",
        &["fops_ioctl", "ashmem_rust6Ashmem"],
        &["MiscdeviceVTable", "ashmem_rust6Ashmem", "6AshmemE5ioctl"],
    ),
    (
        "off_ashmem_compat_ioctl",
        "compat_ashmem_ioctl",
        &["fops_compat_ioctl", "ashmem_rust6Ashmem"],
        &[
            "MiscdeviceVTable",
            "ashmem_rust6Ashmem",
            "6AshmemE12compat_ioctl",
        ],
    ),
    (
        "off_ashmem_mmap",
        "ashmem_mmap",
        &["fops_mmap", "ashmem_rust6Ashmem"],
        &["MiscdeviceVTable", "ashmem_rust6Ashmem", "6AshmemE4mmap"],
    ),
    (
        "off_ashmem_open",
        "ashmem_open",
        &["fops_open", "ashmem_rust6Ashmem"],
        &["MiscdeviceVTable", "ashmem_rust6Ashmem", "6AshmemE4open"],
    ),
    (
        "off_ashmem_release",
        "ashmem_release",
        &["fops_release", "ashmem_rust6Ashmem"],
        &["MiscdeviceVTable", "ashmem_rust6Ashmem", "6AshmemE7release"],
    ),
    (
        "off_ashmem_show_fdinfo",
        "ashmem_show_fdinfo",
        &["fops_show_fdinfo", "ashmem_rust6Ashmem"],
        &[
            "MiscdeviceVTable",
            "ashmem_rust6Ashmem",
            "6AshmemE11show_fdinfo",
        ],
    ),
];

/// file_operations slot offsets: classic C layout (OPPO 6.6) vs 6.12+ Rust
/// vtable, which differ by one 8-byte field before unlocked_ioctl.
pub const ASHMEM_FOPS_LAYOUTS: &[&[(&str, u64)]] = &[
    &[
        ("off_ashmem_ioctl", 0x50),
        ("off_ashmem_compat_ioctl", 0x58),
        ("off_ashmem_mmap", 0x60),
        ("off_ashmem_open", 0x68),
        ("off_ashmem_release", 0x78),
        ("off_ashmem_show_fdinfo", 0xd8),
    ],
    &[
        ("off_ashmem_ioctl", 0x48),
        ("off_ashmem_compat_ioctl", 0x50),
        ("off_ashmem_mmap", 0x58),
        ("off_ashmem_open", 0x68),
        ("off_ashmem_release", 0x78),
        ("off_ashmem_show_fdinfo", 0xd8),
    ],
];

/// GKI kernels drop some data symbols; unresolved optionals emit 0 and the
/// runtime falls back to target.h defaults.
pub const OPTIONAL_SYMBOLS: &[&str] = &[
    "off_security_hook_heads",
    "off_ashmem_fops",
    "off_ashmem_misc_fops",
];

/// struct name -> (offset macro, BTF field)
pub const STRUCT_FIELDS: &[(&str, &[(&str, &str)])] = &[
    (
        "task_struct",
        &[
            ("task_prio", "prio"),
            ("task_normal_prio", "normal_prio"),
            ("task_sched_task_group", "sched_task_group"),
            ("task_pi_lock", "pi_lock"),
            ("task_pi_waiters", "pi_waiters"),
            ("task_pi_top_task", "pi_top_task"),
            ("task_pi_blocked_on", "pi_blocked_on"),
            ("task_pid", "pid"),
            ("task_tgid", "tgid"),
            ("task_atomic_flags", "atomic_flags"),
            ("task_real_cred", "real_cred"),
            ("task_cred", "cred"),
            ("task_comm", "comm"),
            ("task_tasks", "tasks"),
            ("task_seccomp", "seccomp"),
        ],
    ),
    (
        "rt_mutex_waiter",
        &[
            ("waiter_tree", "tree"),
            ("waiter_pi_tree", "pi_tree"),
            ("waiter_task", "task"),
            ("waiter_lock", "lock"),
            ("waiter_wake_state", "wake_state"),
            ("waiter_ww_ctx", "ww_ctx"),
        ],
    ),
    (
        "cred",
        &[
            ("cred_uid", "uid"),
            ("cred_securebits", "securebits"),
            ("cred_caps", "cap_inheritable"),
            ("cred_security", "security"),
        ],
    ),
    (
        "seccomp",
        &[
            ("seccomp_mode", "mode"),
            ("seccomp_filter_count", "filter_count"),
            ("seccomp_filter", "filter"),
        ],
    ),
    (
        "file_operations",
        &[
            ("fops_owner", "owner"),
            ("fops_llseek", "llseek"),
            ("fops_read", "read"),
            ("fops_write", "write"),
            ("fops_read_iter", "read_iter"),
            ("fops_write_iter", "write_iter"),
            ("fops_ioctl", "unlocked_ioctl"),
            ("fops_compat_ioctl", "compat_ioctl"),
            ("fops_mmap", "mmap"),
            ("fops_open", "open"),
            ("fops_release", "release"),
            ("fops_splice_read", "splice_read"),
            ("fops_show_fdinfo", "show_fdinfo"),
        ],
    ),
    (
        "configfs_buffer",
        &[
            ("cfg_page", "page"),
            ("cfg_needs_read_fill", "needs_read_fill"),
            ("cfg_bin_buffer", "bin_buffer"),
            ("cfg_bin_buffer_size", "bin_buffer_size"),
            ("cfg_cb_max_size", "cb_max_size"),
        ],
    ),
];

pub type ResolvedSymbols = BTreeMap<String, Option<u64>>;

pub fn resolve_symbols(
    symbols: &BTreeMap<String, BTreeSet<u64>>,
    types: &BTreeMap<String, BTreeSet<char>>,
    btf: Option<&Btf>,
    base: u64,
    release: Option<&str>,
) -> ResolvedSymbols {
    let mut result: ResolvedSymbols = BTreeMap::new();
    for (name, symbol) in SYMBOLS {
        result.insert((*name).to_string(), unique(symbols, symbol));
    }
    for (name, symbol) in FUNCTIONS {
        result.insert((*name).to_string(), unique(symbols, symbol));
    }
    result.insert(
        "off_slide_loggers_0_1".to_string(),
        unique(symbols, "loggers").map(|value| value + 0x10),
    );
    // Rust ashmem anchors fops in a BSS static (ASHMEM_FOPS_PTR) filled at
    // init; the generic ("ashmem", "fops") match also hits get_shmem_fops/
    // VMFILE_FOPS, so keep it as a last resort.
    let mut ashmem_fops = find_data_symbol(symbols, types, "ashmem_fops", &["ashmem_fops_ptr"]);
    if ashmem_fops.is_none() {
        ashmem_fops = find_data_symbol(symbols, types, "ashmem_fops", &["ashmem", "fops"]);
    }
    result.insert("off_ashmem_fops".to_string(), ashmem_fops);

    let misc = find_data_symbol(symbols, types, "ashmem_misc", &["ashmem_misc"]);
    let mut misc_fops_field = btf.and_then(|b| b.field("miscdevice", "fops"));
    if misc_fops_field.is_none()
        && btf.is_none()
        && kernel_struct_macro(release) == "STRUCT_OFFSETS_6_6"
    {
        // No BTF: miscdevice.fops is at 0x10 on 6.6 (after minor/name).
        misc_fops_field = Some(0x10);
    }
    if let (Some(misc), Some(field)) = (misc, misc_fops_field) {
        result.insert("off_ashmem_misc_fops".to_string(), Some(misc + field as u64));
    } else {
        let mut misc_fops = find_data_symbol(symbols, types, "misc_fops", &["misc_fops"]);
        if misc_fops.is_none() {
            // Fall back to the lockdep key near the MiscDevice static.
            let misc = find_data_symbol(symbols, types, "ashmem_misc", &["ashmem", "misc"]);
            misc_fops = match (misc, misc_fops_field) {
                (Some(misc), Some(field)) => Some(misc + field as u64),
                _ => None,
            };
        }
        result.insert("off_ashmem_misc_fops".to_string(), misc_fops);
    }

    for (field_name, exact, fragments, rust_fragments) in ASHMEM_FUNCTIONS {
        let mut value = unique(symbols, exact);
        if value.is_none() {
            value = find_function(symbols, exact, fragments);
        }
        if value.is_none() {
            value = find_function(symbols, exact, rust_fragments);
        }
        result.insert((*field_name).to_string(), value);
    }
    result
        .iter_mut()
        .for_each(|(_, value)| *value = value.and_then(|v| v.checked_sub(base)));
    result
}

pub fn kernel_struct_macro(release: Option<&str>) -> &'static str {
    if let Some(release) = release {
        let mut parts = release.split('.');
        if let (Some(major), Some(minor)) = (parts.next(), parts.next()) {
            if let (Ok(major), Ok(minor)) = (major.parse::<u32>(), minor.parse::<u32>()) {
                if (major, minor) >= (6, 12) {
                    return "STRUCT_OFFSETS_6_12";
                }
            }
        }
    }
    "STRUCT_OFFSETS_6_6"
}

/// Scan for a file_operations whose slots point at the resolved ashmem
/// functions; 6.12+ Rust ashmem exposes no kallsyms data symbol, so this is
/// the only reliable way to resolve off_ashmem_fops there.
pub fn scan_ashmem_fops(kernel: &[u8], base: u64, resolved: &ResolvedSymbols) -> Option<u64> {
    let mut candidates: BTreeSet<u64> = BTreeSet::new();
    for layout in ASHMEM_FOPS_LAYOUTS {
        let slots: Vec<(&str, u64)> = layout
            .iter()
            .filter(|(key, _)| resolved.get(*key).copied().flatten().is_some())
            .map(|(key, off)| (*key, *off))
            .collect();
        if slots.len() < 4 {
            continue;
        }
        let (anchor_key, anchor_off) = slots[0];
        let anchor_value = base + resolved.get(anchor_key).copied().flatten().unwrap();
        let anchor = anchor_value.to_le_bytes();
        let max_slot = slots.iter().map(|(_, off)| *off).max().unwrap();
        let mut pos = 0usize;
        while let Some(found) = find_anchor(kernel, &anchor, pos) {
            pos = found + 1;
            let found = found as i64;
            let start = found - anchor_off as i64;
            if start < 0 {
                continue;
            }
            let start = start as usize;
            if start % 8 != 0 {
                continue;
            }
            let end = start
                .checked_add(max_slot as usize)
                .and_then(|v| v.checked_add(8));
            let Some(end) = end else { continue };
            if end > kernel.len() {
                continue;
            }
            let matches = slots[1..].iter().all(|(key, off)| {
                let expected = base + resolved.get(*key).copied().flatten().unwrap();
                let actual = u64::from_le_bytes(
                    kernel[start + *off as usize..start + *off as usize + 8]
                        .try_into()
                        .unwrap(),
                );
                actual == expected
            });
            if matches {
                candidates.insert(start as u64);
            }
        }
    }
    if candidates.len() == 1 {
        candidates.iter().next().copied()
    } else {
        None
    }
}

pub type ResolvedStructs = BTreeMap<String, Option<u32>>;

pub fn resolve_structs(btf: Option<&Btf>) -> ResolvedStructs {
    let mut result: ResolvedStructs = BTreeMap::new();
    let Some(btf) = btf else {
        for (_, fields) in STRUCT_FIELDS {
            for (macro_name, _) in *fields {
                result.insert((*macro_name).to_string(), None);
            }
        }
        result.insert("struct_page_size".to_string(), None);
        result.insert("struct_page_compound_head".to_string(), None);
        result.insert("struct_page_type".to_string(), None);
        result.insert("struct_slab_cache".to_string(), None);
        result.insert("struct_mm_struct".to_string(), None);
        return result;
    };
    for (struct_name, fields) in STRUCT_FIELDS {
        if btf.named_struct(struct_name).is_none() {
            for (macro_name, _) in *fields {
                result.insert((*macro_name).to_string(), None);
            }
            continue;
        }
        for (macro_name, field_name) in *fields {
            result.insert(
                (*macro_name).to_string(),
                btf.field(struct_name, field_name),
            );
        }
    }
    result.insert("struct_page_size".to_string(), btf.size("page"));
    result.insert(
        "struct_page_compound_head".to_string(),
        btf.field("page", "compound_head"),
    );
    result.insert("struct_page_type".to_string(), btf.field("page", "page_type"));
    result.insert(
        "struct_slab_cache".to_string(),
        btf.field("slab", "slab_cache"),
    );
    result.insert("struct_mm_struct".to_string(), btf.size("mm_struct"));
    result
}

fn find_anchor(haystack: &[u8], needle: &[u8; 8], from: usize) -> Option<usize> {
    if haystack.len() < 8 {
        return None;
    }
    let from = from.min(haystack.len() - 8);
    (from..=haystack.len() - 8).find(|&i| &haystack[i..i + 8] == needle)
}
