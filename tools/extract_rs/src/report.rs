//! Output rendering and kernel-table registration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::{Value, json};

use crate::derive::McastLayout;
use crate::error::{ExtractError, Result};
use crate::symbols::{OPTIONAL_SYMBOLS, STRUCT_FIELDS, SYMBOLS};

pub const MTK_DEFAULT_PHYS_LOAD: u64 = 0x8000_0000;
pub const QC_PHYS_LOAD_6_6: u64 = 0xA800_0000;
pub const QC_PHYS_LOAD_6_1: u64 = 0xA800_0000;
pub const QC_PHYS_LOAD_5_10: u64 = 0xA800_0000;
pub const QC_PHYS_LOAD_6_12: u64 = 0xC780_0000;

/// Python insertion order of resolve_symbols(): header output matches the
/// Python tool byte-for-byte.
pub fn symbol_render_order() -> Vec<&'static str> {
    let mut keys: Vec<&'static str> = Vec::new();
    for (name, _) in SYMBOLS {
        keys.push(*name);
    }
    keys.push("off_slide_loggers_0_1");
    keys
}

/// Python insertion order of resolve_structs(): struct_fields output in the
/// C header matches the Python tool byte-for-byte.
fn struct_render_order() -> Vec<&'static str> {
    let mut keys: Vec<&'static str> = Vec::new();
    for (_, fields) in STRUCT_FIELDS {
        for (macro_name, _) in *fields {
            keys.push(*macro_name);
        }
    }
    keys.push("struct_page_size");
    keys.push("struct_page_compound_head");
    keys.push("struct_page_type");
    keys.push("struct_slab_cache");
    keys.push("struct_mm_struct");
    keys
}

pub fn kernel_key(release: &str) -> String {
    let mut out = String::new();
    for ch in release.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

pub fn phys_needs_override(release: Option<&str>, phys: Option<u64>) -> bool {
    let Some(phys) = phys else {
        return false;
    };
    if phys == MTK_DEFAULT_PHYS_LOAD {
        return false;
    }
    let default = match crate::symbols::kernel_struct_macro(release) {
        Some("STRUCT_OFFSETS_6_12") => QC_PHYS_LOAD_6_12,
        Some("STRUCT_OFFSETS_6_1") | Some("STRUCT_OFFSETS_5_10") | Some("STRUCT_OFFSETS_5_15") => QC_PHYS_LOAD_6_1,
        _ => QC_PHYS_LOAD_6_6,
    };
    phys != default
}

pub fn pselect_waiter_shift_for(release: Option<&str>) -> i64 {
    match crate::symbols::kernel_struct_macro(release) {
        Some("STRUCT_OFFSETS_6_12") => 0,
        Some("STRUCT_OFFSETS_5_10") => 0,
        // android14-6.1 compiles its fd_set words one qword later than
        // 6.6; the committed tables all measure 1.
        Some("STRUCT_OFFSETS_6_1") => 1,
        _ => -2,
    }
}

pub fn validate_kernel_phys_load(release: Option<&str>, phys: Option<u64>, mtk: bool) -> bool {
    let Some(phys) = phys else {
        return false;
    };
    let expected = if mtk {
        MTK_DEFAULT_PHYS_LOAD
    } else {
        match crate::symbols::kernel_struct_macro(release) {
            Some("STRUCT_OFFSETS_6_12") => QC_PHYS_LOAD_6_12,
            Some("STRUCT_OFFSETS_6_1") | Some("STRUCT_OFFSETS_5_10") | Some("STRUCT_OFFSETS_5_15") => QC_PHYS_LOAD_6_1,
            _ => QC_PHYS_LOAD_6_6,
        }
    };
    if phys == expected {
        return false;
    }
    let note = "the entry will carry it as an explicit override";
    eprintln!(
        "warning: kernel_phys_load=0x{phys:x} does not match the {} default 0x{expected:x}; {note}",
        if mtk { "MediaTek" } else { "Qualcomm" }
    );
    true
}

pub fn render_device(
    release: &str,
    symbols: &BTreeMap<String, Option<u64>>,
    structs: &BTreeMap<String, Option<u32>>,
    phys: Option<u64>,
    pselect_shift: i64,
    pselect_waiter_off: i64,
    mcast: Option<&McastLayout>,
) -> String {
    let mut lines = vec![format!("/* {release} */"), String::new()];
    lines.push("OFFSETS_ENTRY(".to_string());
    lines.push(format!("    \"{release}\","));
    lines.push(format!(
        "    {},",
        // unverified kernels render with the 6.6 layout as a testing start;
        // the extractor warns whenever it falls back
        crate::symbols::kernel_struct_macro(Some(release)).unwrap_or("STRUCT_OFFSETS_6_6")
    ));
    if phys_needs_override(Some(release), phys) {
        lines.push(format!("    .kernel_phys_load = 0x{:x},", phys.unwrap()));
    }
    // 6.1 entries get their mm_struct_sz=0x400 stride from the
    // STRUCT_OFFSETS_6_1 macro itself; nothing extra to emit here.
    lines.push(format!("    .pselect_waiter_shift = {pselect_shift},"));
    if pselect_waiter_off != 0 {
        lines.push(format!("    .pselect_waiter_off = {pselect_waiter_off},"));
    }
    if let Some(mcast) = mcast {
        lines.push(format!("    .mcast_waiter_off = 0x{:x},", mcast.waiter_off));
        lines.push(format!(
            "    .mcast_buffer_size = 0x{:x}, .mcast_task_offset = 0x{:x}, \
             .mcast_lock_offset = 0x{:x},",
            mcast.buffer_size, mcast.task_offset, mcast.lock_offset
        ));
    }
    for key in symbol_render_order() {
        if let Some(value) = symbols.get(key).copied().flatten() {
            lines.push(format!("    .{key} = 0x{value:08x},"));
        }
    }
    lines.push("),".to_string());
    let mut reference: Vec<(&str, u32)> = Vec::new();
    for key in struct_render_order() {
        if key.starts_with("struct_page") || key == "struct_slab_cache" || key == "struct_mm_struct"
        {
            if let Some(value) = structs.get(key).copied().flatten() {
                reference.push((key, value));
            }
        }
    }
    if !reference.is_empty() {
        lines.push(String::new());
        lines.push("/* BTF reference (runtime uses target.h defaults): */".to_string());
        for (key, value) in &reference {
            lines.push(format!(
                "/* #define {} 0x{:X} */",
                key.to_uppercase(),
                value
            ));
        }
    }
    lines.join("\n") + "\n"
}

pub fn render_c(
    release: Option<&str>,
    name: &str,
    symbols: &BTreeMap<String, Option<u64>>,
    structs: &BTreeMap<String, Option<u32>>,
    phys: Option<u64>,
    pselect_shift: i64,
    pselect_waiter_off: i64,
    mcast: Option<&McastLayout>,
) -> String {
    let label = release.unwrap_or(name);
    let mut lines = vec![
        format!("/* Generated offsets for {label}. */"),
        String::new(),
    ];
    lines.push("#define STRUCT_OFFSETS_EXTRACTED \\".to_string());
    let task_keys = [
        "task_prio",
        "task_normal_prio",
        "task_sched_task_group",
        "task_pi_lock",
        "task_pi_waiters",
        "task_pi_top_task",
        "task_pi_blocked_on",
        "task_pid",
        "task_tgid",
        "task_atomic_flags",
        "task_real_cred",
        "task_cred",
        "task_comm",
        "task_tasks",
        "task_seccomp",
    ];
    let present: Vec<(String, u32)> = task_keys
        .iter()
        .filter_map(|key| {
            structs
                .get(*key)
                .copied()
                .flatten()
                .map(|value| ((*key).to_string(), value))
        })
        .collect();
    for (index, (key, value)) in present.iter().enumerate() {
        let suffix = if index + 1 < present.len() { " \\" } else { "" };
        lines.push(format!("  .{key} = 0x{value:X},{suffix}"));
    }
    lines.push(String::new());
    let macro_name = crate::symbols::kernel_struct_macro(release);
    lines.push(format!("OFFSETS_ENTRY(\"{label}\","));
    lines.push(format!(
        "  {},",
        // unverified kernels render with the 6.6 layout as a testing start;
        // the extractor warns whenever it falls back
        macro_name.unwrap_or("STRUCT_OFFSETS_6_6")
    ));
    if phys_needs_override(release, phys) {
        lines.push(format!("  .kernel_phys_load=0x{:X},", phys.unwrap()));
    }
    lines.push(format!("  .pselect_waiter_shift={pselect_shift},"));
    if pselect_waiter_off != 0 {
        lines.push(format!("  .pselect_waiter_off={pselect_waiter_off},"));
    }
    if matches!(
        macro_name,
        Some("STRUCT_OFFSETS_6_1") | Some("STRUCT_OFFSETS_5_10") | Some("STRUCT_OFFSETS_5_15")
    ) {
        // spell the layout fields out so a manually registered header does
        // not depend on the selector macro carrying them
        lines.push("  .compact_waiter=1,".to_string());
        lines.push("  .mm_struct_sz=0x400,".to_string());
    }
    if let Some(mcast) = mcast {
        lines.push(format!("  .mcast_waiter_off=0x{:X},", mcast.waiter_off));
        lines.push(format!(
            "  .mcast_buffer_size=0x{:X}, .mcast_task_offset=0x{:X}, \
             .mcast_lock_offset=0x{:X},",
            mcast.buffer_size, mcast.task_offset, mcast.lock_offset
        ));
    }
    for key in symbol_render_order() {
        if let Some(value) = symbols.get(key).copied().flatten() {
            lines.push(format!("  .{key}=0x{value:08X},"));
        }
    }
    lines.push("),".to_string());
    lines.push(String::new());
    lines.push("/* BTF fields not stored in kernel_offsets: */".to_string());
    for key in struct_render_order() {
        if key.starts_with("task_") {
            continue;
        }
        if let Some(value) = structs.get(key).copied().flatten() {
            lines.push(format!("#define {} 0x{:X}", key.to_uppercase(), value));
        }
    }
    lines.join("\n")
}

pub fn build_report(
    release: Option<&str>,
    base: u64,
    phys: Option<u64>,
    symbols: &BTreeMap<String, Option<u64>>,
    structs: &BTreeMap<String, Option<u32>>,
    btf_size: usize,
    pselect_shift: i64,
    pselect_waiter_off: i64,
    mcast: Option<&McastLayout>,
) -> Value {
    let symbol_json: BTreeMap<String, Value> = symbols
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                match value {
                    Some(v) => json!(v),
                    None => Value::Null,
                },
            )
        })
        .collect();
    let struct_json: BTreeMap<String, Value> = structs
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                match value {
                    Some(v) => json!(v),
                    None => Value::Null,
                },
            )
        })
        .collect();
    let mut report = json!({
        "release": release,
        "kimage_text_base": base,
        "kernel_phys_load": phys,
        "pselect_waiter_shift": pselect_shift,
        "pselect_waiter_off": pselect_waiter_off,
        "symbols": symbol_json,
        "struct_fields": struct_json,
        "btf_size": btf_size,
    });
    if matches!(
        crate::symbols::kernel_struct_macro(release),
        Some("STRUCT_OFFSETS_6_1") | Some("STRUCT_OFFSETS_5_10") | Some("STRUCT_OFFSETS_5_15")
    ) {
        // 0x400 is the device SLUB stride, not the BTF 0x3c0/0x3e0
        report["compact_waiter"] = json!(1);
        report["mm_struct_sz"] = json!(0x400);
    }
    if let Some(mcast) = mcast {
        report["mcast_waiter_off"] = json!(mcast.waiter_off);
        report["mcast_buffer_size"] = json!(mcast.buffer_size);
        report["mcast_task_offset"] = json!(mcast.task_offset);
        report["mcast_lock_offset"] = json!(mcast.lock_offset);
    }
    report
}

/* Resolve the repo the extractor reads and writes kernel tables in.
 * The manifest dir baked in at build time goes stale the moment the
 * binary runs from another checkout or a linked worktree, so ask git
 * for the toplevel of the working directory first and only fall back
 * to the manifest path when there is no repo around (on-device runs). */
fn repo_root() -> PathBuf {
    if let Ok(out) = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
    {
        if out.status.success() {
            let top = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !top.is_empty() {
                return PathBuf::from(top);
            }
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

pub fn kernels_root() -> PathBuf {
    repo_root().join("src").join("kernels")
}

pub fn kernel_header_path(key: &str) -> PathBuf {
    kernels_root().join(key).join("offsets.h")
}

pub type EntryFields = BTreeMap<String, i64>;

fn parse_int(text: &str) -> i64 {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        text.parse::<i64>().unwrap_or(0)
    }
}

/// Map each registered release to its {field: value} from kernel headers.
pub fn existing_entries() -> BTreeMap<String, EntryFields> {
    let mut entries: BTreeMap<String, EntryFields> = BTreeMap::new();
    let entry_re = Regex::new(r#"OFFSETS_ENTRY\(\s*"([^"]+)"#).unwrap();
    let field_re = Regex::new(r"\.([A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|-?\d+)").unwrap();
    let Ok(dir) = std::fs::read_dir(kernels_root()) else {
        return entries;
    };
    for sub in dir.flatten() {
        let header = sub.path().join("offsets.h");
        let Ok(text) = std::fs::read_to_string(&header) else {
            continue;
        };
        for entry_match in entry_re.captures_iter(&text) {
            let release = entry_match[1].to_string();
            let tail = &text[entry_match.get(0).unwrap().end()..];
            let mut fields: EntryFields = BTreeMap::new();
            for field_match in field_re.captures_iter(tail) {
                fields.insert(field_match[1].to_string(), parse_int(&field_match[2]));
            }
            entries.entry(release).or_insert(fields);
        }
    }
    entries
}

pub fn warn_existing_mismatches(
    release: &str,
    symbols: &BTreeMap<String, Option<u64>>,
    mcast: Option<&McastLayout>,
) {
    let entries = existing_entries();
    let Some(existing) = entries.get(release) else {
        return;
    };
    if let Some(mcast) = mcast {
        let measured = [
            ("mcast_waiter_off", mcast.waiter_off),
            ("mcast_buffer_size", mcast.buffer_size as i64),
            ("mcast_task_offset", mcast.task_offset as i64),
            ("mcast_lock_offset", mcast.lock_offset as i64),
        ];
        for (key, value) in measured {
            if let Some(old) = existing.get(key) {
                if *old != value {
                    eprintln!(
                        "warning: {release} is already registered with .{key}=\
                         0x{old:08X}; this image extracts 0x{value:08X}"
                    );
                }
            }
        }
    }
    for (key, value) in symbols {
        let Some(value) = value else { continue };
        if let Some(old) = existing.get(key) {
            if *old != *value as i64 {
                eprintln!(
                    "warning: {release} is already registered with .{key}=\
                     0x{old:08X}; this image extracts 0x{value:08X}"
                );
                if key == "off_slide_loggers_0_1" {
                    eprintln!(
                        "warning:   loggers[0][1] is loggers + NF_LOG_TYPE_ULOG*8 \
                         (disassembly + BTF verified and confirmed on device for \
                         findn5/17pm); the older heuristic loggers + 0x10 was wrong."
                    );
                }
            }
        }
    }
}

/// Natural sort key matching VSCode's folder order.
fn kernel_include_sort_key(include: &str) -> Vec<(u8, SortPart)> {
    let path = include
        .trim_start_matches("#include \"")
        .trim_end_matches("/offsets.h\"");
    let mut key: Vec<(u8, SortPart)> = Vec::new();
    let re = Regex::new(r"(\d+)").unwrap();
    let mut cursor = 0;
    for caps in re.captures_iter(path) {
        let matched = caps.get(0).unwrap();
        if matched.start() > cursor {
            key.push((
                1,
                SortPart::Text(path[cursor..matched.start()].to_ascii_lowercase()),
            ));
        }
        key.push((0, SortPart::Digit(matched.as_str().parse::<u64>().unwrap())));
        cursor = matched.end();
    }
    if cursor < path.len() {
        key.push((1, SortPart::Text(path[cursor..].to_ascii_lowercase())));
    }
    key
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SortPart {
    Digit(u64),
    Text(String),
}

/// Add `#include "<key>/offsets.h"` to src/kernels/offsets.h if missing.
pub fn register_kernel(key: &str) -> Result<PathBuf> {
    let header = kernels_root().join("offsets.h");
    let text = std::fs::read_to_string(&header)
        .map_err(|err| ExtractError::new(format!("cannot read {}: {err}", header.display())))?;
    let include = format!("#include \"{key}/offsets.h\"");
    if text.contains(&include) {
        return Ok(header);
    }
    let marker = Regex::new(r"(?m)^\s*\{\s*\.uname_r\s*=\s*NULL").unwrap();
    let marker = marker
        .find(&text)
        .ok_or_else(|| ExtractError::new(format!("cannot locate NULL terminator in {header:?}")))?;
    let block = &text[..marker.start()];
    let key_order = kernel_include_sort_key(&include);
    let mut insert_at = marker.start();
    let include_re = Regex::new(r#"#include "[^"]+/offsets\.h""#).unwrap();
    for existing in include_re.find_iter(block) {
        if kernel_include_sort_key(existing.as_str()) > key_order {
            insert_at = existing.start();
            break;
        }
    }
    let mut out = text.clone();
    out.insert_str(insert_at, &format!("{include}\n"));
    std::fs::write(&header, out)
        .map_err(|err| ExtractError::new(format!("cannot write {header:?}: {err}")))?;
    Ok(header)
}

pub fn require_fields(
    values: &BTreeMap<String, Option<u64>>,
    optional: &BTreeSet<&str>,
) -> Result<()> {
    let missing: Vec<String> = values
        .iter()
        .filter(|(name, value)| value.is_none() && !optional.contains(name.as_str()))
        .map(|(name, _)| name.clone())
        .collect();
    if !missing.is_empty() {
        return Err(ExtractError::unsupported(format!(
            "missing required values: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

use std::collections::BTreeSet;

pub fn optional_symbols() -> BTreeSet<&'static str> {
    OPTIONAL_SYMBOLS.iter().copied().collect()
}

pub fn task_keys_list() -> &'static [&'static str] {
    &[
        "task_prio",
        "task_normal_prio",
        "task_sched_task_group",
        "task_pi_lock",
        "task_pi_waiters",
        "task_pi_top_task",
        "task_pi_blocked_on",
        "task_pid",
        "task_tgid",
        "task_atomic_flags",
        "task_real_cred",
        "task_cred",
        "task_comm",
        "task_tasks",
        "task_seccomp",
    ]
}

pub fn struct_fields_reference()
-> &'static [(&'static str, &'static [(&'static str, &'static str)])] {
    STRUCT_FIELDS
}

#[cfg(test)]
mod tests {
    use super::{McastLayout, pselect_waiter_shift_for, render_c};
    use std::collections::BTreeMap;

    #[test]
    fn render_c_carries_the_layout_selector_and_6_1_scalars() {
        let symbols: BTreeMap<String, Option<u64>> = BTreeMap::new();
        let structs: BTreeMap<String, Option<u32>> = BTreeMap::new();
        let out = render_c(
            Some("6.1.118-android14-11-gca0ef6d17716-ab13624819"),
            "x",
            &symbols,
            &structs,
            None,
            1,
            8,
            None,
        );
        assert!(out.contains("STRUCT_OFFSETS_6_1"));
        assert!(out.contains(".compact_waiter=1"));
        assert!(out.contains(".mm_struct_sz=0x400"));

        let out66 = render_c(
            Some("6.6.92-android15-8"),
            "x",
            &symbols,
            &structs,
            None,
            -2,
            0,
            None,
        );
        assert!(out66.contains("STRUCT_OFFSETS_6_6"));
        assert!(!out66.contains("compact_waiter"));
    }

    #[test]
    fn render_c_carries_the_5_15_layout_and_mcast_stamp() {
        let symbols: BTreeMap<String, Option<u64>> = BTreeMap::new();
        let structs: BTreeMap<String, Option<u32>> = BTreeMap::new();
        let mcast = McastLayout {
            waiter_off: 0x60,
            buffer_size: 0x108,
            task_offset: 0x30,
            lock_offset: 0x38,
            buffer_depth: -0x348,
            waiter_depth: -0x2F8,
            buffer_local: 0x18,
            chain: "x".to_string(),
            frames: BTreeMap::new(),
        };
        let out = render_c(
            Some("5.15.178-android13-8-00021-g6f2f96be86b9-ab13729987"),
            "x",
            &symbols,
            &structs,
            None,
            -2,
            -0x2F8,
            Some(&mcast),
        );
        assert!(out.contains("STRUCT_OFFSETS_5_15"));
        assert!(out.contains(".compact_waiter=1"));
        assert!(out.contains(".mm_struct_sz=0x400"));
        assert!(out.contains(".pselect_waiter_off=-760,"));
        assert!(out.contains(".mcast_waiter_off=0x60,"));
        assert!(out.contains(".mcast_buffer_size=0x108"));
        assert!(out.contains(".mcast_task_offset=0x30"));
        assert!(out.contains(".mcast_lock_offset=0x38"));
    }

    #[test]
    fn render_c_carries_the_5_10_layout() {
        let symbols: BTreeMap<String, Option<u64>> = BTreeMap::new();
        let structs: BTreeMap<String, Option<u32>> = BTreeMap::new();
        let out = render_c(
            Some("5.10.237-android12-9"),
            "x",
            &symbols,
            &structs,
            None,
            0,
            0,
            None,
        );
        assert!(out.contains("STRUCT_OFFSETS_5_10"));
        assert!(out.contains(".compact_waiter=1"));
        assert!(out.contains(".mm_struct_sz=0x400"));
        assert!(!out.contains("mcast"));
    }

    #[test]
    fn pselect_waiter_shift_matches_the_committed_tables() {
        assert_eq!(
            pselect_waiter_shift_for(Some("6.1.118-android14-11-gca0ef6d17716-ab13624819")),
            1
        );
        assert_eq!(pselect_waiter_shift_for(Some("6.6.92-android15-8")), -2);
        assert_eq!(pselect_waiter_shift_for(Some("6.12.30-android16-0")), 0);
        assert_eq!(pselect_waiter_shift_for(Some("5.10.237-android12-9")), 0);
        assert_eq!(pselect_waiter_shift_for(None), -2);
    }

    #[test]
    fn build_report_carries_the_pselect_window() {
        let report = super::build_report(
            Some("5.15.178-android13"),
            0,
            None,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            -2,
            -0x2F8,
            None,
        );
        assert_eq!(report["pselect_waiter_off"], -0x2F8);
        // structural default renders absent so the header stays small
        let silent = super::build_report(
            Some("5.15.178-android13"),
            0,
            None,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            -2,
            0,
            None,
        );
        assert_eq!(silent["pselect_waiter_off"], 0);
    }
}
