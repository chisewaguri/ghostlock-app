//! Verify the prctl route geometry by hand against an image:
//! frame chain, auxv copy site, and where each waiter word lands.
//! Usage: cargo run --release --example verify_prctl -- <boot.img>
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::btf::Btf;
use ghostlock_extract::derive::{self, derive_futex_waiter, relative_symbols};
use ghostlock_extract::kallsyms;
use ghostlock_extract::{disasm, kallsyms_finder};

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: verify_prctl <boot.img>");
    let boot = BootImage::load(std::path::Path::new(&path))?;
    let btf_at = boot.embedded_btf_at();
    let ks = kallsyms_finder::recover(
        &boot.kernel,
        btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len())),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let symbols = ks.symbols;
    let base = kallsyms::unique(&symbols, "_text")
        .or_else(|| kallsyms::unique(&symbols, "_head"))
        .ok_or_else(|| anyhow::anyhow!("_text/_head not unique"))?;
    let (rel, sorted) = relative_symbols(&symbols, base);

    let btf_ref = boot
        .embedded_btf()
        .map(|blob| Btf::new(&blob))
        .transpose()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("no embedded BTF"))?;

    let futex = derive_futex_waiter(&boot.kernel, &rel, &sorted, &btf_ref)?;
    println!(
        "futex waiter: local={:#x} depth={:#x} chain={}",
        futex.local, futex.depth, futex.chain
    );

    let entry = derive::unique_offset(&rel, "__arm64_sys_prctl")?;
    let deep = derive::unique_offset(&rel, "prctl_set_mm")?;
    let mut chain_sum: u64 = 0;
    for (name, a) in [("__arm64_sys_prctl", entry), ("prctl_set_mm", deep)] {
        let stop = sorted
            .iter()
            .find(|v| **v > a)
            .copied()
            .unwrap_or(a + 0x2000);
        let lines = disasm::disassemble_range(
            &boot.kernel,
            a as usize,
            stop.min(a + 0x2000) as usize,
        )?;
        let frame = disasm::first_sp_frame(&lines, name)?;
        chain_sum += frame;
        println!("{name} @ {a:#x}: frame={frame:#x}");
        for l in lines.iter().filter(|l| {
            l.contains("bl 0x") || l.starts_with("stp x29") || l.contains("sub sp")
        }) {
            println!("    {l}");
        }
    }
    println!("chain_sum={chain_sum:#x}");

    // auxv copy site: every copy_from_user with its dest sp offset and size,
    // as derive_prctl_layout scans them
    let stop = sorted
        .iter()
        .find(|v| **v > deep)
        .copied()
        .unwrap_or(deep + 0x2000);
    let lines = disasm::disassemble_range(
        &boot.kernel,
        deep as usize,
        stop.min(deep + 0x2000) as usize,
    )?;
    let copy = |addr: u64| -> bool {
        rel.iter().any(|(name, addrs)| {
            (name.contains("copy_from_user") || name.contains("copy_from_sockptr"))
                && addrs.contains(&addr)
        })
    };
    for (i, line) in lines.iter().enumerate() {
        let Some(h) = line.strip_prefix("bl 0x") else { continue };
        let Ok(t) = u64::from_str_radix(h.trim(), 16) else { continue };
        if !copy(t) {
            continue;
        }
        let mut off = None;
        let mut size = 0u64;
        for j in (i.saturating_sub(24)..i).rev() {
            if off.is_none() {
                if let Some(r) = lines[j].strip_prefix("add x0, sp, #0x") {
                    if let Ok(v) = u64::from_str_radix(r.trim(), 16) {
                        off = Some(v);
                    }
                }
            }
            if size == 0 {
                if let Some(r) = lines[j].strip_prefix("mov w2, #0x") {
                    if let Ok(v) = u64::from_str_radix(r.trim(), 16) {
                        size = v;
                    }
                }
            }
            if off.is_some() && size != 0 {
                break;
            }
        }
        println!(
            "copy_from_user @ line {i}: dest=sp+{:#?} size={size:#x}",
            off
        );
    }

    // where the registered entry says the words land
    let auxv_off: u64 = 0x8;
    let auxv_size: u64 = 0x190;
    let waiter_off: u64 = 0xb8;
    let task_off = btf_ref
        .field("rt_mutex_waiter", "task")
        .ok_or_else(|| anyhow::anyhow!("BTF rt_mutex_waiter.task missing"))?;
    let lock_off = btf_ref
        .field("rt_mutex_waiter", "lock")
        .ok_or_else(|| anyhow::anyhow!("BTF rt_mutex_waiter.lock missing"))?;
    let auxv_pos = -(chain_sum as i64) + auxv_off as i64;
    let waiter_in_buf = futex.depth - auxv_pos;
    println!("auxv_pos={auxv_pos:#x} waiter_in_buf={waiter_in_buf:#x} (entry says {waiter_off:#x})");
    println!(
        "task word at buf+{:#x}, lock word at buf+{:#x}, buffer size {auxv_size:#x}",
        waiter_in_buf + task_off as i64,
        waiter_in_buf + lock_off as i64
    );
    Ok(())
}
