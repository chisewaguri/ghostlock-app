// dump the actual instructions around the auxv copy site in prctl_set_mm
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{self, relative_symbols};
use ghostlock_extract::kallsyms;
use ghostlock_extract::{disasm, kallsyms_finder};

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: dump_prctl_disasm <boot.img>");
    let boot = BootImage::load(std::path::Path::new(&path))?;
    let btf_at = boot.embedded_btf_at();
    let ks = kallsyms_finder::recover(
        &boot.kernel,
        btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len())),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .ok_or_else(|| anyhow::anyhow!("_text/_head not unique"))?;
    let (rel, sorted) = relative_symbols(&ks.symbols, base);
    let deep = derive::unique_offset(&rel, "prctl_set_mm")?;
    let stop = sorted.iter().find(|v| **v > deep).copied().unwrap_or(deep + 0x2000);
    let lines = disasm::disassemble_range(&boot.kernel, deep as usize, stop.min(deep + 0x2000) as usize)?;
    let copy_addrs: Vec<u64> = rel
        .iter()
        .filter(|(n, _)| n.contains("copy_from_user"))
        .flat_map(|(_, a)| a.iter().copied())
        .collect();
    for (i, line) in lines.iter().enumerate() {
        let Some(h) = line.strip_prefix("bl 0x") else { continue };
        let Ok(t) = u64::from_str_radix(h.trim(), 16) else { continue };
        if copy_addrs.contains(&t) {
            for j in i.saturating_sub(14)..=i {
                println!("{j:4} {}", lines[j]);
            }
            println!("----");
        }
    }
    Ok(())
}
