// Print kallsyms names matching a substring, for locating handlers in an image.
// Usage: cargo run --release --example dump_syms -- <boot.img> [substr ...]
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::kallsyms_finder;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let boot = BootImage::load(std::path::Path::new(&args[1]))?;
    let ks = kallsyms_finder::recover(
        &boot.kernel,
        boot.embedded_btf_at().as_ref().map(|(o, b)| (*o, b.len())),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pats: Vec<String> = args[2..].iter().map(|s| s.to_lowercase()).collect();
    for (name, _) in ks.symbols.iter() {
        let lower = name.to_lowercase();
        if pats.is_empty() || pats.iter().any(|p| lower.contains(p)) {
            println!("{name}");
        }
    }
    Ok(())
}
