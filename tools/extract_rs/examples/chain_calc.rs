// compute the real syscall-chain frame sum for a named path and the coverage
// of a copy at sp+off inside the final function.
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{self, relative_symbols};
use ghostlock_extract::kallsyms;
use ghostlock_extract::{disasm, kallsyms_finder};
fn fr(boot:&BootImage,rel:&derive::RelSymbols,sorted:&[u64],n:&str)->anyhow::Result<u64>{
    let o=derive::unique_offset(rel,n)?;let st=sorted.iter().find(|v| **v>o).copied().unwrap_or(o+0x4000);
    let ls=disasm::disassemble_range(&boot.kernel,o as usize,st.min(o+0x4000) as usize)?;Ok(disasm::first_sp_frame(&ls,n).unwrap_or(0))
}
fn main()->anyhow::Result<()>{
    let a:Vec<String>=std::env::args().collect();
    let boot=BootImage::load(std::path::Path::new(&a[1]))?;
    let ks=kallsyms_finder::recover(&boot.kernel,boot.embedded_btf_at().as_ref().map(|(o,b)|(*o,b.len()))).map_err(|e|anyhow::anyhow!("{e}"))?;
    let base=kallsyms::unique(&ks.symbols,"_text").or_else(||kallsyms::unique(&ks.symbols,"_head")).unwrap();
    let (rel,sorted)=relative_symbols(&ks.symbols,base);
    // args: img chain1,chain2,... spoff size
    let chain:Vec<&str>=a[2].split(',').collect();
    let off=u64::from_str_radix(a[3].trim_start_matches("0x"),16)?;
    let size=u64::from_str_radix(a[4].trim_start_matches("0x"),16)?;
    let mut sum=0;for f in &chain{let x=fr(&boot,&rel,&sorted,f)?;sum+=x;println!("  {f}={x:#x}");}
    let base_d=sum-off;
    let waiter_off=base_d as i64 - 0x1a0;
    println!("sum={sum:#x} copy sp+{off:#x} size={size:#x}");
    println!("base_depth={base_d:#x} waiter_off={waiter_off:#x} covers={}", waiter_off>=0 && waiter_off+0x70<=size as i64);
    Ok(())
}
