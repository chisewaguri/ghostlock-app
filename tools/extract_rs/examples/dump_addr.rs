// Dump fn disassembly with real virtual addresses. Usage: dump_addr <img> <fn> [from_addr] [to_addr]
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{self, relative_symbols};
use ghostlock_extract::kallsyms;
use ghostlock_extract::{disasm, kallsyms_finder};
fn main()->anyhow::Result<()>{
    let a:Vec<String>=std::env::args().collect();
    let boot=BootImage::load(std::path::Path::new(&a[1]))?;
    let ks=kallsyms_finder::recover(&boot.kernel,boot.embedded_btf_at().as_ref().map(|(o,b)|(*o,b.len()))).map_err(|e|anyhow::anyhow!("{e}"))?;
    let base=kallsyms::unique(&ks.symbols,"_text").or_else(||kallsyms::unique(&ks.symbols,"_head")).unwrap();
    let (rel,sorted)=relative_symbols(&ks.symbols,base);
    let off=derive::unique_offset(&rel,&a[2])?;
    let stop=sorted.iter().find(|v| **v>off).copied().unwrap_or(off+0x4000);
    let lines=disasm::disassemble_range(&boot.kernel,off as usize,stop.min(off+0x4000) as usize)?;
    let mut names:Vec<(u64,String)>=Vec::new();
    for (n,x) in rel.iter(){for v in x{names.push((*v,n.clone()));}}
    let f:u64=a.get(3).and_then(|s|u64::from_str_radix(s.trim_start_matches("0x"),16).ok()).unwrap_or(off);
    let t:u64=a.get(4).and_then(|s|u64::from_str_radix(s.trim_start_matches("0x"),16).ok()).unwrap_or(off+0x4000);
    for (i,line) in lines.iter().enumerate(){
        let addr=off+4*i as u64;
        if addr<f||addr>t{continue;}
        let mut note=String::new();
        if let Some(h)=line.strip_prefix("bl 0x"){ if let Ok(x)=u64::from_str_radix(h.trim(),16){ if let Some((_,n))=names.iter().find(|(y,_)|*y==x){note=format!("   ; {n}");}}}
        println!("{addr:#012x} {line}{note}");
    }
    Ok(())
}
