//! sigmaos-dos CLI — inspect a DOS executable.

use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: sigmaos-dos <file.exe|file.com>")?;
    let data = fs::read(path)?;
    println!("kind: {}", sigmaos_dos::detect_kind(&data));
    if let Ok(h) = sigmaos_dos::parse_mz(&data) {
        println!(
            "pages: {} relocations: {} header_bytes: {}",
            h.pages,
            h.reloc_count,
            sigmaos_dos::header_size(&h)
        );
        println!(
            "entry: CS={:#06x} IP={:#06x} SS={:#06x} SP={:#06x}",
            h.cs, h.ip, h.ss, h.sp
        );
        println!("image_size: {} bytes", sigmaos_dos::image_size(&h));
    }
    Ok(())
}
