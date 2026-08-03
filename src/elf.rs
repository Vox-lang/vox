//! Minimal ELF64 `.dynsym` reader (plan 230 stage A4).
//!
//! The `.lib` file is trusted for TYPES (Vox types are not recoverable from
//! ELF) but verified for EXISTENCE: every mangled name it promises must appear
//! as a defined dynamic symbol in the `.so` its `Location` names. That is the
//! only staleness check available, and it works by walking the ELF section
//! headers to the `SHT_DYNSYM` table — no `nm` subprocess and no ELF crate,
//! so the compiler keeps its `nasm` + `ld` + `cargo`-only dependency set.
//!
//! The reader is deliberately narrow: little-endian ELF64 only (the only
//! object format Vox emits), sections only (no program headers, no hash
//! tables). Anything outside that shape is rejected with a message naming
//! what was wrong, so a truncated or 32-bit file reads as a clear error
//! rather than a panic.

use std::fs;
use std::path::Path;

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const SHT_DYNSYM: u32 = 11;
const SHN_UNDEF: u16 = 0;

const EHDR_SIZE: usize = 64;
const SHDR_SIZE: usize = 64;
const SYM_SIZE: u64 = 24;

fn u16_le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

fn u64_le(b: &[u8], off: usize) -> Option<u64> {
    let mut a = [0u8; 8];
    for (i, byte) in a.iter_mut().enumerate() {
        *byte = *b.get(off + i)?;
    }
    Some(u64::from_le_bytes(a))
}

/// The defined dynamic symbol names of the ELF64 object at `path`. A symbol
/// counts as defined when its `st_shndx` is not `SHN_UNDEF` — exactly the set
/// `nm -D --defined-only` prints, which is the set a caller may link against.
/// Errors name the file and the specific thing that was wrong with it.
pub fn defined_dynamic_symbols(path: &Path) -> Result<Vec<String>, String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("could not read '{}': {}", path.display(), e))?;
    let syms = defined_dynamic_symbols_from_bytes(&bytes)
        .map_err(|why| format!("'{}': {}", path.display(), why))?;
    Ok(syms)
}

/// As `defined_dynamic_symbols`, but over an in-memory image so the reader can
/// be unit-tested without a toolchain-built `.so`.
pub fn defined_dynamic_symbols_from_bytes(b: &[u8]) -> Result<Vec<String>, String> {
    if b.len() < EHDR_SIZE {
        return Err(format!(
            "not an ELF64 file ({} bytes, smaller than the {}-byte ELF header)",
            b.len(),
            EHDR_SIZE
        ));
    }
    if b[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err("not an ELF file (bad magic)".to_string());
    }
    if b[4] != ELFCLASS64 {
        return Err("not a 64-bit (ELFCLASS64) object".to_string());
    }
    if b[5] != ELFDATA2LSB {
        return Err("not a little-endian (ELFDATA2LSB) object".to_string());
    }

    let err = |field: &str| format!("truncated ELF header (missing {})", field);
    let shoff = u64_le(b, 0x28).ok_or_else(|| err("e_shoff"))?;
    let shentsize = u16_le(b, 0x3a).ok_or_else(|| err("e_shentsize"))? as usize;
    let shnum = u16_le(b, 0x3c).ok_or_else(|| err("e_shnum"))? as usize;

    if shoff == 0 || shnum == 0 {
        return Err("has no section headers, so no dynamic symbol table".to_string());
    }
    if shentsize < SHDR_SIZE {
        return Err(format!(
            "section headers are {} bytes, smaller than the ELF64 minimum {}",
            shentsize, SHDR_SIZE
        ));
    }

    // Section header i lives at shoff + i * shentsize. Read the fixed-offset
    // fields only; the rest of the header is ignored.
    let shdr = |i: usize| -> Result<(u32, u64, u64, u32, u64), String> {
        let base = (shoff as usize)
            .checked_add(i * shentsize)
            .ok_or("section header offset overflow")?;
        if base.checked_add(SHDR_SIZE).map_or(true, |end| end > b.len()) {
            return Err(format!(
                "section header {} extends past the end of the file",
                i
            ));
        }
        let sh_type = u32_le(b, base + 4).unwrap();
        let sh_offset = u64_le(b, base + 24).unwrap();
        let sh_size = u64_le(b, base + 32).unwrap();
        let sh_link = u32_le(b, base + 48).unwrap();
        let sh_entsize = u64_le(b, base + 56).unwrap();
        Ok((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    };

    let mut dynsym: Option<(u64, u64, u32, u64)> = None;
    for i in 0..shnum {
        let (sh_type, sh_offset, sh_size, sh_link, sh_entsize) = shdr(i)?;
        if sh_type == SHT_DYNSYM {
            if dynsym.is_some() {
                return Err("has more than one SHT_DYNSYM section".to_string());
            }
            dynsym = Some((sh_offset, sh_size, sh_link, sh_entsize));
        }
    }

    let (sym_off, sym_size, str_link, entsize) = dynsym
        .ok_or("has no .dynsym section (is this a shared library?)")?;
    let entsize = if entsize == 0 { SYM_SIZE } else { entsize };
    if entsize < SYM_SIZE {
        return Err(format!(
            ".dynsym entries are {} bytes, smaller than the ELF64 minimum {}",
            entsize, SYM_SIZE
        ));
    }

    let (_, str_off, str_size, _, _) = shdr(str_link as usize)
        .map_err(|e| format!("linked string table: {}", e))?;
    let str_end = (str_off as usize)
        .checked_add(str_size as usize)
        .ok_or("string table offset overflow")?;
    if str_end > b.len() {
        return Err("string table extends past the end of the file".to_string());
    }
    let strtab = &b[str_off as usize..str_end];

    let count = sym_size / entsize;
    let mut names = Vec::new();
    for i in 0..count {
        let base = (sym_off as usize)
            .checked_add((i * entsize) as usize)
            .ok_or("symbol table offset overflow")?;
        if base.checked_add(SYM_SIZE as usize).map_or(true, |end| end > b.len()) {
            return Err("symbol table extends past the end of the file".to_string());
        }
        // st_name (offset into the linked string table), st_shndx (section the
        // symbol is defined in; SHN_UNDEF = referenced but not defined here).
        // Elf64_Sym: st_name u32 @0, st_info u8 @4, st_other u8 @5,
        // st_shndx u16 @6, st_value u64 @8, st_size u64 @16.
        let st_name = u32_le(b, base).unwrap() as usize;
        let st_shndx = u16_le(b, base + 6).unwrap();
        if st_shndx == SHN_UNDEF {
            continue;
        }
        let name_end = match strtab[st_name.min(strtab.len())..]
            .iter()
            .position(|&c| c == 0)
        {
            Some(rel) => st_name.min(strtab.len()) + rel,
            None => return Err(format!("symbol {} name is not NUL-terminated", i)),
        };
        if st_name >= strtab.len() && st_name != 0 {
            return Err(format!("symbol {} name offset is past the string table", i));
        }
        let name = std::str::from_utf8(&strtab[st_name.min(strtab.len())..name_end])
            .map_err(|_| format!("symbol {} name is not valid UTF-8", i))?;
        names.push(name.to_string());
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the smallest legal ELF64 image carrying a .dynsym: header, a null
    /// section, a SHT_DYNSYM section and its string table. `names[0]` is left
    /// undefined (the mandatory STN_UNDEF first entry); the rest are defined
    /// against section 1. This is exactly the shape the reader walks, so the
    /// test catches a field-offset regression without nasm/ld.
    fn synthetic_dynsym_elf(names: &[&str]) -> Vec<u8> {
        let mut strtab = vec![0u8]; // string tables begin with a NUL
        let mut name_offsets = Vec::new();
        for n in names {
            name_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(n.as_bytes());
            strtab.push(0);
        }

        let mut syms = Vec::new();
        for (i, off) in name_offsets.iter().enumerate() {
            syms.extend_from_slice(&off.to_le_bytes()); // st_name
            syms.push(0); // st_info
            syms.push(0); // st_other
            let shndx: u16 = if i == 0 { SHN_UNDEF } else { 1 };
            syms.extend_from_slice(&shndx.to_le_bytes()); // st_shndx
            syms.extend_from_slice(&0u64.to_le_bytes()); // st_value
            syms.extend_from_slice(&0u64.to_le_bytes()); // st_size
        }

        let shoff: u64 = (EHDR_SIZE + syms.len() + strtab.len()) as u64;

        let mut b = vec![0u8; EHDR_SIZE];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = ELFCLASS64;
        b[5] = ELFDATA2LSB;
        b[6] = 1; // EV_CURRENT
        b[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        b[0x3a..0x3c].copy_from_slice(&(SHDR_SIZE as u16).to_le_bytes());
        b[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes()); // 3 sections

        b.extend_from_slice(&syms);
        b.extend_from_slice(&strtab);

        // section 0: the all-zero NULL section (already zeroed by the header
        // size here only conceptually — emit a real zeroed header).
        b.extend_from_slice(&[0u8; SHDR_SIZE]);

        // section 1: SHT_DYNSYM, link=2 (the string table section).
        let mut sh = [0u8; SHDR_SIZE];
        // sh_name = 0 (we never name sections; the reader does not need it)
        sh[4..8].copy_from_slice(&SHT_DYNSYM.to_le_bytes());
        sh[24..32].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // offset
        sh[32..40].copy_from_slice(&(syms.len() as u64).to_le_bytes()); // size
        sh[48..52].copy_from_slice(&2u32.to_le_bytes()); // sh_link -> section 2
        sh[56..64].copy_from_slice(&SYM_SIZE.to_le_bytes()); // sh_entsize
        b.extend_from_slice(&sh);

        // section 2: the string table.
        let mut sh = [0u8; SHDR_SIZE];
        sh[4..8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        sh[24..32].copy_from_slice(&((EHDR_SIZE + syms.len()) as u64).to_le_bytes());
        sh[32..40].copy_from_slice(&(strtab.len() as u64).to_le_bytes());
        b.extend_from_slice(&sh);

        b
    }

    #[test]
    fn reads_defined_symbols_and_skips_undefined() {
        let elf = synthetic_dynsym_elf(&["", "mathkit_1_0_greet", "mathkit_1_0_add_two_numbers"]);
        let got = defined_dynamic_symbols_from_bytes(&elf).unwrap();
        assert_eq!(
            got,
            vec![
                "mathkit_1_0_greet".to_string(),
                "mathkit_1_0_add_two_numbers".to_string()
            ]
        );
    }

    #[test]
    fn rejects_non_elf_and_wrong_class() {
        assert!(defined_dynamic_symbols_from_bytes(b"nope").unwrap_err().contains("smaller"));
        let mut not_elf = synthetic_dynsym_elf(&["x"]);
        not_elf[0] = 0;
        assert!(defined_dynamic_symbols_from_bytes(&not_elf)
            .unwrap_err()
            .contains("bad magic"));
        let mut not_64 = synthetic_dynsym_elf(&["x"]);
        not_64[4] = 1; // ELFCLASS32
        assert!(defined_dynamic_symbols_from_bytes(&not_64)
            .unwrap_err()
            .contains("64-bit"));
    }

    #[test]
    fn missing_dynsym_section_is_a_named_error() {
        // An ELF with section headers but no SHT_DYNSYM. The synthetic helper
        // always emits one, so swap its type to SHT_PROGBITS here.
        let mut elf = synthetic_dynsym_elf(&["x"]);
        let shoff = u64_le(&elf, 0x28).unwrap() as usize;
        let first_sh_type = shoff + SHDR_SIZE + 4;
        elf[first_sh_type..first_sh_type + 4].copy_from_slice(&1u32.to_le_bytes());
        let err = defined_dynamic_symbols_from_bytes(&elf).unwrap_err();
        assert!(err.contains("no .dynsym section"), "got: {}", err);
    }
}
