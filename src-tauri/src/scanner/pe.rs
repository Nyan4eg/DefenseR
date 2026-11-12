//! Minimal, forgiving PE parser: reads only the fields the model's features need.
//! Malformed input never panics; whatever cannot be read is left empty.

use std::collections::HashSet;

pub const SECTION_CODE: u32 = 0x20;
pub const SECTION_EXECUTE: u32 = 0x2000_0000;
pub const SECTION_READ: u32 = 0x4000_0000;
pub const SECTION_WRITE: u32 = 0x8000_0000;

// Bounds against hostile headers. Windows itself refuses more than 96 sections.
const MAX_SECTIONS: usize = 96;
const MAX_IMPORT_DLLS: usize = 1024;
const MAX_IMPORTS_PER_DLL: usize = 65_536;
const MAX_NAME_LEN: usize = 4096;
const MAX_EXPORTS: usize = 65_536;

pub struct Section {
    pub name: String,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub characteristics: u32,
}

pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

#[derive(Default)]
pub struct Imports {
    /// Distinct DLL names as written in the file.
    pub dlls: HashSet<String>,
    /// Imported functions, by name or by ordinal.
    pub function_count: usize,
    /// Names of functions imported by name.
    pub functions: HashSet<String>,
}

pub struct Pe {
    pub timestamp: u32,
    pub machine: u16,
    pub characteristics: u16,
    pub magic: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub linker_version: (u8, u8),
    pub os_version: (u16, u16),
    pub image_version: (u16, u16),
    pub subsystem_version: (u16, u16),
    pub sizeof_code: u32,
    pub sizeof_headers: u32,
    pub sizeof_heap_commit: u64,
    pub data_directories: Vec<DataDirectory>,
    pub sections: Vec<Section>,
    pub imports: Imports,
    pub export_count: u32,
}

fn read<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    read(bytes, offset).map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    read(bytes, offset).map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    read(bytes, offset).map(u64::from_le_bytes)
}

/// NUL-terminated string, without the terminator.
fn c_string(bytes: &[u8], offset: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let tail = &tail[..tail.len().min(MAX_NAME_LEN)];
    let end = tail.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

impl Pe {
    /// File offset of a relative virtual address.
    fn offset_of(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            let len = section.virtual_size.max(section.raw_size) as u64;
            let start = section.virtual_address as u64;
            if (start..start + len).contains(&(rva as u64)) {
                return Some(section.raw_offset as usize + (rva - section.virtual_address) as usize);
            }
        }
        (rva < self.sizeof_headers).then_some(rva as usize)
    }

    /// The bytes of a section that get loaded, clipped to the file's end. Like LIEF, which built
    /// the training data, this leaves out file padding beyond the section's virtual size.
    pub fn section_data<'a>(&self, bytes: &'a [u8], section: &Section) -> &'a [u8] {
        let len = match section.virtual_size {
            0 => section.raw_size,
            virtual_size => virtual_size.min(section.raw_size),
        };
        let start = (section.raw_offset as usize).min(bytes.len());
        let end = start.saturating_add(len as usize).min(bytes.len());
        &bytes[start..end]
    }

}

pub fn parse(bytes: &[u8]) -> Option<Pe> {
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let signature = u32_at(bytes, 0x3c)? as usize;
    if bytes.get(signature..signature.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = signature + 4;
    let section_count = u16_at(bytes, coff + 2)? as usize;
    let optional_size = u16_at(bytes, coff + 16)? as usize;

    let opt = coff + 20;
    let magic = u16_at(bytes, opt)?;
    let pe64 = match magic {
        0x10b => false,
        0x20b => true,
        _ => return None,
    };

    let mut pe = Pe {
        machine: u16_at(bytes, coff)?,
        timestamp: u32_at(bytes, coff + 4)?,
        characteristics: u16_at(bytes, coff + 18)?,
        magic,
        linker_version: (*bytes.get(opt + 2)?, *bytes.get(opt + 3)?),
        sizeof_code: u32_at(bytes, opt + 4)?,
        os_version: (u16_at(bytes, opt + 40)?, u16_at(bytes, opt + 42)?),
        image_version: (u16_at(bytes, opt + 44)?, u16_at(bytes, opt + 46)?),
        subsystem_version: (u16_at(bytes, opt + 48)?, u16_at(bytes, opt + 50)?),
        sizeof_headers: u32_at(bytes, opt + 60)?,
        subsystem: u16_at(bytes, opt + 68)?,
        dll_characteristics: u16_at(bytes, opt + 70)?,
        sizeof_heap_commit: if pe64 { u64_at(bytes, opt + 96)? } else { u32_at(bytes, opt + 84)? as u64 },
        data_directories: Vec::new(),
        sections: Vec::new(),
        imports: Imports::default(),
        export_count: 0,
    };

    let directories = opt + if pe64 { 112 } else { 96 };
    let directory_count = u32_at(bytes, directories - 4)?.min(16) as usize;
    for i in 0..directory_count {
        let (Some(rva), Some(size)) = (u32_at(bytes, directories + i * 8), u32_at(bytes, directories + i * 8 + 4)) else {
            break;
        };
        pe.data_directories.push(DataDirectory { rva, size });
    }

    let table = opt + optional_size;
    for i in 0..section_count.min(MAX_SECTIONS) {
        let at = table + i * 40;
        let Some(name) = read::<8>(bytes, at) else { break };
        let (Some(virtual_size), Some(virtual_address), Some(raw_size), Some(raw_offset), Some(characteristics)) = (
            u32_at(bytes, at + 8),
            u32_at(bytes, at + 12),
            u32_at(bytes, at + 16),
            u32_at(bytes, at + 20),
            u32_at(bytes, at + 36),
        ) else {
            break;
        };
        let name_len = name.iter().position(|&b| b == 0).unwrap_or(8);
        pe.sections.push(Section {
            name: String::from_utf8_lossy(&name[..name_len]).into_owned(),
            raw_size,
            raw_offset,
            virtual_size,
            virtual_address,
            characteristics,
        });
    }

    pe.imports = parse_imports(bytes, &pe, pe64).unwrap_or_default();
    pe.export_count = parse_export_count(bytes, &pe).unwrap_or(0);
    Some(pe)
}

fn parse_imports(bytes: &[u8], pe: &Pe, pe64: bool) -> Option<Imports> {
    let directory = pe.data_directories.get(1)?;
    if directory.rva == 0 {
        return None;
    }
    let mut imports = Imports::default();
    let table = pe.offset_of(directory.rva)?;

    for i in 0..MAX_IMPORT_DLLS {
        let descriptor = table + i * 20;
        let (Some(lookup_rva), Some(name_rva), Some(address_rva)) =
            (u32_at(bytes, descriptor), u32_at(bytes, descriptor + 12), u32_at(bytes, descriptor + 16))
        else {
            break;
        };
        if name_rva == 0 {
            break;
        }
        let Some(name) = pe.offset_of(name_rva).and_then(|offset| c_string(bytes, offset)) else {
            break;
        };
        imports.dlls.insert(name);

        let thunks_rva = if lookup_rva != 0 { lookup_rva } else { address_rva };
        let Some(thunks) = pe.offset_of(thunks_rva) else { continue };
        for j in 0..MAX_IMPORTS_PER_DLL {
            let (entry, by_ordinal) = if pe64 {
                match u64_at(bytes, thunks + j * 8) {
                    Some(value) => (value, value >> 63 == 1),
                    None => break,
                }
            } else {
                match u32_at(bytes, thunks + j * 4) {
                    Some(value) => (value as u64, value >> 31 == 1),
                    None => break,
                }
            };
            if entry == 0 {
                break;
            }
            imports.function_count += 1;
            if !by_ordinal {
                // Hint/name entry: a two-byte hint followed by the name.
                let name = pe.offset_of(entry as u32).and_then(|offset| c_string(bytes, offset + 2));
                if let Some(name) = name {
                    imports.functions.insert(name);
                }
            }
        }
    }
    Some(imports)
}

fn parse_export_count(bytes: &[u8], pe: &Pe) -> Option<u32> {
    let directory = pe.data_directories.first()?;
    if directory.rva == 0 {
        return None;
    }
    let table = pe.offset_of(directory.rva)?;
    let function_count = (u32_at(bytes, table + 20)? as usize).min(MAX_EXPORTS);
    let addresses = pe.offset_of(u32_at(bytes, table + 28)?)?;
    let name_count = (u32_at(bytes, table + 24)? as usize).min(MAX_EXPORTS);
    let name_ordinals = pe.offset_of(u32_at(bytes, table + 36)?)?;

    // Like LIEF, count the functions exported by name: each name points at a slot of the address
    // table, and unused slots hold zero.
    let mut named = 0;
    for i in 0..name_count {
        let Some(slot) = u16_at(bytes, name_ordinals + i * 2) else { break };
        let slot = slot as usize;
        if slot < function_count && u32_at(bytes, addresses + slot * 4).is_some_and(|rva| rva != 0) {
            named += 1;
        }
    }
    Some(named)
}
