//! Feature vector for the file model. Must match `ml/features.py` exactly:
//! same features, same order, same arithmetic. `ml/parity.py` checks this.

use super::pe::{self, Pe};

const COFF_FLAGS: [u16; 15] = [
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
];

const DLL_FLAGS: [u16; 11] = [0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000];

const SUBSYSTEMS: [u16; 13] = [1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 16];

const STANDARD_SECTIONS: [&str; 21] = [
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".bss", ".tls", ".CRT", ".didat",
    ".00cfg", ".gfids", ".xdata", ".debug", ".ndata", ".itext", "CODE", "DATA", "BSS",
];

const DLLS: [&str; 32] = [
    "kernel32.dll", "user32.dll", "advapi32.dll", "gdi32.dll", "shell32.dll", "ole32.dll",
    "oleaut32.dll", "comctl32.dll", "msvcrt.dll", "ntdll.dll", "ws2_32.dll", "wsock32.dll",
    "wininet.dll", "urlmon.dll", "winhttp.dll", "shlwapi.dll", "crypt32.dll", "mscoree.dll",
    "msvbvm60.dll", "version.dll", "psapi.dll", "netapi32.dll", "iphlpapi.dll", "comdlg32.dll",
    "winmm.dll", "rpcrt4.dll", "setupapi.dll", "wtsapi32.dll", "userenv.dll", "dbghelp.dll",
    "vcruntime140.dll", "api-ms-win-crt-runtime-l1-1-0.dll",
];

const APIS: [&str; 74] = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory",
    "ReadProcessMemory", "CreateRemoteThread", "OpenProcess", "LoadLibraryA", "LoadLibraryW",
    "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "CreateProcessA", "CreateProcessW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW", "URLDownloadToFileA",
    "URLDownloadToFileW", "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetReadFile",
    "HttpSendRequestA", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "CreateToolhelp32Snapshot",
    "Process32First", "Process32Next", "AdjustTokenPrivileges", "OpenProcessToken",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CreateServiceA", "CreateServiceW",
    "StartServiceA", "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext",
    "ResumeThread", "QueueUserAPC", "GetTickCount", "Sleep", "FindResourceA", "LoadResource",
    "SizeofResource", "CreateFileA", "CreateFileW", "DeleteFileA", "DeleteFileW", "MoveFileExA",
    "GetTempPathA", "GetTempPathW", "WSAStartup", "connect", "send", "recv", "socket",
    "_CorExeMain", "_CorDllMain", "ExitProcess", "GetModuleHandleA", "EventRegister",
];

const DATA_DIRECTORIES: usize = 15;

pub const FEATURE_COUNT: usize = 256 + 256 + 104 + 2 + 2 + 15 + 1 + 11 + 12 + 16 + 2 + 32 + 74 + 2 * DATA_DIRECTORIES;

pub struct Extracted {
    pub vector: Vec<f32>,
    pub pe: Option<Pe>,
    /// Highest entropy among the sections, in bits per byte.
    pub max_section_entropy: f64,
}

/// Shannon entropy of the byte distribution, in bits per byte.
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let total = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / total; -p * p.log2() }).sum()
}

fn push_normalized(out: &mut Vec<f32>, counts: &[u64]) {
    let total: u64 = counts.iter().sum();
    let total = if total > 0 { total as f32 } else { 1.0 };
    out.extend(counts.iter().map(|&c| c as f32 / total));
}

/// Joint histogram of byte value and local entropy over sliding 2048-byte windows (EMBER's "byteentropy").
fn byte_entropy_histogram(bytes: &[u8]) -> [u64; 256] {
    const WINDOW: usize = 2048;
    const STEP: usize = 1024;
    let mut output = [0u64; 256];

    let mut add_block = |block: &[u8]| {
        let mut coarse = [0u64; 16];
        for &byte in block {
            coarse[(byte >> 4) as usize] += 1;
        }
        // Single precision on purpose: the dataset was built with float32.
        let mut h = 0f32;
        for &c in coarse.iter().filter(|&&c| c > 0) {
            let p = c as f32 / WINDOW as f32;
            h -= p * p.log2();
        }
        let bin = ((h * 2.0 * 2.0) as usize).min(15);
        for (i, &c) in coarse.iter().enumerate() {
            output[bin * 16 + i] += c;
        }
    };

    if bytes.len() < WINDOW {
        add_block(bytes);
    } else {
        let mut start = 0;
        while start + WINDOW <= bytes.len() {
            add_block(&bytes[start..start + WINDOW]);
            start += STEP;
        }
    }
    output
}

/// Counts non-overlapping matches of `matcher`, which returns the match length at a position.
fn count_matches(bytes: &[u8], matcher: impl Fn(&[u8]) -> Option<usize>) -> u64 {
    let mut count = 0;
    let mut i = 0;
    while i < bytes.len() {
        match matcher(&bytes[i..]) {
            Some(len) => {
                count += 1;
                i += len;
            }
            None => i += 1,
        }
    }
    count
}

fn push_strings(out: &mut Vec<f32>, bytes: &[u8]) {
    let mut count = 0u64;
    let mut printables = 0u64;
    let mut dist = [0u64; 96];

    // Strings are runs of at least five bytes in 0x20..=0x7f.
    let mut run_start = 0;
    for i in 0..=bytes.len() {
        if i < bytes.len() && (0x20..=0x7f).contains(&bytes[i]) {
            continue;
        }
        if i - run_start >= 5 {
            count += 1;
            printables += (i - run_start) as u64;
            for &byte in &bytes[run_start..i] {
                dist[(byte - 0x20) as usize] += 1;
            }
        }
        run_start = i + 1;
    }

    let average = if count > 0 { printables as f64 / count as f64 } else { 0.0 };
    let string_entropy: f64 = dist
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / printables as f64; -p * p.log2() })
        .sum();

    out.extend([count as f32, average as f32, printables as f32]);
    let divisor = if printables > 0 { printables as f32 } else { 1.0 };
    out.extend(dist.iter().map(|&c| c as f32 / divisor));

    let paths = count_matches(bytes, |s| (s.len() >= 3 && s[0].eq_ignore_ascii_case(&b'c') && &s[1..3] == b":\\").then_some(3));
    let urls = count_matches(bytes, |s| {
        if s.len() < 7 || !s[..4].eq_ignore_ascii_case(b"http") {
            return None;
        }
        let rest = if s[4].eq_ignore_ascii_case(&b's') { 5 } else { 4 };
        s[rest..].starts_with(b"://").then_some(rest + 3)
    });
    let registry = count_matches(bytes, |s| s.starts_with(b"HKEY_").then_some(5));
    let mz = count_matches(bytes, |s| s.starts_with(b"MZ").then_some(2));
    out.extend([string_entropy as f32, paths as f32, urls as f32, registry as f32, mz as f32]);
}

fn flag(value: bool) -> f32 {
    if value { 1.0 } else { 0.0 }
}

fn push_header(out: &mut Vec<f32>, pe: Option<&Pe>) {
    let Some(pe) = pe else {
        out.extend([0.0; 2 + 15 + 1 + 11 + 12]);
        return;
    };
    let machine = match pe.machine {
        0x14c => 1.0,
        0x8664 => 2.0,
        0x1c0 | 0x1c2 | 0x1c4 => 3.0,
        0xaa64 => 4.0,
        0x200 => 5.0,
        _ => 0.0,
    };
    out.extend([pe.timestamp as f32, machine]);
    out.extend(COFF_FLAGS.iter().map(|&bit| flag(pe.characteristics & bit != 0)));
    out.push(if SUBSYSTEMS.contains(&pe.subsystem) { pe.subsystem as f32 } else { 0.0 });
    out.extend(DLL_FLAGS.iter().map(|&bit| flag(pe.dll_characteristics & bit != 0)));
    out.extend([
        if pe.magic == 0x20b { 2.0 } else { 1.0 },
        pe.image_version.0 as f32,
        pe.image_version.1 as f32,
        pe.linker_version.0 as f32,
        pe.linker_version.1 as f32,
        pe.os_version.0 as f32,
        pe.os_version.1 as f32,
        pe.subsystem_version.0 as f32,
        pe.subsystem_version.1 as f32,
        pe.sizeof_code as f32,
        pe.sizeof_headers as f32,
        pe.sizeof_heap_commit as f32,
    ]);
}

/// Appends the section features and returns the highest section entropy.
fn push_sections(out: &mut Vec<f32>, bytes: &[u8], pe: Option<&Pe>) -> f64 {
    let size = bytes.len() as u64;
    let Some(pe) = pe.filter(|pe| !pe.sections.is_empty()) else {
        out.extend([0.0; 15]);
        out.push(size.saturating_sub(pe.map_or(0, |pe| pe.sizeof_headers as u64)) as f32);
        return 0.0;
    };
    let sections = &pe.sections;
    let count = |predicate: &dyn Fn(&pe::Section) -> bool| sections.iter().filter(|s| predicate(s)).count() as f32;
    let has = |section: &pe::Section, bits: u32| section.characteristics & bits == bits;

    let entropies: Vec<f64> = sections.iter().map(|s| entropy(pe.section_data(bytes, s))).collect();
    let entropy_max = entropies.iter().copied().fold(f64::MIN, f64::max);
    let entropy_min = entropies.iter().copied().fold(f64::MAX, f64::min);
    let entropy_mean = entropies.iter().sum::<f64>() / entropies.len() as f64;
    let size_sum: u64 = sections.iter().map(|s| s.raw_size as u64).sum();

    out.extend([
        sections.len() as f32,
        count(&|s| s.raw_size == 0),
        count(&|s| s.name.is_empty()),
        count(&|s| has(s, pe::SECTION_READ | pe::SECTION_EXECUTE)),
        count(&|s| has(s, pe::SECTION_WRITE)),
        count(&|s| has(s, pe::SECTION_WRITE | pe::SECTION_EXECUTE)),
        count(&|s| has(s, pe::SECTION_CODE)),
        count(&|s| !STANDARD_SECTIONS.contains(&s.name.as_str())),
        count(&|s| s.name.starts_with("UPX")),
        entropy_max as f32,
        entropy_min as f32,
        entropy_mean as f32,
        sections.iter().map(|s| s.raw_size).max().unwrap_or(0) as f32,
        size_sum as f32,
        sections.iter().map(|s| s.virtual_size as u64).sum::<u64>() as f32,
        size.saturating_sub(pe.sizeof_headers as u64).saturating_sub(size_sum) as f32,
    ]);
    entropy_max
}

fn push_imports(out: &mut Vec<f32>, pe: Option<&Pe>) {
    let Some(imports) = pe.map(|pe| &pe.imports) else {
        out.extend([0.0; 2 + 32 + 74]);
        return;
    };
    out.extend([imports.dlls.len() as f32, imports.function_count as f32]);
    let lowercase: Vec<String> = imports.dlls.iter().map(|name| name.to_lowercase()).collect();
    out.extend(DLLS.iter().map(|&dll| flag(lowercase.iter().any(|name| name == dll))));
    out.extend(APIS.iter().map(|&api| flag(imports.functions.contains(api))));
}

pub fn extract(bytes: &[u8]) -> Extracted {
    let pe = pe::parse(bytes);
    let mut out = Vec::with_capacity(FEATURE_COUNT);

    let mut histogram = [0u64; 256];
    for &byte in bytes {
        histogram[byte as usize] += 1;
    }
    push_normalized(&mut out, &histogram);
    push_normalized(&mut out, &byte_entropy_histogram(bytes));
    push_strings(&mut out, bytes);

    out.extend([bytes.len() as f32, pe.as_ref().map_or(0, |pe| pe.export_count) as f32]);
    push_header(&mut out, pe.as_ref());
    let max_section_entropy = push_sections(&mut out, bytes, pe.as_ref());
    push_imports(&mut out, pe.as_ref());

    for i in 0..DATA_DIRECTORIES {
        let directory = pe.as_ref().and_then(|pe| pe.data_directories.get(i));
        out.extend([directory.map_or(0, |d| d.size) as f32, directory.map_or(0, |d| d.rva) as f32]);
    }

    debug_assert_eq!(out.len(), FEATURE_COUNT);
    Extracted { vector: out, pe, max_section_entropy }
}
