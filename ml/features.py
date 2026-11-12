"""Feature vector shared by training and the app.

`vectorize` turns an EMBER-style raw feature record into the vector the model
is trained on. The Rust extractor (src-tauri/src/scanner/features.rs) must
produce the same vector from a file's bytes; `parity.py` checks that.

Only features that can be reproduced without LIEF are used: byte statistics,
strings, plain header fields, section aggregates and import names.
"""
import numpy as np

MACHINES = {"I386": 1, "AMD64": 2, "ARM": 3, "ARMNT": 3, "THUMB": 3, "ARM64": 4, "IA64": 5}

COFF_FLAGS = [
    "RELOCS_STRIPPED", "EXECUTABLE_IMAGE", "LINE_NUMS_STRIPPED", "LOCAL_SYMS_STRIPPED",
    "AGGRESSIVE_WS_TRIM", "LARGE_ADDRESS_AWARE", "BYTES_REVERSED_LO", "CHARA_32BIT_MACHINE",
    "DEBUG_STRIPPED", "REMOVABLE_RUN_FROM_SWAP", "NET_RUN_FROM_SWAP", "SYSTEM", "DLL",
    "UP_SYSTEM_ONLY", "BYTES_REVERSED_HI",
]

SUBSYSTEMS = {
    "NATIVE": 1, "WINDOWS_GUI": 2, "WINDOWS_CUI": 3, "OS2_CUI": 5, "POSIX_CUI": 7,
    "NATIVE_WINDOWS": 8, "WINDOWS_CE_GUI": 9, "EFI_APPLICATION": 10,
    "EFI_BOOT_SERVICE_DRIVER": 11, "EFI_RUNTIME_DRIVER": 12, "EFI_ROM": 13, "XBOX": 14,
    "WINDOWS_BOOT_APPLICATION": 16,
}

DLL_FLAGS = [
    "HIGH_ENTROPY_VA", "DYNAMIC_BASE", "FORCE_INTEGRITY", "NX_COMPAT", "NO_ISOLATION",
    "NO_SEH", "NO_BIND", "APPCONTAINER", "WDM_DRIVER", "GUARD_CF", "TERMINAL_SERVER_AWARE",
]

MAGICS = {"PE32": 1, "PE32_PLUS": 2}

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".bss",
    ".tls", ".CRT", ".didat", ".00cfg", ".gfids", ".xdata", ".debug", ".ndata", ".itext",
    "CODE", "DATA", "BSS",
}

DLLS = [
    "kernel32.dll", "user32.dll", "advapi32.dll", "gdi32.dll", "shell32.dll", "ole32.dll",
    "oleaut32.dll", "comctl32.dll", "msvcrt.dll", "ntdll.dll", "ws2_32.dll", "wsock32.dll",
    "wininet.dll", "urlmon.dll", "winhttp.dll", "shlwapi.dll", "crypt32.dll", "mscoree.dll",
    "msvbvm60.dll", "version.dll", "psapi.dll", "netapi32.dll", "iphlpapi.dll", "comdlg32.dll",
    "winmm.dll", "rpcrt4.dll", "setupapi.dll", "wtsapi32.dll", "userenv.dll", "dbghelp.dll",
    "vcruntime140.dll", "api-ms-win-crt-runtime-l1-1-0.dll",
]

APIS = [
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
]

DATA_DIRECTORIES = 15

SECTION_FEATURES = [
    "count", "zero_size", "empty_name", "read_execute", "write", "write_execute", "code",
    "nonstandard_name", "upx_name", "entropy_max", "entropy_min", "entropy_mean", "size_max",
    "size_sum", "vsize_sum", "overlay",
]

NAMES = (
    [f"hist_{i}" for i in range(256)]
    + [f"byteentropy_{i}" for i in range(256)]
    + ["str_count", "str_avlength", "str_printables"]
    + [f"str_dist_{i}" for i in range(96)]
    + ["str_entropy", "str_paths", "str_urls", "str_registry", "str_mz"]
    + ["size", "exports"]
    + ["timestamp", "machine"]
    + [f"coff_{n}" for n in COFF_FLAGS]
    + ["subsystem"]
    + [f"dllchar_{n}" for n in DLL_FLAGS]
    + ["magic", "image_major", "image_minor", "linker_major", "linker_minor", "os_major",
       "os_minor", "subsystem_major", "subsystem_minor", "sizeof_code", "sizeof_headers",
       "sizeof_heap_commit"]
    + [f"sec_{n}" for n in SECTION_FEATURES]
    + ["imp_dlls", "imp_functions"]
    + [f"dll_{n}" for n in DLLS]
    + [f"api_{n}" for n in APIS]
    + [f"dir_{i}_{part}" for i in range(DATA_DIRECTORIES) for part in ("size", "rva")]
)
FEATURE_COUNT = len(NAMES)


def vectorize(raw: dict) -> np.ndarray:
    out = np.zeros(FEATURE_COUNT, dtype=np.float32)
    pos = 0

    for key in ("histogram", "byteentropy"):
        counts = np.asarray(raw[key], dtype=np.float32)
        total = counts.sum()
        out[pos:pos + 256] = counts / total if total > 0 else counts
        pos += 256

    s = raw["strings"]
    out[pos:pos + 3] = (s["numstrings"], s["avlength"], s["printables"])
    pos += 3
    divisor = float(s["printables"]) if s["printables"] > 0 else 1.0
    out[pos:pos + 96] = np.asarray(s["printabledist"], dtype=np.float32) / divisor
    pos += 96
    out[pos:pos + 5] = (s["entropy"], s["paths"], s["urls"], s["registry"], s["MZ"])
    pos += 5

    size = raw["general"]["size"]
    out[pos:pos + 2] = (size, len(raw["exports"]))
    pos += 2

    coff = raw["header"]["coff"]
    opt = raw["header"]["optional"]
    out[pos:pos + 2] = (coff["timestamp"], MACHINES.get(coff["machine"], 0))
    pos += 2
    flags = set(coff["characteristics"])
    out[pos:pos + len(COFF_FLAGS)] = [name in flags for name in COFF_FLAGS]
    pos += len(COFF_FLAGS)
    out[pos] = SUBSYSTEMS.get(opt["subsystem"], 0)
    pos += 1
    flags = set(opt["dll_characteristics"])
    out[pos:pos + len(DLL_FLAGS)] = [name in flags for name in DLL_FLAGS]
    pos += len(DLL_FLAGS)
    out[pos:pos + 12] = (
        MAGICS.get(opt["magic"], 0),
        opt["major_image_version"], opt["minor_image_version"],
        opt["major_linker_version"], opt["minor_linker_version"],
        opt["major_operating_system_version"], opt["minor_operating_system_version"],
        opt["major_subsystem_version"], opt["minor_subsystem_version"],
        opt["sizeof_code"], opt["sizeof_headers"], opt["sizeof_heap_commit"],
    )
    pos += 12

    sections = raw["section"]["sections"]
    if sections:
        props = [set(sec["props"]) for sec in sections]
        entropies = [sec["entropy"] for sec in sections]
        sizes = [sec["size"] for sec in sections]
        size_sum = sum(sizes)
        out[pos:pos + 16] = (
            len(sections),
            sum(sec["size"] == 0 for sec in sections),
            sum(sec["name"] == "" for sec in sections),
            sum("MEM_READ" in p and "MEM_EXECUTE" in p for p in props),
            sum("MEM_WRITE" in p for p in props),
            sum("MEM_WRITE" in p and "MEM_EXECUTE" in p for p in props),
            sum("CNT_CODE" in p for p in props),
            sum(sec["name"] not in STANDARD_SECTIONS for sec in sections),
            sum(sec["name"].startswith("UPX") for sec in sections),
            max(entropies), min(entropies), sum(entropies) / len(entropies),
            max(sizes), size_sum, sum(sec["vsize"] for sec in sections),
            max(0, size - opt["sizeof_headers"] - size_sum),
        )
    else:
        out[pos + 15] = max(0, size - opt["sizeof_headers"])
    pos += 16

    imports = raw["imports"]
    out[pos:pos + 2] = (len(imports), sum(len(funcs) for funcs in imports.values()))
    pos += 2
    dlls = {name.lower() for name in imports}
    out[pos:pos + len(DLLS)] = [name in dlls for name in DLLS]
    pos += len(DLLS)
    functions = set()
    for funcs in imports.values():
        functions.update(funcs)
    out[pos:pos + len(APIS)] = [name in functions for name in APIS]
    pos += len(APIS)

    for i, directory in enumerate(raw["datadirectories"][:DATA_DIRECTORIES]):
        out[pos + 2 * i] = directory["size"]
        out[pos + 2 * i + 1] = directory["virtual_address"]
    pos += 2 * DATA_DIRECTORIES

    assert pos == FEATURE_COUNT
    return out
