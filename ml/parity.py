"""Check that the Rust extractor matches the Python feature definition.

For a sample of local PE files, builds EMBER-style raw features with LIEF,
vectorizes them with `features.vectorize`, and compares the result with the
output of the Rust example `pe_features`.

Usage: python parity.py [max_files]
"""
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import lief
import numpy as np

from features import COFF_FLAGS, DLL_FLAGS, MACHINES, MAGICS, NAMES, SUBSYSTEMS, vectorize

ROOT = Path(__file__).parent.parent
EXTRACTOR = ROOT / "src-tauri" / "target" / "debug" / "examples" / "pe_features.exe"

MACHINE_NAMES = {0x14c: "I386", 0x8664: "AMD64", 0x1c0: "ARM", 0x1c2: "THUMB", 0x1c4: "ARMNT",
                 0xaa64: "ARM64", 0x200: "IA64"}
COFF_BITS = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000,
             0x4000, 0x8000]
DLL_BITS = [0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000]
SUBSYSTEM_NAMES = {code: name for name, code in SUBSYSTEMS.items()}
MAGIC_NAMES = {0x10b: "PE32", 0x20b: "PE32_PLUS"}
SECTION_BITS = {0x20: "CNT_CODE", 0x20000000: "MEM_EXECUTE", 0x40000000: "MEM_READ",
                0x80000000: "MEM_WRITE"}


def byte_entropy(data: np.ndarray):
    """EMBER's ByteEntropyHistogram.raw_features."""
    window, step = 2048, 1024

    def bin_counts(block):
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / window
        wh = np.where(c)[0]
        h = np.sum(-p[wh] * np.log2(p[wh])) * 2
        hbin = int(h * 2)
        return (15 if hbin == 16 else hbin), c

    output = np.zeros((16, 16), dtype=np.int64)
    if data.shape[0] < window:
        hbin, c = bin_counts(data)
        output[hbin, :] += c
    else:
        shape = data.shape[:-1] + (data.shape[-1] - window + 1, window)
        strides = data.strides + (data.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(data, shape=shape, strides=strides)[::step, :]
        for block in blocks:
            hbin, c = bin_counts(block)
            output[hbin, :] += c
    return output.flatten().tolist()


def strings(bytez: bytes):
    """EMBER's StringExtractor.raw_features."""
    allstrings = re.findall(b"[\x20-\x7f]{5,}", bytez)
    if allstrings:
        lengths = [len(s) for s in allstrings]
        avlength = sum(lengths) / len(lengths)
        shifted = np.frombuffer(b"".join(allstrings), dtype=np.uint8) - 0x20
        c = np.bincount(shifted, minlength=96)
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        entropy = np.sum(-p[wh] * np.log2(p[wh]))
    else:
        avlength, c, entropy, csum = 0, np.zeros(96), 0, 0
    return {
        "numstrings": len(allstrings), "avlength": avlength, "printabledist": c.tolist(),
        "printables": int(csum), "entropy": float(entropy),
        "paths": len(re.findall(b"c:\\\\", bytez, re.IGNORECASE)),
        "urls": len(re.findall(b"https?://", bytez, re.IGNORECASE)),
        "registry": len(re.findall(b"HKEY_", bytez)),
        "MZ": len(re.findall(b"MZ", bytez)),
    }


def raw_features(bytez: bytes) -> dict:
    data = np.frombuffer(bytez, dtype=np.uint8)
    raw = {
        "histogram": np.bincount(data, minlength=256).tolist(),
        "byteentropy": byte_entropy(data),
        "strings": strings(bytez),
        "general": {"size": len(bytez)},
        "header": {
            "coff": {"timestamp": 0, "machine": "", "characteristics": []},
            "optional": {
                "subsystem": "", "dll_characteristics": [], "magic": "",
                "major_image_version": 0, "minor_image_version": 0,
                "major_linker_version": 0, "minor_linker_version": 0,
                "major_operating_system_version": 0, "minor_operating_system_version": 0,
                "major_subsystem_version": 0, "minor_subsystem_version": 0,
                "sizeof_code": 0, "sizeof_headers": 0, "sizeof_heap_commit": 0,
            },
        },
        "section": {"entry": "", "sections": []},
        "imports": {},
        "exports": [],
        "datadirectories": [],
    }
    binary = lief.PE.parse(list(bytez))
    if binary is None:
        return raw

    header, opt = binary.header, binary.optional_header
    raw["header"]["coff"] = {
        "timestamp": header.time_date_stamps,
        "machine": MACHINE_NAMES.get(int(header.machine), "OTHER"),
        "characteristics": [n for n, bit in zip(COFF_FLAGS, COFF_BITS) if int(header.characteristics) & bit],
    }
    raw["header"]["optional"] = {
        "subsystem": SUBSYSTEM_NAMES.get(int(opt.subsystem), "OTHER"),
        "dll_characteristics": [n for n, bit in zip(DLL_FLAGS, DLL_BITS) if int(opt.dll_characteristics) & bit],
        "magic": MAGIC_NAMES.get(int(opt.magic), ""),
        "major_image_version": opt.major_image_version,
        "minor_image_version": opt.minor_image_version,
        "major_linker_version": opt.major_linker_version,
        "minor_linker_version": opt.minor_linker_version,
        "major_operating_system_version": opt.major_operating_system_version,
        "minor_operating_system_version": opt.minor_operating_system_version,
        "major_subsystem_version": opt.major_subsystem_version,
        "minor_subsystem_version": opt.minor_subsystem_version,
        "sizeof_code": opt.sizeof_code,
        "sizeof_headers": opt.sizeof_headers,
        "sizeof_heap_commit": opt.sizeof_heap_commit,
    }
    raw["section"]["sections"] = [
        {
            "name": s.name, "size": s.size, "entropy": s.entropy, "vsize": s.virtual_size,
            "props": [n for bit, n in SECTION_BITS.items() if int(s.characteristics) & bit],
        }
        for s in binary.sections
    ]
    for lib in binary.imports:
        entries = raw["imports"].setdefault(lib.name, [])
        for entry in lib.entries:
            entries.append("ordinal" + str(entry.ordinal) if entry.is_ordinal else entry.name[:10000])
    raw["exports"] = [f.name for f in binary.exported_functions]
    raw["datadirectories"] = [{"size": d.size, "virtual_address": d.rva} for d in binary.data_directories]
    return raw


def sample_files(limit: int):
    files = []
    roots = [Path(r"C:\Windows\System32"), Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)")]
    patterns = [("*.exe", "*.dll", "*.sys"), ("*/*.exe", "*/*/*.exe", "*/*.dll"), ("*/*.exe", "*/*/*.exe", "*/*.dll")]
    per_root = limit // len(roots)
    for root, globs in zip(roots, patterns):
        found = []
        for pattern in globs:
            found.extend(root.glob(pattern))
        found = [f for f in sorted(found) if f.is_file() and f.stat().st_size < 64 * 1024 * 1024]
        step = max(1, len(found) // per_root)
        files.extend(found[::step][:per_root])
    return files


def main():
    lief.logging.disable()
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    files = sample_files(limit)

    expected, kept = [], []
    for path in files:
        try:
            bytez = path.read_bytes()
        except OSError:
            continue
        expected.append(vectorize(raw_features(bytez)))
        kept.append(path)

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as listing:
        listing.write("\n".join(str(p) for p in kept))
    output = subprocess.run([str(EXTRACTOR), listing.name], capture_output=True, check=True).stdout
    actual = [np.asarray(json.loads(line), dtype=np.float32) for line in output.splitlines()]
    assert len(actual) == len(kept), (len(actual), len(kept))

    mismatched_features = Counter()
    mismatched_files = 0
    examples = {}
    for path, want, got in zip(kept, expected, actual):
        if got.shape != want.shape:
            print("no vector for", path)
            mismatched_files += 1
            continue
        bad = np.where(~np.isclose(want, got, rtol=1e-4, atol=1e-6))[0]
        if len(bad):
            mismatched_files += 1
        for i in bad:
            mismatched_features[NAMES[i]] += 1
            examples.setdefault(NAMES[i], (str(path), float(want[i]), float(got[i])))

    print(f"files: {len(kept)}, with differences: {mismatched_files}")
    for name, count in mismatched_features.most_common(40):
        path, want, got = examples[name]
        print(f"  {name}: {count} files; e.g. {path}: python={want} rust={got}")


if __name__ == "__main__":
    main()
