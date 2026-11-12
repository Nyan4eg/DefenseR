"""Convert the EMBER 2018 raw feature files into numpy arrays.

Usage: python prepare.py
Reads  data/ember2018/{train_features_N,test_features}.jsonl
Writes data/{train,test}_{X,y}.npy  (unlabeled rows are dropped)
"""
import json
import sys
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

import numpy as np

from features import (COFF_FLAGS, DLL_FLAGS, FEATURE_COUNT, MACHINES, MAGICS, SUBSYSTEMS,
                      vectorize)

DATA = Path(__file__).parent / "data"
SOURCE = DATA / "ember2018"


def convert(path: Path):
    rows, labels = [], []
    # Values the name tables do not know: reported so a wrong table is noticed.
    unknown = Counter()
    with open(path, "rb") as f:
        for line in f:
            raw = json.loads(line)
            if raw["label"] not in (0, 1):
                continue
            coff, opt = raw["header"]["coff"], raw["header"]["optional"]
            if coff["machine"] not in MACHINES:
                unknown["machine:" + coff["machine"]] += 1
            if opt["subsystem"] not in SUBSYSTEMS:
                unknown["subsystem:" + opt["subsystem"]] += 1
            if opt["magic"] not in MAGICS:
                unknown["magic:" + opt["magic"]] += 1
            for name in coff["characteristics"]:
                if name not in COFF_FLAGS:
                    unknown["coff:" + name] += 1
            for name in opt["dll_characteristics"]:
                if name not in DLL_FLAGS:
                    unknown["dllchar:" + name] += 1
            rows.append(vectorize(raw))
            labels.append(raw["label"])
    out = np.vstack(rows) if rows else np.zeros((0, FEATURE_COUNT), dtype=np.float32)
    return path.name, out, np.asarray(labels, dtype=np.int8), unknown


def main():
    train_files = sorted(SOURCE.glob("train_features_*.jsonl"))
    test_file = SOURCE / "test_features.jsonl"
    if not train_files or not test_file.exists():
        sys.exit(f"EMBER files not found in {SOURCE}")

    with Pool(len(train_files) + 1) as pool:
        results = pool.map(convert, train_files + [test_file])

    unknown = Counter()
    for name, X, y, unk in results:
        print(f"{name}: {len(y)} rows, {int(y.sum())} malicious", flush=True)
        unknown.update(unk)
    print("unknown names:", dict(unknown.most_common(40)))

    train = results[:-1]
    np.save(DATA / "train_X.npy", np.vstack([r[1] for r in train]))
    np.save(DATA / "train_y.npy", np.concatenate([r[2] for r in train]))
    np.save(DATA / "test_X.npy", results[-1][1])
    np.save(DATA / "test_y.npy", results[-1][2])


if __name__ == "__main__":
    main()
