"""Train the PE file model on EMBER 2018 and export it for the app.

Usage: python train.py
Reads  data/{train,test}_{X,y}.npy (from prepare.py)
Writes ../src-tauri/model/pe-model.onnx and pe-model.json

Thresholds are picked on a validation split of the training set; the metrics
in pe-model.json are measured on the EMBER test set with the exported ONNX
model, i.e. with exactly what the app runs.
"""
import json
from datetime import date
from pathlib import Path

import lightgbm as lgb
import numpy as np
import onnxruntime as ort
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

from features import FEATURE_COUNT, NAMES

DATA = Path(__file__).parent / "data"
OUT = Path(__file__).parent.parent / "src-tauri" / "model"

# False positive rates the two verdict thresholds aim for.
SUSPICIOUS_FPR = 0.01
MALICIOUS_FPR = 0.001


def threshold_at_fpr(scores: np.ndarray, labels: np.ndarray, fpr: float) -> float:
    benign = np.sort(scores[labels == 0])
    return float(benign[min(len(benign) - 1, int(np.ceil(len(benign) * (1 - fpr))))])


def onnx_scores(path: Path, X: np.ndarray) -> np.ndarray:
    session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    name = session.get_inputs()[0].name
    parts = [session.run(["probabilities"], {name: X[i:i + 50_000]})[0][:, 1] for i in range(0, len(X), 50_000)]
    return np.concatenate(parts)


def main():
    X = np.load(DATA / "train_X.npy")
    y = np.load(DATA / "train_y.npy")
    assert X.shape[1] == FEATURE_COUNT
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.1, random_state=0, stratify=y)
    del X

    model = lgb.LGBMClassifier(
        n_estimators=1000, learning_rate=0.08, num_leaves=128, min_child_samples=50,
        colsample_bytree=0.5, n_jobs=12, verbose=-1,
    )
    model.fit(
        X_train, y_train, eval_set=[(X_val, y_val)], eval_metric="auc",
        callbacks=[lgb.early_stopping(50), lgb.log_evaluation(50)],
    )
    trees = model.best_iteration_ or model.n_estimators
    print("trees:", trees, flush=True)

    OUT.mkdir(exist_ok=True)
    onnx_model = convert_lightgbm(
        model, initial_types=[("input", FloatTensorType([None, FEATURE_COUNT]))], zipmap=False,
    )
    model_path = OUT / "pe-model.onnx"
    model_path.write_bytes(onnx_model.SerializeToString())
    print(f"onnx: {model_path.stat().st_size / 1e6:.1f} MB", flush=True)

    val_scores = onnx_scores(model_path, X_val)
    suspicious = threshold_at_fpr(val_scores, y_val, SUSPICIOUS_FPR)
    malicious = threshold_at_fpr(val_scores, y_val, MALICIOUS_FPR)

    X_test = np.load(DATA / "test_X.npy")
    y_test = np.load(DATA / "test_y.npy")
    scores = onnx_scores(model_path, X_test)
    drift = float(np.abs(scores - model.predict_proba(X_test)[:, 1]).max())
    print("max |onnx - lightgbm| on test:", drift)

    def rates(threshold):
        flagged = scores >= threshold
        return float(flagged[y_test == 1].mean()), float(flagged[y_test == 0].mean())

    sus_tpr, sus_fpr = rates(suspicious)
    mal_tpr, mal_fpr = rates(malicious)
    meta = {
        "featureCount": FEATURE_COUNT,
        "dataset": "EMBER 2018",
        "trained": date.today().isoformat(),
        "trainSamples": int(len(y_train)),
        "testSamples": int(len(y_test)),
        "trees": int(trees),
        "auc": float(roc_auc_score(y_test, scores)),
        "suspiciousThreshold": suspicious,
        "maliciousThreshold": malicious,
        "suspiciousDetection": sus_tpr,
        "suspiciousFalsePositives": sus_fpr,
        "maliciousDetection": mal_tpr,
        "maliciousFalsePositives": mal_fpr,
    }
    (OUT / "pe-model.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))

    gain = model.booster_.feature_importance(importance_type="gain")
    top = np.argsort(gain)[::-1][:25]
    print("top features:", ", ".join(NAMES[i] for i in top))


if __name__ == "__main__":
    main()
