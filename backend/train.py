# coding: utf-8
"""Train and compare the phishing-URL classifiers.

Fully reproducible and offline: reads the URL lists in ``raw_datasets/``,
extracts lexical features with :mod:`featureExtraction`, trains three models
(Random Forest, Histogram Gradient Boosting, Logistic Regression), evaluates
them, and saves every model plus a combined metadata file describing the run and
naming the best model as the default.

Run with::

    python train.py
"""

from __future__ import annotations

import json
import pickle
import platform
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import featureExtraction as fe

ROOT = Path(__file__).parent
RAW = ROOT / "raw_datasets"
MODELS_DIR = ROOT / "models"
METADATA_PATH = MODELS_DIR / "models_metadata.json"

RANDOM_STATE = 42

# label 0 = legitimate, label 1 = phishing
DATASETS = [
    (RAW / "legitimate_urls.txt", 0),
    (RAW / "100-legitimate-art.txt", 0),
    # Curated realistic deep links so the model does not equate "long URL" with
    # "phishing" (see scripts/generate_legit_deeplinks.py).
    (RAW / "legitimate_deeplinks.txt", 0),
    (RAW / "1000-phishing.txt", 1),
]


def make_models() -> dict:
    """Return the model zoo: name -> (display_name, estimator)."""
    return {
        "random_forest": (
            "Random Forest",
            RandomForestClassifier(
                n_estimators=300,
                min_samples_leaf=2,
                class_weight="balanced",
                n_jobs=-1,
                random_state=RANDOM_STATE,
            ),
        ),
        "hist_gradient_boosting": (
            "Histogram Gradient Boosting",
            HistGradientBoostingClassifier(
                max_iter=400,
                learning_rate=0.08,
                max_leaf_nodes=31,
                l2_regularization=1.0,
                random_state=RANDOM_STATE,
            ),
        ),
        "logistic_regression": (
            "Logistic Regression",
            Pipeline(
                [
                    ("scaler", StandardScaler()),
                    ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
                ]
            ),
        ),
    }


def load_urls(path: Path) -> list[str]:
    urls: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip().strip('"').strip()
        if not line or line.lower() == "websites":
            continue
        urls.append(line)
    return urls


def build_dataset() -> pd.DataFrame:
    rows: list[dict] = []
    seen: set[str] = set()
    for path, label in DATASETS:
        if not path.exists():
            raise FileNotFoundError(f"Missing dataset: {path}")
        for url in load_urls(path):
            if url in seen:
                continue
            seen.add(url)
            features = fe.extract_features(url)
            features["label"] = label
            rows.append(features)
    return pd.DataFrame(rows)


def evaluate(model, X_train, X_test, y_train, y_test, X, y) -> dict:
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    cv_splitter = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv = cross_val_score(model, X, y, cv=cv_splitter, scoring="accuracy")
    return {
        "test_accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "test_precision": round(float(precision_score(y_test, pred)), 4),
        "test_recall": round(float(recall_score(y_test, pred)), 4),
        "test_f1": round(float(f1_score(y_test, pred)), 4),
        "test_roc_auc": round(float(roc_auc_score(y_test, proba)), 4),
        "cv5_accuracy_mean": round(float(cv.mean()), 4),
        "cv5_accuracy_std": round(float(cv.std()), 4),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
    }


def main() -> None:
    MODELS_DIR.mkdir(exist_ok=True)

    print("Building dataset from raw_datasets/ ...")
    data = build_dataset()
    counts = data["label"].value_counts().to_dict()
    print(f"  samples: {len(data)}  "
          f"(legitimate={counts.get(0, 0)}, phishing={counts.get(1, 0)})")

    X = data[fe.FEATURE_NAMES]
    y = data["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_STATE, stratify=y
    )

    models_meta: dict[str, dict] = {}
    fitted: dict[str, object] = {}
    for name, (display, estimator) in make_models().items():
        print(f"\nTraining {display} ...")
        metrics = evaluate(estimator, X_train, X_test, y_train, y_test, X, y)
        fitted[name] = estimator
        models_meta[name] = {"display_name": display, "metrics": metrics}
        with (MODELS_DIR / f"{name}.sav").open("wb") as fh:
            pickle.dump(estimator, fh)
        print(f"  accuracy={metrics['test_accuracy']:.4f} "
              f"auc={metrics['test_roc_auc']:.4f} "
              f"cv={metrics['cv5_accuracy_mean']:.4f}")

    # Choose the default model: best CV accuracy, tie-break on ROC AUC.
    default_model = max(
        models_meta,
        key=lambda n: (
            models_meta[n]["metrics"]["cv5_accuracy_mean"],
            models_meta[n]["metrics"]["test_roc_auc"],
        ),
    )
    print(f"\nDefault model (best CV accuracy): {default_model}")

    # Feature importances for the default model (permutation importance works
    # for every estimator type and is directly comparable).
    print("Computing permutation importances for the default model ...")
    perm = permutation_importance(
        fitted[default_model], X_test, y_test,
        n_repeats=10, random_state=RANDOM_STATE, n_jobs=-1,
    )
    importances = sorted(
        zip(fe.FEATURE_NAMES, perm.importances_mean),
        key=lambda kv: kv[1], reverse=True,
    )

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
        "numpy_version": np.__version__,
        "python_version": platform.python_version(),
        "random_state": RANDOM_STATE,
        "n_samples": int(len(data)),
        "n_legitimate": int(counts.get(0, 0)),
        "n_phishing": int(counts.get(1, 0)),
        "feature_names": fe.FEATURE_NAMES,
        "feature_descriptions": dict(fe.FEATURE_DESCRIPTIONS),
        "default_model": default_model,
        "models": models_meta,
        "feature_importances": {
            name: round(float(v), 4) for name, v in importances
        },
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("\n=== Model comparison (held-out test set) ===")
    header = f"{'model':<28}{'acc':>8}{'prec':>8}{'rec':>8}{'f1':>8}{'auc':>8}{'cv':>8}"
    print(header)
    for name, meta in models_meta.items():
        m = meta["metrics"]
        star = " *" if name == default_model else ""
        print(f"{meta['display_name']:<28}"
              f"{m['test_accuracy']:>8.3f}{m['test_precision']:>8.3f}"
              f"{m['test_recall']:>8.3f}{m['test_f1']:>8.3f}"
              f"{m['test_roc_auc']:>8.3f}{m['cv5_accuracy_mean']:>8.3f}{star}")
    print("\n(* = default model)")
    print(f"Saved {len(fitted)} models + metadata -> {MODELS_DIR}/")


if __name__ == "__main__":
    main()
