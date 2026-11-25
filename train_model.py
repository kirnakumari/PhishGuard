"""Train the PhishGuard URL classifier from a labelled CSV supplied by the user.

Expected CSV columns by default:
    url,label

Labels accepted:
    phishing / malicious / bad / 1
    legitimate / benign / safe / good / 0

Example:
    python train_model.py --dataset data/phishing_urls.csv
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from url_features import extract_url_features

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "models"
MODEL_PATH = MODEL_DIR / "url_phishing_model.joblib"
METRICS_PATH = MODEL_DIR / "model_metrics.json"

PHISHING_LABELS = {"1", "phishing", "malicious", "bad", "fraud", "unsafe"}
LEGIT_LABELS = {"0", "legitimate", "benign", "safe", "good", "clean"}

def normalize_label(value) -> int:
    label = str(value).strip().lower()
    if label in PHISHING_LABELS:
        return 1
    if label in LEGIT_LABELS:
        return 0
    raise ValueError(
        f"Unsupported label {value!r}. Use 1/phishing or 0/legitimate."
    )

def main():
    parser = argparse.ArgumentParser(description="Train PhishGuard URL phishing classifier")
    parser.add_argument("--dataset", required=True, help="Path to labelled CSV")
    parser.add_argument("--url-column", default="url", help="URL column name")
    parser.add_argument("--label-column", default="label", help="Label column name")
    args = parser.parse_args()

    csv_path = Path(args.dataset)
    if not csv_path.is_absolute():
        csv_path = ROOT / csv_path
    if not csv_path.exists():
        raise SystemExit(f"Dataset not found: {csv_path}")

    data = pd.read_csv(csv_path)
    if args.url_column not in data.columns or args.label_column not in data.columns:
        raise SystemExit(
            f"CSV must contain columns {args.url_column!r} and {args.label_column!r}. "
            f"Found: {list(data.columns)}"
        )

    data = data[[args.url_column, args.label_column]].dropna()
    data[args.url_column] = data[args.url_column].astype(str).str.strip()
    data = data[data[args.url_column] != ""].drop_duplicates(subset=[args.url_column])
    if len(data) < 20:
        raise SystemExit("At least 20 labelled URL rows are required; more balanced data is strongly recommended.")

    try:
        y = data[args.label_column].map(normalize_label)
    except ValueError as exc:
        raise SystemExit(str(exc))

    if y.nunique() != 2 or y.value_counts().min() < 2:
        raise SystemExit("Dataset must contain at least two examples of each class: phishing and legitimate.")

    X = [extract_url_features(url) for url in data[args.url_column]]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = Pipeline([
        ("vectorizer", DictVectorizer(sparse=False)),
        ("classifier", RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        ))
    ])
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, list(model.named_steps["classifier"].classes_).index(1)]

    metrics = {
        "dataset_file": csv_path.name,
        "total_rows_after_cleaning": int(len(data)),
        "training_rows": int(len(X_train)),
        "testing_rows": int(len(X_test)),
        "class_counts": {
            "legitimate": int((y == 0).sum()),
            "phishing": int((y == 1).sum())
        },
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision_phishing": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
        "recall_phishing": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
        "f1_phishing": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
        "confusion_matrix_labels_order": ["legitimate", "phishing"],
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
        "classification_report": classification_report(
            y_test, predictions, labels=[0, 1],
            target_names=["legitimate", "phishing"], output_dict=True, zero_division=0
        ),
        "note": "Metrics are from this dataset's held-out split; they are not a guarantee of real-world performance."
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    print(f"\nSaved model: {MODEL_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")

if __name__ == "__main__":
    main()
