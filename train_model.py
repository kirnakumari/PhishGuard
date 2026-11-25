
"""Train PhishGuard using domain-wise validation.

Expected CSV columns: url,label

Labels:
    phishing / malicious / bad / 1
    legitimate / benign / safe / good / 0
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
import tldextract

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score
)

from url_features import extract_url_features


ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "models"

# Versioned output: production model is not overwritten.
MODEL_PATH = MODEL_DIR / "url_phishing_model_v3.joblib"
METRICS_PATH = MODEL_DIR / "model_metrics_v3.json"

PHISHING_LABELS = {
    "1", "phishing", "malicious", "bad", "fraud", "unsafe"
}

LEGIT_LABELS = {
    "0", "legitimate", "benign", "safe", "good", "clean"
}

# Uses the package's bundled public suffix data.
extract_domain = tldextract.TLDExtract(suffix_list_urls=())


def normalize_label(value) -> int:
    label = str(value).strip().lower()

    if label in PHISHING_LABELS:
        return 1

    if label in LEGIT_LABELS:
        return 0

    raise ValueError(f"Unsupported label: {value!r}")


def get_domain(url: str) -> str:
    """Return registrable domain for grouping related URLs."""

    value = str(url).strip()

    if not value.lower().startswith(("http://", "https://")):
        value = "http://" + value

    parsed = urlparse(value)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return "invalid_" + str(abs(hash(value)))

    result = extract_domain(hostname)

    if result.domain and result.suffix:
        return result.domain + "." + result.suffix

    return hostname


def main():

    parser = argparse.ArgumentParser(
        description="Train PhishGuard URL classifier"
    )

    parser.add_argument("--dataset", required=True)
    parser.add_argument("--url-column", default="url")
    parser.add_argument("--label-column", default="label")

    args = parser.parse_args()

    csv_path = Path(args.dataset)

    if not csv_path.is_absolute():
        csv_path = ROOT / csv_path

    if not csv_path.exists():
        raise SystemExit(f"Dataset not found: {csv_path}")

    data = pd.read_csv(csv_path)

    required = [args.url_column, args.label_column]

    if not all(col in data.columns for col in required):
        raise SystemExit(
            f"CSV must contain columns {required}. "
            f"Found: {list(data.columns)}"
        )

    data = data[required].dropna().copy()

    data[args.url_column] = (
        data[args.url_column].astype(str).str.strip()
    )

    data = data[
        data[args.url_column] != ""
    ].drop_duplicates(subset=[args.url_column])

    data["target"] = data[args.label_column].map(normalize_label)

    if data["target"].nunique() != 2:
        raise SystemExit("Both phishing and legitimate classes are required.")

    if data["target"].value_counts().min() < 5:
        raise SystemExit("At least 5 examples per class are required.")

    # Group URLs by registrable domain.
    data["domain_group"] = data[args.url_column].apply(get_domain)

    X = [
        extract_url_features(url)
        for url in data[args.url_column]
    ]

    y = data["target"].reset_index(drop=True)
    groups = data["domain_group"].reset_index(drop=True)

    # Five-fold stratified group validation.
    # One fold is held out for testing.
    splitter = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=42
    )

    selected_split = None
    best_difference = float("inf")

    for train_idx, test_idx in splitter.split(X, y, groups):

        train_classes = set(y.iloc[train_idx])
        test_classes = set(y.iloc[test_idx])

        if len(train_classes) != 2 or len(test_classes) != 2:
            continue

        difference = abs(len(test_idx) / len(data) - 0.20)

        if difference < best_difference:
            best_difference = difference
            selected_split = (train_idx, test_idx)

    if selected_split is None:
        raise SystemExit(
            "Could not create a valid domain-wise split. "
            "Check whether both classes have enough distinct domains."
        )

    train_idx, test_idx = selected_split

    X_train = [X[i] for i in train_idx]
    X_test = [X[i] for i in test_idx]

    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    train_domains = set(groups.iloc[train_idx])
    test_domains = set(groups.iloc[test_idx])

    overlap = train_domains.intersection(test_domains)

    if overlap:
        raise SystemExit("Domain leakage detected. Training stopped.")

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

    print("Training model with domain-wise split...")

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    classifier = model.named_steps["classifier"]

    phishing_index = list(classifier.classes_).index(1)

    probabilities = model.predict_proba(X_test)[:, phishing_index]

    metrics = {
        "dataset_file": csv_path.name,
        "validation_method": "StratifiedGroupKFold",
        "split_seed": 42,
        "total_rows": int(len(data)),
        "training_rows": int(len(train_idx)),
        "testing_rows": int(len(test_idx)),
        "training_domains": int(len(train_domains)),
        "testing_domains": int(len(test_domains)),
        "domain_overlap": int(len(overlap)),
        "class_counts": {
            "legitimate": int((y == 0).sum()),
            "phishing": int((y == 1).sum())
        },
        "accuracy": round(
            float(accuracy_score(y_test, predictions)), 4
        ),
        "precision_phishing": round(
            float(precision_score(y_test, predictions, zero_division=0)), 4
        ),
        "recall_phishing": round(
            float(recall_score(y_test, predictions, zero_division=0)), 4
        ),
        "f1_phishing": round(
            float(f1_score(y_test, predictions, zero_division=0)), 4
        ),
        "roc_auc": round(
            float(roc_auc_score(y_test, probabilities)), 4
        ),
        "confusion_matrix_labels_order": [
            "legitimate", "phishing"
        ],
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=[0, 1]
        ).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            output_dict=True,
            zero_division=0
        ),
        "note": (
            "Domain-wise held-out evaluation. "
            "This is not a guarantee of real-world performance."
        )
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH, compress=3)

    METRICS_PATH.write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8"
    )

    print(json.dumps(metrics, indent=2))

    print(f"\nSaved model: {MODEL_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")


if __name__ == "__main__":
    main()
