# PhishGuard URL ML Upgrade

This is an add-on for the existing PhishGuard Streamlit project. It keeps the
existing URL rule checks and VirusTotal integration separate.

## Files to add/replace

Copy these files into the root of your existing PhishGuard project:
- `url_features.py` (new)
- `train_model.py` (new)
- `url_scanner.py` (replace existing)
- `requirements.txt` (replace existing)
- `models/` (folder; the trained model will be generated here)
- `data/README_DATASET.txt` (dataset instructions)

No change to `app.py`, `database.py`, `email_detector.py`, or `dashboard.py`
is required. The current URL Scanner already displays `result` and `checks`,
so it will show the ML probability and explanation after a model is trained.

## Step 1 — Install dependencies

In the VS Code terminal, from the PhishGuard project folder:

```bash
pip install -r requirements.txt
```

## Step 2 — Add a real labelled dataset

Create `data/phishing_urls.csv` with columns:

```csv
url,label
```

Use a genuine labelled dataset with both phishing and legitimate URL examples.
Accepted labels:
- `1`, `phishing`, `malicious`, `bad`, `fraud`, `unsafe`
- `0`, `legitimate`, `benign`, `safe`, `good`, `clean`

At least 20 rows are required by the script, but this is only a technical
minimum. A larger, balanced, representative dataset is necessary for meaningful
evaluation. Record the dataset source and licence.

## Step 3 — Train the model

```bash
python train_model.py --dataset data/phishing_urls.csv
```

The script creates:
- `models/url_phishing_model.joblib`
- `models/model_metrics.json`

It prints accuracy, precision, recall, F1-score and confusion matrix from a
stratified held-out test split. These are dataset-specific metrics, not a
guarantee of real-world accuracy.

## Step 4 — Run the app

```bash
streamlit run app.py
```

After the model file exists, URL scans will use:
- existing rule-based URL checks (40% of combined score)
- ML phishing probability (60% of combined score)
- existing VirusTotal reputation check (displayed separately by app.py)

If the model file is absent, URL scanning falls back to the original rule-based
analysis and continues to work.

## Important notes

- The feature extractor does not visit or execute the submitted URL.
- The model is not trained until you supply a real labelled dataset.
- Do not upload API keys, secrets, database files, or private scan history to GitHub.
- VirusTotal results are external threat-intelligence signals and are not the
  same thing as the local ML prediction.
- Do not describe the model as production-grade without proper validation,
  temporal testing, external testing and ongoing monitoring.
