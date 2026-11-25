
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import joblib
import requests

from url_features import extract_url_features


# ========== CONFIGURATION ==========

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "banking",
    "password", "secure", "update", "free",
    "gift", "winner", "confirm", "wallet"
]

SHORTENED_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "shorturl.at", "cutt.ly"
]

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "models"
    / "url_phishing_model.joblib"
)

MODEL_URL = (
    "https://github.com/kirnakumari/PhishGuard/"
    "releases/download/v1.0.0/"
    "url_phishing_model_compressed.joblib"
)


# ========== MODEL LOADING ==========

@lru_cache(maxsize=1)
def _load_model():

    try:
        if not MODEL_PATH.exists():

            MODEL_PATH.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            response = requests.get(
                MODEL_URL,
                timeout=180
            )

            response.raise_for_status()

            temp_path = MODEL_PATH.with_suffix(".tmp")

            temp_path.write_bytes(response.content)

            temp_path.replace(MODEL_PATH)

        return joblib.load(MODEL_PATH)

    except Exception as error:
        print("ML Model loading error:", error)
        return None


# ========== RISK CLASSIFICATION ==========

def _classify(score):

    if score >= 70:
        return "High"

    if score >= 35:
        return "Medium"

    return "Low"


# ========== URL SCANNER ==========

def scan_url(url):

    url = str(url or "").strip()

    if not url:
        return {
            "risk_score": 0,
            "risk_level": "Invalid",
            "result": "Please enter a URL.",
            "checks": [],
            "ml_status": "not_available",
            "ml_probability": None
        }

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.hostname or ""

    if not domain or "." not in domain:
        return {
            "risk_score": 0,
            "risk_level": "Invalid",
            "result": "Invalid URL format.",
            "checks": [],
            "ml_status": "not_available",
            "ml_probability": None
        }

    score = 0
    checks = []

    # HTTPS check
    if parsed.scheme.lower() != "https":
        score += 20
        checks.append("URL does not use HTTPS.")
    else:
        checks.append("HTTPS connection is used.")

    # IP address check
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 25
        checks.append(
            "URL uses an IP address instead of a domain name."
        )
    else:
        checks.append("URL uses a domain name.")

    # Shortened URL check
    if domain.lower() in SHORTENED_DOMAINS:
        score += 20
        checks.append("URL uses a shortened domain.")
    else:
        checks.append("No known URL shortener detected.")

    # Suspicious keyword check
    matched_keywords = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in url.lower()
    ]

    if matched_keywords:
        score += min(len(matched_keywords) * 10, 30)
        checks.append(
            "Suspicious keywords found: "
            + ", ".join(matched_keywords)
        )
    else:
        checks.append("No listed suspicious keywords found.")

    # Special character check
    if "@" in url:
        score += 20
        checks.append("URL contains an @ symbol.")

    # URL length check
    if len(url) > 100:
        score += 10
        checks.append("URL is unusually long.")
    else:
        checks.append("URL length looks normal.")

    rule_score = min(score, 100)

    # ========== MACHINE LEARNING ==========

    model = _load_model()

    ml_probability = None
    ml_status = "not_trained"

    if model is not None:

        try:
            features = extract_url_features(url)

            probabilities = model.predict_proba(
                [features]
            )[0]

            classes = list(
                model.named_steps["classifier"].classes_
            )

            phishing_index = classes.index(1)

            ml_probability = float(
                probabilities[phishing_index]
            )

            # Combined risk score
            final_score = round(
                (0.40 * rule_score)
                + (0.60 * ml_probability * 100)
            )

            score = final_score
            ml_status = "active"

            checks.append(
                f"ML phishing probability: "
                f"{ml_probability * 100:.1f}%."
            )

            checks.append(
                f"Rule-based score: {rule_score}/100."
            )

            checks.append(
                "Combined score: 40% rule-based + 60% ML."
            )

        except Exception as error:

            print("ML prediction error:", error)

            score = rule_score
            ml_status = "model_error"

            checks.append(
                "ML prediction failed. "
                "Rule-based result is shown."
            )

    else:

        score = rule_score

        checks.append(
            "ML model unavailable. "
            "Rule-based analysis is shown."
        )

    # ========== FINAL RESULT ==========

    risk_level = _classify(score)

    if ml_status == "active":

        result = (
            "Combined rule-based and machine-learning "
            "analysis completed. This is a risk estimate, "
            "not proof that a URL is malicious or safe."
        )

    else:

        result = (
            "Rule-based URL analysis completed. "
            "ML model is currently unavailable."
        )

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "result": result,
        "checks": checks,
        "ml_status": ml_status,
        "ml_probability": ml_probability,
        "rule_score": rule_score
    }
