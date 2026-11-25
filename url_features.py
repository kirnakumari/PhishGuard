"""Extract lexical and structural features from a URL without visiting it."""
import re
from urllib.parse import urlparse

SUSPICIOUS_TERMS = (
    "login", "verify", "account", "bank", "secure", "update",
    "password", "signin", "confirm", "wallet", "payment", "support",
    "free", "gift", "bonus", "claim", "reset", "webscr"
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "rebrand.ly", "shorturl.at"
}
BRAND_TERMS = (
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "whatsapp", "銀行", "sbi"
)

def extract_url_features(raw_url: str) -> dict:
    """Return a stable set of numeric URL-only features for model training/inference."""
    value = str(raw_url or "").strip()
    normalized = value if re.match(r"^https?://", value, re.I) else "http://" + value
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    path_query = (parsed.path + "?" + parsed.query).lower()
    full = value.lower()

    try:
        port = parsed.port
    except ValueError:
        port = None

    labels = [part for part in host.split(".") if part]
    tld = labels[-1] if len(labels) > 1 else ""
    digits = sum(ch.isdigit() for ch in value)
    special = sum(not ch.isalnum() for ch in value)
    terms = sum(term in full for term in SUSPICIOUS_TERMS)
    brand_hits = sum(term in full for term in BRAND_TERMS)
    ip_host = bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))

    return {
        "url_length": len(value),
        "hostname_length": len(host),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "dot_count": value.count("."),
        "hyphen_count": value.count("-"),
        "at_count": value.count("@"),
        "slash_count": value.count("/"),
        "question_count": value.count("?"),
        "equal_count": value.count("="),
        "ampersand_count": value.count("&"),
        "percent_count": value.count("%"),
        "digit_count": digits,
        "digit_ratio": digits / max(len(value), 1),
        "special_char_count": special,
        "subdomain_count": max(len(labels) - 2, 0),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_ip_address": int(ip_host),
        "has_port": int(port is not None),
        "has_punycode": int("xn--" in host),
        "has_fragment": int(bool(parsed.fragment)),
        "is_shortener": int(host in SHORTENERS),
        "suspicious_term_count": terms,
        "brand_term_count": brand_hits,
        "uses_https_scheme": int(parsed.scheme.lower() == "https"),
        "tld": tld,
        "path_has_login_word": int(any(x in path_query for x in ("login", "signin", "verify"))),
    }
