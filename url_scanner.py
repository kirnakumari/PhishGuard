import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
	"login", "verify", "account", "banking",
	"password", "secure", "update", "free",
	"gift", "winner", "confirm", "wallet"
]

SHORTENED_DOMAINS = [
	"bit.ly", "tinyurl.com", "t.co",
	"is.gd", "shorturl.at", "cutt.ly"
]


def scan_url(url):
	url = url.strip()

	if not url:
		return {
			"risk_score": 0,
			"risk_level": "Invalid",
			"result": "Please enter a URL.",
			"checks": []
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
			"checks": []
		}

	score = 0
	checks = []

	if parsed.scheme != "https":
		score += 20
		checks.append("URL does not use HTTPS.")
	else:
		checks.append("HTTPS connection is used.")

	if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
		score += 25
		checks.append("URL uses an IP address instead of a domain name.")
	else:
		checks.append("URL uses a domain name.")

	if domain.lower() in SHORTENED_DOMAINS:
		score += 20
		checks.append("URL uses a shortened domain.")
	else:
		checks.append("No known URL shortener detected.")

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

	if "@" in url:
		score += 20
		checks.append("URL contains an @ symbol.")

	if len(url) > 100:
		score += 10
		checks.append("URL is unusually long.")
	else:
		checks.append("URL length looks normal.")

	score = min(score, 100)

	if score >= 50:
		risk_level = "High"
		result = "This URL contains multiple suspicious indicators."
	elif score >= 25:
		risk_level = "Medium"
		result = "This URL has some suspicious indicators."
	else:
		risk_level = "Low"
		result = "Few suspicious indicators were detected."

	return {
		"risk_score": score,
		"risk_level": risk_level,
		"result": result,
		"checks": checks
	}
