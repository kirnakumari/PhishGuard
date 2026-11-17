import re

SUSPICIOUS_PHRASES = [
	"verify your account",
	"account suspended",
	"account blocked",
	"urgent action required",
	"click here immediately",
	"claim your prize",
	"you have won",
	"limited time offer",
	"confirm your password",
	"update your banking details",
	"send your otp",
	"share your otp",
	"reset your password"
]

SENSITIVE_WORDS = [
	"password", "otp", "pin",
	"cvv", "bank details", "credit card"
]


def detect_email(email_text):

	email_text = email_text.strip()

	if not email_text:
		return {
			"risk_score": 0,
			"risk_level": "Invalid",
			"result": "Please enter email content.",
			"checks": []
		}

	text = email_text.lower()

	score = 0
	checks = []

	# Check suspicious phrases
	matched_phrases = [
		phrase for phrase in SUSPICIOUS_PHRASES
		if phrase in text
	]

	if matched_phrases:
		score += min(len(matched_phrases) * 15, 45)
		checks.append(
			"Suspicious phrases detected: "
			+ ", ".join(matched_phrases)
		)
	else:
		checks.append("No listed suspicious phrases detected.")

	# Check sensitive information requests
	matched_sensitive = [
		word for word in SENSITIVE_WORDS
		if word in text
	]

	if matched_sensitive:
		score += 25
		checks.append(
			"Sensitive information terms found: "
			+ ", ".join(matched_sensitive)
		)
	else:
		checks.append("No sensitive information terms found.")

	# Check links
	urls = re.findall(
		r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
		email_text,
		re.IGNORECASE
	)

	if urls:
		score += 15
		checks.append(
			f"Email contains {len(urls)} link(s). Review them carefully."
		)
	else:
		checks.append("No visible links detected.")

	# Check urgency
	urgency_words = [
		"immediately", "urgent", "now",
		"expires today", "within 24 hours"
	]

	matched_urgency = [
		word for word in urgency_words
		if word in text
	]

	if matched_urgency:
		score += 15
		checks.append(
			"Urgency-related language found: "
			+ ", ".join(matched_urgency)
		)
	else:
		checks.append("No listed urgency-related language found.")

	score = min(score, 100)

	if score >= 50:
		risk_level = "High"
		result = "This email contains several phishing indicators."
	elif score >= 25:
		risk_level = "Medium"
		result = "This email contains some suspicious indicators."
	else:
		risk_level = "Low"
		result = "Few phishing indicators were detected."

	return {
		"risk_score": score,
		"risk_level": risk_level,
		"result": result,
		"checks": checks
	}
