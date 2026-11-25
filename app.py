
import streamlit as st
import pandas as pd
import requests
import os
import base64

from database import create_database, save_scan, get_scans
from url_scanner import scan_url
from email_detector import detect_email
from dashboard import show_dashboard

st.set_page_config(
    page_title="PhishGuard | Cybersecurity",
    page_icon="🛡️",
    layout="wide"
)

create_database()

try:
    VT_API_KEY = st.secrets.get("VT_API_KEY", "")
except Exception:
    VT_API_KEY = os.getenv("VT_API_KEY", "")


def virustotal_scan(url):
    if not VT_API_KEY:
        return {"status": "No VirusTotal API key configured."}

    try:
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        headers = {"x-apikey": VT_API_KEY}

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=20
        )

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"].get(
                "last_analysis_stats", {}
            )
            return {"status": "found", "stats": stats}

        if response.status_code == 404:
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=20
            )
            if submit.status_code == 200:
                return {"status": "submitted"}
            return {"status": f"API error: {submit.status_code}"}

        if response.status_code == 401:
            return {"status": "Invalid API key."}
        if response.status_code == 429:
            return {"status": "API rate limit reached."}

        return {"status": f"API error: {response.status_code}"}

    except requests.RequestException:
        return {"status": "Could not connect to VirusTotal."}


st.title("🛡️ PhishGuard")
st.caption("AI-Assisted Phishing Detection and Security Analysis")

menu = st.sidebar.radio(
    "Navigation",
    [
        "Home",
        "URL Scanner",
        "Email Detector",
        "Analytics Dashboard",
        "Scan Reports"
    ]
)

if menu == "Home":
    st.header("Welcome to PhishGuard")
    st.write(
        "PhishGuard helps identify suspicious URLs and phishing emails "
        "using rule-based analysis and VirusTotal threat intelligence."
    )

    col1, col2, col3 = st.columns(3)
    col1.metric("Detection", "URL & Email")
    col2.metric("Threat Intelligence", "VirusTotal")
    col3.metric("Database", "SQLite")

elif menu == "URL Scanner":
    st.header("🌐 URL Security Scanner")
    url = st.text_input("Enter URL to scan")

    if st.button("Scan URL"):
        if not url.strip():
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Scanning URL..."):
                result = scan_url(url)

            save_scan(
                "URL", url, result["risk_level"],
                result["risk_score"], result["result"]
            )

            st.subheader("Local Security Analysis")
            st.metric("Risk Score", f'{result["risk_score"]}/100')
            st.write("Risk Level:", result["risk_level"])
            st.progress(result["risk_score"] / 100)
            st.write(result["result"])

            for check in result.get("checks", []):
                st.write("•", check)

            st.divider()
            st.subheader("VirusTotal Threat Intelligence")

            with st.spinner("Checking VirusTotal..."):
                vt_result = virustotal_scan(url.strip())

            if vt_result["status"] == "found":
                stats = vt_result["stats"]
                st.write("Latest available VirusTotal analysis:")
                st.write(f"Malicious: {stats.get('malicious', 0)}")
                st.write(f"Suspicious: {stats.get('suspicious', 0)}")
                st.write(f"Harmless: {stats.get('harmless', 0)}")
                st.write(f"Undetected: {stats.get('undetected', 0)}")
            elif vt_result["status"] == "submitted":
                st.info(
                    "URL submitted to VirusTotal. Analysis may take time. "
                    "Please scan again later."
                )
            else:
                st.warning(vt_result["status"])

elif menu == "Email Detector":
    st.header("📧 Email Phishing Detector")
    email_text = st.text_area("Paste email content")

    if st.button("Analyze Email"):
        if not email_text.strip():
            st.warning("Please enter email content.")
        else:
            result = detect_email(email_text)

            save_scan(
                "Email", email_text, result["risk_level"],
                result["risk_score"], result["result"]
            )

            st.metric("Risk Score", f'{result["risk_score"]}/100')
            st.write("Risk Level:", result["risk_level"])
            st.progress(result["risk_score"] / 100)
            st.write(result["result"])

            for check in result.get("checks", []):
                st.write("•", check)

elif menu == "Analytics Dashboard":
    st.header("📊 Analytics Dashboard")
    show_dashboard()

elif menu == "Scan Reports":
    st.header("📁 Scan Reports")
    records = get_scans()

    if records:
        df = pd.DataFrame(
            records,
            columns=[
                "ID", "Scan Type", "Input", "Risk Level",
                "Risk Score", "Result", "Scan Time"
            ]
        )

        st.dataframe(df, use_container_width=True)

        st.download_button(
            "Download CSV",
            df.to_csv(index=False),
            "phishguard_reports.csv",
            "text/csv"
        )

        report = df.to_string(index=False)
        st.download_button(
            "Download TXT",
            report,
            "phishguard_reports.txt",
            "text/plain"
        )
    else:
        st.info("No scan records found yet.")
