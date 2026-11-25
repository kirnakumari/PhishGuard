
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
        return {"status": "VirusTotal API key is missing."}

    try:
        headers = {"x-apikey": VT_API_KEY}
        encoded_url = base64.urlsafe_b64encode(
            url.encode("utf-8")
        ).decode("utf-8").rstrip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
            headers=headers,
            timeout=20
        )

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"].get(
                "last_analysis_stats", {}
            )
            return {"status": "success", "stats": stats}

        if response.status_code == 404:
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=20
            )

            if submit.status_code in (200, 201):
                return {"status": "submitted"}

            return {
                "status": "error",
                "message": submit.text
            }

        return {
            "status": "error",
            "message": response.text,
            "code": response.status_code
        }

    except requests.RequestException as e:
        return {"status": "error", "message": str(e)}


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

    c1, c2, c3 = st.columns(3)
    c1.metric("Detection", "URL & Email")
    c2.metric("Threat Intelligence", "VirusTotal")
    c3.metric("Database", "SQLite")

    st.info("Protect yourself from suspicious links and phishing emails.")

elif menu == "URL Scanner":
    st.header("🌐 URL Security Scanner")
    url = st.text_input("Enter URL to scan")

    if st.button("Scan URL"):
        if not url.strip():
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Scanning URL..."):
                result = scan_url(url.strip())

            save_scan(
                "URL",
                url.strip(),
                result["risk_level"],
                result["risk_score"],
                result["result"]
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
                vt = virustotal_scan(url.strip())

            if vt["status"] == "success":
                stats = vt["stats"]
                st.write("Latest VirusTotal Analysis")
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Malicious", stats.get("malicious", 0))
                c2.metric("Suspicious", stats.get("suspicious", 0))
                c3.metric("Harmless", stats.get("harmless", 0))
                c4.metric("Undetected", stats.get("undetected", 0))

            elif vt["status"] == "submitted":
                st.info(
                    "URL submitted to VirusTotal. Analysis is pending. "
                    "Please scan again after some time."
                )

            else:
                st.error("VirusTotal could not complete the scan.")
                st.write(vt.get("code", ""))
                st.code(vt.get("message", vt.get("status", "Unknown error")))

elif menu == "Email Detector":
    st.header("📧 Email Phishing Detector")
    email_text = st.text_area("Paste email content")

    if st.button("Analyze Email"):
        if not email_text.strip():
            st.warning("Please enter email content.")
        else:
            result = detect_email(email_text)

            save_scan(
                "Email",
                email_text,
                result["risk_level"],
                result["risk_score"],
                result["result"]
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

        st.download_button(
            "Download TXT",
            df.to_string(index=False),
            "phishguard_reports.txt",
            "text/plain"
        )
    else:
        st.info("No scan records found yet.")
