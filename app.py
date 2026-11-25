
import streamlit as st
import pandas as pd
import requests
import os
import base64

from database import create_database, save_scan, get_scans
from url_scanner import scan_url
from email_detector import detect_email
from dashboard import show_dashboard

# ================= PAGE CONFIG =================

st.set_page_config(
    page_title="PhishGuard | Cybersecurity",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

create_database()

try:
    VT_API_KEY = st.secrets.get("VT_API_KEY", "")
except Exception:
    VT_API_KEY = os.getenv("VT_API_KEY", "")

# ================= CUSTOM DESIGN =================

st.markdown("""
<style>
.stApp {
    background-color: #080f1c;
    color: #e2e8f0;
}
[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid #263449;
}
.hero {
    padding: 42px 25px;
    text-align: center;
    border-radius: 18px;
    background: linear-gradient(120deg, #111827, #1e3a8a, #312e81);
    border: 1px solid #334155;
    margin-bottom: 25px;
}
.hero h1 {
    color: white;
    font-size: 43px;
    font-weight: 800;
}
.hero p {
    color: #dbeafe;
    font-size: 16px;
}
.feature {
    background: #111827;
    border: 1px solid #263449;
    border-radius: 14px;
    padding: 20px;
    min-height: 155px;
    margin-bottom: 15px;
}
.feature h3 {
    color: #93c5fd;
}
.feature p {
    color: #cbd5e1;
}
div.stButton > button {
    background: linear-gradient(90deg, #2563eb, #4f46e5);
    color: white;
    border: none;
    border-radius: 9px;
    font-weight: 600;
}
div.stButton > button:hover {
    background: #1d4ed8;
    color: white;
    border: none;
}
</style>
""", unsafe_allow_html=True)


# ================= VIRUSTOTAL FUNCTION =================

def virustotal_scan(url):

    if not VT_API_KEY:
        return {"status": "API key missing"}

    try:
        url_id = base64.urlsafe_b64encode(
            url.encode("utf-8")
        ).decode("utf-8").rstrip("=")

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
                "code": submit.status_code,
                "message": submit.text
            }

        return {
            "status": "error",
            "code": response.status_code,
            "message": response.text
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }


# ================= SIDEBAR =================

st.sidebar.markdown("## 🛡️ PhishGuard")
st.sidebar.caption("Cybersecurity Intelligence Platform")

menu = st.sidebar.radio(
    "MAIN MENU",
    [
        "Home",
        "URL Scanner",
        "Email Detector",
        "Analytics Dashboard",
        "Scan Reports"
    ]
)

st.sidebar.divider()
st.sidebar.markdown("**Security Modules**")
st.sidebar.caption("• URL Threat Detection")
st.sidebar.caption("• Email Phishing Analysis")
st.sidebar.caption("• VirusTotal Intelligence")
st.sidebar.caption("• Security Analytics")

st.sidebar.divider()
st.sidebar.caption("PhishGuard | Version 2.0")


# ================= HOME PAGE =================

if menu == "Home":

    st.markdown("""
    <div class="hero">
        <h1>🛡️ PhishGuard</h1>
        <p>SMART PHISHING DETECTION & CYBER THREAT INTELLIGENCE</p>
        <p>Detect suspicious links. Analyze phishing emails.
        Protect your digital identity.</p>
    </div>
    """, unsafe_allow_html=True)

    st.subheader("Welcome to Your Security Center")

    st.write(
        "PhishGuard is a cybersecurity application designed to "
        "identify suspicious URLs and phishing emails using "
        "rule-based analysis and VirusTotal threat intelligence."
    )

    st.divider()
    st.subheader("⚡ Core Security Features")

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("""
        <div class="feature">
            <h3>🌐 URL Security Scanner</h3>
            <p>Analyze suspicious URLs and identify possible
            phishing indicators using rule-based checks
            and VirusTotal reputation data.</p>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown("""
        <div class="feature">
            <h3>📧 Email Phishing Detector</h3>
            <p>Examine email content and detect suspicious
            patterns that may indicate phishing attempts.</p>
        </div>
        """, unsafe_allow_html=True)

    c3, c4 = st.columns(2)

    with c3:
        st.markdown("""
        <div class="feature">
            <h3>📊 Security Analytics</h3>
            <p>Explore interactive charts, risk distribution,
            scan trends and security statistics.</p>
        </div>
        """, unsafe_allow_html=True)

    with c4:
        st.markdown("""
        <div class="feature">
            <h3>📁 Scan Reports</h3>
            <p>Access previous scan records and download
            reports for security review.</p>
        </div>
        """, unsafe_allow_html=True)

    st.divider()
    st.subheader("🔄 How PhishGuard Works")

    steps = st.columns(5)

    workflow = [
        ("01", "Input", "Enter URL or email"),
        ("02", "Analyze", "Check suspicious indicators"),
        ("03", "Verify", "Check VirusTotal reputation"),
        ("04", "Results", "View risk information"),
        ("05", "Reports", "Save scan history")
    ]

    for col, (number, title, description) in zip(steps, workflow):
        with col:
            st.markdown(f"**{number} | {title}**")
            st.caption(description)

    st.info(
        "Security Note: Automated detection is not a guarantee "
        "that a URL or email is completely safe."
    )


# ================= URL SCANNER =================

elif menu == "URL Scanner":

    st.title("🌐 URL Security Scanner")
    st.caption("Analyze URLs using local security rules and VirusTotal.")

    url = st.text_input(
        "Enter website URL",
        placeholder="https://example.com"
    )

    if st.button("🔍 Scan URL", use_container_width=True):

        if not url.strip():
            st.warning("Please enter a URL.")

        else:

            with st.spinner("Analyzing URL..."):

                result = scan_url(url.strip())

            if result["risk_level"] == "Invalid":
                st.error(result["result"])

            else:

                save_scan(
                    "URL",
                    url.strip(),
                    result["risk_level"],
                    result["risk_score"],
                    result["result"]
                )

                st.subheader("Local Security Analysis")

                c1, c2 = st.columns(2)

                c1.metric(
                    "Risk Score",
                    f'{result["risk_score"]}/100'
                )

                c2.metric(
                    "Risk Classification",
                    result["risk_level"]
                )

                st.progress(result["risk_score"] / 100)
                st.write(result["result"])

                with st.expander("View Security Checks", expanded=True):
                    for check in result.get("checks", []):
                        st.write("•", check)

                st.divider()
                st.subheader("🛡️ VirusTotal Threat Intelligence")

                with st.spinner("Checking VirusTotal..."):
                    vt = virustotal_scan(url.strip())

                if vt["status"] == "success":

                    stats = vt["stats"]

                    a, b, c, d = st.columns(4)

                    a.metric("Malicious", stats.get("malicious", 0))
                    b.metric("Suspicious", stats.get("suspicious", 0))
                    c.metric("Harmless", stats.get("harmless", 0))
                    d.metric("Undetected", stats.get("undetected", 0))

                    if stats.get("malicious", 0) > 0:
                        st.error("VirusTotal detected malicious engines.")
                    else:
                        st.success(
                            "No malicious detections reported in this analysis."
                        )

                elif vt["status"] == "submitted":

                    st.info(
                        "URL submitted to VirusTotal. "
                        "Analysis is pending. Scan again later."
                    )

                else:

                    st.error("VirusTotal scan could not be completed.")
                    st.write("Error Code:", vt.get("code", "Unavailable"))
                    st.code(
                        vt.get("message", vt.get("status", "Unknown error"))
                    )


# ================= EMAIL DETECTOR =================

elif menu == "Email Detector":

    st.title("📧 Email Phishing Detector")
    st.caption("Analyze suspicious email content.")

    email_text = st.text_area(
        "Paste email content",
        height=220,
        placeholder="Paste the complete email here..."
    )

    if st.button("🔍 Analyze Email", use_container_width=True):

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

            st.subheader("Email Security Analysis")

            c1, c2 = st.columns(2)

            c1.metric(
                "Risk Score",
                f'{result["risk_score"]}/100'
            )

            c2.metric(
                "Risk Classification",
                result["risk_level"]
            )

            st.progress(result["risk_score"] / 100)
            st.write(result["result"])

            with st.expander("View Detection Details", expanded=True):
                for check in result.get("checks", []):
                    st.write("•", check)


# ================= ANALYTICS DASHBOARD =================

elif menu == "Analytics Dashboard":

    show_dashboard()


# ================= SCAN REPORTS =================

elif menu == "Scan Reports":

    st.title("📁 Security Scan Reports")
    st.caption("View, search and download your saved scan history.")

    records = get_scans()

    if records:

        df = pd.DataFrame(
            records,
            columns=[
                "ID",
                "Scan Type",
                "Input",
                "Risk Level",
                "Risk Score",
                "Result",
                "Scan Time"
            ]
        )

        st.metric("Total Saved Scans", len(df))

        search = st.text_input("Search scan records")

        if search.strip():
            df = df[
                df["Input"].astype(str).str.contains(
                    search,
                    case=False,
                    regex=False,
                    na=False
                )
            ]

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇️ Download CSV Report",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="PhishGuard_Scan_Reports.csv",
            mime="text/csv",
            use_container_width=True
        )

        st.download_button(
            "⬇️ Download TXT Report",
            data=df.to_string(index=False),
            file_name="PhishGuard_Scan_Reports.txt",
            mime="text/plain",
            use_container_width=True
        )

    else:

        st.info("No scan records available. Scan a URL or email first.")

# ================= FOOTER =================

st.divider()

st.markdown(
    "<div style='text-align:center;color:#94a3b8;'>"
    "🛡️ PhishGuard | Cybersecurity & Threat Intelligence"
    "</div>",
    unsafe_allow_html=True
)
