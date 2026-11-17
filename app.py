
import streamlit as st
import pandas as pd

from database import create_database, save_scan, get_scans
from url_scanner import scan_url
from email_detector import detect_email
from dashboard import show_dashboard


# ========== PAGE CONFIG ==========
st.set_page_config(
    page_title="PhishGuard | Cybersecurity",
    page_icon="🛡️",
    layout="wide"
)

create_database()


# ========== CUSTOM CSS ==========
st.markdown("""
<style>
.stApp {
    background-color: #0e1117;
}
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}
h1, h2, h3 {
    color: #58a6ff;
}
[data-testid="stMetric"] {
    background-color: #161b22;
    padding: 15px;
    border-radius: 10px;
    border: 1px solid #30363d;
}
.stButton button {
    border-radius: 8px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)


# ========== NAVIGATION ==========
PAGES = [
    "Home",
    "URL Scanner",
    "Email Detector",
    "Analytics Dashboard",
    "Scan Reports"
]

if "selected_page" not in st.session_state:
    st.session_state.selected_page = "Home"

st.sidebar.title("🛡️ PhishGuard")
st.sidebar.caption("Cybersecurity Threat Detection System")
st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    PAGES,
    key="selected_page"
)

st.sidebar.divider()
st.sidebar.info("Analyze suspicious URLs and email messages.")
st.sidebar.caption("Python | Streamlit | SQLite")


# ========== COMMON RESULT DISPLAY ==========
def display_result(data):

    st.subheader("Scan Results")

    score = data["risk_score"]
    level = data["risk_level"]

    col1, col2 = st.columns(2)

    col1.metric("Risk Score", f"{score}/100")
    col2.metric("Risk Level", level)

    st.progress(score / 100)

    if level == "High":
        st.error(data["result"])
    elif level == "Medium":
        st.warning(data["result"])
    elif level == "Low":
        st.success(data["result"])
    else:
        st.error(data["result"])

    st.subheader("Security Checks")

    for check in data["checks"]:
        st.write("•", check)


# ========== HOME ==========
if page == "Home":

    st.title("🛡️ Welcome to PhishGuard")

    st.subheader("Cybersecurity Threat Detection System")

    st.write("""
    PhishGuard is a Python-based security analysis
    application that checks website URLs and email
    messages for common suspicious characteristics.
    """)

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🔗 URL Scanner")
        st.write("Analyze website links for suspicious indicators.")

        if st.button("Open URL Scanner"):
            st.session_state.selected_page = "URL Scanner"
            st.rerun()

    with col2:
        st.subheader("📧 Email Detector")
        st.write("Analyze email messages for phishing indicators.")

        if st.button("Open Email Detector"):
            st.session_state.selected_page = "Email Detector"
            st.rerun()

    st.divider()

    st.subheader("Project Features")

    features = [
        "Website URL analysis",
        "Email phishing detection",
        "Automated risk score",
        "SQLite scan history",
        "Security analytics dashboard",
        "Search and filter scan records",
        "Individual scan reports",
        "CSV and TXT downloads"
    ]

    for feature in features:
        st.write("✓", feature)


# ========== URL SCANNER ==========
elif page == "URL Scanner":

    st.title("🔗 URL Security Scanner")

    st.write("Enter a website URL for security analysis.")

    url = st.text_input(
        "Website URL",
        placeholder="https://example.com"
    )

    if st.button("Analyze URL", type="primary"):

        if not url.strip():
            st.warning("Please enter a URL.")

        else:
            with st.spinner("Analyzing URL..."):
                result = scan_url(url)

            if result["risk_level"] != "Invalid":

                save_scan(
                    "URL",
                    url,
                    result["risk_level"],
                    result["risk_score"],
                    result["result"]
                )

            display_result(result)


# ========== EMAIL DETECTOR ==========
elif page == "Email Detector":

    st.title("📧 Email Phishing Detector")

    st.write("Paste an email message to analyze it.")

    email_text = st.text_area(
        "Email Content",
        placeholder="Paste email message here...",
        height=220
    )

    if st.button("Analyze Email", type="primary"):

        if not email_text.strip():
            st.warning("Please enter email content.")

        else:
            with st.spinner("Analyzing email..."):
                result = detect_email(email_text)

            if result["risk_level"] != "Invalid":

                save_scan(
                    "Email",
                    email_text,
                    result["risk_level"],
                    result["risk_score"],
                    result["result"]
                )

            display_result(result)


# ========== ANALYTICS DASHBOARD ==========
elif page == "Analytics Dashboard":

    show_dashboard()


# ========== SCAN REPORTS ==========
elif page == "Scan Reports":

    st.title("📄 Individual Scan Reports")

    st.write("View and download previously saved scan reports.")

    records = get_scans()

    if not records:

        st.info("No scan reports available. Perform a scan first.")

    else:

        columns = [
            "ID",
            "Scan Type",
            "Input",
            "Risk Level",
            "Risk Score",
            "Result",
            "Scan Time"
        ]

        df = pd.DataFrame(records, columns=columns)

        selected_id = st.selectbox(
            "Select Scan ID",
            df["ID"].tolist()
        )

        report = df[df["ID"] == selected_id].iloc[0]

        st.divider()

        st.subheader("Scan Information")

        col1, col2 = st.columns(2)

        col1.write(f"**Scan ID:** {report['ID']}")
        col1.write(f"**Scan Type:** {report['Scan Type']}")

        col2.write(f"**Scan Time:** {report['Scan Time']}")
        col2.write(f"**Risk Level:** {report['Risk Level']}")

        st.subheader("Analyzed Input")
        st.code(str(report["Input"]))

        st.subheader("Security Assessment")

        st.metric(
            "Risk Score",
            f"{report['Risk Score']}/100"
        )

        st.write("**Assessment:**", report["Result"])

        report_text = f"""
PHISHGUARD - SECURITY SCAN REPORT

Scan ID: {report['ID']}
Scan Type: {report['Scan Type']}
Scan Time: {report['Scan Time']}

Analyzed Input:
{report['Input']}

Risk Score: {report['Risk Score']}/100
Risk Level: {report['Risk Level']}

Assessment:
{report['Result']}

DISCLAIMER:
This report is generated using rule-based
educational security analysis. It does not
guarantee that a website or email is safe.
"""

        st.download_button(
            "Download Individual TXT Report",
            data=report_text,
            file_name=f"PhishGuard_Report_{selected_id}.txt",
            mime="text/plain"
        )

        csv_data = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "Download All Scan Records (CSV)",
            data=csv_data,
            file_name="PhishGuard_All_Reports.csv",
            mime="text/csv"
        )


# ========== FOOTER ==========
st.divider()

st.caption(
    "PhishGuard | Educational Cybersecurity Project | "
    "Developed using Python and Streamlit"
)

st.caption(
    "Rule-based analysis only. Not a replacement for professional security tools."
)
