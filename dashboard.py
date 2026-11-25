
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from database import get_scans


def show_dashboard():

    st.markdown("""
    <style>
    .dash-header {
        padding: 25px;
        border-radius: 15px;
        background: linear-gradient(120deg, #101827, #172554, #312e81);
        border: 1px solid #334155;
        margin-bottom: 22px;
    }
    .dash-header h1 {
        color: white;
        font-size: 32px;
        margin: 0;
    }
    .dash-header p {
        color: #cbd5e1;
        margin: 8px 0 0 0;
    }
    .metric-card {
        background: #111827;
        border: 1px solid #263449;
        border-radius: 13px;
        padding: 18px;
        min-height: 112px;
    }
    .metric-label {
        color: #94a3b8;
        font-size: 13px;
    }
    .metric-value {
        color: white;
        font-size: 27px;
        font-weight: 700;
        margin-top: 8px;
    }
    .section-label {
        font-size: 20px;
        font-weight: 650;
        margin: 12px 0;
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="dash-header">
        <h1>🛡️ Security Intelligence Center</h1>
        <p>PhishGuard | Real-time security monitoring and threat analytics</p>
    </div>
    """, unsafe_allow_html=True)

    records = get_scans()

    if not records:
        st.info("No scan records available. Start scanning URLs or emails to view analytics.")
        return

    columns = [
        "ID", "Scan Type", "Input", "Risk Level",
        "Risk Score", "Result", "Scan Time"
    ]

    df = pd.DataFrame(records, columns=columns)
    df["Risk Score"] = pd.to_numeric(
        df["Risk Score"], errors="coerce"
    ).fillna(0)

    df["Scan Time"] = pd.to_datetime(
        df["Scan Time"], errors="coerce"
    )

    # SIDEBAR FILTERS
    st.sidebar.markdown("## 🎛️ Dashboard Filters")

    scan_type = st.sidebar.selectbox(
        "Scan Category", ["All", "URL", "Email"]
    )

    risk_level = st.sidebar.selectbox(
        "Risk Classification", ["All", "High", "Medium", "Low"]
    )

    date_range = st.sidebar.selectbox(
        "Time Period",
        ["All Time", "Last 7 Days", "Last 30 Days"]
    )

    search = st.sidebar.text_input("Search URL or Email")

    filtered = df.copy()

    if scan_type != "All":
        filtered = filtered[filtered["Scan Type"] == scan_type]

    if risk_level != "All":
        filtered = filtered[filtered["Risk Level"] == risk_level]

    if date_range != "All Time":
        days = 7 if date_range == "Last 7 Days" else 30
        cutoff = pd.Timestamp.now() - pd.Timedelta(days=days)
        filtered = filtered[filtered["Scan Time"] >= cutoff]

    if search.strip():
        filtered = filtered[
            filtered["Input"].astype(str).str.contains(
                search, case=False, regex=False, na=False
            )
        ]

    # KPI METRICS
    st.markdown('<div class="section-label">📊 Security Overview</div>',
                unsafe_allow_html=True)

    total = len(filtered)
    high = int((filtered["Risk Level"] == "High").sum())
    medium = int((filtered["Risk Level"] == "Medium").sum())
    low = int((filtered["Risk Level"] == "Low").sum())
    avg = round(filtered["Risk Score"].mean(), 1) if total else 0

    def metric_card(label, value, icon):
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">{icon} {label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """, unsafe_allow_html=True)

    cards = [
        ("Total Scans", total, "🔍"),
        ("High Risk", high, "🚨"),
        ("Medium Risk", medium, "⚠️"),
        ("Low Risk", low, "✅"),
        ("Average Score", f"{avg}/100", "📈")
    ]

    cols = st.columns(5)
    for col, card in zip(cols, cards):
        with col:
            metric_card(*card)

    st.divider()

    if filtered.empty:
        st.warning("No scans match the selected filters.")
        return

    # CHART THEME
    chart_layout = dict(
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        font=dict(color="#e2e8f0"),
        margin=dict(l=25, r=25, t=55, b=25),
        legend=dict(font=dict(color="#cbd5e1"))
    )

    # RISK AND SCAN CATEGORY
    st.markdown('<div class="section-label">🎯 Threat Analysis</div>',
                unsafe_allow_html=True)

    left, right = st.columns(2)

    risk_data = (
        filtered["Risk Level"]
        .value_counts()
        .reindex(["High", "Medium", "Low"], fill_value=0)
        .rename_axis("Risk Level")
        .reset_index(name="Scans")
    )

    with left:
        fig = px.pie(
            risk_data,
            names="Risk Level",
            values="Scans",
            hole=0.65,
            color="Risk Level",
            color_discrete_map={
                "High": "#ef4444",
                "Medium": "#f59e0b",
                "Low": "#10b981"
            },
            title="Threat Distribution"
        )
        fig.update_layout(**chart_layout)
        st.plotly_chart(fig, use_container_width=True)

    with right:
        type_data = (
            filtered["Scan Type"]
            .value_counts()
            .rename_axis("Scan Type")
            .reset_index(name="Scans")
        )

        fig = px.bar(
            type_data,
            x="Scan Type",
            y="Scans",
            color="Scan Type",
            text="Scans",
            color_discrete_sequence=["#6366f1", "#06b6d4"],
            title="URL vs Email Analysis"
        )
        fig.update_layout(**chart_layout)
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # RISK SCORE DISTRIBUTION
    st.markdown('<div class="section-label">📉 Risk Score Analysis</div>',
                unsafe_allow_html=True)

    fig = px.histogram(
        filtered,
        x="Risk Score",
        nbins=10,
        color="Risk Level",
        color_discrete_map={
            "High": "#ef4444",
            "Medium": "#f59e0b",
            "Low": "#10b981"
        },
        title="Distribution of Security Risk Scores"
    )
    fig.update_layout(**chart_layout)
    st.plotly_chart(fig, use_container_width=True)

    # SCAN ACTIVITY
    st.markdown('<div class="section-label">📅 Scan Activity Timeline</div>',
                unsafe_allow_html=True)

    trend = filtered.dropna(subset=["Scan Time"]).copy()

    if not trend.empty:
        trend["Date"] = trend["Scan Time"].dt.date

        trend_data = (
            trend.groupby("Date")
            .size()
            .reset_index(name="Total Scans")
        )

        fig = px.area(
            trend_data,
            x="Date",
            y="Total Scans",
            markers=True,
            title="Daily Security Scanning Activity"
        )
        fig.update_traces(
            line=dict(color="#818cf8", width=3),
            fillcolor="rgba(99,102,241,0.15)"
        )
        fig.update_layout(**chart_layout)
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # SCAN RECORDS
    st.markdown('<div class="section-label">🗂️ Scan History & Reports</div>',
                unsafe_allow_html=True)

    recent = filtered.sort_values("ID", ascending=False).copy()

    st.dataframe(
        recent[
            [
                "ID", "Scan Type", "Input", "Risk Level",
                "Risk Score", "Scan Time"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )

    csv = filtered.to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇️ Download Complete Analytics Report",
        data=csv,
        file_name="PhishGuard_Security_Analytics.csv",
        mime="text/csv",
        use_container_width=True
    )

    st.caption(
        "PhishGuard Security Analytics | Data based on saved scan records"
    )
