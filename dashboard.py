
import streamlit as st
import pandas as pd
import plotly.express as px
from database import get_scans


def show_dashboard():

    st.title("📊 Security Analytics Dashboard")
    st.caption("Monitor threats, analyze scan activity and track security risks.")

    records = get_scans()

    if not records:
        st.info("No scan history available. Start scanning URLs or emails first.")
        return

    columns = [
        "ID", "Scan Type", "Input",
        "Risk Level", "Risk Score",
        "Result", "Scan Time"
    ]

    df = pd.DataFrame(records, columns=columns)

    df["Risk Score"] = pd.to_numeric(
        df["Risk Score"], errors="coerce"
    ).fillna(0)

    df["Scan Time"] = pd.to_datetime(
        df["Scan Time"], errors="coerce"
    )

    # Filters
    st.subheader("🔎 Filter Scan Records")

    c1, c2, c3 = st.columns(3)

    with c1:
        scan_filter = st.selectbox(
            "Scan Type", ["All", "URL", "Email"]
        )

    with c2:
        risk_filter = st.selectbox(
            "Risk Level", ["All", "High", "Medium", "Low"]
        )

    with c3:
        search = st.text_input(
            "Search Input", placeholder="Search URL or email..."
        )

    filtered = df.copy()

    if scan_filter != "All":
        filtered = filtered[filtered["Scan Type"] == scan_filter]

    if risk_filter != "All":
        filtered = filtered[filtered["Risk Level"] == risk_filter]

    if search.strip():
        filtered = filtered[
            filtered["Input"].astype(str).str.contains(
                search, case=False, regex=False, na=False
            )
        ]

    st.divider()

    # KPI Cards
    st.subheader("📌 Security Overview")

    total = len(filtered)
    high = (filtered["Risk Level"] == "High").sum()
    medium = (filtered["Risk Level"] == "Medium").sum()
    low = (filtered["Risk Level"] == "Low").sum()

    avg_score = (
        round(filtered["Risk Score"].mean(), 1)
        if total else 0
    )

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Total Scans", total)
    c2.metric("High Risk", int(high))
    c3.metric("Medium Risk", int(medium))
    c4.metric("Low Risk", int(low))
    c5.metric("Average Score", f"{avg_score}/100")

    st.divider()

    if filtered.empty:
        st.warning("No records match your selected filters.")
        return

    # Risk Distribution
    st.subheader("📈 Risk Distribution")

    risk_data = (
        filtered["Risk Level"]
        .value_counts()
        .reindex(["High", "Medium", "Low"], fill_value=0)
        .rename_axis("Risk Level")
        .reset_index(name="Scans")
    )

    col1, col2 = st.columns(2)

    with col1:
        fig = px.pie(
            risk_data,
            names="Risk Level",
            values="Scans",
            hole=0.5,
            title="Risk Level Breakdown",
            color="Risk Level",
            color_discrete_map={
                "High": "#EF4444",
                "Medium": "#F59E0B",
                "Low": "#10B981"
            }
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
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
            title="URL vs Email Scans",
            text="Scans"
        )
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # Scan Trend
    st.subheader("📅 Scan Activity Trend")

    trend = filtered.dropna(subset=["Scan Time"]).copy()

    if not trend.empty:
        trend["Date"] = trend["Scan Time"].dt.date

        trend_data = (
            trend.groupby("Date")
            .size()
            .reset_index(name="Total Scans")
        )

        fig = px.line(
            trend_data,
            x="Date",
            y="Total Scans",
            markers=True,
            title="Daily Scan Activity"
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Scan date information is unavailable.")

    st.divider()

    # Scan History
    st.subheader("🗂️ Recent Scan History")

    display_df = filtered.sort_values(
        "ID", ascending=False
    ).copy()

    display_df["Input"] = (
        display_df["Input"].astype(str).str.slice(0, 80)
    )

    st.dataframe(
        display_df[
            [
                "ID", "Scan Type", "Input",
                "Risk Level", "Risk Score", "Scan Time"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )

    csv_data = filtered.to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇️ Download Dashboard Report",
        data=csv_data,
        file_name="phishguard_dashboard_report.csv",
        mime="text/csv"
    )
