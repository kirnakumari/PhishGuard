
import streamlit as st
import pandas as pd
import plotly.express as px

from database import get_scans


def show_dashboard():

    st.title("Security Analytics Dashboard")
    st.write("Monitor and analyze your security scan history.")

    records = get_scans()

    if not records:
        st.info("No scan history available.")
        return

    columns = [
        "ID", "Scan Type", "Input",
        "Risk Level", "Risk Score",
        "Result", "Scan Time"
    ]

    df = pd.DataFrame(records, columns=columns)

    # Search and filter section
    st.subheader("Search and Filter")

    col1, col2 = st.columns(2)

    with col1:
        scan_filter = st.selectbox(
            "Select Scan Type",
            ["All", "URL", "Email"]
        )

    with col2:
        risk_filter = st.selectbox(
            "Select Risk Level",
            ["All", "High", "Medium", "Low"]
        )

    search = st.text_input(
        "Search website or email content",
        placeholder="Enter a keyword..."
    )

    filtered_df = df.copy()

    if scan_filter != "All":
        filtered_df = filtered_df[
            filtered_df["Scan Type"] == scan_filter
        ]

    if risk_filter != "All":
        filtered_df = filtered_df[
            filtered_df["Risk Level"] == risk_filter
        ]

    if search.strip():
        filtered_df = filtered_df[
            filtered_df["Input"].str.contains(
                search,
                case=False,
                na=False,
                regex=False
            )
        ]

    st.divider()

    # Metrics based on filtered records
    st.subheader("Scan Overview")

    total = len(filtered_df)

    high = len(
        filtered_df[filtered_df["Risk Level"] == "High"]
    )

    medium = len(
        filtered_df[filtered_df["Risk Level"] == "Medium"]
    )

    low = len(
        filtered_df[filtered_df["Risk Level"] == "Low"]
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Scans", total)
    c2.metric("High Risk", high)
    c3.metric("Medium Risk", medium)
    c4.metric("Low Risk", low)

    st.divider()

    # Risk chart
    st.subheader("Risk Distribution")

    if total > 0:

        risk_data = pd.DataFrame({
            "Risk Level": ["High", "Medium", "Low"],
            "Count": [high, medium, low]
        })

        fig = px.pie(
            risk_data,
            names="Risk Level",
            values="Count",
            hole=0.45,
            title="Security Scan Results"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:
        st.warning("No records match your selected filters.")

    st.divider()

    # Scan history
    st.subheader("Recent Scan History")

    if total > 0:

        display_df = filtered_df[
            [
                "ID", "Scan Type", "Input",
                "Risk Level", "Risk Score", "Scan Time"
            ]
        ].copy()

        display_df["Input"] = (
            display_df["Input"].str.slice(0, 70)
        )

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )

        # Download filtered history
        csv_data = filtered_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "Download Filtered History",
            data=csv_data,
            file_name="phishguard_history.csv",
            mime="text/csv"
        )

    else:
        st.info("No scan records found.")
