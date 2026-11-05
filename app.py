
import streamlit as st
import pandas as pd
import ipaddress
import datetime
import json

from modules.virustotal import check_virustotal, identify_indicator
from modules.abuseipdb import check_abuseipdb
from modules.history import save_history, get_history


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ==================================================
# CUSTOM DESIGN
# ==================================================

st.markdown("""
<style>
.stApp {
    background-color: #0B1220;
}

[data-testid="stSidebar"] {
    background-color: #111C2E;
}

.main-title {
    font-size: 32px;
    font-weight: 700;
    color: #38BDF8;
}

.subtitle {
    color: #94A3B8;
    font-size: 14px;
}

div[data-testid="stMetric"] {
    background-color: #142238;
    border: 1px solid #263B55;
    padding: 16px;
    border-radius: 12px;
}

div[data-testid="stMetric"] label {
    color: #94A3B8;
}

.stButton > button {
    background-color: #0284C7;
    color: white;
    border-radius: 8px;
    border: none;
    font-weight: 600;
}

.stButton > button:hover {
    background-color: #0369A1;
    color: white;
}
</style>
""", unsafe_allow_html=True)


# ==================================================
# HELPER FUNCTIONS
# ==================================================

def show_value(value):
    if value is None or value == "":
        return "Not available"

    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, default=str)

    return str(value)


def format_timestamp(value):
    if not value:
        return "Not available"

    try:
        return datetime.datetime.fromtimestamp(
            int(value),
            datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError, OSError):
        return show_value(value)


def make_table(data):
    rows = []

    for key, value in data.items():
        rows.append({
            "Information": key,
            "Value": show_value(value)
        })

    return pd.DataFrame(rows)


def save_investigation(indicator, vt_result, abuse_result):

    today = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if vt_result and "error" not in vt_result:

        attrs = vt_result.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        save_history({
            "Date": today,
            "Indicator": indicator,
            "Source": "VirusTotal",
            "Malicious": stats.get("malicious", 0),
            "Suspicious": stats.get("suspicious", 0),
            "Harmless": stats.get("harmless", 0),
            "Undetected": stats.get("undetected", 0)
        })

    if abuse_result and "error" not in abuse_result:

        save_history({
            "Date": today,
            "Indicator": indicator,
            "Source": "AbuseIPDB",
            "Abuse Score": abuse_result.get(
                "abuseConfidenceScore", ""
            ),
            "Total Reports": abuse_result.get(
                "totalReports", ""
            ),
            "Country": abuse_result.get(
                "countryCode", ""
            )
        })


# ==================================================
# SIDEBAR NAVIGATION
# IMPORTANT: key="page" IS INCLUDED
# ==================================================

st.sidebar.markdown("## 🛡️ Threat Intelligence")
st.sidebar.caption("Automated Investigation Platform")

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Investigate Indicator",
        "History",
        "Analytics",
        "About Project"
    ],
    key="page"
)

st.sidebar.divider()

st.sidebar.caption("Data Sources")
st.sidebar.write("🟢 VirusTotal API")
st.sidebar.write("🟢 AbuseIPDB API")


# ==================================================
# OVERVIEW PAGE
# ==================================================

if page == "Overview":

    st.markdown(
        '<div class="main-title">🛡️ Threat Intelligence Dashboard</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">Automated investigation of suspicious IPs, domains, URLs and file hashes.</div>',
        unsafe_allow_html=True
    )

    st.write("")

    try:
        history = get_history()
    except Exception:
        history = []

    total_records = len(history)

    total_indicators = len(set(
        item.get("Indicator", "")
        for item in history
        if item.get("Indicator")
    ))

    def safe_int(value):
        try:
           return int(value)
        except (ValueError, TypeError):
            return 0

    malicious_count = sum(
        safe_int(item.get("Malicious"))
        for item in history
    )

    abuse_count = sum(
        int(item.get("Abuse Score") or 0) > 0
        for item in history
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Investigation Records", total_records)
    c2.metric("Unique Indicators", total_indicators)
    c3.metric("Malicious Detections", malicious_count)
    c4.metric("Abuse Records", abuse_count)

    st.divider()

    st.subheader("Quick Investigation")

    quick_indicator = st.text_input(
        "Enter an IP address, domain, URL or file hash",
        key="overview_indicator",
        placeholder="Example: 8.8.8.8"
    )

    if st.button("Go to Investigation"):

        if quick_indicator.strip():

            st.session_state["prefill_indicator"] = quick_indicator.strip()

            # Navigate to the investigation page
            st.session_state["page"] = "Investigate Indicator"

            st.rerun()

        else:
            st.warning("Please enter an indicator first.")

    st.divider()

    st.subheader("Recent Investigations")

    if history:

        recent = pd.DataFrame(history).head(5)

        st.dataframe(
            recent,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No investigations yet. Start by checking an indicator.")


# ==================================================
# INVESTIGATE INDICATOR PAGE
# ==================================================

elif page == "Investigate Indicator":

    st.title("🔍 Investigate Indicator")

    st.write(
        "Enter an IP address, domain, URL or file hash "
        "to retrieve threat intelligence."
    )

    default_value = st.session_state.pop(
        "prefill_indicator",
        ""
    )

    with st.form("investigation_form"):

        indicator = st.text_input(
            "Indicator",
            value=default_value,
            placeholder="Example: 8.8.8.8 or example.com"
        )

        analyze_button = st.form_submit_button(
            "Analyze Indicator",
            use_container_width=True
        )

    if analyze_button:

        indicator = indicator.strip()

        if not indicator:

            st.warning("Please enter an indicator.")

        else:

            indicator_type = identify_indicator(indicator)

            if not indicator_type:

                st.error(
                    "Invalid input. Enter a valid IP, domain, URL or file hash."
                )

            else:

                with st.spinner("Collecting threat intelligence..."):

                    vt_result = check_virustotal(indicator)

                    abuse_result = None

                    if indicator_type == "ip":
                        abuse_result = check_abuseipdb(indicator)

                    st.session_state["last_indicator"] = indicator
                    st.session_state["last_vt"] = vt_result
                    st.session_state["last_abuse"] = abuse_result

                    save_investigation(
                        indicator,
                        vt_result,
                        abuse_result
                    )

    # DISPLAY RESULTS

    if st.session_state.get("last_vt"):

        indicator = st.session_state.get("last_indicator")
        vt_result = st.session_state.get("last_vt")
        abuse_result = st.session_state.get("last_abuse")

        st.divider()

        st.subheader("Investigation Results")

        st.write("**Indicator:**", indicator)

        # ------------------------------------------
        # VIRUSTOTAL
        # ------------------------------------------

        if "error" in vt_result:

            st.error("VirusTotal: " + vt_result["error"])

            if vt_result.get("details"):
                st.caption(vt_result["details"])

        else:

            attrs = vt_result.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            st.markdown("### 🦠 VirusTotal Analysis")

            if stats:

                a, b, c, d = st.columns(4)

                a.metric("Malicious", stats.get("malicious", 0))
                b.metric("Suspicious", stats.get("suspicious", 0))
                c.metric("Harmless", stats.get("harmless", 0))
                d.metric("Undetected", stats.get("undetected", 0))

                chart_data = pd.DataFrame({
                    "Detection Type": list(stats.keys()),
                    "Count": list(stats.values())
                })

                st.bar_chart(
                    chart_data.set_index("Detection Type")
                )

            else:

                st.info(
                    "VirusTotal has not provided analysis statistics for this indicator."
                )

            # GENERAL INFORMATION

            st.markdown("#### General Information")

            general_fields = [
                "country",
                "continent",
                "asn",
                "as_owner",
                "network",
                "registrar",
                "creation_date",
                "last_update_date",
                "reputation",
                "last_analysis_date",
                "last_modification_date",
                "size",
                "type_description",
                "meaningful_name"
            ]

            general_data = {}

            for field in general_fields:

                if field in attrs:

                    value = attrs[field]

                    if field in (
                        "last_analysis_date",
                        "last_modification_date",
                        "creation_date",
                        "last_update_date"
                    ):
                        value = format_timestamp(value)

                    general_data[field.replace("_", " ").title()] = value

            if general_data:

                st.dataframe(
                    make_table(general_data),
                    use_container_width=True,
                    hide_index=True
                )

            else:
                st.info("General information is not available.")

            # VENDOR-WISE DETECTION

            st.markdown("#### 🛡️ Security Vendor Results")

            vendor_results = attrs.get("last_analysis_results", {})

            if vendor_results:

                vendor_rows = []

                for vendor, result in vendor_results.items():

                    vendor_rows.append({
                        "Security Vendor": vendor,
                        "Category": result.get("category", "Unknown"),
                        "Detection Result": result.get("result") or "No detection name",
                        "Method": result.get("method", "Not available"),
                        "Engine Version": result.get("engine_version", "Not available"),
                        "Engine Update": result.get("engine_update", "Not available")
                    })

                vendor_df = pd.DataFrame(vendor_rows)

                filter_choice = st.selectbox(
                    "Filter vendor results",
                    [
                        "All",
                        "Malicious",
                        "Suspicious",
                        "Harmless",
                        "Undetected"
                    ]
                )

                if filter_choice != "All":

                    vendor_df = vendor_df[
                        vendor_df["Category"].str.lower()
                        == filter_choice.lower()
                    ]

                st.dataframe(
                    vendor_df,
                    use_container_width=True,
                    hide_index=True
                )

                st.download_button(
                    "Download Vendor Results CSV",
                    vendor_df.to_csv(index=False),
                    file_name="virustotal_vendor_results.csv",
                    mime="text/csv"
                )

            else:

                st.info("No vendor-wise results are available.")

            # COMMUNITY REPUTATION

            st.markdown("#### 🌐 Community Reputation")

            votes = attrs.get("total_votes", {})

            v1, v2, v3 = st.columns(3)

            v1.metric(
                "Community Harmless Votes",
                votes.get("harmless", 0)
            )

            v2.metric(
                "Community Malicious Votes",
                votes.get("malicious", 0)
            )

            v3.metric(
                "Reputation Score",
                attrs.get("reputation", "N/A")
            )

            # THREAT TAGS

            st.markdown("#### 🏷️ Threat Tags")

            tags = attrs.get("tags", [])

            if tags:
                st.write(", ".join(str(tag) for tag in tags))
            else:
                st.info("No threat tags available.")

            # WHOIS

            st.markdown("#### 🌍 WHOIS Information")

            whois = attrs.get("whois")

            if whois:

                with st.expander("View WHOIS details"):
                    st.text(str(whois))

            else:
                st.info("WHOIS information is not available.")

            # DNS

            st.markdown("#### 🌐 DNS Information")

            dns_records = attrs.get("last_dns_records", [])

            if dns_records:

                dns_df = pd.DataFrame(dns_records)

                st.dataframe(
                    dns_df,
                    use_container_width=True,
                    hide_index=True
                )

            else:
                st.info("DNS records are not available for this indicator.")

            # SSL CERTIFICATE

            st.markdown("#### 🔐 SSL Certificate Information")

            certificate = attrs.get("last_https_certificate")

            if certificate:

                cert_fields = [
                    "version",
                    "serial_number",
                    "thumbprint",
                    "thumbprint_sha256",
                    "issuer",
                    "subject",
                    "validity",
                    "extensions",
                    "public_key"
                ]

                cert_data = {
                    key: certificate[key]
                    for key in cert_fields
                    if key in certificate
                }

                if cert_data:
                    st.json(cert_data)
                else:
                    st.json(certificate)

            else:
                st.info("SSL certificate information is not available.")

            st.caption(
                "VirusTotal information depends on indicator type, analysis availability and API access."
            )

        # ------------------------------------------
        # ABUSEIPDB
        # ------------------------------------------

        if abuse_result is not None:

            st.divider()

            st.markdown("### 🚨 AbuseIPDB Analysis")

            if "error" in abuse_result:

                st.error("AbuseIPDB: " + abuse_result["error"])

                if abuse_result.get("details"):
                    st.caption(abuse_result["details"])

            else:

                score = abuse_result.get("abuseConfidenceScore", 0)
                total_reports = abuse_result.get("totalReports", 0)
                distinct_users = abuse_result.get("numDistinctUsers", 0)

                x, y, z = st.columns(3)

                x.metric("Abuse Confidence Score", f"{score}/100")
                y.metric("Total Reports", total_reports)
                z.metric("Distinct Reporters", distinct_users)

                st.progress(
                    max(0, min(100, int(score))) / 100
                )

                if score >= 80:
                    st.error("High reported abuse confidence.")

                elif score >= 30:
                    st.warning("Moderate reported abuse confidence.")

                elif score > 0:
                    st.info("Low reported abuse confidence.")

                else:
                    st.success("No abuse confidence reported.")

                # IP AND NETWORK INFORMATION

                st.markdown("#### IP and Network Information")

                abuse_fields = [
                    "ipAddress",
                    "ipVersion",
                    "isPublic",
                    "isWhitelisted",
                    "countryCode",
                    "usageType",
                    "isp",
                    "domain",
                    "hostnames",
                    "isTor",
                    "lastReportedAt"
                ]

                abuse_data = {
                    field: abuse_result.get(field)
                    for field in abuse_fields
                    if field in abuse_result
                }

                if abuse_data:

                    st.dataframe(
                        make_table(abuse_data),
                        use_container_width=True,
                        hide_index=True
                    )

                # INDIVIDUAL REPORTS

                st.markdown("#### 📋 Individual Abuse Reports")

                reports = abuse_result.get("reports", [])

                if reports:

                    report_rows = []

                    for report in reports:

                        report_rows.append({
                            "Reported At": report.get(
                                "reportedAt", "Not available"
                            ),
                            "Categories": ", ".join(
                                str(category)
                                for category in report.get("categories", [])
                            ),
                            "Comment": report.get("comment", ""),
                            "Reporter Country": report.get(
                                "reporterCountryName", "Not available"
                            )
                        })

                    reports_df = pd.DataFrame(report_rows)

                    st.dataframe(
                        reports_df,
                        use_container_width=True,
                        hide_index=True
                    )

                    st.download_button(
                        "Download Abuse Reports CSV",
                        reports_df.to_csv(index=False),
                        file_name="abuseipdb_reports.csv",
                        mime="text/csv"
                    )

                else:

                    st.info("No individual abuse reports were returned.")

                st.caption(
                    "AbuseIPDB reports are based on user submissions and are not proof of malicious activity."
                )

        # ------------------------------------------
        # COMPLETE JSON REPORT
        # ------------------------------------------

        st.divider()

        st.download_button(
            "Download Complete Investigation JSON",

            json.dumps(
                {
                    "indicator": indicator,
                    "virustotal": vt_result,
                    "abuseipdb": abuse_result
                },
                indent=4,
                default=str
            ),

            file_name="threat_investigation.json",
            mime="application/json"
        )


# ==================================================
# HISTORY PAGE
# ==================================================

elif page == "History":

    st.title("📜 Investigation History")

    history = get_history()

    if history:

        df = pd.DataFrame(history)

        search = st.text_input("Search by indicator")

        if search:

            df = df[
                df["Indicator"].astype(str).str.contains(
                    search,
                    case=False,
                    na=False
                )
            ]

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "Download History CSV",
            df.to_csv(index=False),
            file_name="investigation_history.csv",
            mime="text/csv"
        )

    else:

        st.info("No investigation history available.")


# ==================================================
# ANALYTICS PAGE
# ==================================================

elif page == "Analytics":

    st.title("📊 Threat Analytics")

    history = get_history()

    if history:

        df = pd.DataFrame(history)

        st.subheader("Investigations by Source")

        source_counts = df["Source"].value_counts()

        st.bar_chart(source_counts)

        st.subheader("Malicious Detections")

        if "Malicious" in df.columns:

            malicious_df = df.copy()

            malicious_df["Malicious"] = pd.to_numeric(
                malicious_df["Malicious"],
                errors="coerce"
            ).fillna(0)

            vt_df = malicious_df[
                malicious_df["Source"] == "VirusTotal"
            ]

            if not vt_df.empty:

                st.bar_chart(
                    vt_df.set_index("Indicator")["Malicious"]
                )

            else:

                st.info("No VirusTotal records available for this chart.")

        st.subheader("Recent Investigation Activity")

        if "Date" in df.columns:

            date_df = df.copy()

            date_df["Date"] = pd.to_datetime(
                date_df["Date"],
                errors="coerce"
            )

            date_df = date_df.dropna(subset=["Date"])

            if not date_df.empty:

                daily = date_df.groupby(
                    date_df["Date"].dt.date
                ).size()

                st.line_chart(daily)

    else:

        st.info("Perform investigations to generate analytics.")


# ==================================================
# ABOUT PROJECT PAGE
# ==================================================

elif page == "About Project":

    st.title("ℹ️ About This Project")

    st.markdown("""
    ## Automated Threat Intelligence Dashboard

    This project investigates suspicious cyber indicators
    using threat intelligence APIs.

    ### Integrated APIs

    **1. VirusTotal**
    - Antivirus vendor detection
    - IP, domain, URL and file hash analysis
    - WHOIS and DNS information where available
    - SSL certificate information where available
    - Community reputation and threat tags

    **2. AbuseIPDB**
    - IP abuse confidence score
    - Abuse reports and reporter counts
    - ISP, domain and country information
    - Tor and whitelist status
    - Individual abuse report details

    ### Technologies Used

    - Python
    - Streamlit
    - Pandas
    - Requests
    - SQLite
    - VirusTotal API
    - AbuseIPDB API

    ### Project Purpose

    To provide a simple interface for collecting and reviewing
    threat intelligence during cybersecurity investigations.
    """)

    st.info(
        "This tool supports investigations. It does not independently prove that an indicator is malicious or safe."
    )
