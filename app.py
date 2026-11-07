
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
    - Supabase PostgreSQL
    - Supabase Authentication
    - VirusTotal API
    - AbuseIPDB API

    ### Project Purpose

    To provide a simple interface for collecting and reviewing
    threat intelligence during cybersecurity investigations.
    """)

    st.info(
        "This tool supports investigations. It does not independently prove that an indicator is malicious or safe."
    )


# ==================================================
# ADMIN AUDIT LOGS PAGE
# ==================================================

elif page == "Admin Audit Logs":

    st.title("🔐 Admin Audit Logs")
    st.caption("Visible only to accounts with the admin role.")

    if current_user.get("role") != "admin":
        st.error("You do not have permission to view audit logs.")
    else:
        try:
            audit_rows = (
                supabase.table("audit_logs")
                .select("created_at, user_id, username, action, indicator, status, details")
                .order("created_at", desc=True)
                .limit(500)
                .execute()
                .data
            )

            if audit_rows:
                audit_df = pd.DataFrame(audit_rows)
                st.dataframe(
                    audit_df,
                    use_container_width=True,
                    hide_index=True
                )
                st.download_button(
                    "Download Audit Logs CSV",
                    audit_df.to_csv(index=False),
                    file_name="admin_audit_logs.csv",
                    mime="text/csv"
                )
            else:
                st.info("No audit log records are available yet.")
        except Exception as exc:
            st.error("Could not load audit logs. Check the audit_logs table and RLS policies.")
            st.caption(str(exc))
