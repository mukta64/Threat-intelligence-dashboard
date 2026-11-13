# 🛡️ Automated Threat Intelligence Dashboard

## Project Overview

The Automated Threat Intelligence Dashboard is a cybersecurity project developed using Python and Streamlit. It helps users investigate suspicious IP addresses, domains, URLs and file hashes by collecting threat intelligence from VirusTotal and AbuseIPDB APIs.

The dashboard provides investigation results, threat indicators, historical records and analytics through a user-friendly interface.

## Features

- **Threat Intelligence Investigation:** Analyze IP addresses, domains, URLs and file hashes.
- **VirusTotal Integration:** View malicious detections, security vendor results, community reputation and threat information.
- **AbuseIPDB Integration:** Check IP abuse confidence scores, report counts, ISP information and abuse reports.
- **User Authentication:** Sign up and log in using Supabase Authentication.
- **Role-Based Access:** Separate normal user and administrator access.
- **Investigation History:** Store and review investigation records.
- **Admin Audit Logs:** Allow administrators to review security-related activity.
- **Analytics Dashboard:** Visualize investigation statistics.
- **Report Export:** Download investigation results in JSON and CSV formats.

## Technologies Used

- Python
- Streamlit
- Pandas
- Supabase
- PostgreSQL
- VirusTotal API
- AbuseIPDB API
- Git and GitHub

## Project Architecture

1. User signs in through Supabase Authentication.
2. User submits an IP address, domain, URL or file hash.
3. The application validates the submitted indicator.
4. VirusTotal retrieves available threat intelligence.
5. AbuseIPDB checks IP addresses.
6. Results are displayed in the dashboard.
7. Investigation history and audit events are stored in Supabase.

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd Threat-intelligence-dashboard
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a `.env` file in the project root:

```env
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
SUPABASE_URL=your_supabase_project_url
SUPABASE_KEY=your_supabase_anon_key
```

Never upload your `.env` file or API keys to GitHub.

### 4. Run the application

```bash
streamlit run app.py
```

## Security Considerations

- API credentials are stored outside the application source code.
- User authentication is handled through Supabase.
- User and administrator roles are managed through database profiles.
- Supabase Row Level Security (RLS) is used to control database access.
- Audit logging records relevant application activities.

## Project Purpose

The purpose of this project is to demonstrate practical cybersecurity skills in threat intelligence gathering, API integration, security monitoring, authentication, database security and dashboard development.

## Disclaimer

This dashboard is intended for educational and cybersecurity investigation purposes. Threat intelligence results depend on external API availability and submitted data. A reported indicator should not automatically be treated as proof of malicious activity.
