# 🛡️ Automated Threat Intelligence Dashboard

An interactive, web-based threat intelligence platform built with Python and Streamlit. It helps users investigate suspicious IP addresses, domains, URLs, and file hashes using external threat intelligence services.

## 📌 Project Overview

The Automated Threat Intelligence Dashboard brings threat intelligence information into one place. Users can submit an indicator of compromise (IOC) and review available security information from VirusTotal and AbuseIPDB.

The application includes user authentication, investigation history, analytics, and an administrative audit-log interface.

## ✨ Features

- **Indicator Investigation:** Investigate IP addresses, domains, URLs, and file hashes.
- **VirusTotal Integration:** Retrieve threat intelligence results from VirusTotal.
- **AbuseIPDB Integration:** Check public IP addresses for abuse reports and confidence scores.
- **User Authentication:** Sign-in and account creation using Supabase.
- **Investigation History:** Store and view investigation records.
- **Analytics Dashboard:** Visualize investigation activity and detection information.
- **Admin Dashboard:** Access the administrative audit-log interface.
- **Interactive Interface:** Dark-themed dashboard built with Streamlit.

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Streamlit | Web application and dashboard |
| VirusTotal API | Threat intelligence lookups |
| AbuseIPDB API | IP reputation checks |
| Supabase | Authentication and database |
| Pandas | Data handling and analysis |
| Git and GitHub | Version control and project hosting |
| Streamlit Community Cloud | Application deployment |

## 🏗️ Project Structure

```text
Threat-intelligence-dashboard/
│
├── app.py
├── requirements.txt
├── .gitignore
├── README.md
│
└── modules/
    ├── __init__.py
    ├── virustotal.py
    ├── abuseipdb.py
    ├── history.py
    ├── auth.py
    └── supabase_client.py
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-GITHUB-USERNAME/Threat-intelligence-dashboard.git
```

### 2. Open the project folder

```bash
cd Threat-intelligence-dashboard
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API keys and Supabase credentials

Create a `.env` file in the project folder and add your credentials:

```env
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
SUPABASE_URL=your_supabase_project_url
SUPABASE_KEY=your_supabase_anon_or_publishable_key
```

Use your own credentials. Never upload `.env` to GitHub.

### 5. Run the application

```bash
streamlit run app.py
```

The application will open in your browser.

## 🔍 How It Works

1. A user signs in or creates an account.
2. The user enters an IP address, domain, URL, or file hash.
3. The application identifies the indicator type.
4. VirusTotal is queried for available threat intelligence.
5. AbuseIPDB is queried for public IP addresses.
6. The investigation results are displayed in the dashboard.
7. Investigation records are stored in Supabase.
8. Users can review available history and analytics.

## 🔐 Security Considerations

- API credentials are configured through environment variables or Streamlit secrets.
- User authentication is handled through Supabase.
- Database access is intended to be controlled through Supabase Row Level Security policies.
- Administrative functionality is role-based.
- Sensitive credentials should never be committed to the public repository.

## 🚀 Deployment

The application is designed to be deployed using Streamlit Community Cloud.

Configure the required credentials in the application's Streamlit Cloud secrets settings before deployment.

## 🎯 Learning Outcomes

Through this project, I gained practical experience with:

- Threat intelligence and IOC investigation.
- Integrating external security APIs.
- Python-based application development.
- Streamlit dashboard development.
- Authentication and database integration.
- GitHub version control and cloud deployment.

## 👩‍💻 Author

**Cybersecurity Student | Aspiring Threat Intelligence Analyst**

