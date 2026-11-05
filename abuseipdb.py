
import os
import ipaddress
import requests
from dotenv import load_dotenv

load_dotenv()


def get_api_key():
    key = os.getenv("ABUSEIPDB_API_KEY")

    if key:
        return key

    try:
        import streamlit as st
        return st.secrets.get("ABUSEIPDB_API_KEY")
    except Exception:
        return None


def check_abuseipdb(ip):
    api_key = get_api_key()

    if not api_key:
        return {"error": "AbuseIPDB API key not found. Check your .env or Streamlit secrets."}

    try:
        parsed_ip = ipaddress.ip_address(ip.strip())

        if not parsed_ip.is_global:
            return {"error": "AbuseIPDB checking is intended for public IP addresses."}

    except ValueError:
        return {"error": "Please enter a valid IP address."}

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": str(parsed_ip),
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=25
        )

        if response.status_code == 200:
            result = response.json()
            return result.get("data", {})

        if response.status_code == 401:
            return {"error": "AbuseIPDB API key is invalid or unauthorized."}

        if response.status_code == 403:
            return {"error": "AbuseIPDB access forbidden. Check your API permissions."}

        if response.status_code == 422:
            return {"error": "AbuseIPDB could not process this IP address."}

        if response.status_code == 429:
            return {"error": "AbuseIPDB API rate limit exceeded. Try again later."}

        return {
            "error": f"AbuseIPDB API error: {response.status_code}",
            "details": response.text[:500]
        }

    except requests.Timeout:
        return {"error": "AbuseIPDB request timed out. Try again."}

    except requests.RequestException as error:
        return {"error": f"Network error: {error}"}
