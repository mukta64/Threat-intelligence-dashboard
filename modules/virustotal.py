
import os
import re
import ipaddress
import base64
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

def get_api_key():
    key = os.getenv("VT_API_KEY")

    if key:
        return key

    try:
        import streamlit as st
        return st.secrets.get("VT_API_KEY")
    except Exception:
        return None


def identify_indicator(indicator):
    indicator = indicator.strip()

    if not indicator or len(indicator) > 2048:
        return None

    # Reject whitespace and control characters
    if any(char.isspace() or ord(char) < 32 for char in indicator):
        return None

    # IP address
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass

    # File hashes: MD5, SHA-1 and SHA-256
    if re.fullmatch(r"[a-fA-F0-9]{32}", indicator):
        return "file"

    if re.fullmatch(r"[a-fA-F0-9]{40}", indicator):
        return "file"

    if re.fullmatch(r"[a-fA-F0-9]{64}", indicator):
        return "file"

    # Domain validation
    domain_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    # URL validation
    if "://" in indicator:
        try:
            parsed = urlparse(indicator)

            if parsed.scheme not in ("http", "https"):
                return None

            if not parsed.hostname:
                return None

            # Reject invalid ports
            if parsed.port is not None and not (
                1 <= parsed.port <= 65535
            ):
                return None

            hostname = parsed.hostname.lower().rstrip(".")

            try:
                ipaddress.ip_address(hostname)
                return "url"
            except ValueError:
                pass

            if re.fullmatch(domain_pattern, hostname):
                return "url"

            return None

        except ValueError:
            return None

    # Normal domain
    domain = indicator.lower().rstrip(".")

    if re.fullmatch(domain_pattern, domain):
        return "domain"

    return None


def get_endpoint(indicator, indicator_type):
    if indicator_type == "ip":
        return f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"

    if indicator_type == "domain":
        return f"https://www.virustotal.com/api/v3/domains/{indicator}"

    if indicator_type == "file":
        return f"https://www.virustotal.com/api/v3/files/{indicator}"

    if indicator_type == "url":
        url_id = base64.urlsafe_b64encode(
            indicator.encode()
        ).decode().rstrip("=")

        return f"https://www.virustotal.com/api/v3/urls/{url_id}"

    return None


def check_virustotal(indicator):
    indicator = indicator.strip()
    api_key = get_api_key()

    if not api_key:
        return {"error": "VirusTotal API key not found. Check your .env or Streamlit secrets."}

    indicator_type = identify_indicator(indicator)

    if not indicator_type:
        return {"error": "Invalid IP, domain, URL or file hash."}

    endpoint = get_endpoint(indicator, indicator_type)

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=25
        )

        if response.status_code == 200:
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})

            if not attributes:
                return {"error": "VirusTotal returned no analysis information."}

            return {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "attributes": attributes
            }

        if response.status_code == 401:
            return {"error": "VirusTotal API key is invalid or unauthorized."}

        if response.status_code == 403:
            return {"error": "VirusTotal access forbidden. Check API permissions."}

        if response.status_code == 404:
            return {"error": "Indicator not found in VirusTotal."}

        if response.status_code == 429:
            return {"error": "VirusTotal API rate limit exceeded. Try again later."}

        return {
            "error": f"VirusTotal API error: {response.status_code}",
            "details": response.text[:500]
        }

    except requests.Timeout:
        return {"error": "VirusTotal request timed out. Try again."}

    except requests.RequestException as error:
        return {"error": f"Network error: {error}"}
