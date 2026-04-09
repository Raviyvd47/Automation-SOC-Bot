import requests
import os
from dotenv import load_dotenv

# Module 1: Configuration Loader [cite: 112]
# Load API key securely from .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def check_file_threat(file_hash):
    """
    Module 11: Threat Query Module [cite: 151]
    Sends the digital fingerprint to VirusTotal Cloud[cite: 341].
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }

    try:
        # Module 10: API Connection Manager [cite: 146]
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Module 12: Response Parsing [cite: 155]
            data = response.json()
            # Extracting malicious_votes (Module 12 Logic) [cite: 159]
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            
            # Module 13: Decision Engine [cite: 160]
            # IF malicious_votes > 0 THEN Status = THREAT [cite: 162]
            status = "THREAT" if malicious_count > 0 else "CLEAN"
            return malicious_count, status
            
        elif response.status_code == 404:
            return 0, "NOT_FOUND"  # Hash not in VT database [cite: 344]
        elif response.status_code == 429:
            return 0, "RATE_LIMIT_EXCEEDED"  # Public API limit: 4/min [cite: 336]
        else:
            return 0, f"API_ERROR_{response.status_code}"

    except Exception as e:
        return 0, "CONNECTION_FAILED"  # Module 10: Handle network timeouts [cite: 149]


def check_ip_threat(ip_address):
    """
    Query VirusTotal for IP address reputation.
    Returns (malicious_count, status) tuple.
    """
    import re
    # Basic IP validation
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip_address):
        return 0, "INVALID_IP"

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            status = "THREAT" if malicious_count > 0 else "CLEAN"
            return malicious_count, status
        elif response.status_code == 404:
            return 0, "NOT_FOUND"
        elif response.status_code == 429:
            return 0, "RATE_LIMIT_EXCEEDED"
        else:
            return 0, f"API_ERROR_{response.status_code}"

    except Exception as e:
        return 0, "CONNECTION_FAILED"


def check_url_threat(target_url):
    """
    Query VirusTotal for URL reputation.
    The URL must be base64-encoded (without padding) for the v3 API.
    Returns (malicious_count, status) tuple.
    """
    import base64

    # Base64 encode the URL (no padding) as required by VT API v3
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")

    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            status = "THREAT" if malicious_count > 0 else "CLEAN"
            return malicious_count, status
        elif response.status_code == 404:
            return 0, "NOT_FOUND"
        elif response.status_code == 429:
            return 0, "RATE_LIMIT_EXCEEDED"
        else:
            return 0, f"API_ERROR_{response.status_code}"

    except Exception as e:
        return 0, "CONNECTION_FAILED"