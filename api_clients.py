import requests
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
import re

# --- Helper to detect type ---
def detect_ioc_type(ioc):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        return "hash"
    else:
        return "domain"

# --- VirusTotal Lookup ---
def check_virustotal(ioc, ioc_type):
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        raise ValueError("Unsupported IOC type for VirusTotal")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

    try:
        return response.json()
    except Exception as e:
        print("VT response error:", e)
        return {}


# --- AbuseIPDB Lookup (only for IPs) ---
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    response = requests.get(url, headers=headers, params=params)
    return response.json()

# --- IP Geolocation ---
def get_geolocation_data(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        if response.status_code == 200:
            data = response.json()
            return {
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "city": data.get("city"),
                "country": data.get("country_name")
            }
    except Exception as e:
        print(f"Geo Error: {e}")
    return None

