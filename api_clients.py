import requests
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

def check_virustotal(ip_or_domain):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_or_domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    response = requests.get(url, headers=headers, params=params)
    return response.json()

def get_geolocation_data(ip):
    try:
        import requests
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

