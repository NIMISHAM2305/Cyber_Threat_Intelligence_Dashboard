import requests
import datetime
from db import collection  # <-- This line must be outside try/except

def fetch_threat_feed():
    print("🔁 Fetching threat feed...")

    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {
            "X-OTX-API-KEY": "YOUR_OTX_API_KEY"  # Replace with your valid key
        }

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            print(f"❌ Error {response.status_code}: Failed to fetch feed")
            return

        data = response.json()
        pulses = data.get("results", [])

        new_iocs = 0

        for pulse in pulses:
            pulse_name = pulse.get("name", "Unknown Pulse")
            created_at = pulse.get("created", datetime.datetime.utcnow().isoformat())
            pulse_tags = pulse.get("tags", [])
            author = pulse.get("author_name", "Unknown")
            pulse_id = pulse.get("id", "")

            for indicator in pulse.get("indicators", []):
                ioc = indicator.get("indicator")
                ioc_type = indicator.get("type")
                country = indicator.get("country", "Unknown")

                if not collection.find_one({"ioc": ioc}):
                    collection.insert_one({
                        "ioc": ioc,
                        "type": ioc_type,
                        "source": "AlienVault",
                        "tag": pulse_name,
                        "tags": pulse_tags,
                        "pulse_id": pulse_id,
                        "author": author,
                        "country": country,
                        "timestamp": datetime.datetime.now(datetime.UTC),
                        "origin_date": created_at
                    })
                    new_iocs += 1

        print(f"✅ {new_iocs} new IOCs saved.")

    except Exception as e:
        print("❗ Exception occurred during feed fetch:", str(e))
