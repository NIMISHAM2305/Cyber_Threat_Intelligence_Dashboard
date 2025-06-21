
from flask import Flask, render_template, request, make_response, send_file
from api_clients import check_virustotal, check_abuseipdb
from db import collection
import datetime
from collections import defaultdict
import csv
import io
import json
from scheduler import start_scheduler
import folium
import os

start_scheduler()
app = Flask(__name__)

# Helper to map threat level
def get_threat_level_numeric(result):
    if not result:
        return 0

    # Try VirusTotal crowdsourced_context severity
    try:
        context = result.get("vt", {}).get("data", {}).get("attributes", {}).get("crowdsourced_context", [])
        if context:
            sev = context[0].get("severity", "").lower()
            return {"low": 1, "medium": 2, "high": 3}.get(sev, 0)
    except:
        pass

    # Try VT malicious statistics
    try:
        stats = result.get("vt", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats:
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious >= 5:
                return 3  # High
            elif malicious >= 1 or suspicious >= 3:
                return 2  # Medium
            elif suspicious >= 1:
                return 1  # Low
    except:
        pass

    # Try AbuseIPDB confidence score
    try:
        abuse_score = result.get("abuse", {}).get("data", {}).get("abuseConfidenceScore", 0)
        if abuse_score >= 80:
            return 3
        elif abuse_score >= 40:
            return 2
        elif abuse_score >= 1:
            return 1
    except:
        pass

    return 0  # Default to None


# Helper to get mock geolocation (replace with API call in real use)
def get_mock_geolocation(ip):
    sample_geo = {
        "8.8.8.8": [37.751, -97.822],
        "185.220.100.255": [52.52, 13.405],
        "1.1.1.1": [-33.8675, 151.207]
    }
    return sample_geo.get(ip, None)

@app.route('/', methods=['GET', 'POST'])
def dashboard():
    result = {}
    history = list(collection.find().sort("timestamp", -1).limit(10))

    if request.method == 'POST':
        ioc = request.form['ioc']
        tag = request.form.get('tag', 'unknown')
        vt_result = check_virustotal(ioc)
        abuse_result = check_abuseipdb(ioc)

        # Clean abuse result if missing
        if not abuse_result or "data" not in abuse_result:
            abuse_result = {}

        result = {
            "ioc": ioc,
            "vt": vt_result,
            "abuse": abuse_result,
            "tag": tag
        }

        threat_level_numeric = get_threat_level_numeric(result)

        collection.insert_one({
            "ioc": ioc,
            "vt": vt_result,
            "abuse": abuse_result,
            "tag": tag,
            "threat_level_numeric": threat_level_numeric,
            "timestamp": datetime.datetime.utcnow()
        })

        history = list(collection.find().sort("timestamp", -1).limit(10))

    # Chart data
    chart_data = defaultdict(list)
    for entry in collection.find():
        date = entry.get("timestamp")
        level = entry.get("threat_level_numeric", 0)
        if date:
            day = date.strftime("%Y-%m-%d")
            chart_data[day].append(level)

    sorted_dates = sorted(chart_data.keys())[-7:]
    labels = sorted_dates
    values = [sum(chart_data[day]) / len(chart_data[day]) for day in labels]

    return render_template('dashboard.html', result=result, history=history, labels=labels, values=values)

@app.route('/map')
def ip_map():
    entries = list(collection.find().sort("timestamp", -1))
    m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')

    for entry in entries:
        ip = entry.get("ioc")
        loc = get_mock_geolocation(ip)
        if loc:
            folium.CircleMarker(
                location=loc,
                radius=8,
                popup=f"IP: {ip}",
                color="#ff6666",
                fill=True,
                fill_color="#ff6666"
            ).add_to(m)

    map_path = "templates/ip_map.html"
    m.save(map_path)
    return render_template('ip_map.html')

# ... export_csv, export_json, feed_stats endpoints (keep them unchanged) ...

if __name__ == '__main__':
    app.run(debug=True)

