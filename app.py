from flask import Flask, render_template, request, make_response, send_file
from api_clients import check_virustotal, check_abuseipdb
from db import collection
from collections import defaultdict, Counter
import io
import json
from scheduler import start_scheduler
import folium
import requests
from flask import render_template_string
from weasyprint import HTML
from datetime import datetime  # ✅ KEEP THIS

start_scheduler()
app = Flask(__name__)

# Helper: calculate threat level
def get_threat_level_numeric(result):
    try:
        attributes = result.get("vt", {}).get("data", {}).get("attributes", {})
        context = attributes.get("crowdsourced_context", [])
        if context:
            sev = context[0].get("severity", "").lower()
            return {"low": 1, "medium": 2, "high": 3}.get(sev, 0)
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious >= 10 or suspicious >= 10:
            return 3
        elif malicious >= 3 or suspicious >= 3:
            return 2
        elif malicious >= 1 or suspicious >= 1:
            return 1
        else:
            return 0
    except Exception as e:
        print("Threat level detection error:", e)
        return 0

# IP geolocation using ip-api.com
def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data.get('status') == 'success':
            return [data['lat'], data['lon']]
    except Exception as e:
        print("Geolocation fetch error:", e)
    return None

# Detect IOC type
def get_ioc_type(ioc):
    if ":" in ioc:
        return "hash"
    elif all(c in "0123456789abcdefABCDEF" for c in ioc) and len(ioc) in [32, 40, 64]:
        return "hash"
    elif any(c.isalpha() for c in ioc) and "." in ioc:
        return "domain"
    else:
        return "ip"

@app.route('/', methods=['GET', 'POST'])
def dashboard():
    result = {}
    history = list(collection.find().sort("timestamp", -1).limit(10))

    def get_ioc_type(ioc):
        import re
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            return "ip"
        elif re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", ioc):
            return "domain"
        else:
            return "hash"

    if request.method == 'POST':
        ioc = request.form['ioc']
        tag = request.form.get('tag', 'unknown')

        ioc_type = get_ioc_type(ioc)
        vt_result = check_virustotal(ioc, ioc_type)  #  Pass both

        abuse_result = check_abuseipdb(ioc) if ioc_type == 'ip' else {}

        if not abuse_result or "data" not in abuse_result:
            abuse_result = {}

        attributes = vt_result.get("data", {}).get("attributes", {})

        registrar = attributes.get("registrar", None)
        creation_date = attributes.get("creation_date", None)
        if creation_date:
            created_years_ago = int((datetime.utcnow() - datetime.utcfromtimestamp(creation_date)).days / 365)
            creation_str = f"{created_years_ago} years ago"
        else:
            creation_str = "Unknown"

        summary = {
            "vendor_count": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "total_vendors": sum(attributes.get("last_analysis_stats", {}).values()),
            "community_score": attributes.get("reputation", 0),
            "asn": attributes.get("asn", registrar or "Unknown"),
            "as_owner": attributes.get("as_owner", creation_str),
            "country": attributes.get("country", "Unknown"),
            "network": attributes.get("network", "Unknown"),
            "rir": attributes.get("regional_internet_registry", "Unknown"),
            "whois": attributes.get("whois", None),
            "last_analysis_date": datetime.utcfromtimestamp(
                attributes.get("last_analysis_date", 0)
            ).strftime('%Y-%m-%d %H:%M:%S UTC') if attributes.get("last_analysis_date") else "Unknown"
        }

        result = {
            "ioc": ioc,
            "vt": vt_result,
            "abuse": abuse_result,
            "tag": tag,
            "summary": summary
        }

        threat_level_numeric = get_threat_level_numeric(result)

        collection.insert_one({
            "ioc": ioc,
            "vt": vt_result,
            "abuse": abuse_result,
            "tag": tag,
            "threat_level_numeric": threat_level_numeric,
            "timestamp": datetime.utcnow()
        })

        history = list(collection.find().sort("timestamp", -1).limit(10))

    chart_data = defaultdict(list)
    for entry in collection.find():
        ts = entry.get("timestamp")
        if ts:
            day = ts.strftime("%Y-%m-%d")
            chart_data[day].append(entry.get("threat_level_numeric", 0))

    labels = sorted(chart_data.keys())[-7:]
    values = [sum(chart_data[day]) / len(chart_data[day]) for day in labels]

    all_iocs = [entry.get("ioc") for entry in collection.find() if entry.get("ioc")]
    top_entities = Counter(all_iocs).most_common(10)
    top_entity_labels = [ioc for ioc, _ in top_entities]
    top_entity_counts = [count for _, count in top_entities]

    all_entries = list(collection.find())
    total_lookups = len(all_entries)
    total_reports = sum(1 for entry in all_entries if entry.get("vt"))
    total_malicious = sum(
        entry.get("vt", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        for entry in all_entries
    )
    total_countries = len(set(
        entry.get("vt", {}).get("data", {}).get("attributes", {}).get("country", "Unknown")
        for entry in all_entries if entry.get("vt")
    ))
    unique_iocs = len(set(entry.get("ioc") for entry in all_entries if entry.get("ioc")))

    return render_template('dashboard.html',
                           result=result,
                           history=history,
                           labels=labels,
                           values=values,
                           top_entity_labels=top_entity_labels,
                           top_entity_counts=top_entity_counts,
                           total_lookups=total_lookups,
                           total_reports=total_reports,
                           total_malicious=total_malicious,
                           total_countries=total_countries,
                           unique_iocs=unique_iocs)

@app.route('/map')
def ip_map():
    latest_entry = collection.find().sort("timestamp", -1).limit(1)
    m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
    for entry in latest_entry:
        ip = entry.get("ioc")
        loc = get_geolocation(ip)
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

@app.route('/export/pdf')
def export_pdf():
    latest = collection.find_one(sort=[("timestamp", -1)])
    if not latest:
        return "No data to generate PDF", 404

    vt_result = latest.get("vt", {})
    abuse_result = latest.get("abuse", {})
    attributes = vt_result.get("data", {}).get("attributes", {})

    summary = {
        "vendor_count": attributes.get("last_analysis_stats", {}).get("malicious", 0),
        "total_vendors": sum(attributes.get("last_analysis_stats", {}).values()),
        "community_score": attributes.get("reputation", 0),
        "asn": attributes.get("asn", "Unknown"),
        "as_owner": attributes.get("as_owner", "Unknown"),
        "country": attributes.get("country", "Unknown"),
        "network": attributes.get("network", "Unknown"),
        "rir": attributes.get("regional_internet_registry", "Unknown"),
        "whois": attributes.get("whois", None),
        "registrar": attributes.get("registrar", "Unknown"),
        "domain_creation": latest.get("summary", {}).get("domain_creation", "Unknown"),
        "last_analysis_date": datetime.utcfromtimestamp(
            attributes.get("last_analysis_date", 0)
        ).strftime('%Y-%m-%d %H:%M:%S UTC') if attributes.get("last_analysis_date") else "Unknown"
    }

    result = {
        "ioc": latest.get("ioc"),
        "vt": vt_result,
        "abuse": abuse_result,
        "tag": latest.get("tag", "unknown"),
        "summary": summary
    }

    html = render_template("pdf_report.html", result=result, now=datetime.utcnow())
    pdf = HTML(string=html).write_pdf()

    return send_file(
        io.BytesIO(pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="ioc_threat_report.pdf"
    )

@app.route('/export/json')
def export_json():
    entries = list(collection.find().sort("timestamp", -1))
    data = [{
        "timestamp": str(entry.get("timestamp")),
        "ioc": entry.get("ioc"),
        "tag": entry.get("tag"),
        "threat_level_numeric": entry.get("threat_level_numeric")
    } for entry in entries]
    return make_response(json.dumps(data, indent=2), 200, {'Content-Type': 'application/json'})

@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        return datetime.utcfromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return "Unknown"

if __name__ == '__main__':
    app.run(debug=True)
