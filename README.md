# 🛡️ Cyber Threat Intelligence Dashboard

A professional-grade **Cyber Threat Intelligence (CTI) Dashboard** built using **Flask**, **MongoDB**, and open-source threat intelligence APIs like **VirusTotal**, **AbuseIPDB**, and **ip-api**.

This tool enables security analysts to search IOCs (IPs, Domains, Hashes), analyze threat levels, view geographical origin on a map, and export detailed reports. Ideal for academic use or as a base for SOC/IR tools.

---

## 🔥 Key Features

- 🔍 Lookup support for IPs, Domains, and File Hashes
- 🧠 Threat scoring using VirusTotal (malicious/suspicious vendors)
- 🛑 AbuseIPDB threat reputation (for IPs)
- 🌍 Real-time Geolocation with interactive map (folium)
- 📊 Threat Level Trend chart (time-series)
- 📌 Top 10 most queried IOCs (entities)
- 📁 IOC summary cards: ASN/Registrar, Community Score, Country, Last Seen
- 📝 WHOIS record display for domains/IPs
- 📄 Export option: PDF Report (with all IOC details)
- 🧾 Tags and Lookup History

---

## ⚙️ Setup Instructions

### 1️. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/Cyber_Threat_Intelligence_Dashboard.git
cd Cyber_Threat_Intelligence_Dashboard
# Create virtual environment
python -m venv .venv
```
### 2. Create and Activate (choose one based on OS)
```bash
python -m venv .venv #create
.venv\Scripts\activate    # Windows
source .venv/bin/activate # macOS/Linux
```
### 3. Install dependencies
```bash
pip install -r requirements.txt
```
### 4. Add API Keys
```bash
# config.py
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
```
### 5. Ensure MongoDB is running
```bash
mongod
```
### 6. Run the dashboard
```bash
python app.py
```
### 7.Open you browser and go to
```bash
http://localhost:5000
```
---
## 🔍 Sample Searches to Try

You can use the following IOCs (Indicators of Compromise) to test the dashboard:

| Type   | Value               | Description        | Tag        |
|--------|---------------------|--------------------|------------|
| IP     | `8.8.8.8`           | Google Public DNS  | benign     |
| IP     | `185.220.100.255`   | Tor exit / malicious | malicious  |
| IP     | `223.187.109.137`   | Normal Indian ISP  | normal     |
| Domain | `malware.wicar.org` | Malware Test Site  | trojan     |
| Domain | `example.com`       | Reserved example domain (Safe)  | benign     |
| IP     | `1.1.1.1`           | Cloudflare DNS (Safe) | benign     |





