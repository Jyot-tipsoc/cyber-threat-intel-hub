# 🛡️ Cyber Threat Intelligence Hub

**Advanced Threat Intelligence Platform (TIP) for Financial Institutions**

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.13-green)](https://elastic.co)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue)](https://docker.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-orange)](LICENSE)

---

## 📌 Project Overview

The **Cyber Threat Intelligence Hub** is a fully automated Threat Intelligence Platform (TIP) designed for financial institutions to proactively defend against cyber threats.

The platform:
- Collects malicious IPs, domains, and URLs from 5 OSINT sources
- Normalizes and risk-scores every indicator (HIGH / MEDIUM / LOW)
- Pushes data into Elasticsearch and visualizes it in Kibana
- Automatically blocks high-risk IPs using Linux iptables
- Generates threat reports and runs a full automated test suite

---

## 📁 Project Structure

```
cyber-threat-intel-hub/
│
├── Week1/                          # OSINT Data Collection
│   ├── feed_collector.py
│   ├── requirements.txt
│   ├── .env                        # API keys (never commit)
│   └── data/
│       └── raw_indicators.json
│
├── Week2/                          # Normalization + ELK SIEM
│   ├── normalizer.py
│   ├── elk_pusher.py
│   ├── docker-compose.yml
│   ├── requirements.txt
│   └── data/
│       ├── raw_indicators.json
│       └── normalized_indicators.json
│
├── Week3/                          # Dynamic Policy Enforcement
│   ├── policy_enforcer.py
│   ├── rollback.py
│   ├── requirements.txt
│   └── data/
│       ├── blocked_ips.json
│       └── enforcement_log.json
│
├── Week4/                          # Alerting + Testing
│   ├── alert_system.py
│   ├── test_suite.py
│   ├── requirements.txt
│   └── data/
│       ├── alert_report.json
│       └── test_results.json
│
├── Config/                         # Central Configuration
│   ├── config.yml
│   ├── mongo_init.js
│   └── blocklist.py
│
├── docker-compose.yml              # Full ELK + MongoDB stack
├── requirements.txt
├── .gitignore
├── LICENSE                         # Apache 2.0
└── README.md
```

---

## 🔄 How It Works

**Week 1** → Feed Collector pulls threat data from 5 OSINT sources and saves to `raw_indicators.json`

**Week 2** → Normalizer cleans and scores the data, then ELK Pusher sends it to Elasticsearch for Kibana visualization

**Week 3** → Policy Enforcer reads high-risk IPs and blocks them using Linux iptables. Rollback tool lets SOC analysts undo any block

**Week 4** → Alert System generates a threat summary report. Test Suite automatically validates all 4 weeks

---

## ⚡ Quick Start

### Install requirements
```bash
pip3 install -r requirements.txt --break-system-packages
```

### Week 1 — Collect threat data
```bash
cd Week1
nano .env          # add your API keys
python3 feed_collector.py
```

### Week 2 — Normalize + push to Kibana
```bash
cd Week2
cp ../Week1/data/raw_indicators.json data/
python3 normalizer.py
sudo docker compose up -d
python3 elk_pusher.py
# Open Kibana: http://localhost:5601
```

### Week 3 — Block malicious IPs
```bash
cd Week3
cp ../Week2/data/normalized_indicators.json data/
python3 policy_enforcer.py
python3 rollback.py list
```

### Week 4 — Alerts and testing
```bash
cd Week4
python3 alert_system.py
python3 test_suite.py
```

---

## 📊 OSINT Sources

| Source | Data Type | API Key |
|--------|-----------|---------|
| AlienVault OTX | IPs, Domains, URLs | Free |
| VirusTotal | Malicious IPs | Free |
| AbuseIPDB | Reported IPs | Free |
| Feodo Tracker | Botnet C2 IPs | Not needed |
| URLhaus | Malware URLs | Not needed |

---

## 🎯 Risk Scoring

| Score | Severity | Action |
|-------|----------|--------|
| 80 – 100 | 🔴 HIGH | Auto-blocked by enforcer |
| 50 – 79 | 🟡 MEDIUM | Logged and monitored |
| 0 – 49 | 🟢 LOW | Logged only |

---

## 🛠️ Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Language | Python | 3.11 |
| SIEM | Elasticsearch + Kibana | 8.13 |
| Database | MongoDB | 7.0 |
| Firewall | Linux iptables | - |
| Infrastructure | Docker + Compose | - |
| Version Control | Git + GitHub | - |

---

## 🔑 API Keys Setup

Create `Week1/.env` file:
```
OTX_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

Get free keys from:
- OTX → https://otx.alienvault.com
- VirusTotal → https://www.virustotal.com
- AbuseIPDB → https://www.abuseipdb.com

> ⚠️ Never commit your `.env` file to GitHub!

---

## 🗺️ Project Roadmap

| Week | Task | Status |
|------|------|--------|
| Week 1 | OSINT Data Collection | ✅ Complete |
| Week 2 | Normalization + ELK SIEM | ✅ Complete |
| Week 3 | Dynamic Policy Enforcer | ✅ Complete |
| Week 4 | Alert System + Test Suite | ✅ Complete |

---


# Week 1 — OSINT Feed Collector

## Files in this folder

```
week1/
├── feed_collector.py   ← main script (only file you need to run)
├── requirements.txt    ← 2 Python packages
├── .env                ← your API keys go here
└── output/             ← auto-created when you run the script
    └── raw_indicators.json
```

---

## Step-by-step commands

### Step 1 — Go to your project folder
```bash
cd ~/Downloads/week1
```

### Step 2 — Install the required packages
```bash
pip install -r requirements.txt
```

### Step 3 — Add your API keys
```bash
nano .env
```
Paste your keys like this (no quotes):
```
OTX_API_KEY=abc123yourkeyhere
VIRUSTOTAL_API_KEY=xyz789yourkeyhere
ABUSEIPDB_API_KEY=def456yourkeyhere
```
Save with **Ctrl+O**, exit with **Ctrl+X**

> No keys yet? That's OK — Sources 4 and 5 are completely free and work without any keys.

### Step 4 — Run the collector
```bash
python3 feed_collector.py
```

---

## Sample output (what you should see)

```
══════════════════════════════════════════════════
   WEEK 1 — OSINT Feed Collector
   Threat Intelligence Platform (TIP)
══════════════════════════════════════════════════
   Started: 2026-04-22 10:30:00 UTC

──────────────────────────────────────────────────
  SOURCE 1 — AlienVault OTX
──────────────────────────────────────────────────
  → Connecting to OTX API...
  → Fetched 5 threat pulses
  [+] IPv4       185.220.101.45
  [+] domain     malicious-site.ru
  ✅ OTX total: 12 indicators

──────────────────────────────────────────────────
  SOURCE 2 — VirusTotal
──────────────────────────────────────────────────
  → Looking up 3 IPs on VirusTotal...
  🔴 185.220.101.1        8/90 detections  [DE]
  🟢 198.51.100.23        0/90 detections  [US]
  ✅ VirusTotal total: 1 indicators

──────────────────────────────────────────────────
  SOURCE 3 — AbuseIPDB
──────────────────────────────────────────────────
  → Fetching top reported IPs (confidence ≥ 90%)...
  🔴 45.141.84.83         confidence: 100%   reports: 5823   [DE]
  🔴 179.43.175.6         confidence: 100%   reports: 3210   [BR]
  ✅ AbuseIPDB total: 20 indicators

──────────────────────────────────────────────────
  SOURCE 4 — Feodo Tracker  (FREE — no key needed)
──────────────────────────────────────────────────
  → Downloading botnet C2 IP blocklist...
  🔴 103.75.190.3
  🔴 45.95.168.157
  ... and 245 more
  ✅ Feodo Tracker total: 250 indicators

──────────────────────────────────────────────────
  SOURCE 5 — URLhaus  (FREE — no key needed)
──────────────────────────────────────────────────
  → Downloading active malware URLs...
  🔴 http://malware-host.xyz/payload.exe
  🔴 http://badsite.top/drop/file.bin
  ... and 1843 more
  ✅ URLhaus total: 1848 indicators

══════════════════════════════════════════════════
   COLLECTION COMPLETE — SUMMARY
══════════════════════════════════════════════════
   AlienVault_OTX              12 indicators
   VirusTotal                   1 indicators
   AbuseIPDB                   20 indicators
   Feodo_Tracker              250 indicators
   URLhaus                   1848 indicators
──────────────────────────────────────────────────
   TOTAL                     2131 indicators
──────────────────────────────────────────────────

   📁 Saved to: output/raw_indicators.json

   ✅ Week 1 complete!
   → Ready for Week 2: normalization + Elasticsearch
══════════════════════════════════════════════════
```

---

## Check the saved file
```bash
# See how many indicators were collected
cat output/raw_indicators.json | python3 -m json.tool | head -40
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `pip: command not found` | Use `pip3` instead of `pip` |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` again |
| OTX/VT/AbuseIPDB shows "skipping" | Check your key is pasted correctly in `.env` with no spaces |
| Output file is empty | Check internet connection, at least Feodo+URLhaus should always work |


## 🚀 Future Improvements

- MongoDB integration for persistent long-term storage
- Scheduled feed collection every 6 hours via cron
- REST API for SOC dashboard integration
- Email and Slack alerts for HIGH risk blocks
- GeoIP world map visualization in Kibana
- Machine learning anomaly detection on threat patterns

---

## 📄 License

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Internship Project — Finance & Banking Cybersecurity**
Threat Intelligence Platform (TIP) | Advanced Security Engineering
GitHub: [@Jyot-tipsoc](https://github.com/Jyot-tipsoc)

> ⚠️ `DRY_RUN = True` is set by default in `policy_enforcer.py` for safety.
> Only disable on a dedicated security VM.
