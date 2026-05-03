# 🛡️ Threat Intelligence Platform (TIP)

A production-grade Threat Intelligence Platform with automated firewall enforcement, SIEM integration, and SOC dashboard — built for financial institutions.


📌 Project Overview
The Cyber Threat Intelligence Hub is a fully automated Threat Intelligence
Platform (TIP) designed for financial institutions to proactively defend against
cyber threats such as botnets, malware distribution networks, and abusive IPs.
The platform collects malicious indicators (IPs, domains, URLs) from multiple
OSINT sources, normalizes and risk-scores them, enforces firewall rules via
iptables, and provides a Kibana SIEM dashboard for real-time visualization.

🏗️ Architecture
┌──────────────────────────────────────────────────────────────┐
│                   TIP — System Architecture                  │
│                                                              │
│  OSINT Sources         Week 1            Output              │
│  ┌───────────┐      ┌──────────┐      ┌──────────┐          │
│  │ OTX       │─────▶│  Feed    │─────▶│  raw_    │          │
│  │VirusTotal │─────▶│Collector │      │indicators│          │
│  │ AbuseIPDB │─────▶│          │      │  .json   │          │
│  │ Feodo     │─────▶│          │      └──────────┘          │
│  │ URLhaus   │─────▶│          │            │                │
│  └───────────┘      └──────────┘            │                │
│                                             ▼                │
│                          Week 2      ┌──────────┐            │
│                       ┌──────────┐   │Normalized│            │
│                       │Normalizer│──▶│indicators│            │
│                       │+ Scoring │   │  .json   │            │
│                       └──────────┘   └──────────┘            │
│                            │               │                  │
│                            ▼               ▼                  │
│                       ┌──────────┐   ┌──────────┐            │
│                       │   ELK    │   │  Week 3  │            │
│                       │  Stack   │   │  Policy  │            │
│                       │ Kibana   │   │ Enforcer │            │
│                       └──────────┘   └──────────┘            │
│                                            │                  │
│                          Week 4            ▼                  │
│                       ┌──────────────────────┐               │
│                       │  Alert System +      │               │
│                       │  Test Suite +        │               │
│                       │  Final Report        │               │
│                       └──────────────────────┘               │
└──────────────────────────────────────────────────────────────┘

📁 Project Structure
cyber-threat-intel-hub/
│
├── Week1/                              # OSINT Data Collection
│   ├── feed_collector.py               # Pulls data from 5 OSINT sources
│   ├── requirements.txt
│   ├── .env                            # API keys (never commit this)
│   └── data/
│       └── raw_indicators.json
│
├── Week2/                              # Normalization + SIEM
│   ├── normalizer.py                   # Cleans + risk-scores data
│   ├── elk_pusher.py                   # Pushes to Elasticsearch
│   ├── docker-compose.yml
│   ├── requirements.txt
│   └── data/
│       ├── raw_indicators.json
│       └── normalized_indicators.json
│
├── Week3/                              # Dynamic Policy Enforcement
│   ├── policy_enforcer.py              # Blocks IPs via iptables
│   ├── rollback.py                     # SOC analyst rollback tool
│   ├── requirements.txt
│   └── data/
│       ├── blocked_ips.json
│       └── enforcement_log.json
│
├── Week4/                              # Alerting + Testing
│   ├── alert_system.py                 # Generates threat reports
│   ├── test_suite.py                   # Tests all 4 weeks
│   ├── requirements.txt
│   └── data/
│       ├── alert_report.json
│       └── test_results.json
│
├── Config/                             # Central Configuration
│   ├── config.yml                      # All settings
│   ├── mongo_init.js                   # MongoDB initialization
│   └── blocklist.py                    # Blocklist management
│
├── docker-compose.yml                  # Full ELK + MongoDB stack
├── requirements.txt                    # All Python dependencies
├── .gitignore
├── LICENSE                             # Apache 2.0
└── README.md

⚡ Quick Start
bash# Install packages
pip3 install -r requirements.txt --break-system-packages

# Week 1 - Collect data
cd Week1 && python3 feed_collector.py

# Week 2 - Normalize + push to ELK
cd ../Week2
cp ../Week1/data/raw_indicators.json data/
python3 normalizer.py
sudo docker compose up -d
python3 elk_pusher.py
# Open: http://localhost:5601

# Week 3 - Enforce firewall rules
cd ../Week3
cp ../Week2/data/normalized_indicators.json data/
python3 policy_enforcer.py
python3 rollback.py list

# Week 4 - Alerts + Testing
cd ../Week4
python3 alert_system.py
python3 test_suite.py

📅 Week-by-Week Guide
✅ Week 1 — OSINT Data Collection
SourceData TypeAPI KeyAlienVault OTXIPs, Domains, URLsFreeVirusTotalMalicious IPsFreeAbuseIPDBReported IPsFreeFeodo TrackerBotnet C2 IPsNot neededURLhausMalware URLsNot needed
✅ Week 2 — Normalization + ELK SIEM
Risk Scoring:
ScoreSeverity80-100🔴 HIGH50-79🟡 MEDIUM0-49🟢 LOW
✅ Week 3 — Dynamic Policy Enforcement
bashpython3 rollback.py list              # show blocked IPs
python3 rollback.py unblock 1.2.3.4  # rollback false positive
python3 rollback.py log              # view audit log
✅ Week 4 — Alerting + Testing
Automated test suite checks all 4 weeks and generates a pass/fail report.

🛠️ Technology Stack
ComponentTechnologyVersionLanguagePython3.11OSINTOTX, VirusTotal, AbuseIPDB, Feodo, URLhaus-SIEMElasticsearch + Kibana8.13DatabaseMongoDB7.0FirewallLinux iptables-InfrastructureDocker + Compose-

🔑 Environment Variables
Create Week1/.env:
OTX_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here

⚠️ Never commit your .env file!


🗺️ Project Roadmap
WeekTaskStatusWeek 1OSINT Data Collection✅ CompleteWeek 2Normalization + ELK SIEM✅ CompleteWeek 3Dynamic Policy Enforcer✅ CompleteWeek 4Alert System + Test Suite✅ Complete

🚀 Future Improvements

MongoDB integration for persistent storage
Scheduled collection via cron (every 6 hours)
REST API for SOC dashboard
Email + Slack alerts for HIGH risk blocks
GeoIP mapping on Kibana world map
Machine learning anomaly detection


📄 License
Licensed under the Apache License 2.0 — see LICENSE.
Apache 2.0 provides patent protection, commercial use freedom,
and required attribution when code is reused.

👤 Author
Internship Project — Finance & Banking Cybersecurity
Threat Intelligence Platform (TIP) | Advanced Security Engineering
GitHub: @Jyot-tipsoc

⚠️ DRY_RUN = True by default in policy_enforcer.py.
Only disable on a dedicated security VM.
ShareContentProject 1: Finance & Banking - Advanced Threat
Intelligence Platform (TIP) & Dynamic Policy Enforcer
Executive Problem Statement
Financial institutions face a relentless barrage of sophisticated cyber attacks. Traditional static
firewall rules and isolated security perimeters are insufficient agpasted
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

                           Copyright 2026 Jyot-tipsoc

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definipasted(function(){function c(){var b=a.contentDocument||a.contentWindow.document;if(b){var d=b.createElement('script');d.nonce='8BU8OeXC5ZTIrEGC+v5zhw==';d.innerHTML="window.__CF$cv$params={r:'9f60a40fd856bff9',t:'MTc3NzgyNTcyNw=='};var a=document.createElement('script');a.nonce='8BU8OeXC5ZTIrEGC+v5zhw==';a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';document.getElementsByTagName('head')[0].appendChild(a);";b.getElementsByTagName('head')[0].appendChild(d)}}if(document.body){var a=document.createElement('iframe');a.height=1;a.width=1;a.style.position='absolute';a.style.top=0;a.style.left=0;a.style.border='none';a.style.visibility='hidden';document.body.appendChild(a);if('loading'!==document.readyState)c();else if(window.addEventListener)document.addEventListener('DOMContentLoaded',c);else{var e=document.onreadystatechange||function(){};document.onreadystatechange=function(b){e(b);'loading'!==document.readyState&&(document.onreadystatechange=e,c())}}}})();host.** Set `ENFORCER_DRY_RUN=true` during development to simulate without affecting real firewall rules.
