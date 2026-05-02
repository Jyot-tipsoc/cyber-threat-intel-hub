# 🛡️ Threat Intelligence Platform (TIP)

A production-grade Threat Intelligence Platform with automated firewall enforcement, SIEM integration, and SOC dashboard — built for financial institutions.

---

## 📐 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        TIP Architecture                          │
│                                                                  │
│  OSINT Feeds          Aggregator            Storage              │
│  ┌─────────┐          ┌─────────┐           ┌──────────┐        │
│  │OTX      │─────────▶│         │──────────▶│ MongoDB  │        │
│  │VirusTotal│────────▶│ Python  │           └──────────┘        │
│  │AbuseIPDB│─────────▶│ daemon  │           ┌──────────┐        │
│  │Blocklists│────────▶│         │──────────▶│  Elastic │        │
│  └─────────┘          └─────────┘           └────┬─────┘        │
│                                                   │              │
│  Enforcer             Policy Engine          ┌────▼─────┐       │
│  ┌─────────┐          ┌─────────┐            │  Kibana  │       │
│  │iptables │◀─────────│ Python  │            │Dashboard │       │
│  │ ipset   │          │ daemon  │◀───────────└──────────┘       │
│  └─────────┘          └─────────┘                               │
│                                                                  │
│  Dashboard            REST API + Nginx                           │
│  ┌─────────┐          ┌─────────┐                               │
│  │  Flask  │◀─────────│  Nginx  │                               │
│  │  API    │          │  :80    │                               │
│  └─────────┘          └─────────┘                               │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
tip-platform/
├── docker-compose.yml          # Orchestrates all services
├── .env.example                # Environment variable template
├── .gitignore
├── pytest.ini
│
├── aggregator/                 # OSINT feed collection daemon
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 # Scheduler entry point
│   ├── normalizer.py           # Schema normalization
│   ├── feeds/
│   │   ├── blocklists.py       # Free public blocklists (no key needed)
│   │   ├── otx.py              # AlienVault OTX
│   │   ├── virustotal.py       # VirusTotal
│   │   └── abuseipdb.py        # AbuseIPDB
│   └── storage/
│       ├── mongo.py            # MongoDB layer
│       └── elastic.py          # Elasticsearch layer
│
├── enforcer/                   # Dynamic Policy Enforcer daemon
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── enforcer.py             # iptables/ipset enforcement daemon
│   └── rollback.py             # SOC analyst rollback CLI tool
│
├── dashboard/                  # REST API for SOC dashboard
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app.py                  # Flask API
│
├── nginx/
│   └── nginx.conf              # Reverse proxy config
│
├── scripts/
│   ├── mongo-init.js           # MongoDB initialization
│   ├── kibana-objects.json     # Pre-built Kibana dashboard
│   └── import-kibana.sh        # Kibana import helper
│
└── tests/
    └── test_normalizer.py      # Unit tests
```

---

## ⚡ Prerequisites

- **Linux** (Ubuntu 20.04+ recommended — enforcer uses iptables)
- **Docker** ≥ 24.0
- **Docker Compose** ≥ 2.20
- **Git**

```bash
# Install Docker (if not installed)
curl -fsSL https://get.docker.com | bash
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

---

## 🚀 Quick Start (Local)

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/tip-platform.git
cd tip-platform
```

### Step 2 — Configure environment variables

```bash
cp .env.example .env
nano .env      # or: vim .env / code .env
```

Edit the `.env` file:
```
MONGO_PASSWORD=your_strong_password_here
OTX_API_KEY=your_otx_key          # Free at otx.alienvault.com
ABUSEIPDB_API_KEY=your_key        # Free at abuseipdb.com
VIRUSTOTAL_API_KEY=your_key       # Free at virustotal.com (optional)
ENFORCER_DRY_RUN=true             # Set false when ready for live blocking
```

> **Note:** The platform works without API keys using free public blocklists. Add keys to enrich with more threat data.

### Step 3 — Start all services

```bash
docker compose up -d
```

Watch startup progress:
```bash
docker compose logs -f
```

### Step 4 — Verify services are healthy

```bash
docker compose ps

# Expected output:
# tip_mongodb        running (healthy)
# tip_elasticsearch  running (healthy)
# tip_aggregator     running
# tip_enforcer       running
# tip_dashboard      running
# tip_kibana         running
# tip_nginx          running
```

### Step 5 — Import Kibana dashboards

```bash
chmod +x scripts/import-kibana.sh
bash scripts/import-kibana.sh
```

---

## 🌐 Service URLs

| Service | URL | Description |
|---|---|---|
| Nginx Gateway | http://localhost:80 | Main entry point |
| Dashboard API | http://localhost:8080/api/stats | TIP REST API |
| Kibana | http://localhost:5601 | SIEM dashboard |
| Elasticsearch | http://localhost:9200 | Search engine |
| MongoDB | localhost:27017 | Database |

---

## 📊 API Endpoints

```bash
# Platform stats
curl http://localhost:8080/api/stats

# List indicators (paginated)
curl "http://localhost:8080/api/indicators?type=ip&min_risk=70&page=1"

# List blocked IPs
curl "http://localhost:8080/api/indicators?blocked=true"

# Audit log
curl http://localhost:8080/api/audit

# Rollback a blocked IP (requires auth token)
curl -X POST http://localhost:8080/api/rollback \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4"}'
```

---

## 🔁 SOC Analyst — Rollback Blocked IPs

If an automated block is a false positive, use the CLI rollback tool inside the enforcer container:

```bash
# List all currently blocked IPs
docker exec tip_enforcer python rollback.py --list-blocked

# Roll back a specific IP
docker exec tip_enforcer python rollback.py --ip 1.2.3.4

# Mark as false positive (prevents future blocking)
docker exec tip_enforcer python rollback.py --false-positive 1.2.3.4
```

---

## 🧪 Running Tests

```bash
# Install test dependencies
pip install pytest pymongo requests python-dotenv colorlog

# Run unit tests
pytest tests/ -v
```

---

## 🐛 Common Issues

| Problem | Solution |
|---|---|
| `Elasticsearch` keeps restarting | Increase Docker memory to ≥ 4 GB in Docker Desktop → Settings → Resources |
| `enforcer` exits immediately | Run `docker compose logs tip_enforcer` — check iptables permissions. Ensure `privileged: true` is set. |
| No indicators collected | Check API keys in `.env`. The blocklist feed works without any keys. |
| MongoDB auth fails | Ensure `MONGO_PASSWORD` in `.env` matches what was set on first boot. Run `docker compose down -v` to reset volumes. |

---

## 📤 Uploading to GitHub

### Step 1 — Create a new repository on GitHub

Go to https://github.com/new and create a repository named `tip-platform`. **Do NOT initialize it with a README.**

### Step 2 — Initialize git locally

```bash
cd tip-platform

git init
git add .
git commit -m "feat: initial TIP platform implementation"
```

### Step 3 — Connect and push

```bash
git remote add origin https://github.com/YOUR_USERNAME/tip-platform.git
git branch -M main
git push -u origin main
```

### Step 4 — Protect secrets (IMPORTANT)

Never commit your `.env` file — it is already in `.gitignore`. If you accidentally committed API keys:
```bash
git rm --cached .env
git commit -m "chore: remove .env from tracking"
```

Use **GitHub Secrets** for CI/CD (already configured in `.github/workflows/ci.yml`):
- Go to your repo → Settings → Secrets and variables → Actions
- Add: `OTX_API_KEY`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`

---

## 🛑 Stopping the Platform

```bash
# Stop containers (preserves data volumes)
docker compose down

# Stop AND remove all data volumes (full reset)
docker compose down -v
```

---

## 📋 Four-Week Roadmap Checklist

| Week | Task | Status |
|---|---|---|
| 1 | Python OSINT feed scripts (OTX, VirusTotal, AbuseIPDB, Blocklists) | ✅ |
| 1 | MongoDB schema + deduplication | ✅ |
| 2 | Indicator normalization with risk scoring | ✅ |
| 2 | Elasticsearch + Kibana SIEM integration | ✅ |
| 3 | Dynamic Policy Enforcer daemon (iptables + ipset) | ✅ |
| 3 | Webhook alerting | ✅ |
| 4 | Rollback / false-positive CLI tool | ✅ |
| 4 | Kibana dashboard pre-built objects | ✅ |
| 4 | GitHub Actions CI/CD | ✅ |
| 4 | REST API for SOC dashboard | ✅ |

---

## ⚠️ Security Notice

The `enforcer` service requires `privileged: true` and `network_mode: host` to modify the host's firewall rules. **Deploy this only on a dedicated security host.** Set `ENFORCER_DRY_RUN=true` during development to simulate without affecting real firewall rules.
