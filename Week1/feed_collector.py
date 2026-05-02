"""
STEP 1 — feed_collector.py
Pulls threat indicators from OTX, VirusTotal, and AbuseIPDB.
Saves raw results to data/raw_indicators.json
"""

import os
import json
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

OTX_KEY      = os.getenv("OTX_API_KEY", "")
VT_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

all_indicators = []


# ─────────────────────────────────────────────
# SOURCE 1: AlienVault OTX
# ─────────────────────────────────────────────
def collect_otx():
    print("\n[1/3] Collecting from AlienVault OTX...")

    if not OTX_KEY:
        print("  ⚠ No OTX key found in .env — skipping.")
        return []

    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    results = []

    try:
        resp = requests.get(url, headers=headers, params={"limit": 5}, timeout=15)
        resp.raise_for_status()
        pulses = resp.json().get("results", [])

        for pulse in pulses:
            for ioc in pulse.get("indicators", []):
                ioc_type = ioc.get("type", "")
                # Only keep IPs and domains
                if ioc_type not in ("IPv4", "domain", "URL"):
                    continue
                results.append({
                    "value":       ioc.get("indicator", ""),
                    "type":        ioc_type,
                    "source":      "OTX",
                    "description": pulse.get("name", ""),
                    "tags":        pulse.get("tags", []),
                })

        print(f"  ✓ Got {len(results)} indicators from OTX")
    except Exception as e:
        print(f"  ✗ OTX error: {e}")

    return results


# ─────────────────────────────────────────────
# SOURCE 2: VirusTotal (sample known-bad IPs)
# ─────────────────────────────────────────────
def collect_virustotal():
    print("\n[2/3] Collecting from VirusTotal...")

    if not VT_KEY:
        print("  ⚠ No VirusTotal key found in .env — skipping.")
        return []

    # A small list of known malicious IPs to look up (free tier: 4 req/min)
    test_ips = ["198.51.100.1", "45.33.32.156", "192.0.2.1"]
    results  = []
    headers  = {"x-apikey": VT_KEY}

    for ip in test_ips:
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers, timeout=15
            )
            if resp.status_code == 429:
                print("  ⚠ VirusTotal rate limit hit — try again in 1 minute.")
                break
            if resp.status_code != 200:
                continue

            attrs   = resp.json().get("data", {}).get("attributes", {})
            stats   = attrs.get("last_analysis_stats", {})
            bad     = stats.get("malicious", 0)
            total   = sum(stats.values()) or 1
            score   = int((bad / total) * 100)

            if bad > 0:
                results.append({
                    "value":       ip,
                    "type":        "IPv4",
                    "source":      "VirusTotal",
                    "risk_score":  score,
                    "description": f"Detected by {bad}/{total} VT engines",
                    "tags":        ["virustotal"],
                    "country":     attrs.get("country", ""),
                })
        except Exception as e:
            print(f"  ✗ VT error for {ip}: {e}")

    print(f"  ✓ Got {len(results)} indicators from VirusTotal")
    return results


# ─────────────────────────────────────────────
# SOURCE 3: AbuseIPDB blacklist
# ─────────────────────────────────────────────
def collect_abuseipdb():
    print("\n[3/3] Collecting from AbuseIPDB...")

    if not ABUSEIPDB_KEY:
        print("  ⚠ No AbuseIPDB key found in .env — skipping.")
        return []

    results = []
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"confidenceMinimum": 90, "limit": 100},
            timeout=30
        )
        resp.raise_for_status()

        for entry in resp.json().get("data", []):
            results.append({
                "value":       entry.get("ipAddress", ""),
                "type":        "IPv4",
                "source":      "AbuseIPDB",
                "risk_score":  entry.get("abuseConfidenceScore", 0),
                "description": f"Reported {entry.get('totalReports', 0)} times",
                "tags":        ["abuse", "reported"],
                "country":     entry.get("countryCode", ""),
            })

        print(f"  ✓ Got {len(results)} indicators from AbuseIPDB")
    except Exception as e:
        print(f"  ✗ AbuseIPDB error: {e}")

    return results


# ─────────────────────────────────────────────
# FREE FALLBACK: Public blocklists (no key needed)
# ─────────────────────────────────────────────
def collect_free_blocklist():
    print("\n[+] Collecting free public blocklist (no API key needed)...")
    results = []
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    try:
        resp = requests.get(url, timeout=20)
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            results.append({
                "value":       line,
                "type":        "IPv4",
                "source":      "Feodo_Blocklist",
                "risk_score":  90,
                "description": "C2 botnet IP from Feodo Tracker",
                "tags":        ["botnet", "c2", "free_feed"],
                "country":     "",
            })
        print(f"  ✓ Got {len(results)} indicators from free blocklist")
    except Exception as e:
        print(f"  ✗ Blocklist error: {e}")
    return results


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  TIP — Feed Collector (Week 1)")
    print("=" * 50)

    all_indicators += collect_otx()
    all_indicators += collect_virustotal()
    all_indicators += collect_abuseipdb()
    all_indicators += collect_free_blocklist()

    # Save raw output
    os.makedirs("data", exist_ok=True)
    output_file = "data/raw_indicators.json"
    with open(output_file, "w") as f:
        json.dump(all_indicators, f, indent=2)

    print("\n" + "=" * 50)
    print(f"  ✅ Total collected: {len(all_indicators)} indicators")
    print(f"  📁 Saved to: {output_file}")
    print("=" * 50)
    print("\nNext step → run:  python normalizer.py")
