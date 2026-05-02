"""
=======================================================
  WEEK 2 — STEP 1: Normalizer
  Threat Intelligence Platform (TIP)
=======================================================
  Reads:   output/raw_indicators.json  (from Week 1)
  Cleans:  removes invalid/duplicate entries
  Scores:  assigns a risk score 0-100
  Saves:   output/normalized_indicators.json
=======================================================
"""

import json
import hashlib
import ipaddress
import os
from datetime import datetime

INPUT_FILE  = "output/raw_indicators.json"
OUTPUT_FILE = "output/normalized_indicators.json"

# ── Risk score defaults per source ──────────────────
SOURCE_SCORES = {
    "AlienVault_OTX":  75,
    "VirusTotal":      80,
    "AbuseIPDB":       85,
    "Feodo_Tracker":   90,
    "URLhaus":         85,
}

# ── Standardise type names ───────────────────────────
TYPE_MAP = {
    "IPv4":     "ip",
    "IPv6":     "ip",
    "ip":       "ip",
    "domain":   "domain",
    "hostname": "domain",
    "URL":      "url",
    "url":      "url",
}


def make_id(ioc_type: str, value: str) -> str:
    """Create a unique ID from type + value for deduplication."""
    return hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:16]


def normalize_one(raw: dict) -> dict | None:
    value  = str(raw.get("value", "")).strip()
    source = str(raw.get("source", "unknown"))

    # Skip empty values
    if not value:
        return None

    # Standardise the type
    raw_type = str(raw.get("type", "unknown"))
    ioc_type = TYPE_MAP.get(raw_type, raw_type.lower())

    # Validate IP addresses — skip invalid ones
    if ioc_type == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            return None

    # Get risk score
    risk_score = raw.get("risk_score", SOURCE_SCORES.get(source, 50))
    try:
        risk_score = int(risk_score)
    except (ValueError, TypeError):
        risk_score = 50
    risk_score = max(0, min(100, risk_score))  # clamp between 0 and 100

    # Assign severity label
    if risk_score >= 80:
        severity = "HIGH"
    elif risk_score >= 50:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "id":           make_id(ioc_type, value),
        "value":        value,
        "type":         ioc_type,
        "source":       source,
        "risk_score":   risk_score,
        "severity":     severity,
        "tags":         raw.get("tags", []),
        "description":  str(raw.get("description", ""))[:200],
        "country":      str(raw.get("country", "")),
        "first_seen":   now,
        "last_seen":    now,
        "blocked":      False,
    }


if __name__ == "__main__":
    print("\n" + "═"*50)
    print("  WEEK 2 — STEP 1: Normalizer")
    print("  Threat Intelligence Platform (TIP)")
    print("═"*50)

    # ── Load raw data from Week 1 ────────────────────
    if not os.path.exists(INPUT_FILE):
        print(f"\n  ✗ File not found: {INPUT_FILE}")
        print("  → Copy your Week 1 output/raw_indicators.json here first!")
        exit(1)

    with open(INPUT_FILE) as f:
        raw_list = json.load(f)

    print(f"\n  📥 Loaded {len(raw_list)} raw indicators from Week 1")

    # ── Normalize each indicator ─────────────────────
    normalized = {}
    skipped    = 0

    for raw in raw_list:
        result = normalize_one(raw)

        if result is None:
            skipped += 1
            continue

        # Deduplication — if same indicator from 2 feeds, keep higher risk score
        existing = normalized.get(result["id"])
        if existing:
            if result["risk_score"] > existing["risk_score"]:
                result["first_seen"] = existing["first_seen"]
                normalized[result["id"]] = result
        else:
            normalized[result["id"]] = result

    # ── Sort by risk score highest first ─────────────
    final = sorted(normalized.values(), key=lambda x: x["risk_score"], reverse=True)

    # ── Save output ──────────────────────────────────
    os.makedirs("output", exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(final, f, indent=2)

    # ── Print summary ────────────────────────────────
    high   = sum(1 for x in final if x["severity"] == "HIGH")
    medium = sum(1 for x in final if x["severity"] == "MEDIUM")
    low    = sum(1 for x in final if x["severity"] == "LOW")

    print(f"\n  ✅ Normalized:  {len(final)} unique indicators")
    print(f"  🗑  Skipped:     {skipped} invalid/duplicate entries")
    print(f"\n  🔴 HIGH   (80-100): {high}")
    print(f"  🟡 MEDIUM (50-79):  {medium}")
    print(f"  🟢 LOW    (0-49):   {low}")
    print(f"\n  📁 Saved to: {OUTPUT_FILE}")
    print("═"*50)
    print("\n  Next → run:  python3 elk_pusher.py")
