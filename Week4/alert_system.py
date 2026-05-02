"""
=======================================================
  WEEK 4 — Alert System
  Threat Intelligence Platform (TIP)
=======================================================
  Monitors enforcement_log.json for new blocks
  Sends alerts to console + optional webhook
  Generates daily threat summary report
=======================================================
"""

import json
import os
import requests
from datetime import datetime

LOG_FILE     = "data/enforcement_log.json"
BLOCKED_FILE = "data/blocked_ips.json"
REPORT_FILE  = "data/alert_report.json"

# Optional: paste your Slack/Teams webhook URL here
WEBHOOK_URL  = ""   # e.g. https://hooks.slack.com/services/xxx


def load_file(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []


def send_webhook_alert(message: str, ip: str, risk_score: int):
    """Send alert to Slack/Teams webhook if configured."""
    if not WEBHOOK_URL:
        return
    try:
        payload = {
            "text": f"🚨 TIP ALERT: {message}",
            "attachments": [{
                "color": "danger",
                "fields": [
                    {"title": "IP Address", "value": ip, "short": True},
                    {"title": "Risk Score", "value": str(risk_score), "short": True},
                ]
            }]
        }
        requests.post(WEBHOOK_URL, json=payload, timeout=10)
        print(f"  📤 Webhook alert sent for {ip}")
    except Exception as e:
        print(f"  ⚠ Webhook failed: {e}")


def generate_report():
    """Generate a full threat summary report."""
    log     = load_file(LOG_FILE)
    blocked = load_file(BLOCKED_FILE)

    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Count actions
    blocks   = [e for e in log if e.get("action") == "BLOCK"]
    unblocks = [e for e in log if e.get("action") in ("UNBLOCK", "ROLLBACK")]

    # Group by source
    by_source = {}
    for b in blocks:
        src = b.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1

    # Risk score distribution
    scores = [b.get("risk_score", 0) for b in blocks]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0

    report = {
        "generated_at":       now,
        "summary": {
            "total_blocks":        len(blocks),
            "total_unblocks":      len(unblocks),
            "currently_blocked":   len(blocked),
            "average_risk_score":  avg_score,
        },
        "by_source":           by_source,
        "top_blocked_ips":     blocked[:10],
        "recent_log":          log[-10:],
    }

    os.makedirs("data", exist_ok=True)
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    return report


def print_report(report: dict):
    """Print the report in a readable format."""
    s = report["summary"]
    print("\n" + "="*55)
    print("  THREAT INTELLIGENCE PLATFORM — ALERT REPORT")
    print(f"  Generated: {report['generated_at']}")
    print("="*55)
    print(f"\n  📊 SUMMARY")
    print(f"  {'Total IPs Blocked:':<30} {s['total_blocks']}")
    print(f"  {'Total Rollbacks:':<30} {s['total_unblocks']}")
    print(f"  {'Currently Blocked:':<30} {s['currently_blocked']}")
    print(f"  {'Average Risk Score:':<30} {s['average_risk_score']}")

    print(f"\n  📡 BLOCKS BY SOURCE")
    for src, count in report["by_source"].items():
        bar = "█" * min(count, 30)
        print(f"  {src:<25} {count:>5}  {bar}")

    print(f"\n  🔴 TOP 10 BLOCKED IPs")
    print(f"  {'IP':<20} {'Risk':>5}  {'Source':<20}")
    print("  " + "-"*50)
    for b in report["top_blocked_ips"]:
        print(f"  {b['ip']:<20} {b['risk_score']:>5}  {b['source']:<20}")

    print(f"\n  📁 Report saved to: {REPORT_FILE}")
    print("="*55)


def run_alerts():
    """Check for new blocks and send alerts."""
    log = load_file(LOG_FILE)
    if not log:
        print("\n  No enforcement log found.")
        print("  Run policy_enforcer.py first!")
        return

    recent_blocks = [e for e in log if e.get("action") == "BLOCK"][-5:]

    print(f"\n  🔔 Recent Block Alerts (last 5):")
    print(f"  {'IP':<20} {'Risk':>5}  {'Source':<20}  Timestamp")
    print("  " + "-"*70)

    for entry in recent_blocks:
        ip    = entry.get("ip", "")
        risk  = entry.get("risk_score", 0)
        src   = entry.get("source", "")
        ts    = entry.get("timestamp", "")
        mode  = "[DRY]" if entry.get("dry_run") else "[LIVE]"
        print(f"  {ip:<20} {risk:>5}  {src:<20}  {ts} {mode}")
        send_webhook_alert(f"Blocked malicious IP: {ip}", ip, risk)


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  WEEK 4 — Alert System")
    print("  Threat Intelligence Platform (TIP)")
    print("="*55)

    os.makedirs("data", exist_ok=True)

    # Run alerts
    run_alerts()

    # Generate report
    print("\n  📋 Generating threat report...")
    report = generate_report()
    print_report(report)

    print("\n  ✅ Week 4 Alert System complete!")
    print("  Next → run: python3 test_suite.py")
