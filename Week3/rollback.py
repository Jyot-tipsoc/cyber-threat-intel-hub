"""
=======================================================
  WEEK 3 — Rollback Tool
  Threat Intelligence Platform (TIP)
=======================================================
  Use this to:
  - List all blocked IPs
  - Unblock a specific IP (false positive fix)
  - View full audit log
=======================================================
"""

import json
import os
import sys
from datetime import datetime

BLOCKED_FILE = "data/blocked_ips.json"
LOG_FILE     = "data/enforcement_log.json"


def load_file(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []


def save_file(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def list_blocked():
    blocked = load_file(BLOCKED_FILE)
    print("\n" + "="*60)
    print("  Currently Blocked IPs")
    print("="*60)
    if not blocked:
        print("  No IPs are currently blocked.")
    else:
        print(f"  {'#':<4} {'IP':<20} {'Risk':>5}  {'Source':<20}  Mode")
        print("  " + "-"*60)
        for i, b in enumerate(blocked, 1):
            mode = "DRY-RUN" if b.get("dry_run") else "LIVE"
            print(f"  {i:<4} {b['ip']:<20} {b['risk_score']:>5}  {b['source']:<20}  {mode}")
    print(f"\n  Total: {len(blocked)} blocked IPs")
    print("="*60)


def rollback_ip(ip):
    blocked = load_file(BLOCKED_FILE)
    log     = load_file(LOG_FILE)

    entry = next((b for b in blocked if b["ip"] == ip), None)
    if not entry:
        print(f"\n  ✗ IP {ip} not found in blocked list.")
        print("  Run: python3 rollback.py list")
        return

    blocked.remove(entry)
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    log.append({
        "action":    "ROLLBACK",
        "ip":        ip,
        "rule_id":   entry.get("rule_id", ""),
        "reason":    "SOC analyst manual rollback",
        "timestamp": now,
    })

    save_file(BLOCKED_FILE, blocked)
    save_file(LOG_FILE, log)

    print(f"\n  ✅ Successfully rolled back: {ip}")
    print(f"  Rule ID was: {entry.get('rule_id', 'N/A')}")
    print(f"  Logged at:   {now}")

    if not entry.get("dry_run"):
        os.system(f"sudo iptables -D INPUT -s {ip} -j DROP 2>/dev/null")
        print(f"  iptables rule removed for {ip}")


def view_log():
    log = load_file(LOG_FILE)
    print("\n" + "="*60)
    print("  Enforcement Audit Log")
    print("="*60)
    if not log:
        print("  No log entries yet.")
    else:
        for entry in log[-20:]:  # show last 20 entries
            action = entry.get("action", "")
            ip     = entry.get("ip", "")
            ts     = entry.get("timestamp", "")
            mode   = "[DRY]" if entry.get("dry_run") else "[LIVE]"
            if action == "BLOCK":
                print(f"  🔴 {ts}  BLOCK    {ip:<20} {mode}")
            elif action in ("UNBLOCK", "ROLLBACK"):
                reason = entry.get("reason", "")
                print(f"  🟢 {ts}  {action:<8} {ip:<20} ({reason})")
    print(f"\n  Total log entries: {len(log)}")
    print("="*60)


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  WEEK 3 — Rollback & Audit Tool")
    print("  Threat Intelligence Platform (TIP)")
    print("="*60)

    if len(sys.argv) < 2:
        print("\n  Usage:")
        print("    python3 rollback.py list              # show blocked IPs")
        print("    python3 rollback.py unblock <IP>      # remove a block")
        print("    python3 rollback.py log               # view audit log")
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "list":
        list_blocked()

    elif cmd == "unblock":
        if len(sys.argv) < 3:
            print("  Usage: python3 rollback.py unblock <IP>")
        else:
            rollback_ip(sys.argv[2])

    elif cmd == "log":
        view_log()

    else:
        print(f"  Unknown command: {cmd}")
