"""
=======================================================
  WEEK 3 — Dynamic Security Policy Enforcer
  Threat Intelligence Platform (TIP)
=======================================================
  Reads:   data/normalized_indicators.json  (from Week 2)
  Action:  Blocks high-risk IPs using iptables
  Logs:    data/enforcement_log.json
  Safety:  DRY RUN mode by default (no real blocking)
           Set DRY_RUN = False to enable live blocking
=======================================================
"""

import json
import os
import subprocess
import hashlib
from datetime import datetime

# ── Config ────────────────────────────────────────────
INPUT_FILE     = "data/normalized_indicators.json"
LOG_FILE       = "data/enforcement_log.json"
BLOCKED_FILE   = "data/blocked_ips.json"

RISK_THRESHOLD = 80        # Only block HIGH risk (80+)
DRY_RUN        = True      # True = simulate only, False = real iptables

# ─────────────────────────────────────────────────────


def load_indicators():
    """Load normalized indicators from Week 2."""
    if not os.path.exists(INPUT_FILE):
        print(f"\n  ✗ File not found: {INPUT_FILE}")
        print("  → Copy normalized_indicators.json from week2/data/ first!")
        exit(1)
    with open(INPUT_FILE) as f:
        return json.load(f)


def load_blocked():
    """Load existing blocked IPs list."""
    if os.path.exists(BLOCKED_FILE):
        with open(BLOCKED_FILE) as f:
            return json.load(f)
    return []


def save_blocked(blocked_list):
    """Save updated blocked IPs list."""
    with open(BLOCKED_FILE, "w") as f:
        json.dump(blocked_list, f, indent=2)


def load_log():
    """Load enforcement audit log."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            return json.load(f)
    return []


def save_log(log):
    """Save enforcement audit log."""
    with open(LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)


def run_iptables(ip: str, action: str) -> bool:
    """
    Run iptables command to block or unblock an IP.
    action: 'block' or 'unblock'
    """
    if action == "block":
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    else:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

    if DRY_RUN:
        print(f"    [DRY-RUN] Would run: {' '.join(cmd)}")
        return True

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True
        else:
            print(f"    ✗ iptables error: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"    ✗ Command failed: {e}")
        return False


def block_ip(ip: str, indicator: dict, log: list, blocked: list) -> bool:
    """Block a single IP and log the action."""
    # Skip if already blocked
    if any(b["ip"] == ip for b in blocked):
        return False

    success = run_iptables(ip, "block")

    if success:
        rule_id = hashlib.sha256(f"block:{ip}:{datetime.utcnow()}".encode()).hexdigest()[:12]
        now     = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        blocked.append({
            "ip":          ip,
            "rule_id":     rule_id,
            "risk_score":  indicator.get("risk_score", 0),
            "source":      indicator.get("source", ""),
            "blocked_at":  now,
            "dry_run":     DRY_RUN,
        })

        log.append({
            "action":     "BLOCK",
            "ip":         ip,
            "rule_id":    rule_id,
            "risk_score": indicator.get("risk_score", 0),
            "source":     indicator.get("source", ""),
            "severity":   indicator.get("severity", ""),
            "timestamp":  now,
            "dry_run":    DRY_RUN,
        })

        status = "[DRY-RUN]" if DRY_RUN else "[LIVE]"
        print(f"  🔴 {status} BLOCKED  {ip:<20} risk={indicator.get('risk_score')}  source={indicator.get('source')}")
        return True

    return False


def unblock_ip(ip: str, reason: str, log: list, blocked: list) -> bool:
    """Unblock an IP (rollback) and log the action."""
    entry = next((b for b in blocked if b["ip"] == ip), None)
    if not entry:
        print(f"  ✗ IP {ip} not found in blocked list.")
        return False

    success = run_iptables(ip, "unblock")

    if success:
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        blocked.remove(entry)

        log.append({
            "action":    "UNBLOCK",
            "ip":        ip,
            "rule_id":   entry.get("rule_id", ""),
            "reason":    reason,
            "timestamp": now,
            "dry_run":   DRY_RUN,
        })

        print(f"  🟢 UNBLOCKED {ip}  (reason: {reason})")
        return True

    return False


def show_blocked_list(blocked: list):
    """Print all currently blocked IPs."""
    print("\n  Currently Blocked IPs:")
    print(f"  {'IP':<20} {'Risk':>5}  {'Source':<20}  {'Blocked At'}")
    print("  " + "-"*70)
    if not blocked:
        print("  (none)")
    for b in blocked:
        tag = " [DRY]" if b.get("dry_run") else " [LIVE]"
        print(f"  {b['ip']:<20} {b['risk_score']:>5}  {b['source']:<20}  {b['blocked_at']}{tag}")


def enforce():
    """Main enforcement cycle — block all high-risk IPs."""
    indicators = load_indicators()
    blocked    = load_blocked()
    log        = load_log()

    # Filter only high-risk IPs
    high_risk = [
        ind for ind in indicators
        if ind.get("type") == "ip"
        and ind.get("risk_score", 0) >= RISK_THRESHOLD
    ]

    print(f"\n  Found {len(high_risk)} high-risk IPs (score >= {RISK_THRESHOLD})")
    print(f"  Already blocked: {len(blocked)}")
    print(f"  Mode: {'DRY RUN (simulation)' if DRY_RUN else '⚠ LIVE MODE (real iptables)'}\n")

    new_blocks = 0
    for ind in high_risk:
        ip = ind.get("value", "")
        if not ip:
            continue
        if block_ip(ip, ind, log, blocked):
            new_blocks += 1

    # Save updated state
    save_blocked(blocked)
    save_log(log)

    return new_blocks, len(blocked)


if __name__ == "__main__":
    import sys

    print("\n" + "="*55)
    print("  WEEK 3 — Dynamic Security Policy Enforcer")
    print("  Threat Intelligence Platform (TIP)")
    print("="*55)

    os.makedirs("data", exist_ok=True)

    # Handle command line arguments
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()

        if cmd == "unblock" and len(sys.argv) > 2:
            ip     = sys.argv[2]
            reason = sys.argv[3] if len(sys.argv) > 3 else "manual rollback"
            blocked = load_blocked()
            log     = load_log()
            unblock_ip(ip, reason, log, blocked)
            save_blocked(blocked)
            save_log(log)

        elif cmd == "list":
            blocked = load_blocked()
            show_blocked_list(blocked)

        elif cmd == "status":
            blocked = load_blocked()
            log     = load_log()
            print(f"\n  Total blocked:    {len(blocked)}")
            print(f"  Total log entries: {len(log)}")
            show_blocked_list(blocked)

        else:
            print(f"  Unknown command: {cmd}")
            print("  Usage:")
            print("    python3 policy_enforcer.py              # run enforcement")
            print("    python3 policy_enforcer.py list         # show blocked IPs")
            print("    python3 policy_enforcer.py status       # full status")
            print("    python3 policy_enforcer.py unblock <IP> # rollback a block")

    else:
        # Run enforcement
        new_blocks, total_blocked = enforce()

        print("\n" + "="*55)
        print(f"  New IPs blocked:   {new_blocks}")
        print(f"  Total blocked:     {total_blocked}")
        print(f"  Log saved to:      {LOG_FILE}")
        print(f"  Blocked list:      {BLOCKED_FILE}")
        print("="*55)

        if DRY_RUN:
            print("\n  ℹ  DRY RUN MODE — no real firewall rules applied.")
            print("  To enable live blocking, open policy_enforcer.py")
            print("  and set:  DRY_RUN = False")

        print("\n  Next steps:")
        print("  → View blocked IPs:  python3 policy_enforcer.py list")
        print("  → Rollback an IP:    python3 policy_enforcer.py unblock <IP>")
        print("="*55 + "\n")
