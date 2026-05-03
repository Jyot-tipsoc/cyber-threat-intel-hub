"""
================================================================
  Cyber Threat Intelligence Hub — Blocklist Module
  config/blocklist.py
================================================================
  Provides blocklist management logic for the Policy Enforcer.
  Used by week3/policy_enforcer.py to check, add, and remove
  IPs and domains from the active blocklist.
================================================================
"""

import json
import os
import ipaddress
import hashlib
from datetime import datetime

# Default paths
BLOCKED_IPS_FILE    = "week3/data/blocked_ips.json"
BLOCKED_DOMAINS_FILE = "week3/data/blocked_domains.json"

# ── Known malicious IP ranges (CIDR) ────────────────────────────
# These are example ranges commonly associated with abuse.
# In production, this list is populated from OSINT feeds.
KNOWN_MALICIOUS_RANGES = [
    "185.220.0.0/16",    # Known Tor exit nodes / abuse range
    "45.95.168.0/24",    # Known scanner range
    "192.0.2.0/24",      # RFC 5737 - documentation range (demo)
    "198.51.100.0/24",   # RFC 5737 - documentation range (demo)
    "203.0.113.0/24",    # RFC 5737 - documentation range (demo)
]

# ── Known malicious domains ──────────────────────────────────────
KNOWN_MALICIOUS_DOMAINS = [
    "malware-host.example.com",
    "phishing-site.example.net",
    "c2-server.example.org",
    "botnet-controller.example.ru",
]


# ── Helper Functions ─────────────────────────────────────────────

def load_blocklist(filepath: str) -> list:
    """Load blocklist from JSON file."""
    if os.path.exists(filepath):
        try:
            with open(filepath) as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_blocklist(filepath: str, data: list):
    """Save blocklist to JSON file."""
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)


def generate_rule_id(ip: str) -> str:
    """Generate a unique rule ID for an IP block."""
    raw = f"block:{ip}:{datetime.utcnow().isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


# ── IP Blocklist Functions ───────────────────────────────────────

def is_ip_blocked(ip: str, blocked_list: list = None) -> bool:
    """Check if an IP is currently in the blocklist."""
    if blocked_list is None:
        blocked_list = load_blocklist(BLOCKED_IPS_FILE)
    return any(entry.get("ip") == ip for entry in blocked_list)


def is_ip_in_malicious_range(ip: str) -> bool:
    """Check if IP falls within any known malicious CIDR range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in KNOWN_MALICIOUS_RANGES:
            try:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def add_to_blocklist(ip: str, risk_score: int, source: str,
                     dry_run: bool = True) -> dict:
    """
    Add an IP to the blocklist.
    Returns the blocklist entry that was created.
    """
    blocked_list = load_blocklist(BLOCKED_IPS_FILE)

    # Skip if already blocked
    if is_ip_blocked(ip, blocked_list):
        return None

    entry = {
        "ip":         ip,
        "rule_id":    generate_rule_id(ip),
        "risk_score": risk_score,
        "source":     source,
        "blocked_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dry_run":    dry_run,
    }

    blocked_list.append(entry)
    save_blocklist(BLOCKED_IPS_FILE, blocked_list)
    return entry


def remove_from_blocklist(ip: str, reason: str = "manual") -> bool:
    """
    Remove an IP from the blocklist (rollback).
    Returns True if removed, False if not found.
    """
    blocked_list = load_blocklist(BLOCKED_IPS_FILE)
    original_len = len(blocked_list)
    blocked_list = [e for e in blocked_list if e.get("ip") != ip]

    if len(blocked_list) < original_len:
        save_blocklist(BLOCKED_IPS_FILE, blocked_list)
        return True
    return False


def get_all_blocked_ips() -> list:
    """Return all currently blocked IPs."""
    return load_blocklist(BLOCKED_IPS_FILE)


def get_blocked_count() -> int:
    """Return total number of blocked IPs."""
    return len(load_blocklist(BLOCKED_IPS_FILE))


# ── Domain Blocklist Functions ───────────────────────────────────

def is_domain_blocked(domain: str) -> bool:
    """Check if a domain is in the blocklist."""
    blocked = load_blocklist(BLOCKED_DOMAINS_FILE)
    domain = domain.lower().strip()
    return (domain in KNOWN_MALICIOUS_DOMAINS or
            any(e.get("domain") == domain for e in blocked))


def add_domain_to_blocklist(domain: str, risk_score: int,
                             source: str, dry_run: bool = True) -> dict:
    """Add a domain to the domain blocklist."""
    blocked = load_blocklist(BLOCKED_DOMAINS_FILE)
    domain  = domain.lower().strip()

    if is_domain_blocked(domain):
        return None

    entry = {
        "domain":     domain,
        "rule_id":    generate_rule_id(domain),
        "risk_score": risk_score,
        "source":     source,
        "blocked_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dry_run":    dry_run,
    }

    blocked.append(entry)
    save_blocklist(BLOCKED_DOMAINS_FILE, blocked)
    return entry


# ── Summary ──────────────────────────────────────────────────────

def get_blocklist_summary() -> dict:
    """Return a summary of the current blocklist state."""
    ips     = load_blocklist(BLOCKED_IPS_FILE)
    domains = load_blocklist(BLOCKED_DOMAINS_FILE)

    live_ips = [e for e in ips if not e.get("dry_run")]
    dry_ips  = [e for e in ips if e.get("dry_run")]

    return {
        "total_blocked_ips":     len(ips),
        "live_blocks":           len(live_ips),
        "dry_run_blocks":        len(dry_ips),
        "total_blocked_domains": len(domains),
        "known_malicious_ranges": len(KNOWN_MALICIOUS_RANGES),
    }


# ── Main (test/demo) ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  TIP — Blocklist Module Test")
    print("  " + "="*40)

    # Test IP check
    test_ips = ["192.0.2.1", "8.8.8.8", "45.95.168.5"]
    for ip in test_ips:
        in_range = is_ip_in_malicious_range(ip)
        print(f"  IP: {ip:<20} malicious range: {in_range}")

    # Test domain check
    test_domains = ["malware-host.example.com", "google.com"]
    for domain in test_domains:
        blocked = is_domain_blocked(domain)
        print(f"  Domain: {domain:<35} blocked: {blocked}")

    # Show summary
    summary = get_blocklist_summary()
    print(f"\n  Summary: {summary}")
    print("  " + "="*40)
