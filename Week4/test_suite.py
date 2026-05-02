"""
=======================================================
  WEEK 4 — Test Suite
  Threat Intelligence Platform (TIP)
=======================================================
  Tests all components of the TIP platform:
  - Week 1: Feed collector output
  - Week 2: Normalizer output
  - Week 3: Policy enforcer output
  - Week 4: Alert system output
=======================================================
"""

import json
import os
import ipaddress
from datetime import datetime

PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠  WARN"

results = []


def test(name: str, condition: bool, message: str = ""):
    status = PASS if condition else FAIL
    results.append({"test": name, "status": status, "message": message})
    print(f"  {status}  {name}")
    if message and not condition:
        print(f"        → {message}")
    return condition


def section(title: str):
    print(f"\n  {'─'*50}")
    print(f"  {title}")
    print(f"  {'─'*50}")


# ── Week 1 Tests ─────────────────────────────────────
def test_week1():
    section("WEEK 1 — OSINT Feed Collector")

    # Check raw_indicators.json exists
    paths = [
        "../week1/output/raw_indicators.json",
        "../../week1/output/raw_indicators.json",
        "../week2/data/raw_indicators.json",
        "data/raw_indicators.json",
    ]
    raw_file = next((p for p in paths if os.path.exists(p)), None)

    if test("raw_indicators.json exists", raw_file is not None,
            "Run feed_collector.py first"):

        with open(raw_file) as f:
            raw = json.load(f)

        test("raw_indicators.json not empty",
             len(raw) > 0, "File is empty")

        test("Has 10+ indicators",
             len(raw) >= 10, f"Only {len(raw)} indicators found")

        test("Indicators have 'value' field",
             all("value" in r for r in raw[:5]),
             "Some indicators missing 'value'")

        test("Indicators have 'source' field",
             all("source" in r for r in raw[:5]),
             "Some indicators missing 'source'")

        sources = set(r.get("source", "") for r in raw)
        test("Has 3+ OSINT sources",
             len(sources) >= 3,
             f"Only {len(sources)} sources: {sources}")


# ── Week 2 Tests ─────────────────────────────────────
def test_week2():
    section("WEEK 2 — Normalizer")

    paths = [
        "../week2/data/normalized_indicators.json",
        "data/normalized_indicators.json",
    ]
    norm_file = next((p for p in paths if os.path.exists(p)), None)

    if test("normalized_indicators.json exists", norm_file is not None,
            "Run normalizer.py first"):

        with open(norm_file) as f:
            norm = json.load(f)

        test("Normalized file not empty",
             len(norm) > 0, "File is empty")

        test("Has required fields",
             all(all(k in n for k in ["id","value","type","risk_score","severity"])
                 for n in norm[:5]),
             "Missing required fields")

        test("Risk scores are 0-100",
             all(0 <= n.get("risk_score", -1) <= 100 for n in norm),
             "Invalid risk scores found")

        test("Severity labels correct",
             all(n.get("severity") in ["HIGH","MEDIUM","LOW"] for n in norm),
             "Invalid severity labels")

        test("No duplicate IDs",
             len(set(n["id"] for n in norm)) == len(norm),
             "Duplicate IDs found")

        high = sum(1 for n in norm if n.get("severity") == "HIGH")
        test("Has HIGH risk indicators",
             high > 0, "No HIGH risk indicators found")

        # Validate IP format
        ip_inds = [n for n in norm if n.get("type") == "ip"]
        valid_ips = 0
        for ind in ip_inds[:20]:
            try:
                ipaddress.ip_address(ind["value"])
                valid_ips += 1
            except ValueError:
                pass
        test("IP addresses are valid format",
             valid_ips == len(ip_inds[:20]),
             f"{len(ip_inds[:20]) - valid_ips} invalid IPs found")


# ── Week 3 Tests ─────────────────────────────────────
def test_week3():
    section("WEEK 3 — Policy Enforcer")

    paths = [
        "../week3/data/blocked_ips.json",
        "data/blocked_ips.json",
    ]
    blocked_file = next((p for p in paths if os.path.exists(p)), None)

    if test("blocked_ips.json exists", blocked_file is not None,
            "Run policy_enforcer.py first"):

        with open(blocked_file) as f:
            blocked = json.load(f)

        test("Blocked list not empty",
             len(blocked) > 0, "No IPs have been blocked")

        test("Blocked entries have required fields",
             all(all(k in b for k in ["ip","rule_id","risk_score","blocked_at"])
                 for b in blocked[:5]),
             "Missing fields in blocked entries")

        test("Has 10+ blocked IPs",
             len(blocked) >= 10,
             f"Only {len(blocked)} IPs blocked")

    log_paths = [
        "../week3/data/enforcement_log.json",
        "data/enforcement_log.json",
    ]
    log_file = next((p for p in log_paths if os.path.exists(p)), None)

    if test("enforcement_log.json exists", log_file is not None,
            "Run policy_enforcer.py first"):

        with open(log_file) as f:
            log = json.load(f)

        test("Log has BLOCK entries",
             any(e.get("action") == "BLOCK" for e in log),
             "No BLOCK entries in log")

        test("Log entries have timestamps",
             all("timestamp" in e for e in log),
             "Missing timestamps in log")


# ── Week 4 Tests ─────────────────────────────────────
def test_week4():
    section("WEEK 4 — Alert System")

    report_paths = [
        "../week4/data/alert_report.json",
        "data/alert_report.json",
    ]
    report_file = next((p for p in report_paths if os.path.exists(p)), None)

    if test("alert_report.json exists", report_file is not None,
            "Run alert_system.py first"):

        with open(report_file) as f:
            report = json.load(f)

        test("Report has summary section",
             "summary" in report,
             "Missing summary section")

        test("Report has by_source breakdown",
             "by_source" in report and len(report["by_source"]) > 0,
             "Missing source breakdown")

        test("Report has generated_at timestamp",
             "generated_at" in report,
             "Missing timestamp")


# ── Final Summary ─────────────────────────────────────
def print_summary():
    passed = sum(1 for r in results if r["status"] == PASS)
    failed = sum(1 for r in results if r["status"] == FAIL)
    total  = len(results)

    print("\n" + "="*55)
    print("  TEST SUMMARY")
    print("="*55)
    print(f"  Total:  {total}")
    print(f"  Passed: {passed}  ✅")
    print(f"  Failed: {failed}  ❌")
    print(f"  Score:  {round(passed/total*100)}%")

    # Save results
    os.makedirs("data", exist_ok=True)
    with open("data/test_results.json", "w") as f:
        json.dump({
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total": total,
            "passed": passed,
            "failed": failed,
            "score": f"{round(passed/total*100)}%",
            "results": results,
        }, f, indent=2)

    print(f"\n  📁 Results saved to: data/test_results.json")
    print("="*55)


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  WEEK 4 — Full Test Suite")
    print("  Threat Intelligence Platform (TIP)")
    print("="*55)

    test_week1()
    test_week2()
    test_week3()
    test_week4()
    print_summary()
