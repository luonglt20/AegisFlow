#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent.resolve()
OUTPUT_FILE = ROOT_DIR / "security-results" / "dast_results.json"
SCAN_TARGET = str(os.environ.get("SCAN_TARGET", "")).strip()
TARGET_URL = str(os.environ.get("TARGET_URL", "")).strip()
DAST_MODE = str(os.environ.get("DAST_MODE", "LIVE")).strip().upper()


def infer_target_url(scan_target):
    normalized = scan_target.replace("\\", "/").lower()
    if "juice-shop" in normalized:
        return "http://juice-shop:3000"
    return ""


def resolve_scan_context():
    global TARGET_URL, DAST_MODE

    if not TARGET_URL:
        TARGET_URL = infer_target_url(SCAN_TARGET)

    if TARGET_URL:
        DAST_MODE = "LIVE"
    else:
        DAST_MODE = "PREDICTIVE"


def write_results(results, target_url):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps({
        "site": [{"alerts": results}],
        "scan_metadata": {
            "mode": DAST_MODE,
            "scan_target": SCAN_TARGET,
            "target_url": target_url
        }
    }, indent=2), encoding="utf-8")


def build_predictive_fallback():
    print("  [!] No live target URL for the selected app. Skipping live DAST to avoid scanning the wrong application.")
    print("  [*] DAST result will be recorded as an empty predictive placeholder for this run.")
    write_results([], "")


def normalize_finding(finding):
    info = finding.get("info", {})
    return {
        "id": f"DAST-{finding.get('template-id')}",
        "source_tool": "Nuclei",
        "scan_type": "DAST",
        "title": info.get("name"),
        "severity": info.get("severity", "MEDIUM").upper(),
        "affected_url": finding.get("matched-at"),
        "business_impact": info.get("description", "Potential vulnerability detected in live application."),
        "remediation_hint": info.get("remediation", "Follow OWASP best practices for this vulnerability type."),
        "cvss_v3": 7.5,
        "status": "PENDING_TRIAGE"
    }


def run_live_scan():
    print("  [*] Running Nuclei vulnerability scan...")
    print(f"  [*] Target URL: {TARGET_URL}")
    cmd = ["nuclei", "-u", TARGET_URL, "-tags", "xss,sqli,lfi,rce", "-jsonl", "-o", str(OUTPUT_FILE)]

    subprocess.run(cmd, check=False)

    results = []
    if OUTPUT_FILE.exists():
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    results.append(normalize_finding(json.loads(line)))
                except Exception:
                    continue

    write_results(results, TARGET_URL)
    print(f"  [+] Real DAST Scan completed. Found {len(results)} vulnerabilities.")


def main():
    resolve_scan_context()
    print("  🚀 NUCLEI REAL-TIME DAST ENGINE")
    print(f"  [*] Mode: {DAST_MODE}")
    print(f"  [*] Source Target: {SCAN_TARGET or 'N/A'}")

    if DAST_MODE != "LIVE":
        build_predictive_fallback()
        return

    try:
        run_live_scan()
    except Exception as e:
        print(f"  [!] Error running real DAST: {e}")
        write_results([], TARGET_URL)


if __name__ == "__main__":
    main()
