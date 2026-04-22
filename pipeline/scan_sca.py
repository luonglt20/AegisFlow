#!/usr/bin/env python3
"""
pipeline/scan_sca.py
─────────────────────────────────────────────────────────────────────────────
Hybrid SCA Bridge:
  • PRODUCTION:  Runs 'trivy' CLI if available in PATH.
  • SIMULATION:  Falls back to context-aware package.json analysis.

Output: Trivy JSON format in mock-data/sca_results.json
"""

import json
import os
import sys
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR  = Path(__file__).parent.resolve()
ROOT_DIR    = SCRIPT_DIR.parent
APP_DIR     = ROOT_DIR / "vulnerable-app"
PKG_FILE    = APP_DIR / "package.json"
OUTPUT_FILE = ROOT_DIR / "mock-data" / "sca_results.json"

# ─────────────────────────────────────────────────────────────
# Simulation Database
# ─────────────────────────────────────────────────────────────
CVE_DATABASE = {
    "lodash": [
        {"id": "CVE-2021-23337", "sev": "HIGH", "fixed": "4.17.21", "title": "Command Injection"},
    ],
    "axios": [
        {"id": "CVE-2022-0155", "sev": "HIGH", "fixed": "0.21.2", "title": "SSRF / Auth Leak"},
    ],
    "log4j-core": [
        {"id": "CVE-2021-44228", "sev": "CRITICAL", "fixed": "2.15.0", "title": "Log4Shell RCE"},
    ]
}

# ─────────────────────────────────────────────────────────────
# Real Tool Integration
# ─────────────────────────────────────────────────────────────

def run_real_scan() -> bool:
    trivy_path = shutil.which("trivy")
    if not trivy_path:
        return False

    print(f"  [PRODUCTION] Found 'trivy' at {trivy_path}. Running filesystem scan...")

    try:
        # scan the app directory
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--output", str(OUTPUT_FILE),
            "--severity", "CRITICAL,HIGH,MEDIUM",
            str(APP_DIR)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode == 0 and OUTPUT_FILE.exists():
            print(f"  ✓ PRODUCTION Scan Complete (Real Trivy results saved)")
            return True
        else:
            print(f"  [ERROR] Trivy failed: {result.stderr[:200]}")

    except Exception as e:
        print(f"  [ERROR] Exception during real scan: {e}")

    return False

# ─────────────────────────────────────────────────────────────
# Simulation Logic
# ─────────────────────────────────────────────────────────────

def run_simulation():
    print("  [SIMULATION] Trivy not found. Analyzing package.json...")

    if not PKG_FILE.exists():
        print(f"  [ERROR] Not found: {PKG_FILE}")
        return

    try:
        pkg = json.loads(PKG_FILE.read_text())
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    except:
        deps = {}

    vulnerabilities = []
    for name, ver in deps.items():
        clean_ver = ver.lstrip("^~>=<v")
        if name in CVE_DATABASE:
            for cve in CVE_DATABASE[name]:
                # Simple version check (simulated)
                if clean_ver < cve["fixed"]:
                    vulnerabilities.append({
                        "VulnerabilityID": cve["id"], "PkgName": name, "InstalledVersion": clean_ver,
                        "FixedVersion": cve["fixed"], "Severity": cve["sev"], "Title": cve["title"],
                        "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve['id'].lower()}"
                    })

    report = {
        "SchemaVersion": 2,
        "Results": [{
            "Target": "package.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": vulnerabilities,
            "Metadata": {"Mode": "SIMULATED"}
        }]
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(report, indent=2))
    print(f"  ✓ SIMULATION Scan Complete: {len(vulnerabilities)} vulnerabilities detected.")

def main():
    print("─" * 60)
    print("  SCA SCANNER BRIDGE (Trivy)")
    print("─" * 60)

    if not run_real_scan():
        run_simulation()

    print(f"  → Report: {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print()

if __name__ == "__main__":
    main()
