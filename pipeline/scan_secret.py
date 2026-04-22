#!/usr/bin/env python3
"""
pipeline/scan_secret.py
─────────────────────────────────────────────────────────────────────────────
Hybrid Secret Scanner Bridge:
  • PRODUCTION:  Runs 'gitleaks' CLI if available.
  • SIMULATION:  Falls back to demo results based on repo scan simulation.

Output: Gitleaks JSON format in mock-data/secret_results.json
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
OUTPUT_FILE = ROOT_DIR / "mock-data" / "secret_results.json"

# ─────────────────────────────────────────────────────────────
# Real Tool Integration
# ─────────────────────────────────────────────────────────────

def run_real_scan() -> bool:
    gitleaks_path = shutil.which("gitleaks")
    if not gitleaks_path:
        return False

    print(f"  [PRODUCTION] Found 'gitleaks' at {gitleaks_path}. Running secret detection...")

    try:
        # scan the project
        cmd = [
            "gitleaks", "detect",
            "--source", str(ROOT_DIR),
            "--report-path", str(OUTPUT_FILE),
            "--report-format", "json",
            "--redact" # prevent leaking real secrets in case study
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        # Gitleaks exits 1 if findings are found
        if result.returncode in [0, 1] and OUTPUT_FILE.exists():
            print(f"  ✓ PRODUCTION Scan Complete (Real Gitleaks results saved)")
            return True
        else:
            print(f"  [ERROR] Gitleaks failed: {result.stderr[:200]}")

    except Exception as e:
        print(f"  [ERROR] Exception during real scan: {e}")

    return False

# ─────────────────────────────────────────────────────────────
# Simulation Logic
# ─────────────────────────────────────────────────────────────

def run_simulation():
    print("  [SIMULATION] Gitleaks not found. Simulating secret scanning...")

    # Static mock findings for demonstration
    findings = [
        {
            "Description": "Generic API Key",
            "File": "vulnerable-app/src/config/aws.js",
            "RuleID": "aws-access-token",
            "Match": "AKIAIOSFODNN7EXAMPLE",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "StartLine": 12,
            "mode": "SIMULATED"
        },
        {
            "Description": "Private Key",
            "File": "vulnerable-app/certs/jwt-private.pem",
            "RuleID": "private-key",
            "Match": "-----BEGIN PRIVATE KEY-----",
            "Secret": "-----BEGIN PRIVATE KEY-----",
            "StartLine": 1,
            "mode": "SIMULATED"
        }
    ]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(findings, indent=2))
    print(f"  ✓ SIMULATION Scan Complete: {len(findings)} secrets detected.")

def main():
    print("─" * 60)
    print("  SECRET SCANNER BRIDGE (Gitleaks)")
    print("─" * 60)

    if not run_real_scan():
        run_simulation()

    print(f"  → Report: {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print()

if __name__ == "__main__":
    main()
