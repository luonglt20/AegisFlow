#!/usr/bin/env python3
"""
pipeline/scan_iac.py
─────────────────────────────────────────────────────────────────────────────
Hybrid IaC Bridge:
  • PRODUCTION:  Runs 'checkov' CLI if available in PATH.
  • SIMULATION:  Falls back to Dockerfile pattern analysis.

Output: Checkov JSON format in mock-data/iac_results.json
"""

import json
import os
import re
import sys
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent.resolve()
ROOT_DIR     = SCRIPT_DIR.parent
DOCKERFILE   = ROOT_DIR / "vulnerable-app" / "Dockerfile"
OUTPUT_FILE  = ROOT_DIR / "mock-data" / "iac_results.json"

# ─────────────────────────────────────────────────────────────
# Real Tool Integration
# ─────────────────────────────────────────────────────────────

def run_real_scan() -> bool:
    checkov_path = shutil.which("checkov")
    if not checkov_path:
        return False

    print(f"  [PRODUCTION] Found 'checkov' at {checkov_path}. Running IaC scan...")

    try:
        # scan the app directory
        cmd = [
            "checkov",
            "-f", str(DOCKERFILE),
            "--output", "json",
            "--quiet"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode in [0, 1] and result.stdout.strip():
            # Checkov might output multiple blocks if multiple files are scanned,
            # but we targeted one file.
            OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT_FILE.write_text(result.stdout, encoding="utf-8")
            print(f"  ✓ PRODUCTION Scan Complete (Real Checkov results saved)")
            return True
        else:
            print(f"  [ERROR] Checkov failed or returned empty: {result.stderr[:200]}")

    except Exception as e:
        print(f"  [ERROR] Exception during real scan: {e}")

    return False

# ─────────────────────────────────────────────────────────────
# Simulation Logic
# ─────────────────────────────────────────────────────────────

def run_simulation():
    print("  [SIMULATION] Checkov not found. Analyzing Dockerfile patterns...")

    if not DOCKERFILE.exists():
        print(f"  [ERROR] Not found: {DOCKERFILE}")
        return

    try:
        content = DOCKERFILE.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()
    except Exception as e:
        print(f"  [ERROR] Cannot read Dockerfile: {e}")
        return

    failed_checks = []

    # Simple pattern checks
    if not re.search(r"^\s*USER\s+", content, re.IGNORECASE | re.MULTILINE):
        failed_checks.append({
            "check_id": "CKV_DOCKER_2",
            "check_name": "Ensure non-root user is specified",
            "severity": "CRITICAL",
            "file_path": "Dockerfile",
            "message": "No USER instruction found. Container runs as root.",
            "mode": "SIMULATED"
        })

    if not re.search(r"^\s*HEALTHCHECK\s+", content, re.IGNORECASE | re.MULTILINE):
        failed_checks.append({
            "check_id": "CKV_DOCKER_7",
            "check_name": "Ensure HEALTHCHECK instructions are added",
            "severity": "MEDIUM",
            "file_path": "Dockerfile",
            "message": "No HEALTHCHECK defined.",
            "mode": "SIMULATED"
        })

    if re.search(r"^\s*EXPOSE\s+22\b", content, re.IGNORECASE | re.MULTILINE):
        failed_checks.append({
            "check_id": "CKV_DOCKER_1",
            "check_name": "Ensure port 22 is not exposed",
            "severity": "HIGH",
            "file_path": "Dockerfile",
            "message": "SSH port 22 is exposed.",
            "mode": "SIMULATED"
        })

    report = {
        "check_type": "dockerfile",
        "results": {
            "failed_checks": failed_checks,
            "passed_checks": []
        },
        "summary": {
            "failed": len(failed_checks),
            "passed": 1,
            "resource_count": 1
        }
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(report, indent=2))
    print(f"  ✓ SIMULATION Scan Complete: {len(failed_checks)} failed checks detected.")

def main():
    print("─" * 60)
    print("  IaC SCANNER BRIDGE (Checkov)")
    print("─" * 60)

    if not run_real_scan():
        run_simulation()

    print(f"  → Report: {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print()

if __name__ == "__main__":
    main()
