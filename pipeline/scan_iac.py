#!/usr/bin/env python3
"""
pipeline/scan_iac.py - REAL MODE
─────────────────────────────────────────────────────────────────────────────
Runs REAL Checkov scan against the target application (Docker/K8s).
"""

import json
import os
import sys
import subprocess
import shutil
from pathlib import Path

SCRIPT_DIR   = Path(__file__).parent.resolve()
ROOT_DIR     = SCRIPT_DIR.parent
TARGET_DIR   = Path(os.environ.get("SCAN_TARGET", ROOT_DIR / "_target_required_"))
OUTPUT_FILE  = ROOT_DIR / "security-results" / "iac_results.json"

def run_real_scan():
    # Find checkov - installed via pip in Docker (/usr/local/bin/checkov)
    checkov_path = shutil.which("checkov")

    if not checkov_path:
        print("  [ERROR] Checkov not found in PATH. Is it installed in Docker?")
        sys.exit(1)

    print(f"  [REAL-MODE] Running Checkov on: {TARGET_DIR}")

    try:
        # Run checkov in JSON format
        cmd = [checkov_path, "-d", str(TARGET_DIR), "-o", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.stdout.strip():
            # Checkov might return a list or a single dict
            OUTPUT_FILE.write_text(result.stdout, encoding="utf-8")
            print(f"  ✓ IaC Scan Complete.")
        else:
            print(f"  [ERROR] Checkov produced no output.")
            sys.exit(1)

    except Exception as e:
        print(f"  [ERROR] Checkov failed: {e}")
        sys.exit(1)

def main():
    print("─" * 60)
    print("  IaC SCANNER - REAL MODE")
    print("─" * 60)
    run_real_scan()

if __name__ == "__main__":
    main()
