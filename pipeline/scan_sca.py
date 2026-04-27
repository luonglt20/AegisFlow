#!/usr/bin/env python3
"""
pipeline/scan_sca.py - REAL MODE
─────────────────────────────────────────────────────────────────────────────
Runs REAL Trivy scan against the target application to find vulnerable dependencies.
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
OUTPUT_FILE  = ROOT_DIR / "security-results" / "sca_results.json"

def run_real_scan():
    # Find trivy - installed via install.sh in Docker (/usr/local/bin/trivy)
    trivy_path = shutil.which("trivy")

    if not trivy_path:
        print("  [ERROR] Trivy not found in PATH. Is it installed in Docker?")
        sys.exit(1)

    print(f"  [REAL-MODE] Running Trivy SCA on: {TARGET_DIR}")

    try:
        # trivy fs --format json -o output.json path
        cmd = [trivy_path, "fs", "--format", "json", "-o", str(OUTPUT_FILE), str(TARGET_DIR)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if OUTPUT_FILE.exists():
            print(f"  ✓ SCA Scan Complete. Results: {OUTPUT_FILE.name}")
        else:
            print(f"  [ERROR] Trivy failed to generate report. Stderr: {result.stderr}")
            sys.exit(1)

    except Exception as e:
        print(f"  [ERROR] Trivy execution failed: {e}")
        sys.exit(1)

def main():
    print("─" * 60)
    print("  SCA SCANNER - REAL MODE")
    print("─" * 60)
    run_real_scan()

if __name__ == "__main__":
    main()
