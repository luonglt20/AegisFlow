#!/usr/bin/env python3
"""
pipeline/scan_sast.py - REAL MODE
─────────────────────────────────────────────────────────────────────────────
Runs REAL Semgrep scan against the target application.
No security-results, no simulation.
"""

import json
import os
import sys
import subprocess
import shutil
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent.resolve()
ROOT_DIR     = SCRIPT_DIR.parent
# Default target, can be overridden by env var
TARGET_DIR   = Path(os.environ.get("SCAN_TARGET", ROOT_DIR / "_target_required_"))
OUTPUT_FILE  = ROOT_DIR / "security-results" / "sast_results.json"

def run_real_scan():
    """
    Runs semgrep CLI and outputs SARIF.
    """
    # Find semgrep - installed via pip in Docker (/usr/local/bin/semgrep)
    semgrep_path = shutil.which("semgrep")

    if not semgrep_path:
        print("  [ERROR] Semgrep not found in PATH. Is it installed in Docker?")
        sys.exit(1)

    print(f"  [REAL-MODE] Running Semgrep on: {TARGET_DIR}")

    try:
        # Use 'auto' config - it's the most reliable way to get the best rules
        cmd = [
            semgrep_path, "scan",
            "--sarif",
            "--config", "auto",
            str(TARGET_DIR)
        ]

        # We allow return code 1 because it often indicates findings found
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.stdout.strip():
            OUTPUT_FILE.write_text(result.stdout, encoding="utf-8")
            print(f"  ✓ SAST Scan Complete. Findings saved to {OUTPUT_FILE.name}")
        else:
            print(f"  [ERROR] Semgrep produced no output. Stderr: {result.stderr}")
            sys.exit(1)

    except Exception as e:
        print(f"  [ERROR] Semgrep execution failed: {e}")
        sys.exit(1)

def main():
    print("─" * 60)
    print("  SAST SCANNER - REAL MODE")
    print("─" * 60)
    run_real_scan()

if __name__ == "__main__":
    main()
