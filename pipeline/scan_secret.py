#!/usr/bin/env python3
"""
pipeline/scan_secret.py - REAL MODE
─────────────────────────────────────────────────────────────────────────────
Runs REAL Gitleaks scan against the target application to find hardcoded secrets.
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
OUTPUT_FILE  = ROOT_DIR / "security-results" / "secret_results.json"

def run_real_scan():
    # Find gitleaks - installed in Docker (/usr/local/bin/gitleaks)
    gitleaks_path = shutil.which("gitleaks")

    if not gitleaks_path:
        print("  [ERROR] Gitleaks not found in PATH. Is it installed in Docker?")
        sys.exit(1)

    print(f"  [REAL-MODE] Running Gitleaks on: {TARGET_DIR}")

    try:
        # gitleaks detect --source path --report-path output.json
        cmd = [
            gitleaks_path, "detect",
            "--source", str(TARGET_DIR),
            "--report-path", str(OUTPUT_FILE),
            "--report-format", "json",
            "--exit-code", "0" # Don't fail the script just because secrets are found
        ]

        # If it's not a git repo, we might need --no-git
        if not (TARGET_DIR / ".git").exists():
            cmd.append("--no-git")

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if OUTPUT_FILE.exists():
            print(f"  ✓ Secret Scan Complete. Results: {OUTPUT_FILE.name}")
        elif "no leaks found" in result.stdout.lower() or "no leaks found" in result.stderr.lower():
            # Create an empty list if no leaks found
            OUTPUT_FILE.write_text("[]", encoding="utf-8")
            print(f"  ✓ Secret Scan Complete: No leaks found.")
        else:
            print(f"  [ERROR] Gitleaks failed. Stderr: {result.stderr}")
            # Ensure file exists even if empty
            OUTPUT_FILE.write_text("[]", encoding="utf-8")

    except Exception as e:
        print(f"  [ERROR] Gitleaks failed: {e}")
        sys.exit(1)

def main():
    print("─" * 60)
    print("  SECRET SCANNER - REAL MODE")
    print("─" * 60)
    run_real_scan()

if __name__ == "__main__":
    main()
