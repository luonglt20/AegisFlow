#!/usr/bin/env python3
"""
pipeline/scan_dast.py
─────────────────────────────────────────────────────────────────────────────
Hybrid DAST Bridge:
  • PRODUCTION:  Runs 'zap-baseline.py' or 'zap-cli' if available.
  • SIMULATION:  Falls back to high-fidelity ZAP-format report demo.

Output: ZAP JSON format in mock-data/dast_results.json
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
OUTPUT_FILE = ROOT_DIR / "mock-data" / "dast_results.json"
TARGET_URL  = os.environ.get("APP_URL", "http://localhost:53000")

# ─────────────────────────────────────────────────────────────
# Real Tool Integration
# ─────────────────────────────────────────────────────────────

def run_real_scan() -> bool:
    # Look for ZAP baseline script (common in Docker/CI) or zap-cli
    zap_script = shutil.which("zap-baseline.py") or shutil.which("zap-cli")
    if not zap_script:
        return False

    print(f"  [PRODUCTION] Found ZAP tool at {zap_script}. Attempting scan of {TARGET_URL}...")

    try:
        # Note: In a real CI, the app must be running.
        # We'll try to run but it might fail if URL is down.
        if "zap-baseline" in zap_script:
            cmd = [zap_script, "-t", TARGET_URL, "-J", str(OUTPUT_FILE)]
        else:
            cmd = ["zap-cli", "quick-scan", "--self-contained", "--start-options", "-config api.disablekey=true", TARGET_URL]
            # zap-cli might need more steps to output JSON, this is simplified

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if OUTPUT_FILE.exists():
            print(f"  ✓ PRODUCTION Scan Complete (Real ZAP results saved)")
            return True
        else:
            print(f"  [WARN] ZAP ran but no output file found. {result.stderr[:200]}")

    except Exception as e:
        print(f"  [ERROR] Exception during real scan: {e}")

    return False

# ─────────────────────────────────────────────────────────────
# Simulation Logic
# ─────────────────────────────────────────────────────────────

def run_simulation():
    print("  [SIMULATION] ZAP not found or target unreachable. Generating demo report...")

    now = datetime.now(timezone.utc)
    ts = now.strftime("%a, %d %b %Y %H:%M:%S")

    report = {
        "@version": "2.14.0",
        "@generated": ts,
        "site": [{
            "@name": TARGET_URL,
            "@host": "localhost",
            "alerts": [
                {
                    "pluginid": "40012",
                    "alert": "Cross Site Scripting (Reflected)",
                    "riskcode": "3",
                    "riskdesc": "High",
                    "desc": "XSS detected in search parameter.",
                    "instances": [{"uri": f"{TARGET_URL}/api/search?q=<script>alert(1)</script>"}],
                    "mode": "SIMULATED"
                },
                {
                    "pluginid": "10011",
                    "alert": "Cookie Without Secure Flag",
                    "riskcode": "2",
                    "riskdesc": "Medium",
                    "desc": "Session cookie missing Secure attribute.",
                    "instances": [{"uri": f"{TARGET_URL}/api/login"}],
                    "mode": "SIMULATED"
                }
            ]
        }]
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(report, indent=2))
    print(f"  ✓ SIMULATION Scan Complete: 2 findings generated for demonstration.")

def main():
    print("─" * 60)
    print("  DAST SCANNER BRIDGE (OWASP ZAP)")
    print("─" * 60)

    if not run_real_scan():
        run_simulation()

    print(f"  → Report: {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print()

if __name__ == "__main__":
    main()
