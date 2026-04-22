#!/usr/bin/env python3
"""
pipeline/scan_sast.py
─────────────────────────────────────────────────────────────────────────────
Hybrid SAST Bridge:
  • PRODUCTION:  Runs 'semgrep' CLI if available in PATH.
  • SIMULATION:  Falls back to regex-based scanning for demo/case-study.

Output: SARIF 2.1.0 format in mock-data/sast_results.json
"""

import json
import os
import re
import sys
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent.resolve()
ROOT_DIR     = SCRIPT_DIR.parent
SRC_DIR      = ROOT_DIR / "vulnerable-app" / "src"
OUTPUT_FILE  = ROOT_DIR / "mock-data" / "sast_results.json"

# ─────────────────────────────────────────────────────────────
# Detection Rules (Simulation Mode)
# ─────────────────────────────────────────────────────────────
RULES = [
    {
        "id":          "javascript.express.security.audit.sqli",
        "name":        "ExpressSQLInjection",
        "pattern":     re.compile(r'(\"SELECT|\'SELECT|"INSERT|\'INSERT|"UPDATE|\'UPDATE|"DELETE|\'DELETE).*\+\s*(req\.(params|query|body)\.\w+|id\b)', re.IGNORECASE),
        "severity":    "CRITICAL",
        "cvss":        9.8,
        "cwe":         "CWE-89",
        "owasp":       "A03:2025 – Injection",
        "message":     "SQL Injection detected: user-supplied input is concatenated directly into a SQL query string.",
    },
    {
        "id":          "generic.secrets.security.detected-generic-secret",
        "name":        "HardcodedAPISecret",
        "pattern":     re.compile(r"(const|let|var)\s+\w*(API_KEY|SECRET|PASSWORD|TOKEN|PASS|CREDENTIAL|JWT)\w*\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
        "severity":    "HIGH",
        "cvss":        7.5,
        "cwe":         "CWE-798",
        "owasp":       "A07:2025 – Identification and Authentication Failures",
        "message":     "Hardcoded secret detected in source file.",
    },
     {
        "id":          "javascript.lang.security.audit.path-traversal",
        "name":        "PathTraversalViaUserInput",
        "pattern":     re.compile(r'(__dirname|__filename|path\.join|path\.resolve)\s*\+\s*(req\.(query|params|body)\.\w+)', re.IGNORECASE),
        "severity":    "HIGH",
        "cvss":        7.3,
        "cwe":         "CWE-22",
        "owasp":       "A01:2025 – Broken Access Control",
        "message":     "Path traversal vulnerability: user-controlled parameter appended to filesystem path.",
    }
]

# ─────────────────────────────────────────────────────────────
# Real Tool Integration
# ─────────────────────────────────────────────────────────────

def run_real_scan() -> bool:
    """
    Attempt to run a real Semgrep scan.
    Returns True if successful, False if Semgrep is missing or failed.
    """
    semgrep_path = shutil.which("semgrep")
    if not semgrep_path:
        return False

    print(f"  [PRODUCTION] Found 'semgrep' at {semgrep_path}. Running real scan...")

    try:
        # We use --sarif to get the industry-standard format directly
        cmd = [
            "semgrep", "scan",
            "--sarif",
            "--config", "p/javascript",
            "--config", "p/ci",
            "--config", "p/owasp-top-ten",
            str(SRC_DIR)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        # Semgrep exits 1 if findings are found, which is acceptable
        if result.returncode in [0, 1]:
            if result.stdout.strip():
                OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
                OUTPUT_FILE.write_text(result.stdout, encoding="utf-8")
                print(f"  ✓ PRODUCTION Scan Complete (Real Semgrep results saved)")
                return True
            else:
                print("  [WARN] Semgrep produced empty output.")
        else:
            print(f"  [ERROR] Semgrep failed with code {result.returncode}")

    except Exception as e:
        print(f"  [ERROR] Exception during real scan: {e}")

    return False

# ─────────────────────────────────────────────────────────────
# Simulation Logic
# ─────────────────────────────────────────────────────────────

def scan_file_simulated(filepath: Path) -> list:
    findings = []
    try:
        lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
        for line_no, line in enumerate(lines, start=1):
            for rule in RULES:
                if rule["pattern"].search(line):
                    findings.append({
                        "rule": rule,
                        "line_no": line_no,
                        "snippet": line.strip(),
                        "file": filepath
                    })
    except Exception: pass
    return findings

def run_simulation():
    print("  [SIMULATION] Semgrep not found in PATH. Running context-aware simulation...")

    all_findings = []
    if SRC_DIR.exists():
        for js_file in SRC_DIR.rglob("*.js"):
            all_findings.extend(scan_file_simulated(js_file))

    # Generate SARIF
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Semgrep (Simulated Bridge)",
                    "version": "1.0.0",
                    "informationUri": "https://semgrep.dev"
                }
            },
            "results": []
        }]
    }

    for f in all_findings:
        r = f["rule"]
        rel_path = str(f["file"].relative_to(ROOT_DIR / "vulnerable-app")).replace("\\", "/")
        sarif["runs"][0]["results"].append({
            "ruleId": r["id"],
            "level": "error",
            "message": {"text": r["message"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": rel_path},
                "region": {"startLine": f["line_no"], "snippet": {"text": f["snippet"]}}
            }}],
            "properties": {
                "severity": r["severity"],
                "cvss_v3": r["cvss"],
                "cwe": r["cwe"],
                "owasp_category": r["owasp"],
                "mode": "SIMULATED"
            }
        })

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"  ✓ SIMULATION Scan Complete: {len(all_findings)} findings detected.")

# ─────────────────────────────────────────────────────────────
# Execution
# ─────────────────────────────────────────────────────────────

def main():
    print("─" * 60)
    print("  SAST SCANNER BRIDGE")
    print("  Target: " + str(SRC_DIR.relative_to(ROOT_DIR)))
    print("─" * 60)

    # Attempt production scan first
    if not run_real_scan():
        run_simulation()

    print(f"  → Report: {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print()

if __name__ == "__main__":
    main()
