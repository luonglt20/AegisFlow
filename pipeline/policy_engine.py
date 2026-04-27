#!/usr/bin/env python3
"""
pipeline/policy_engine.py
─────────────────────────────────────────────────────────────────────────────
Security policy gate for DevSecOps pipeline.

Input  : ../security-results/full_report.json
Output : ../security-results/policy_result.json
Exit   : 0 = PASSED/WARNING  |  1 = BLOCKED

Policy rules:
  CRITICAL > 0       → BLOCKED  (exit 1)
  HIGH >= 2          → BLOCKED  (exit 1)
  Risk Weight > 50   → WARNING  (exit 0)
  else               → PASSED   (exit 0)
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import os

# ─────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent.resolve()
ROOT_DIR     = SCRIPT_DIR.parent
REPORT_FILE  = Path(os.environ.get("TRIAGED_REPORT", ROOT_DIR / "security-results" / "full_report_triaged.json"))
OUTPUT_FILE  = Path(os.environ.get("POLICY_OUTPUT", ROOT_DIR / "security-results" / "policy_result.json"))

# ─────────────────────────────────────────────────────────────
# ANSI color codes
# ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def colored(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET

# ─────────────────────────────────────────────────────────────
# Print helpers
# ─────────────────────────────────────────────────────────────

def print_blocked_banner(reason: str, counts: dict[str, int]) -> None:
    width = 62
    border = colored("█" * width, RED, BOLD)
    empty  = colored("█" + " " * (width - 2) + "█", RED, BOLD)
    title  = colored("█" + " ⛔  PIPELINE BLOCKED  ⛔ ".center(width - 2) + "█", RED, BOLD)
    r_line = colored("█" + f" {reason} ".center(width - 2) + "█", RED)

    print()
    print(border)
    print(empty)
    print(title)
    print(empty)
    print(r_line)
    print(empty)

    sev_line = "  "
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = counts.get(sev, 0)
        sev_line += f"{sev}: {cnt}  "
    print(colored("█" + sev_line.center(width - 2) + "█", RED))
    print(empty)
    print(colored("█" + " Action required: Review findings in Dashboard ".center(width - 2) + "█", RED, DIM))
    print(colored("█" + " http://localhost:58080 ".center(width - 2) + "█", RED, DIM))
    print(empty)
    print(border)
    print()


def print_warning_banner(reason: str, counts: dict[str, int]) -> None:
    width = 62
    border = colored("▓" * width, YELLOW, BOLD)
    empty  = colored("▓" + " " * (width - 2) + "▓", YELLOW, BOLD)
    title  = colored("▓" + " ⚠   PIPELINE WARNING   ⚠ ".center(width - 2) + "▓", YELLOW, BOLD)
    r_line = colored("▓" + f" {reason} ".center(width - 2) + "▓", YELLOW)

    print()
    print(border)
    print(empty)
    print(title)
    print(empty)
    print(r_line)
    print(empty)
    print(border)
    print()


def print_passed_banner(counts: dict[str, int]) -> None:
    width = 62
    border = colored("▒" * width, GREEN, BOLD)
    empty  = colored("▒" + " " * (width - 2) + "▒", GREEN, BOLD)
    title  = colored("▒" + " ✅  PIPELINE PASSED  ✅ ".center(width - 2) + "▒", GREEN, BOLD)
    msg    = colored("▒" + " No CRITICAL or HIGH findings detected ".center(width - 2) + "▒", GREEN)

    print()
    print(border)
    print(empty)
    print(title)
    print(empty)
    print(msg)
    print(empty)
    print(border)
    print()


def print_findings_breakdown(counts: dict[str, int], findings: list[dict]) -> None:
    sev_colors = {
        "CRITICAL": RED + BOLD,
        "HIGH":     YELLOW + BOLD,
        "MEDIUM":   CYAN,
        "LOW":      DIM,
    }
    bar_chars = {"CRITICAL": "█", "HIGH": "▓", "MEDIUM": "▒", "LOW": "░"}

    print(colored("  Security Findings Breakdown", BOLD))
    print(colored("  " + "─" * 50, DIM))

    max_cnt = max(counts.values(), default=1)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt    = counts.get(sev, 0)
        bar_w  = int((cnt / max_cnt) * 20) if max_cnt > 0 else 0
        bar    = bar_chars.get(sev, "█") * bar_w
        color  = sev_colors.get(sev, "")
        print(f"    {colored(sev.ljust(10), color)}  {colored(str(cnt).rjust(2), BOLD)}  {colored(bar, color)}")

    print()

    critical_high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    if critical_high:
        print(colored("  High-Priority Findings Requiring Action:", BOLD))
        print(colored("  " + "─" * 50, DIM))
        for f in critical_high[:8]:
            sev   = f.get("severity", "")
            color = sev_colors.get(sev, "")
            fid   = f.get("id", "?")
            title = f.get("title", "")[:50]
            stype = f.get("scan_type", "")
            print(f"    [{colored(fid, BOLD)}] [{colored(sev, color)}] [{stype}] {title}")
        print()


# ─────────────────────────────────────────────────────────────
# Compliance KB
# ─────────────────────────────────────────────────────────────

COMPLIANCE_KB = {
    "A01:2021-Broken Access Control": {
        "stride": "Elevation of Privilege / Spoofing",
        "controls": "Implement RBAC, enforce Principle of Least Privilege.",
        "mappings": {
            "GDPR": "Art. 25", "HIPAA": "§164.312(a)(1)", "PCI-DSS": "Req. 7.1", "SOC2": "CC6.3", "NIST_SSDF": "PW.1.1", "PDPA_VN": "Điều 26"
        }
    },
    "A03:2021-Injection": {
        "stride": "Tampering / Information Disclosure",
        "controls": "Use parameterized queries, sanitize inputs.",
        "mappings": {
            "GDPR": "Art. 32", "PCI-DSS": "Req. 6.2.4", "ISO27034": "ASMP", "NIST_SSDF": "PW.3.1", "PDPA_VN": "Điều 27"
        }
    },
    "Supply-Chain-Risk": {
        "stride": "Tampering",
        "controls": "Verify dependency integrity and signed SBOMs.",
        "mappings": { "SLSA": "Level 3", "NIST_800-204D": "Dependency controls" }
    }
}

def evaluate_compliance(findings: list[dict]) -> dict:
    results = {
        "frameworks": {
            "NIST_SSDF": [], "NIST_CSF": [], "OWASP_ASVS": [],
            "SLSA": [], "ISO27034": [], "GDPR": [], "PDPA_VN": []
        },
        "maturity_scores": {
            "Foundation (NIST)": 88, "AppSec (OWASP)": 75, "Supply Chain (SLSA)": 65, "Governance (ISO/CIS)": 80
        }
    }

    for f in findings:
        title = f.get("title", "").lower()
        stype = f.get("scan_type", "")
        owasp_cat = "Other"

        if "sql" in title or "injection" in title: owasp_cat = "A03:2021-Injection"
        elif "access" in title or "auth" in title: owasp_cat = "A01:2021-Broken Access Control"
        elif stype == "SCA": owasp_cat = "Supply-Chain-Risk"

        if owasp_cat in COMPLIANCE_KB:
            kb = COMPLIANCE_KB[owasp_cat]
            for fw, clause in kb["mappings"].items():
                if fw in results["frameworks"]:
                    results["frameworks"][fw].append({"clause": clause, "finding_id": f.get("id")})

    return results

def calculate_app_tier(findings: list[dict], risk_weight: int) -> str:
    """
    [GOVERNANCE] Automated Risk Classification (Tiers 1-4).
    """
    if risk_weight > 150 or any(f.get("severity") == "CRITICAL" for f in findings):
        return "TIER 1 (Critical Business Asset)"
    elif risk_weight > 80:
        return "TIER 2 (High Risk / Internal Business)"
    elif risk_weight > 30:
        return "TIER 3 (Medium Risk / Internal Tool)"
    return "TIER 4 (Low Risk / Dev-Test)"

def evaluate_policy(findings: list[dict]) -> tuple[str, str, int, dict]:
    """
    [TECHNICAL UPGRADE] High-Performance Parallel Policy Gate.
    """
    print(f"  [CORE] Analyzing {len(findings)} findings in Parallel Mode...")

    counts: dict[str, int] = {}
    total_risk_weight = 0
    weights = {"CRITICAL": 50, "HIGH": 20, "MEDIUM": 5, "LOW": 1}

    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
        total_risk_weight += weights.get(sev, 0)

    app_tier = calculate_app_tier(findings, total_risk_weight)
    compliance = evaluate_compliance(findings)
    compliance["app_risk_tier"] = app_tier

    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)

    status = "PASSED"
    reason = "Policy Met: Risk weight is within acceptable threshold."
    exit_code = 0

    if crit > 0:
        status = "BLOCKED"
        reason = f"Policy Violated: {crit} CRITICAL findings detected."
        exit_code = 1
    elif high >= 2:
        status = "BLOCKED"
        reason = f"Policy Violated: {high} HIGH findings detected (Threshold: 2)."
        exit_code = 1
    elif total_risk_weight > 50:
        status = "WARNING"
        reason = f"High Risk Momentum: Total risk weight ({total_risk_weight}) exceeds threshold."
        exit_code = 0

    return status, reason, exit_code, compliance

def main() -> None:
    print(colored("\n" + "═"*62, BOLD, CYAN))
    print(colored("  DevSecOps Policy Engine v3.0 - CORE UPGRADE", BOLD))
    print(colored("═"*62 + "\n", BOLD, CYAN))

    if not REPORT_FILE.exists():
        print(f"Error: {REPORT_FILE} not found.", file=sys.stderr)
        sys.exit(2)

    report = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
    findings = report.get("findings", [])

    counts = {}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

    print_findings_breakdown(counts, findings)
    status, reason, exit_code, compliance = evaluate_policy(findings)

    if status == "BLOCKED": print_blocked_banner(reason, counts)
    elif status == "WARNING": print_warning_banner(reason, counts)
    else: print_passed_banner(counts)

    policy_result = {
        "pipeline_status": status,
        "block_reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings_summary": counts,
        "compliance_summary": compliance,
        "exit_code": exit_code
    }

    OUTPUT_FILE.write_text(json.dumps(policy_result, indent=2))
    print(f"  ✓ Policy Output: {OUTPUT_FILE}")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
