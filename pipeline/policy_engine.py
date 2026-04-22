#!/usr/bin/env python3
"""
pipeline/policy_engine.py
─────────────────────────────────────────────────────────────────────────────
Security policy gate for DevSecOps pipeline.

Input  : ../mock-data/full_report.json
Output : ../mock-data/policy_result.json
Exit   : 0 = PASSED/WARNING  |  1 = BLOCKED

Policy rules:
  CRITICAL > 0       → BLOCKED  (exit 1)
  HIGH >= 3          → BLOCKED  (exit 1)
  HIGH > 0           → WARNING  (exit 0)
  else               → PASSED   (exit 0)

stdlib only – no pip install required.
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
REPORT_FILE  = Path(os.environ.get("TRIAGED_REPORT", ROOT_DIR / "mock-data" / "full_report_triaged.json"))
OUTPUT_FILE  = Path(os.environ.get("POLICY_OUTPUT", ROOT_DIR / "mock-data" / "policy_result.json"))

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
    for sev, cnt in sorted(counts.items(), key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x[0]) if x[0] in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99):
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

    # Show CRITICAL & HIGH details
    critical_high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    if critical_high:
        print(colored("  High-Priority Findings Requiring Action:", BOLD))
        print(colored("  " + "─" * 50, DIM))
        for f in critical_high[:8]:  # cap at 8 for readability
            sev   = f.get("severity", "")
            color = sev_colors.get(sev, "")
            fid   = f.get("id", "?")
            title = f.get("title", "")[:50]
            stype = f.get("scan_type", "")
            print(f"    [{colored(fid, BOLD)}] [{colored(sev, color)}] [{stype}] {title}")
        if len(critical_high) > 8:
            print(f"    ... and {len(critical_high) - 8} more (see full_report.json)")
        print()


# ─────────────────────────────────────────────────────────────
# Policy evaluation
# ─────────────────────────────────────────────────────────────

def evaluate_policy(findings: list[dict]) -> tuple[str, str, int]:
    """
    Returns (status, reason, exit_code).
    """
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)

    if crit > 0:
        return (
            "BLOCKED",
            f"{crit} CRITICAL finding(s) detected — pipeline gate enforced by AppSec policy",
            1,
        )
    elif high >= 3:
        return (
            "BLOCKED",
            f"{high} HIGH findings exceed threshold (max allowed: 2) — pipeline gate enforced",
            1,
        )
    elif high > 0:
        return (
            "WARNING",
            f"{high} HIGH finding(s) require security review before merge",
            0,
        )
    else:
        return "PASSED", "No CRITICAL or HIGH findings — security gate passed", 0

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main() -> None:
    print()
    print(colored("═" * 62, BOLD))
    print(colored("  DevSecOps Policy Engine v1.0", BOLD, CYAN))
    print(colored("  AppSec Pipeline Gate Evaluation", DIM))
    print(colored("═" * 62, BOLD))
    print()

    # Load report
    if not REPORT_FILE.exists():
        print(colored(f"  [ERROR] full_report.json not found: {REPORT_FILE}", RED), file=sys.stderr)
        print(colored("  Run report_generator.py first.", YELLOW), file=sys.stderr)
        sys.exit(2)

    try:
        report = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(colored(f"  [ERROR] Invalid JSON: {exc}", RED), file=sys.stderr)
        sys.exit(2)

    findings = report.get("findings", [])
    metadata = report.get("scan_metadata", {})

    print(colored("  Scan Metadata", BOLD))
    print(colored("  " + "─" * 50, DIM))
    print(f"    App         : {metadata.get('app_name', 'N/A')} {metadata.get('app_version', '')}")
    print(f"    Scan Time   : {metadata.get('scan_timestamp', 'N/A')}")
    print(f"    Pipeline ID : {metadata.get('pipeline_run_id', 'N/A')}")
    print(f"    Tools       : {', '.join(metadata.get('tools_used', []))}")
    print(f"    Findings    : {len(findings)}")
    print()

    # Count by severity
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    print_findings_breakdown(counts, findings)

    # Evaluate policy
    status, reason, exit_code = evaluate_policy(findings)

    now = datetime.now(timezone.utc)
    ts  = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Print status banner
    if status == "BLOCKED":
        print_blocked_banner(reason, counts)
    elif status == "WARNING":
        print_warning_banner(reason, counts)
    else:
        print_passed_banner(counts)

    # Write policy result
    policy_result = {
        "pipeline_status":   status,
        "block_reason":      reason,
        "timestamp":         ts,
        "findings_summary":  counts,
        "total_findings":    len(findings),
        "action_required":   "Human review required via Dashboard" if status != "PASSED" else "None",
        "dashboard_url":     "http://localhost:58080",
        "exception_allowed": True,
        "exception_approver":"Security Lead",
        "policy_version":    "2.1",
        "exit_code":         exit_code,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(policy_result, indent=2), encoding="utf-8")

    print(colored("  Policy Result", BOLD))
    print(colored("  " + "─" * 50, DIM))
    print(f"    Status      : {colored(status, RED + BOLD if status == 'BLOCKED' else (YELLOW + BOLD if status == 'WARNING' else GREEN + BOLD))}")
    print(f"    Reason      : {reason}")
    print(f"    Exit Code   : {exit_code}")
    print(f"    Dashboard   : {colored('http://localhost:58080', CYAN)}")
    print(f"    Output      : {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print()

    if status == "BLOCKED":
        print(colored("  ℹ  Exception override available via Security Lead approval", DIM))
        print(colored("     Dashboard → Findings → Request Exception", DIM))
        print()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
