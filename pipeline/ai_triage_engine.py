#!/usr/bin/env python3
"""
pipeline/ai_triage_engine.py
─────────────────────────────────────────────────────────────────────────────
AI-powered triage engine for DevSecOps pipeline.
Analyzes every finding in full_report.json.
Output: mock-data/full_report_triaged.json
"""

import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

# ─────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR      = Path(__file__).parent.resolve()
ROOT_DIR        = SCRIPT_DIR.parent
MOCK_DIR        = ROOT_DIR / "mock-data"
REPORT_FILE     = Path(os.environ.get("CONSOLIDATED_REPORT", MOCK_DIR / "full_report.json"))
OUTPUT_FILE     = Path(os.environ.get("TRIAGED_REPORT", MOCK_DIR / "full_report_triaged.json"))

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = "llama-3.3-70b-versatile"
SLA_HOURS    = {"CRITICAL": 8, "HIGH": 24, "MEDIUM": 48, "LOW": 72}

# Global counters for summary
stats = {"True Positive": 0, "False Positive": 0, "Needs Review": 0, "error": 0}

# ─────────────────────────────────────────────────────────────
# ANSI colors
# ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + RESET

def compute_sla_deadline(severity: str, now: datetime) -> str:
    hours = SLA_HOURS.get(severity, 168)
    deadline = now + timedelta(hours=hours)
    return deadline.strftime("%Y-%m-%dT%H:%M:%SZ")

def default_mock(finding: dict) -> dict:
    sev   = finding.get("severity", "MEDIUM")
    return {
        "classification": "True Positive",
        "confidence":     85,
        "reasoning":      f"Static analysis indicates this {sev.lower()} finding is likely a True Positive.",
        "code_fix": {
            "before":      finding.get("code_snippet", "vulnerable code"),
            "after":       "fixed code",
            "explanation": "Apply security best practices."
        },
        "business_impact": "Potential data breach or unauthorized access.",
        "priority_score":  {"CRITICAL": 9, "HIGH": 7, "MEDIUM": 5, "LOW": 2}.get(sev, 5),
    }

def triage_finding(finding: dict, target_path: str, mode: str):
    now = datetime.now(timezone.utc)
    severity = finding.get("severity", "MEDIUM")

    # In this simplified demo, we always use mock/default triage
    ai_resp = default_mock(finding)

    # Apply results
    cls = ai_resp.get("classification", "Needs Review")
    finding["ai_analysis"] = f"[{cls}] {ai_resp.get('reasoning', '')}"
    finding["ai_fix"] = ai_resp.get("code_fix", {})
    finding["ai_confidence"] = ai_resp.get("confidence", 70)
    finding["ai_priority_score"] = ai_resp.get("priority_score", 5)
    finding["business_impact"] = ai_resp.get("business_impact", "")
    finding["status"] = "PENDING_HUMAN_VERIFY"
    finding["ai_model"] = f"mock:{GROQ_MODEL}"
    finding["ai_analyzed_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    finding["sla_deadline"] = compute_sla_deadline(severity, now)

    stats[cls] = stats.get(cls, 0) + 1
    print(f"  [TRIAGED] {finding.get('id')} -> {cls}")

def main() -> None:
    start_time = time.time()
    print()
    print(c("═" * 64, BOLD))
    print(c("  AI Triage Engine  –  Security Finding Analysis", BOLD, CYAN))
    print(c("═" * 64, BOLD))
    print()

    if not REPORT_FILE.exists():
        print(c(f"  [ERROR] Not found: {REPORT_FILE}", RED), file=sys.stderr)
        sys.exit(1)

    try:
        report = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        print(c(f"  [ERROR] Failed to load report: {exc}", RED))
        sys.exit(1)

    findings = report.get("findings", [])
    if not findings:
        print(c("  [WARN] No findings to analyze.", YELLOW))
        return

    print(f"  Analyzing {len(findings)} findings in Parallel Mode...")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(lambda f: triage_finding(f, ".", "MOCK"), findings)

    # Save to triaged report
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(report, indent=4), encoding="utf-8")

    elapsed = round(time.time() - start_time, 1)

    print()
    print(c("  " + "─" * 32, DIM))
    print(c("  Triage Summary", BOLD))
    print(c("  " + "─" * 32, DIM))

    for cls, count in stats.items():
        if count > 0 and cls != "error":
            color = RED if "True" in cls else (GREEN if "False" in cls else YELLOW)
            print(f"    {c(cls.ljust(15), color)}: {count} findings")

    print(f"\n  ✅ Analysis complete. Results saved to {OUTPUT_FILE.name}")
    print(f"  Duration: {elapsed}s")
    print(c("═" * 64, BOLD))
    print()

if __name__ == "__main__":
    main()
