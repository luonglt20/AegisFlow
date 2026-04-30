#!/usr/bin/env python3
"""
pipeline/audit_logger.py
─────────────────────────────────────────────────────────────────────────────
Immutable Audit Log for AegisFlow DevSecOps Pipeline.
Records every pipeline execution, status, and summary findings.
"""

import json
import os
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent.resolve()
ROOT_DIR     = SCRIPT_DIR.parent
LOG_FILE     = ROOT_DIR / "security-results" / "audit_log.json"
POLICY_FILE  = ROOT_DIR / "security-results" / "policy_result.json"

def log_event():
    print("─" * 60)
    print("  AUDIT LOGGER: Recording pipeline event...")
    print("─" * 60)

    # 1. Gather context
    now = datetime.now(timezone.utc)
    ts  = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    user = os.environ.get("BUILD_USER", "system-agent")
    pipeline_id = os.environ.get("PIPELINE_ID", f"AF-{now.strftime('%y%m%d')}-{os.getpid()}")

    # 2. Get status from policy engine output
    status = "UNKNOWN"
    summary = {}
    quality_summary = {}
    if POLICY_FILE.exists():
        try:
            policy_data = json.loads(POLICY_FILE.read_text())
            status = policy_data.get("pipeline_status", "UNKNOWN")
            summary = policy_data.get("findings_summary", {})
            quality_summary = policy_data.get("quality_summary", {})
        except: pass

    # 3. Create audit record
    record = {
        "timestamp": ts,
        "event_type": "PIPELINE_EXECUTION",
        "user": user,
        "pipeline_id": pipeline_id,
        "outcome": status,
        "findings_summary": summary,
        "quality_summary": quality_summary,
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record["integrity_hash"] = "sha256:" + hashlib.sha256(canonical).hexdigest()

    # 4. Append to log
    logs = []
    if LOG_FILE.exists():
        try:
            logs = json.loads(LOG_FILE.read_text())
        except: logs = []

    logs.append(record)

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text(json.dumps(logs, indent=2))

    print(f"  ✓ Audit record saved for {pipeline_id}")
    print(f"  ✓ Integrity hash generated: {record['integrity_hash']}")
    print()

if __name__ == "__main__":
    log_event()
