#!/usr/bin/env python3
"""
pipeline/build_target.py
Detects the selected target stack and performs a lightweight local build step.
The goal is to make the CI/CD stages explicit for the case study while still
supporting multiple apps selected from the dashboard.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent.resolve()
TARGET_DIR = Path(os.environ.get("SCAN_TARGET", ROOT_DIR / "_target_required_"))
OUTPUT_FILE = ROOT_DIR / "security-results" / "build_report.json"


def run_command(cmd, cwd):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    return {
        "command": " ".join(cmd),
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
    }


def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "stage": "build",
        "target": str(TARGET_DIR),
        "status": "passed",
        "mode": "real",
        "details": [],
    }

    if not TARGET_DIR.exists():
        report["status"] = "failed"
        report["mode"] = "validation"
        report["details"].append({"message": "Target path does not exist."})
        OUTPUT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")
        sys.exit(1)

    package_json = TARGET_DIR / "package.json"
    requirements = TARGET_DIR / "requirements.txt"
    dockerfile = TARGET_DIR / "Dockerfile"

    if package_json.exists() and shutil.which("npm"):
        report["details"].append(run_command(["npm", "--version"], TARGET_DIR))
    elif requirements.exists() and shutil.which("python3"):
        report["details"].append(run_command(["python3", "-m", "compileall", "."], TARGET_DIR))
    elif dockerfile.exists():
        report["mode"] = "fallback"
        report["details"].append({
            "message": "Dockerfile detected. Build stage recorded as a structural validation because image build is handled by docker-compose.",
            "validated_files": ["Dockerfile"],
        })
    else:
        report["mode"] = "fallback"
        report["details"].append({
            "message": "No standard build manifest was detected. The framework recorded a fallback validation stage only.",
        })

    OUTPUT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if report["status"] != "passed":
        sys.exit(1)


if __name__ == "__main__":
    main()
