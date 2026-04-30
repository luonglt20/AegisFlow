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
import time
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent.resolve()
TARGET_DIR = Path(os.environ.get("SCAN_TARGET", ROOT_DIR / "_target_required_"))
OUTPUT_FILE = ROOT_DIR / "security-results" / "build_report.json"
STRICT_CI = os.environ.get("STRICT_CI", "").lower() in {"1", "true", "yes"}
INSTALL_DEPS = os.environ.get("AEGIS_INSTALL_DEPS", "").lower() in {"1", "true", "yes"}
COMMAND_TIMEOUT = int(os.environ.get("AEGIS_COMMAND_TIMEOUT", "900"))


def run_command(cmd, cwd):
    started = time.time()
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=COMMAND_TIMEOUT,
        )
        return {
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "duration_seconds": round(time.time() - started, 2),
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": " ".join(cmd),
            "returncode": 124,
            "duration_seconds": round(time.time() - started, 2),
            "stdout": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
            "stderr": f"Command timed out after {COMMAND_TIMEOUT}s.",
        }


def load_package_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def has_node_dependencies(target_dir):
    return (target_dir / "node_modules").exists()


def append_result(report, result):
    report["details"].append(result)
    if result.get("returncode", 0) != 0:
        report["status"] = "failed"


def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "stage": "build",
        "target": str(TARGET_DIR),
        "status": "passed",
        "mode": "real",
        "strict_ci": STRICT_CI,
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
        pkg = load_package_json(package_json)
        scripts = pkg.get("scripts", {})
        build_command = os.environ.get("AEGIS_BUILD_COMMAND", "").strip()

        if INSTALL_DEPS and (TARGET_DIR / "package-lock.json").exists():
            append_result(report, run_command(["npm", "ci", "--ignore-scripts"], TARGET_DIR))

        if build_command:
            append_result(report, run_command(build_command.split(), TARGET_DIR))
        elif "build" in scripts and has_node_dependencies(TARGET_DIR):
            append_result(report, run_command(["npm", "run", "build"], TARGET_DIR))
        elif "build:server" in scripts and has_node_dependencies(TARGET_DIR):
            append_result(report, run_command(["npm", "run", "build:server"], TARGET_DIR))
        else:
            report["mode"] = "validation"
            report["details"].append({
                "message": "Node.js target detected. No build command was executed because dependencies are not installed or no portable build script exists.",
                "validated_files": ["package.json"],
                "available_scripts": sorted(scripts.keys()),
                "dependency_install_hint": "Set AEGIS_INSTALL_DEPS=true in CI to run npm ci before build/test.",
            })
            if STRICT_CI and ("build" in scripts or "build:server" in scripts):
                report["status"] = "failed"
                report["details"].append({"message": "STRICT_CI requires the declared build script to execute successfully."})
    elif requirements.exists() and shutil.which("python3"):
        append_result(report, run_command(["python3", "-m", "compileall", "."], TARGET_DIR))
    elif dockerfile.exists():
        report["mode"] = "fallback"
        report["details"].append({
            "message": "Dockerfile detected. Build stage recorded as a structural validation because image build is handled by docker-compose.",
            "validated_files": ["Dockerfile"],
        })
        if STRICT_CI:
            report["status"] = "failed"
            report["details"].append({"message": "STRICT_CI does not accept Dockerfile-only fallback build validation."})
    else:
        report["mode"] = "fallback"
        report["details"].append({
            "message": "No standard build manifest was detected. The framework recorded a fallback validation stage only.",
        })
        if STRICT_CI:
            report["status"] = "failed"

    OUTPUT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if report["status"] != "passed":
        sys.exit(1)


if __name__ == "__main__":
    main()
