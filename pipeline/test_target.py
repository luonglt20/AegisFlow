#!/usr/bin/env python3
"""
pipeline/test_target.py
Runs a lightweight test stage for the selected target.
If no runnable tests are present, the stage falls back to a documented validation
mode so the CI/CD flow remains explicit and reviewable.
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
OUTPUT_FILE = ROOT_DIR / "security-results" / "test_report.json"
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


def select_npm_test_script(scripts):
    explicit = os.environ.get("AEGIS_TEST_COMMAND", "").strip()
    if explicit:
        return explicit.split(), explicit

    for script in ("test:ci", "test:server", "test:api", "test"):
        if script in scripts:
            return ["npm", "run", script] if script != "test" else ["npm", "test"], script

    return None, None


def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "stage": "test",
        "target": str(TARGET_DIR),
        "status": "passed",
        "mode": "fallback",
        "strict_ci": STRICT_CI,
        "details": [],
    }

    package_json = TARGET_DIR / "package.json"
    pytest_ini = TARGET_DIR / "pytest.ini"
    tests_dir = TARGET_DIR / "tests"

    if package_json.exists() and shutil.which("node"):
        pkg = load_package_json(package_json)
        scripts = pkg.get("scripts", {})
        command, selected_script = select_npm_test_script(scripts)

        if INSTALL_DEPS and (TARGET_DIR / "package-lock.json").exists():
            append_result(report, run_command(["npm", "ci", "--ignore-scripts"], TARGET_DIR))

        if command and has_node_dependencies(TARGET_DIR):
            report["mode"] = "real"
            report["selected_script"] = selected_script
            append_result(report, run_command(command, TARGET_DIR))
        elif command:
            report["mode"] = "skipped"
            report["status"] = "skipped"
            report["selected_script"] = selected_script
            report["details"].append({
                "message": "A test script exists, but dependencies are not installed in the selected target, so the test was not executed in local demo mode.",
                "selected_script": selected_script,
                "available_scripts": sorted(scripts.keys()),
                "dependency_install_hint": "Set AEGIS_INSTALL_DEPS=true in CI or preinstall node_modules to execute this test.",
            })
            if STRICT_CI:
                report["status"] = "failed"
                report["details"].append({"message": "STRICT_CI requires the detected test script to execute successfully."})
        else:
            report["mode"] = "validation"
            report["details"].append({
                "message": "Node.js target detected but no test script was declared.",
                "validated_files": ["package.json"],
                "available_scripts": sorted(scripts.keys()),
            })
            if STRICT_CI:
                report["status"] = "failed"
    elif (pytest_ini.exists() or tests_dir.exists()) and shutil.which("python3"):
        report["mode"] = "real"
        append_result(report, run_command(["python3", "-m", "pytest", "-q"], TARGET_DIR))
    else:
        report["status"] = "skipped"
        report["mode"] = "skipped"
        report["details"].append({
            "message": "No runnable test suite was auto-detected for the selected target. The framework keeps the stage explicit and documents the limitation in the final report.",
        })
        if STRICT_CI:
            report["status"] = "failed"

    OUTPUT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if report["status"] == "failed":
        sys.exit(1)


if __name__ == "__main__":
    main()
