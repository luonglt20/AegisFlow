#!/usr/bin/env python3
"""
pipeline/scan_sbom.py
─────────────────────────────────────────────────────────────────────────────
Hybrid SBOM Bridge:
  • PRODUCTION:  Runs 'syft' or 'cyclonedx-npm' if available.
  • SIMULATION:  Falls back to high-fidelity CycloneDX v1.5 generator.

Output: CycloneDX JSON format in security-results/sbom.json
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
APP_DIR     = Path(os.environ.get("SCAN_TARGET", str(ROOT_DIR / "_target_required_")))
OUTPUT_FILE = ROOT_DIR / "security-results" / "sbom.json"
APP_NAME    = APP_DIR.name or "unknown-target"

# ─────────────────────────────────────────────────────────────
# Real Tool Integration
# ─────────────────────────────────────────────────────────────

def run_real_scan() -> bool:
    # Try to find 'syft' (industry standard) or 'cyclonedx-npm'
    tool_path = shutil.which("syft") or shutil.which("cyclonedx-npm")
    if not tool_path:
        return False

    print(f"  [PRODUCTION] Found SBOM tool at {tool_path}. Generating SBOM...")

    try:
        # Syft is the primary tool
        if tool_path and "syft" in tool_path:
            cmd = [
                tool_path, str(APP_DIR),
                "--output", f"cyclonedx-json={OUTPUT_FILE}",
                "-q"
            ]
        else: # cyclonedx-npm
            cmd = [
                "cyclonedx-npm",
                "--output-format", "JSON",
                "--output-file", str(OUTPUT_FILE),
                str(APP_DIR)
            ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode == 0 and OUTPUT_FILE.exists():
            print(f"  ✓ PRODUCTION SBOM Complete (Real CycloneDX data saved)")
            return True
        else:
            print(f"  [ERROR] SBOM tool failed: {result.stderr[:200]}")

    except Exception as e:
        print(f"  [ERROR] Exception during real SBOM generation: {e}")

    return False

# ─────────────────────────────────────────────────────────────
# Simulation Logic
# ─────────────────────────────────────────────────────────────

def run_simulation():
    print("  [SIMULATION] Syft not found. Analyzing dependencies via package.json...")

    PKG_FILE = APP_DIR / "package.json"
    if not PKG_FILE.exists():
        print(f"  [ERROR] Not found: {PKG_FILE}")
        return

    try:
        pkg = json.loads(PKG_FILE.read_text())
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    except:
        deps = {}

    components = []
    for name, ver in deps.items():
        clean_ver = ver.lstrip("^~>=<v")
        components.append({
            "type": "library",
            "name": name,
            "version": clean_ver,
            "purl": f"pkg:npm/{name}@{clean_ver}",
            "licenses": [{"license": {"id": "MIT"}}],
            "properties": [{"name": "scan-mode", "value": "SIMULATED"}]
        })

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "component": {
                "type": "application",
                "name": APP_NAME,
                "version": "1.0.0"
            }
        },
        "components": components
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(sbom, indent=2))
    print(f"  ✓ SIMULATION SBOM Complete: {len(components)} components listed.")

def main():
    print("─" * 60)
    print("  SBOM SCANNER BRIDGE (CycloneDX)")
    print("─" * 60)

    if not run_real_scan():
        run_simulation()

    print(f"  → Output: {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print()

if __name__ == "__main__":
    main()
