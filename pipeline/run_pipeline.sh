#!/usr/bin/env bash
# pipeline/run_pipeline.sh
# ─────────────────────────────────────────────────────────────────────────────
# AegisFlow - DevSecOps Enterprise Pipeline
#
# Usage:
#   cd pipeline/
#   chmod +x run_pipeline.sh
#   ./run_pipeline.sh
#
# On Windows (no bash available):
#   python simulate_sast.py && python simulate_sca.py && \
#   python simulate_iac.py  && python simulate_dast.py && \
#   python report_generator.py && python policy_engine.py
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── Change to script directory so relative paths work ───────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Header ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║         AegisFlow Enterprise Pipeline  v1.0                  ║${RESET}"
echo -e "${BOLD}║         Stage: SECURITY SCAN                                ║${RESET}"
echo -e "${BOLD}║         App:   vulnerable-app  |  Branch: main              ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""

# ─── Timestamp ───────────────────────────────────────────────────────────────
START_TIME=$(date +%s 2>/dev/null || echo "0")
SCAN_DATE=$(date -u "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "N/A")
echo -e "${DIM}  Pipeline started at: ${SCAN_DATE}${RESET}"
echo ""

# ─── Detect Python interpreter ───────────────────────────────────────────────
PYTHON=""
for candidate in python3 python py; do
    if command -v "${candidate}" &>/dev/null; then
        PYTHON="${candidate}"
        PY_VER=$("${PYTHON}" --version 2>&1)
        echo -e "${DIM}  Python interpreter: ${PYTHON} (${PY_VER})${RESET}"
        break
    fi
done

if [[ -z "${PYTHON}" ]]; then
    echo -e "${RED}  [ERROR] Python not found. Please install Python 3.8+.${RESET}" >&2
    exit 1
fi
echo ""

# ─── Helper: run step with error handling ────────────────────────────────────
run_step() {
    local step_num="$1"
    local step_label="$2"
    local script="$3"

    echo -e "${BOLD}[${step_num}/10] ${step_label}${RESET}"
    echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"

    if "${PYTHON}" "${script}"; then
        echo -e "${GREEN}  ✓ Step ${step_num} completed successfully${RESET}"
    else
        echo -e "${RED}  ✗ Step ${step_num} failed (script: ${script})${RESET}" >&2
        echo -e "${YELLOW}  Pipeline will continue with available data...${RESET}"
    fi
    echo ""
}

# ─── Pipeline Steps ──────────────────────────────────────────────────────────

run_step "1" "SAST Scanning  (Semgrep Bridge)"     "scan_sast.py"

run_step "2" "SCA Scanning   (Trivy Bridge)"       "scan_sca.py"

run_step "3" "SBOM Generation (CycloneDX Bridge)"  "scan_sbom.py"

run_step "4" "Secret Scanning (Gitleaks Bridge)"   "scan_secret.py"

run_step "5" "IaC Scanning    (Checkov Bridge)"    "scan_iac.py"

run_step "6" "DAST Scanning   (ZAP Bridge)"        "scan_dast.py"

run_step "7" "Consolidating Security Reports"      "report_generator.py"

run_step "8" "Generating AI Triage & Analysis"     "ai_triage_engine.py"

run_step "9" "Generating HTML/PDF Case Study"      "generate_report.py"

# ─── Policy Gate (may exit 1) ────────────────────────────────────────────────
echo -e "${BOLD}[10/10] Evaluating Security Policy Gate${RESET}"
echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"

POLICY_EXIT=0
"${PYTHON}" policy_engine.py || POLICY_EXIT=$?

# ─── Pipeline summary ─────────────────────────────────────────────────────────
END_TIME=$(date +%s 2>/dev/null || echo "0")
if [[ "${START_TIME}" != "0" && "${END_TIME}" != "0" ]]; then
    ELAPSED=$(( END_TIME - START_TIME ))
    echo -e "${DIM}  Total pipeline duration: ${ELAPSED}s${RESET}"
fi

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
if [[ ${POLICY_EXIT} -eq 0 ]]; then
    echo -e "${BOLD}║  ${GREEN}Pipeline completed – Security gate PASSED / WARNING${RESET}${BOLD}         ║${RESET}"
else
    echo -e "${BOLD}║  ${RED}Pipeline BLOCKED – Critical security findings detected${RESET}${BOLD}      ║${RESET}"
fi
echo -e "${BOLD}║  Dashboard: ${CYAN}http://localhost:58080${RESET}${BOLD}                            ║${RESET}"
echo -e "${BOLD}║  Reports:   mock-data/*.json                                ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""

exit ${POLICY_EXIT}
