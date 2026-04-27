#!/usr/bin/env bash
# pipeline/run_pipeline.sh

# ─── Environment Setup ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for UI
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'

echo "[STEP 1/13] 🔍 AUTO-DISCOVERING PROJECT STRUCTURE..."
if [ -z "$SCAN_TARGET" ]; then
    echo -e "${RED}  [ERROR] No SCAN_TARGET provided. Select or enter a target path before launching the pipeline.${RESET}" >&2
    exit 1
fi
if [ -z "$TARGET_URL" ]; then
    echo "  [!] No Target URL provided. Switching to PREDICTIVE DAST mode..."
    export DAST_MODE="PREDICTIVE"
else
    export DAST_MODE="LIVE"
fi

echo "  [*] Source Target: $SCAN_TARGET"
if [ ! -d "$SCAN_TARGET" ]; then
    echo -e "${YELLOW}  [!] Target not found in root. Searching in real-apps/...${RESET}"
    if [ -d "$ROOT_DIR/real-apps/${SCAN_TARGET##*/}" ]; then
        export SCAN_TARGET="$ROOT_DIR/real-apps/${SCAN_TARGET##*/}"
        echo -e "${GREEN}  ✓ Auto-discovered target: $SCAN_TARGET${RESET}"
    elif [ -d "$ROOT_DIR/vulnerable-app/${SCAN_TARGET##*/}" ]; then
        export SCAN_TARGET="$ROOT_DIR/vulnerable-app/${SCAN_TARGET##*/}"
        echo -e "${GREEN}  ✓ Auto-discovered target: $SCAN_TARGET${RESET}"
    fi
fi
echo "  [*] Mode: Dynamic-to-Static Integrated"

# ─── Timestamp ───────────────────────────────────────────────────────────────
START_TIME=$(date +%s 2>/dev/null || echo "0")
SCAN_DATE=$(date -u "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "N/A")

# ─── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║         AegisFlow Enterprise Pipeline  v1.0                  ║${RESET}"
echo -e "${BOLD}║         Stage: SECURITY SCAN                                ║${RESET}"
echo -e "${BOLD}║         App:   ${SCAN_TARGET##*/}  |  Branch: main              ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""

# ─── Clean previous results ──────────────────────────────────────────────────
echo -e "${DIM}  [*] Clearing previous scan results...${RESET}"
rm -rf "$ROOT_DIR/security-results" "$ROOT_DIR/ingest"
mkdir -p "$ROOT_DIR/security-results" "$ROOT_DIR/ingest"

# ─── Detect Python interpreter ───────────────────────────────────────────────
PYTHON=""
for candidate in python3 python py; do
    if command -v "${candidate}" &>/dev/null; then
        PYTHON="${candidate}"
        break
    fi
done

if [[ -z "${PYTHON}" ]]; then
    echo -e "${RED}  [ERROR] Python not found.${RESET}" >&2
    exit 1
fi

# ─── Helper: run step with error handling ────────────────────────────────────
run_step() {
    local step_num="$1"
    local step_label="$2"
    local script="$3"

    echo -e "${BOLD}[${step_num}/13] ${step_label}${RESET}"
    echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"

    if "${PYTHON}" "${script}"; then
        echo -e "${GREEN}  ✓ Step ${step_num} completed successfully${RESET}"
    else
        echo -e "${RED}  ✗ Step ${step_num} failed (script: ${script})${RESET}" >&2
        echo -e "${YELLOW}  Pipeline will continue with available data...${RESET}"
    fi
    echo ""
}

# ─── Pipeline Steps ──────────────────────────────────────────

# Initial state
"${PYTHON}" pipeline/update_status.py sast running sca pending iac pending dast pending secret pending

run_step "1" "Build Validation Stage"              "pipeline/build_target.py"
run_step "2" "Test Validation Stage"               "pipeline/test_target.py"

run_step "3" "SAST Scanning  (Semgrep Bridge)"     "pipeline/scan_sast.py"
"${PYTHON}" pipeline/update_status.py sast completed sca running

run_step "4" "SCA Scanning   (Trivy Bridge)"       "pipeline/scan_sca.py"
"${PYTHON}" pipeline/update_status.py sca completed sbom running

run_step "5" "SBOM Generation (CycloneDX Bridge)"  "pipeline/scan_sbom.py"
"${PYTHON}" pipeline/update_status.py sbom completed secret running

run_step "6" "Secret Scanning (Gitleaks Bridge)"   "pipeline/scan_secret.py"
"${PYTHON}" pipeline/update_status.py secret completed iac running

run_step "7" "IaC Scanning    (Checkov Bridge)"    "pipeline/scan_iac.py"
"${PYTHON}" pipeline/update_status.py iac completed dast running

run_step "8" "DAST Scanning   (Nuclei Bridge)"     "pipeline/scan_dast.py"
"${PYTHON}" pipeline/update_status.py dast completed

echo -e "${DIM}  [*] Copying scan results to ingestion directory...${RESET}"
mkdir -p "$ROOT_DIR/ingest"
cp "$ROOT_DIR/security-results/"*.json "$ROOT_DIR/ingest/" 2>/dev/null || true

run_step "9" "Consolidating Security Reports"      "pipeline/report_generator.py"

run_step "10" "Generating AI Triage & Analysis"     "pipeline/ai_triage_engine.py"

# [CRITICAL] Sync findings to Dashboard data folder
DASHBOARD_DATA="$ROOT_DIR/dashboard/data"
mkdir -p "$DASHBOARD_DATA"
cp -f "$ROOT_DIR/security-results"/*.json "$DASHBOARD_DATA/" 2>/dev/null || true
echo -e "  ✓ Sync: security-results -> $DASHBOARD_DATA"

run_step "11" "Generating HTML/PDF Case Study"      "pipeline/generate_report.py"

run_step "12" "Audit Logging & Traceability"        "pipeline/audit_logger.py"

# ─── Final State ─────────────────────────────────────────────────────────────
"${PYTHON}" pipeline/update_status.py is_scanning false

# ─── Policy Gate ─────────────────────────────────────────────────────────────
echo -e "${BOLD}[13/13] Evaluating Security Policy Gate${RESET}"
echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"

POLICY_EXIT=0
"${PYTHON}" pipeline/policy_engine.py || POLICY_EXIT=$?

# ─── Summary ─────────────────────────────────────────────────────────────────
END_TIME=$(date +%s 2>/dev/null || echo "0")
ELAPSED=$(( END_TIME - START_TIME ))

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
if [[ ${POLICY_EXIT} -eq 0 ]]; then
    echo -e "${BOLD}║  ${GREEN}Pipeline completed – Security gate PASSED / WARNING${RESET}${BOLD}         ║${RESET}"
else
    echo -e "${BOLD}║  ${RED}Pipeline BLOCKED – Critical security findings detected${RESET}${BOLD}      ║${RESET}"
fi
echo -e "${BOLD}║  Dashboard: http://localhost:58081                            ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""

exit ${POLICY_EXIT}
