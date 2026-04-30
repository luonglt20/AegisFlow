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
STRICT_CI="${STRICT_CI:-false}"
STAGE_FAILURES=0
RUN_STEP_EXIT=0

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
        RUN_STEP_EXIT=0
    else
        RUN_STEP_EXIT=$?
        STAGE_FAILURES=$(( STAGE_FAILURES + 1 ))
        echo -e "${RED}  ✗ Step ${step_num} failed (script: ${script}, exit: ${RUN_STEP_EXIT})${RESET}" >&2
        echo -e "${YELLOW}  Pipeline will continue with available data...${RESET}"
    fi
    echo ""
}

# ─── Pipeline Steps ──────────────────────────────────────────

# Initial state
"${PYTHON}" pipeline/update_status.py build running test pending sast pending sca pending iac pending dast pending secret pending sbom pending policy pending report pending

run_step "1" "Build Validation Stage"              "pipeline/build_target.py"
"${PYTHON}" pipeline/update_status.py build "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)" test running

run_step "2" "Test Validation Stage"               "pipeline/test_target.py"
"${PYTHON}" pipeline/update_status.py test "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)" sast running

run_step "3" "SAST Scanning  (Semgrep Bridge)"     "pipeline/scan_sast.py"
"${PYTHON}" pipeline/update_status.py sast "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)" sca running

run_step "4" "SCA Scanning   (Trivy Bridge)"       "pipeline/scan_sca.py"
"${PYTHON}" pipeline/update_status.py sca "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)" sbom running

run_step "5" "SBOM Generation (CycloneDX Bridge)"  "pipeline/scan_sbom.py"
"${PYTHON}" pipeline/update_status.py sbom "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)" secret running

run_step "6" "Secret Scanning (Gitleaks Bridge)"   "pipeline/scan_secret.py"
"${PYTHON}" pipeline/update_status.py secret "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)" iac running

run_step "7" "IaC Scanning    (Checkov Bridge)"    "pipeline/scan_iac.py"
"${PYTHON}" pipeline/update_status.py iac "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)" dast running

run_step "8" "DAST Scanning   (Nuclei Bridge)"     "pipeline/scan_dast.py"
"${PYTHON}" pipeline/update_status.py dast "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)"

echo -e "${DIM}  [*] Copying scan results to ingestion directory...${RESET}"
mkdir -p "$ROOT_DIR/ingest"
cp "$ROOT_DIR/security-results/"*.json "$ROOT_DIR/ingest/" 2>/dev/null || true

run_step "9" "Consolidating Security Reports"      "pipeline/report_generator.py"

run_step "10" "Generating AI Triage & Analysis"     "pipeline/ai_triage_engine.py"

# ─── Policy Gate ─────────────────────────────────────────────────────────────
"${PYTHON}" pipeline/update_status.py policy running
echo -e "${BOLD}[11/13] Evaluating Security Policy Gate${RESET}"
echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"

POLICY_EXIT=0
"${PYTHON}" pipeline/policy_engine.py || POLICY_EXIT=$?
"${PYTHON}" pipeline/update_status.py policy "$([[ ${POLICY_EXIT} -eq 0 ]] && echo completed || echo failed)" audit running

run_step "12" "Audit Logging & Traceability"        "pipeline/audit_logger.py"
"${PYTHON}" pipeline/update_status.py audit "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)" report running

run_step "13" "Generating HTML/PDF Case Study"      "pipeline/generate_report.py"
"${PYTHON}" pipeline/update_status.py report "$([[ ${RUN_STEP_EXIT} -eq 0 ]] && echo completed || echo failed)"

# [CRITICAL] Sync findings to Dashboard data folder
DASHBOARD_DATA="$ROOT_DIR/dashboard/data"
mkdir -p "$DASHBOARD_DATA"
cp -f "$ROOT_DIR/security-results"/*.json "$DASHBOARD_DATA/" 2>/dev/null || true
echo -e "  ✓ Sync: security-results -> $DASHBOARD_DATA"

# ─── Final State ─────────────────────────────────────────────────────────────
"${PYTHON}" pipeline/update_status.py is_scanning false stage_failures "${STAGE_FAILURES}"

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
