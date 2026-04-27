#!/bin/bash
# AegisFlow Real Scanners for macOS/Linux

TARGET_FOLDER=${1:-"vulnerable-app"}
ROOT_PATH=$(pwd)
BIN_PATH="$ROOT_PATH/pipeline/.bin"
INGEST_PATH="$ROOT_PATH/ingest"
MOCK_DATA_PATH="$ROOT_PATH/security-results"
if [[ "$1" == /* ]]; then
    TARGET_FULL_PATH="$1"
else
    TARGET_FULL_PATH="$ROOT_PATH/$TARGET_FOLDER"
fi

mkdir -p "$BIN_PATH"

echo "=========================================================="
echo " AegisFlow - Real Security Scanner Engine (macOS/Linux)"
echo " Target: $TARGET_FULL_PATH"
echo "=========================================================="

OS=$(uname -s)
ARCH=$(uname -m)

# 1. Map architectures for Trivy and Gitleaks
if [ "$OS" = "Darwin" ]; then
    TRIVY_OS="macOS"
    GL_OS="darwin"
else
    TRIVY_OS="Linux"
    GL_OS="linux"
fi

if [ "$ARCH" = "x86_64" ]; then
    TRIVY_ARCH="64bit"
    GL_ARCH="x64"
elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    TRIVY_ARCH="ARM64"
    GL_ARCH="arm64"
else
    echo "Unknown architecture: $ARCH"
    exit 1
fi

TRIVY_VER="0.70.0"
GL_VER="8.30.1"
NUCLEI_VER="3.8.0"

TRIVY_TAR="trivy_${TRIVY_VER}_${TRIVY_OS}-${TRIVY_ARCH}.tar.gz"
GL_TAR="gitleaks_${GL_VER}_${GL_OS}_${GL_ARCH}.tar.gz"
NUCLEI_ZIP="nuclei_${NUCLEI_VER}_${GL_OS}_${GL_ARCH}.zip"

TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/${TRIVY_TAR}"
GL_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/${GL_TAR}"
NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/${NUCLEI_ZIP}"

TRIVY_EXE="$BIN_PATH/trivy"
GL_EXE="$BIN_PATH/gitleaks"
NUCLEI_EXE="$BIN_PATH/nuclei"

# 2. Download Scanners
if [ ! -f "$TRIVY_EXE" ]; then
    echo "[+] Downloading Trivy scanner ($TRIVY_URL)..."
    curl -sL "$TRIVY_URL" -o "$BIN_PATH/trivy.tar.gz"
    tar -xzf "$BIN_PATH/trivy.tar.gz" -C "$BIN_PATH" trivy
fi

if [ ! -f "$GL_EXE" ]; then
    echo "[+] Downloading Gitleaks scanner ($GL_URL)..."
    curl -sL "$GL_URL" -o "$BIN_PATH/gitleaks.tar.gz"
    tar -xzf "$BIN_PATH/gitleaks.tar.gz" -C "$BIN_PATH" gitleaks
fi

if [ ! -f "$NUCLEI_EXE" ]; then
    echo "[+] Downloading Nuclei DAST scanner ($NUCLEI_URL)..."
    curl -sL "$NUCLEI_URL" -o "$BIN_PATH/nuclei.zip"
    unzip -q "$BIN_PATH/nuclei.zip" -d "$BIN_PATH" nuclei
fi

chmod +x "$TRIVY_EXE" "$GL_EXE" "$NUCLEI_EXE"

# 3. Execute
TRIVY_OUT="$INGEST_PATH/sca_trivy.json"
GL_OUT="$INGEST_PATH/secret_gitleaks.json"
NUCLEI_OUT="$INGEST_PATH/nuclei_dast.json"

echo "[*] Executing Trivy SCA & Misconfig..."
"$TRIVY_EXE" fs "$TARGET_FULL_PATH" --scanners vuln,misconfig --format json --output "$TRIVY_OUT" > /dev/null 2>&1

echo "[*] Executing Gitleaks Secret Scanning..."
"$GL_EXE" detect --source "$TARGET_FULL_PATH" --report-path "$GL_OUT" --report-format json --no-git > /dev/null 2>&1

# 4. Install & Execute Semgrep (SAST)
echo "[*] Ensuring Semgrep (SAST) is installed via pip..."
python3 -m pip install semgrep -q --disable-pip-version-check
SEMGREP_OUT="$INGEST_PATH/sast_semgrep.json"
echo "[*] Executing Semgrep SAST..."
semgrep scan --config=auto --json -o "$SEMGREP_OUT" "$TARGET_FULL_PATH" > /dev/null 2>&1

# 5. Install & Execute Checkov (IaC)
echo "[*] Ensuring Checkov (IaC) is installed via pip..."
python3 -m pip install checkov -q --disable-pip-version-check
CHECKOV_OUT="$INGEST_PATH/iac_checkov.json"
echo "[*] Executing Checkov IaC Configuration Scan..."
checkov -d "$TARGET_FULL_PATH" -o json > "$CHECKOV_OUT" 2> /dev/null

# 6. Execute Nuclei (DAST - Simulated/Lightweight)
echo "[*] Executing Nuclei DAST (Detection)..."
# We run a baseline scan. If the user provided a URL, it would be better.
# For now, we scan for general web vulnerabilities in the project itself (configs, etc.)
"$NUCLEI_EXE" -target "$TARGET_FULL_PATH" -severity critical,high -json -o "$NUCLEI_OUT" > /dev/null 2>&1

# 7. Aggregate using native Report Generator
echo "[*] Aggregating real scanner results via Zero-Config Ingestion..."
export CONSOLIDATED_REPORT="$MOCK_DATA_PATH/full_report.json"
python3 "$ROOT_PATH/pipeline/report_generator.py"


# 8. Trigger Autonomous AI Triage
echo "[*] Waking up Llama-3 AI Triage Engine..."
# ai_triage_engine.py reads from full_report.json by default
python3 "$ROOT_PATH/pipeline/ai_triage_engine.py"

# 9. Sync with Dashboard
mkdir -p "$ROOT_PATH/dashboard/data"
cp "$MOCK_DATA_PATH/full_report_triaged.json" "$ROOT_PATH/dashboard/data/full_report_triaged.json"

if [ $? -eq 0 ]; then
    echo "[OK] Enterprise AegisFlow Engine completed successfully."
    echo "     Results are live on the AI Dashboard."
else
    echo "[!] Engine encountered an issue during analysis."
fi
