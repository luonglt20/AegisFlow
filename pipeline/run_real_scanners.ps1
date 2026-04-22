param (
    [string]$TargetFolder = "vulnerable-app"
)

$ErrorActionPreference = "Stop"

# 1. Setup paths
$RootPath = (Get-Item .).FullName
$MockDataPath = Join-Path $RootPath "mock-data"
$BinPath = Join-Path $RootPath "pipeline\.bin"
If (!(Test-Path $BinPath)) { New-Item -ItemType Directory -Path $BinPath | Out-Null }

$TargetFullPath = Join-Path $RootPath $TargetFolder

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AegisFlow - Real Security Scanner Engine" -ForegroundColor Cyan
Write-Host " Target: $TargetFullPath" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 2. Download Trivy
$TrivyExe = Join-Path $BinPath "trivy.exe"
If (!(Test-Path $TrivyExe)) {
    Write-Host "[+] Downloading Trivy scanner (Aqua Security)..."
    # Trivy Windows zip
    $TrivyZip = Join-Path $BinPath "trivy.zip"
    Invoke-WebRequest -Uri "https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_windows-64bit.zip" -OutFile $TrivyZip
    Expand-Archive -Path $TrivyZip -DestinationPath $BinPath -Force
}

# 3. Download Gitleaks
$GitleaksExe = Join-Path $BinPath "gitleaks.exe"
If (!(Test-Path $GitleaksExe)) {
    Write-Host "[+] Downloading Gitleaks scanner..."
    $GitleaksZip = Join-Path $BinPath "gitleaks.zip"
    Invoke-WebRequest -Uri "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_windows_x64.zip" -OutFile $GitleaksZip
    Expand-Archive -Path $GitleaksZip -DestinationPath $BinPath -Force
}

# 4. Execute Trivy
Write-Host "[*] Executing Trivy SCA & Misconfig..." -ForegroundColor Yellow
$TrivyOutput = Join-Path $BinPath "trivy_out.json"
& $TrivyExe fs $TargetFullPath --scanners vuln,misconfig --format json --output $TrivyOutput

# 5. Execute Gitleaks
Write-Host "[*] Executing Gitleaks Secret Scanning..." -ForegroundColor Yellow
$GitleaksOutput = Join-Path $BinPath "gitleaks_out.json"
try {
    & $GitleaksExe detect --source $TargetFullPath --report-path $GitleaksOutput --report-format json --no-git *>$null
} catch {}

# 6. Install & Execute Semgrep (SAST)
Write-Host "[*] Ensuring Semgrep (SAST) is installed via pip..." -ForegroundColor Yellow
python -m pip install semgrep -q --disable-pip-version-check
$SemgrepOutput = Join-Path $BinPath "semgrep_out.json"
Write-Host "[*] Executing Semgrep SAST..." -ForegroundColor Yellow
# Ignoring exit code natively is slightly tricky in ps1, so we invoke via bash/cmd or suppress error
try {
    cmd /c "semgrep scan --config=auto --json -o `"$SemgrepOutput`" `"$TargetFullPath`" >nul 2>&1"
} catch {}

# 7. Install & Execute Checkov (IaC)
Write-Host "[*] Ensuring Checkov (IaC) is installed via pip..." -ForegroundColor Yellow
python -m pip install checkov -q --disable-pip-version-check
$CheckovOutput = Join-Path $BinPath "checkov_out.json"
Write-Host "[*] Executing Checkov IaC Configuration Scan..." -ForegroundColor Yellow
try {
    cmd /c "checkov -d `"$TargetFullPath`" -o json > `"$CheckovOutput`" 2>nul"
} catch {}

# 8. Parse and Aggregate Data via Python Proxy
Write-Host "[*] Aggregating results into AegisFlow format..." -ForegroundColor Yellow
$FinalReportPath = Join-Path $MockDataPath "full_report_triaged.json"
python "$RootPath\pipeline\aggregate_scanners.py" "$TargetFolder" "$TrivyOutput" "$GitleaksOutput" "$SemgrepOutput" "$CheckovOutput" "$FinalReportPath"

# 9. Trigger Autonomous AI Triage
Write-Host "[*] Waking up Llama-3 AI Triage Engine..." -ForegroundColor Magenta
python "$RootPath\pipeline\ai_triage_engine.py"

Write-Host "[OK] Quad-Core AegisFlow Engine completed successfully." -ForegroundColor Green
Write-Host "     Results are live on the AI Dashboard."
