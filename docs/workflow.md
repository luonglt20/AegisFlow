# AegisFlow Execution Workflow

This document outlines the step-by-step process of an AegisFlow scan, executed primarily by `pipeline/run_pipeline.sh`.

## Pre-Flight & Initialization
When a scan is triggered via the Dashboard, `server.py` sets up the environment:
- `SCAN_TARGET`: The path to the application being scanned (e.g., `./real-apps/JuiceShop`).
- `GROQ_API_KEY`: Extracted from the UI for AI Triage.
- Wipes the `security-results/` directory to ensure a clean state.
- Initializes a `status.json` indicating the pipeline has started.

## The 13-Step Pipeline (`run_pipeline.sh`)

1. **Build Validation Stage (`build_target.py`)**
   - Detects the project type (Node.js, Python, Java) and simulates a lightweight local build step. Fails if `STRICT_CI` is enabled and no build script exists.
2. **Test Validation Stage (`test_target.py`)**
   - Executes available test suites (e.g., `npm test`).
3. **SAST Scanning (`scan_sast.py`)**
   - Runs Semgrep on the `SCAN_TARGET` to detect static vulnerabilities in code. Outputs SARIF format.
4. **SCA Scanning (`scan_sca.py`)**
   - Runs Trivy on the `SCAN_TARGET` filesystem to detect vulnerable dependencies. Outputs JSON.
5. **SBOM Generation (`scan_sbom.py`)**
   - Uses Syft (or cyclonedx-npm) to generate a CycloneDX SBOM (Software Bill of Materials) tracking all project dependencies.
6. **Secret Scanning (`scan_secret.py`)**
   - Runs Gitleaks to detect hardcoded credentials, API keys, and tokens.
7. **IaC Scanning (`scan_iac.py`)**
   - Runs Checkov to analyze Dockerfiles, Kubernetes manifests, and Terraform files for misconfigurations.
8. **DAST Scanning (`scan_dast.py`)**
   - Runs Nuclei against a live target URL (if available) to detect runtime vulnerabilities like XSS, SQLi, and SSRF.
9. **Consolidating Security Reports (`report_generator.py`)**
   - The normalization engine. It ingests the disparate outputs from Steps 3-8 and normalizes them into a unified `full_report.json` using a consistent schema (Severity, CWE, MITRE mapping, CVSS).
10. **Generating AI Triage & Analysis (`ai_triage_engine.py`)**
    - Parses `full_report.json`. If `GROQ_API_KEY` is present, it makes parallel API calls to Groq LLaMA to provide expert analysis and concrete code fixes for CRITICAL and HIGH findings. If API fails (e.g. rate limits), it falls back to a deterministic local rule engine. Outputs `full_report_triaged.json`.
11. **Evaluating Security Policy Gate (`policy_engine.py`)**
    - The Governance layer. It evaluates `full_report_triaged.json` against enterprise rules:
      - `CRITICAL > 0` → **BLOCKED**
      - `HIGH >= 2` → **BLOCKED**
      - Otherwise → **PASSED / WARNING**
    - Outputs `policy_result.json` containing the pass/fail decision and compliance mapping.
12. **Audit Logging & Traceability (`audit_logger.py`)**
    - Generates an immutable, cryptographically hashed JSON log entry documenting the pipeline run, actor, timestamp, and summary.
13. **Generating HTML/PDF Case Study (`generate_report.py`)**
    - Compiles a static HTML/PDF professional case study report representing the scan results, useful for compliance evidence and external sharing.

## Post-Execution
- `server.py` detects the pipeline exit code.
- Copies the final results to `dashboard/data/` for the UI to consume.
- Updates `status.json` with `is_scanning: false`.
- The Dashboard UI updates, displaying the final Executive Summary and interactive Findings List.
