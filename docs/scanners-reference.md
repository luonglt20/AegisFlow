# AegisFlow Security Scanners Reference

This document is the definitive reference for every security tool integrated into AegisFlow. For each scanner, it details what it does, its raw output format, how AegisFlow parses it, and which OWASP/CWE categories it covers.

---

## 1. Semgrep (SAST — Static Analysis)

| Property | Value |
|:---|:---|
| **Type** | Static Application Security Testing (SAST) |
| **Binary** | `semgrep` |
| **Bridge Script** | `pipeline/scan_sast.py` |
| **Parser** | `report_generator.parse_sarif()` |
| **Raw Output** | `security-results/sast_results.json` (SARIF 2.1.0 format) |
| **Target** | Source code files in `SCAN_TARGET` directory |
| **Ruleset** | `p/default` (auto-mode, uses recommended community rules) |
| **Finds** | SQL Injection, XSS, Path Traversal, Hardcoded Secrets, Command Injection |
| **OWASP Top 10** | A01, A02, A03, A05, A07 |
| **Key CWEs** | CWE-89, CWE-79, CWE-22, CWE-798 |
| **Output Format Note** | SARIF: findings live in `runs[0].results[]`, rules in `runs[0].tool.driver.rules[]` |
| **Fallback** | If binary not found, runs in "Simulation Mode" and writes a synthetic SARIF |

---

## 2. Trivy (SCA — Dependency Scanning)

| Property | Value |
|:---|:---|
| **Type** | Software Composition Analysis (SCA) |
| **Binary** | `trivy` |
| **Bridge Script** | `pipeline/scan_sca.py` |
| **Parser** | `report_generator.parse_trivy()` |
| **Raw Output** | `security-results/sca_results.json` (Trivy JSON format) |
| **Target** | `SCAN_TARGET/package.json`, `requirements.txt`, `pom.xml` etc. |
| **Finds** | Known CVEs in open-source dependencies (npm, pip, maven, cargo) |
| **OWASP Top 10** | A06 (Vulnerable and Outdated Components) |
| **Key Fields** | `Results[].Vulnerabilities[].VulnerabilityID`, `.Severity`, `.CVSS.nvd.V3Score` |
| **Fallback** | Generates synthetic findings for CVEs known to be present in common stacks |

---

## 3. Gitleaks (Secret Scanning)

| Property | Value |
|:---|:---|
| **Type** | Secret / Credential Detection |
| **Binary** | `gitleaks` |
| **Bridge Script** | `pipeline/scan_secret.py` |
| **Parser** | `report_generator.parse_gitleaks()` |
| **Raw Output** | `security-results/secret_results.json` (Gitleaks JSON array) |
| **Target** | Full git repository history of `SCAN_TARGET` |
| **Finds** | API Keys, Tokens, Passwords, Private Keys hardcoded in code or history |
| **OWASP Top 10** | A07 (Identification and Authentication Failures) |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) |
| **Key Fields** | Each item in array: `.RuleID`, `.Description`, `.File`, `.StartLine`, `.Match` |
| **Default Severity** | Always `CRITICAL` — hardcoded credentials have no acceptable "low" threshold |

---

## 4. Checkov (IaC — Infrastructure as Code)

| Property | Value |
|:---|:---|
| **Type** | Infrastructure as Code (IaC) Scanning |
| **Binary** | `checkov` (Python package) |
| **Bridge Script** | `pipeline/scan_iac.py` |
| **Parser** | `report_generator.parse_checkov()` |
| **Raw Output** | `security-results/iac_results.json` (Checkov JSON) |
| **Target** | `Dockerfile`, `docker-compose.yml`, `.tf`, `k8s/*.yaml` in `SCAN_TARGET` |
| **Finds** | Running as root, missing HEALTHCHECK, exposed SSH, overly permissive IAM roles |
| **OWASP Top 10** | A05 (Security Misconfiguration) |
| **Key CWEs** | CWE-250 (Execution with Unnecessary Privileges), CWE-778 (Insufficient Logging) |
| **Key Fields** | `results.failed_checks[].check_id`, `.check_name`, `.file_path`, `.code_block` |

---

## 5. Nuclei (DAST — Dynamic Analysis)

| Property | Value |
|:---|:---|
| **Type** | Dynamic Application Security Testing (DAST) |
| **Binary** | `nuclei` (Go binary) |
| **Bridge Script** | `pipeline/scan_dast.py` |
| **Parser** | `report_generator.parse_nuclei()` |
| **Raw Output** | `security-results/dast_results.jsonl` (Newline-delimited JSON) |
| **Target** | `TARGET_URL` (live running application, e.g., `http://juice-shop:3000`) |
| **Finds** | XSS, SQLi, SSRF, misconfigurations, exposed admin panels, CVE exploits |
| **OWASP Top 10** | A01, A03, A05, A10 |
| **Network** | Requires `TARGET_URL` to be reachable from the `aegis-net` Docker bridge network |
| **Fallback** | If no `TARGET_URL` is set or target unreachable, DAST stage is skipped gracefully |
| **Key Fields** | Per JSON line: `.template-id`, `.info.name`, `.info.severity`, `.matched-at` |

---

## 6. Syft (SBOM Generation)

| Property | Value |
|:---|:---|
| **Type** | Software Bill of Materials (SBOM) |
| **Binary** | `syft` (or `cyclonedx-npm` for Node.js) |
| **Bridge Script** | `pipeline/scan_sbom.py` |
| **Parser** | Not parsed into findings — SBOM is stored separately |
| **Raw Output** | `security-results/sbom.json` (CycloneDX 1.4 format) |
| **Target** | `SCAN_TARGET` directory |
| **Purpose** | Creates a complete inventory of all dependencies, their licenses, and versions |
| **Key Fields** | `components[]`: each entry has `.name`, `.version`, `.type`, `.purl` |
| **Dashboard** | Displayed in the "SBOM" tab showing a summary of component count and sample components |

---

## Summary Matrix

| Tool | Scan Type | Output Format | Requires Network | Fallback |
|:---|:---|:---|:---|:---|
| Semgrep | SAST | SARIF (JSON) | No | Yes (Simulation) |
| Trivy | SCA | Trivy JSON | No | Yes (Synthetic) |
| Gitleaks | Secret | JSON Array | No | Yes (Simulation) |
| Checkov | IaC | Checkov JSON | No | Yes (Simulation) |
| Nuclei | DAST | JSONL | **Yes** | Yes (Skip gracefully) |
| Syft | SBOM | CycloneDX JSON | No | Yes (package.json parse) |
