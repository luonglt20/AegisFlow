import sys
import json
import uuid
import datetime
import os

def aggregate():
    if len(sys.argv) < 8:
        print("Usage: aggregate_scanners.py <app_name> <trivy_out> <gl_out> <semgrep_out> <checkov_out> <nuclei_out> <final_out>")
        sys.exit(1)

    app_name = sys.argv[1]
    trivy_path = sys.argv[2]
    gl_path = sys.argv[3]
    semgrep_path = sys.argv[4]
    checkov_path = sys.argv[5]
    nuclei_path = sys.argv[6]
    final_path = sys.argv[7]

    findings = []

    # Read Trivy
    if os.path.exists(trivy_path):
        try:
            with open(trivy_path, 'r', encoding='utf-8') as f:
                trivy_data = json.load(f)

            for res in trivy_data.get('Results', []):
                for vuln in res.get('Vulnerabilities', []):
                    sev = vuln.get('Severity', 'LOW')
                    if sev == "UNKNOWN": sev = "LOW"
                    cvss = vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 0.0)

                    obj = {
                        "id": f"TRIVY-{vuln.get('VulnerabilityID')}",
                        "source_tool": "Trivy",
                        "scan_type": "SCA",
                        "rule_id": vuln.get('VulnerabilityID'),
                        "title": vuln.get('Title', vuln.get('VulnerabilityID', '')),
                        "severity": sev,
                        "cvss_v3": cvss,
                        "affected_package": f"{vuln.get('PkgName')} ({vuln.get('InstalledVersion')})",
                        "business_impact": vuln.get('Description'),
                        "owasp_2025": "A03:2025 – Software Supply Chain Failures",
                        "status": "PENDING_TRIAGE"
                    }
                    findings.append(obj)
        except Exception as e: print(f"Trivy Error: {e}")

    # Read Gitleaks
    if os.path.exists(gl_path):
        try:
            with open(gl_path, 'r', encoding='utf-8') as f:
                gl_data = json.load(f)
                for rule in gl_data:
                    obj = {
                        "id": f"GL-{rule.get('RuleID')}-{str(uuid.uuid4())[:5]}",
                        "source_tool": "Gitleaks",
                        "scan_type": "SECRET",
                        "rule_id": rule.get('RuleID'),
                        "title": f"Hardcoded Secret: {rule.get('RuleID')}",
                        "severity": "CRITICAL",
                        "affected_file": rule.get('File'),
                        "affected_line": rule.get('StartLine'),
                        "owasp_2025": "A07:2025 – Identification and Authentication Failures",
                        "status": "PENDING_TRIAGE"
                    }
                    findings.append(obj)
        except Exception as e: print(f"Gitleaks Error: {e}")

    # Read Semgrep
    if os.path.exists(semgrep_path):
        try:
            with open(semgrep_path, 'r', encoding='utf-8') as f:
                semgrep_data = json.load(f)
                for res in semgrep_data.get('results', []):
                    obj = {
                        "id": f"SEMGREP-{str(uuid.uuid4())[:6]}",
                        "source_tool": "Semgrep",
                        "scan_type": "SAST",
                        "title": f"Code Flaw: {res.get('check_id').split('.')[-1]}",
                        "severity": "HIGH",
                        "affected_file": res.get('path'),
                        "affected_line": res.get('start', {}).get('line', 0),
                        "owasp_2025": "A03:2025 – Injection",
                        "status": "PENDING_TRIAGE"
                    }
                    findings.append(obj)
        except Exception as e: print(f"Semgrep Error: {e}")

    # Read Checkov
    if os.path.exists(checkov_path):
        try:
            with open(checkov_path, 'r', encoding='utf-8') as f:
                checkov_data = json.load(f)
                if not isinstance(checkov_data, list): checkov_data = [checkov_data]
                for run in checkov_data:
                    for check in run.get('results', {}).get('failed_checks', []):
                        obj = {
                            "id": f"CHECKOV-{check.get('check_id')}",
                            "source_tool": "Checkov",
                            "scan_type": "IaC",
                            "title": check.get('check_name'),
                            "severity": "HIGH",
                            "affected_file": check.get('file_path'),
                            "owasp_2025": "A01:2025 – Broken Access Control",
                            "status": "PENDING_TRIAGE"
                        }
                        findings.append(obj)
        except Exception as e: print(f"Checkov Error: {e}")

    # Read Nuclei (DAST)
    if os.path.exists(nuclei_path):
        try:
            with open(nuclei_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip(): continue
                    vuln = json.loads(line)
                    obj = {
                        "id": f"NUCLEI-{vuln.get('template-id')}-{str(uuid.uuid4())[:4]}",
                        "source_tool": "Nuclei",
                        "scan_type": "DAST",
                        "rule_id": vuln.get('template-id'),
                        "title": vuln.get('info', {}).get('name', 'DAST Finding'),
                        "severity": vuln.get('info', {}).get('severity', 'MEDIUM').upper(),
                        "affected_url": vuln.get('matched-at', 'N/A'),
                        "dast_request": vuln.get('request', 'N/A'), # [NEW] Capture Request
                        "dast_response": vuln.get('response', 'N/A'), # [NEW] Capture Response
                        "matcher_name": vuln.get('matcher-name', 'N/A'),
                        "business_impact": vuln.get('info', {}).get('description', ''),
                        "owasp_2025": "A01:2025 – Broken Access Control",
                        "status": "PENDING_TRIAGE"
                    }
                    findings.append(obj)
        except Exception as e: print(f"Nuclei Error: {e}")

    # Smart impact mapping for defaults
    for f in findings:
        title = f.get('title', '').lower()
        if 'sql' in title: f['business_impact'] = "Potential full database compromise and unauthorized data access."
        elif 'secret' in title or 'key' in title: f['business_impact'] = "Exposure of sensitive credentials allowing lateral movement."
        elif 'xss' in title: f['business_impact'] = "Client-side attack allowing session hijacking or defacement."
        elif 'dependency' in title or 'cve' in title: f['business_impact'] = "Use of vulnerable library potentially exposing known exploits."
        elif 'nuclei' in f.get('id',''): f['business_impact'] = "Dynamic endpoint vulnerability detected in runtime environment."
        else: f['business_impact'] = "Security risk exposing application logic or sensitive resources."

    # Calculate real score (Max 100, each Critical -10, High -5, Medium -2, Low -1)
    base_score = 100
    for f in findings:
        s = f.get('severity', 'LOW')
        if s == 'CRITICAL': base_score -= 10
        elif s == 'HIGH':   base_score -= 5
        elif s == 'MEDIUM': base_score -= 2
        else:               base_score -= 1

    score = max(0, base_score)
    grade = "F"
    if score > 90: grade = "A"
    elif score > 80: grade = "B"
    elif score > 70: grade = "C"
    elif score > 50: grade = "D"

    pipeline_id = "real-scan-" + str(uuid.uuid4())[:8]

    report = {
        "scan_metadata": {
            "app_name": app_name,
            "version": "2.0 - Live Penta-Core Scan",
            "pipeline_id": pipeline_id,
            "score": score,
            "grade": grade,
            "status": "COMPLETED"
        },
        "findings": findings
    }

    with open(final_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4)
    print(f"    {len(findings)} findings extracted and triaged (including DAST).")

if __name__ == "__main__":
    aggregate()
