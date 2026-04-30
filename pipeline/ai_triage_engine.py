#!/usr/bin/env python3
"""
pipeline/ai_triage_engine.py
─────────────────────────────────────────────────────────────────────────────
Actionable triage engine for DevSecOps pipeline.
Prefers real AI for critical/high findings when GROQ_API_KEY is available,
but always falls back to a local remediation engine that produces concrete
guidance instead of placeholders.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).parent.resolve()
ROOT_DIR = SCRIPT_DIR.parent
MOCK_DIR = ROOT_DIR / "security-results"
REPORT_FILE = Path(os.environ.get("CONSOLIDATED_REPORT", MOCK_DIR / "full_report.json"))
OUTPUT_FILE = Path(os.environ.get("TRIAGED_REPORT", MOCK_DIR / "full_report_triaged.json"))

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = "llama-3.1-8b-instant"
SLA_HOURS = {"CRITICAL": 8, "HIGH": 24, "MEDIUM": 48, "LOW": 72}
PLACEHOLDER_PATTERNS = (
    "fixed code",
    "best practices",
    "replace with secure code",
    "placeholder",
    "example fix",
    "consult security documentation",
)

stats = {"True Positive": 0, "False Positive": 0, "Needs Review": 0, "error": 0}

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + RESET


def compute_sla_deadline(severity: str, now: datetime) -> str:
    hours = SLA_HOURS.get(severity, 168)
    return (now + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def short_env_name(finding: dict) -> str:
    title = f"{finding.get('title', '')} {finding.get('rule_id', '')}"
    snippet = finding.get("code_snippet", "")
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*[:=]", snippet)
    if match:
        return re.sub(r"[^A-Z0-9_]", "_", match.group(1).upper())
    if "private" in title.lower() and "key" in title.lower():
        return "PRIVATE_KEY"
    if "password" in title.lower():
        return "APP_PASSWORD"
    if "token" in title.lower():
        return "API_TOKEN"
    return "API_KEY"


def make_result(
    finding: dict,
    *,
    reasoning: str,
    impact: str,
    before: Optional[str] = None,
    after: str,
    explanation: str,
    classification: str = "True Positive",
    confidence: int = 90,
    priority_score: Optional[int] = None,
) -> dict:
    severity = (finding.get("severity") or "MEDIUM").upper()
    return {
        "classification": classification,
        "confidence": confidence,
        "reasoning": reasoning,
        "code_fix": {
            "before": before if before is not None else finding.get("code_snippet", ""),
            "after": after,
            "explanation": explanation,
        },
        "business_impact": impact,
        "priority_score": priority_score or {"CRITICAL": 9, "HIGH": 7, "MEDIUM": 5, "LOW": 2}.get(severity, 5),
    }


def remediate_secret(finding: dict) -> dict:
    title = finding.get("title", "").lower()
    file_path = str(finding.get("affected_file", ""))
    snippet = finding.get("code_snippet", "")
    env_name = short_env_name(finding)

    if "private key" in title or "begin rsa private key" in snippet.lower():
        return make_result(
            finding,
            reasoning="A private key committed to the repository is a confirmed credential exposure and should be treated as compromised immediately.",
            impact="Attackers can impersonate the service, decrypt traffic or sign malicious payloads with the leaked private key.",
            after=(
                "1. Remove the private key from source control and rotate the certificate/key pair immediately.\n"
                "2. Regenerate the key outside the repository and store it in a secret manager or mounted runtime secret.\n"
                "3. Update the application to read the key from a protected path or environment-backed secret at deploy time."
            ),
            explanation="Purge the key from git history, revoke the old certificate, issue a new keypair, and load it from a secret store or mounted secret volume.",
        )

    if file_path.endswith((".js", ".ts")):
        after = (
            f"module.exports = {{\n"
            f"  {env_name}: process.env.{env_name}\n"
            f"}};\n\n"
            f"// .env\n"
            f"{env_name}=<rotate-this-secret>"
        )
    elif file_path.endswith((".yml", ".yaml")):
        after = (
            "secrets:\n"
            f"  {env_name}:\n"
            f"    valueFrom: ${env_name}\n"
            "# Inject the secret from CI/CD or your secret manager instead of committing it to YAML."
        )
    else:
        after = (
            f"Remove the hardcoded secret and load it from runtime configuration such as the environment variable `{env_name}`.\n"
            f"Rotate the exposed credential before redeploying."
        )

    return make_result(
        finding,
        reasoning="This secret is hardcoded in a tracked file, so anyone with repo, image or artifact access can reuse it.",
        impact="Exposed credentials can be abused to access external services, impersonate the application or extract protected data.",
        after=after,
        explanation=f"Rotate the exposed credential, replace the literal value with `process.env.{env_name}` or your platform secret injection mechanism, and keep the runtime secret outside version control.",
    )


def remediate_sca(finding: dict) -> dict:
    pkg = finding.get("affected_package") or "the vulnerable dependency"
    cve = finding.get("rule_id") or finding.get("cve_cwe") or "the reported advisory"
    title = finding.get("title", "")
    remediation_hint = finding.get("remediation_hint") or ""
    current = finding.get("affected_version") or "<current-version>"
    suggested = f"{pkg}@latest"
    if "log4j" in title.lower():
        suggested = "log4j-core@2.17.0+"
    elif pkg == "lodash":
        suggested = "lodash@4.17.21"
    elif pkg == "axios":
        suggested = "axios@0.21.2+"

    manifest_guess = "package.json"
    after = (
        f"// {manifest_guess}\n"
        f"\"{pkg}\": \"{suggested}\"\n\n"
        f"# Then reinstall and verify the lockfile is updated:\n"
        f"npm install {pkg}@latest"
    )
    explanation = f"Upgrade {pkg} to a non-vulnerable release, regenerate the lockfile and rerun SCA to confirm {cve} is gone."
    if remediation_hint and remediation_hint not in explanation:
        explanation = f"{explanation} {remediation_hint}"

    return make_result(
        finding,
        reasoning=f"The finding maps to {cve} in {pkg}; dependency vulnerabilities remain exploitable until the vulnerable package version is replaced.",
        impact=f"Attackers may exploit {pkg} through the vulnerable code path described by {cve}, which can lead to denial of service, injection or data exposure depending on application usage.",
        before=f"\"{pkg}\": \"{current}\"",
        after=after,
        explanation=explanation,
    )


def remediate_iac(finding: dict) -> dict:
    rule_id = (finding.get("rule_id") or "").upper()
    title = finding.get("title", "").lower()

    if rule_id == "CKV_DOCKER_2" or "root user" in title:
        after = (
            "RUN addgroup -S app && adduser -S app -G app\n"
            "USER app"
        )
        explanation = "Create a non-root runtime user in the Dockerfile before the final CMD/ENTRYPOINT so container compromise does not immediately grant root privileges."
    elif rule_id == "CKV_DOCKER_7" or "healthcheck" in title:
        after = "HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:3000/health || exit 1"
        explanation = "Add a health check so the orchestrator can stop routing traffic to unhealthy containers."
    elif rule_id == "CKV_DOCKER_1" or "ssh" in title:
        after = "# Remove EXPOSE 22 and do not install or run SSH inside the container."
        explanation = "Containers should not expose SSH; use container exec mechanisms instead."
    elif ".github/workflows/" in str(finding.get("affected_file", "")):
        after = (
            "permissions:\n"
            "  contents: read\n"
            "  packages: read\n"
            "# Narrow token permissions and avoid broad write scopes in CI workflows."
        )
        explanation = "Restrict GitHub Actions token permissions to the minimum required for the workflow."
    else:
        after = finding.get("remediation_hint") or "Apply the configuration hardening recommended by the scanner and rerun policy checks."
        explanation = "Harden the infrastructure configuration at the source file and verify the scanner finding disappears on the next run."

    return make_result(
        finding,
        reasoning="Infrastructure misconfigurations are deterministic findings: the insecure Dockerfile or workflow setting remains in effect until the source configuration is changed.",
        impact="A misconfigured build or runtime environment can expand attack surface, hide failures or make container compromise far more damaging.",
        after=after,
        explanation=explanation,
    )


def remediate_exec_or_injection(finding: dict, snippet: str, language: str) -> dict:
    snippet_lower = snippet.lower()
    if "select " in snippet_lower or "insert " in snippet_lower or "sql" in finding.get("title", "").lower():
        if language == "php":
            after = (
                "$stmt = $db->prepare('SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = ?');\n"
                "$stmt->bind_param('i', $id);\n"
                "$stmt->execute();\n"
                "$result = $stmt->get_result();"
            )
        else:
            after = (
                "const query = 'SELECT * FROM users WHERE id = ?';\n"
                "db.query(query, [id], callback);"
            )
        explanation = "Replace string concatenation in SQL with parameterized queries and strict type validation on user-controlled values."
        impact = "SQL injection can expose, modify or delete application data and may also lead to authentication bypass."
    elif "exec" in snippet_lower or "system(" in snippet_lower or "ping -c 4" in snippet_lower:
        after = (
            "$target = filter_var($target, FILTER_VALIDATE_IP);\n"
            "if ($target === false) { throw new InvalidArgumentException('Invalid target'); }\n"
            "$process = proc_open(['ping', '-c', '4', $target], $descriptorspec, $pipes);"
        ) if language == "php" else (
            "const safe = net.isIP(target) ? target : null;\n"
            "if (!safe) throw new Error('Invalid target');\n"
            "spawn('ping', ['-c', '4', safe]);"
        )
        explanation = "Do not concatenate user input into shell commands; validate the value and pass arguments as a structured list to the process API."
        impact = "Command injection can lead to full remote code execution on the host running the application."
    elif "file_get_contents" in snippet_lower or "readfile" in snippet_lower:
        after = (
            "$safeBase = realpath(DVWA_WEB_PAGE_TO_ROOT);\n"
            "$candidate = realpath($safeBase . DIRECTORY_SEPARATOR . basename($readFile));\n"
            "if ($candidate === false || strpos($candidate, $safeBase) !== 0) { http_response_code(403); exit; }\n"
            "$instructions = file_get_contents($candidate);"
        )
        explanation = "Resolve the requested path against an allowlisted base directory and reject traversal attempts before opening the file."
        impact = "Path traversal lets attackers read arbitrary files such as secrets, configuration and source code."
    elif "access-control-allow-origin" in snippet_lower or "cors" in finding.get("rule_id", "").lower():
        after = 'header("Access-Control-Allow-Origin: https://trusted.example.com");'
        explanation = "Replace wildcard CORS with an explicit allowlist of trusted origins."
        impact = "Permissive CORS can expose authenticated responses to malicious origins."
    elif "phpinfo" in snippet_lower:
        after = "// Remove phpinfo() from production code or gate it behind authenticated admin-only diagnostics."
        explanation = "Do not expose verbose runtime diagnostics in production."
        impact = "Attackers can collect environment, extension and configuration details that improve exploitation."
    else:
        after = finding.get("remediation_hint") or "Refactor the vulnerable code path to validate untrusted input before it reaches the sensitive sink."
        explanation = "Apply targeted input validation and safer APIs at the exact sink reported by the scanner."
        impact = finding.get("business_impact") or "This pattern can expose the application to attacker-controlled input reaching a sensitive operation."

    return make_result(
        finding,
        reasoning="The reported code path connects untrusted input to a sensitive sink, so the finding remains actionable until the sink is protected.",
        impact=impact,
        after=after,
        explanation=explanation,
    )


def remediate_sast(finding: dict) -> dict:
    file_path = str(finding.get("affected_file", "")).lower()
    rule_id = (finding.get("rule_id") or "").lower()
    title = (finding.get("title") or "").lower()
    snippet = finding.get("code_snippet", "")
    language = "php" if file_path.endswith(".php") else "js"

    if any(token in rule_id for token in ("tainted-sql", "sqli", "sql-string")) or "sql" in title:
        return remediate_exec_or_injection(finding, snippet, language)
    if any(token in rule_id for token in ("tainted-exec", "exec-use", "command")) or "exec" in snippet.lower():
        return remediate_exec_or_injection(finding, snippet, language)
    if any(token in rule_id for token in ("tainted-filename", "path-traversal", "lfi")):
        return remediate_exec_or_injection(finding, snippet, language)
    if "cors" in rule_id or "phpinfo" in rule_id:
        return remediate_exec_or_injection(finding, snippet, language)

    return make_result(
        finding,
        reasoning="Static analysis found a concrete insecure pattern in application code at the reported file and line.",
        impact=finding.get("business_impact") or "The vulnerable code pattern can be exploited if reachable in production traffic.",
        after=finding.get("remediation_hint") or "Refactor the reported sink to use a safe API and validate attacker-controlled input.",
        explanation="Use the exact file and line in the finding to replace the insecure API or pattern with the safer variant recommended by the scanner.",
    )


def remediate_dast(finding: dict) -> dict:
    title = finding.get("title", "")
    return make_result(
        finding,
        reasoning=f"Dynamic scanning observed behavior consistent with {title}, so the issue should be validated in the corresponding route or controller and fixed at the server-side source.",
        impact=finding.get("business_impact") or "A live endpoint appears vulnerable and may be exploitable remotely.",
        after=finding.get("remediation_hint") or "Trace the affected URL to its handler, patch the vulnerable server-side logic and rerun DAST to confirm the endpoint no longer matches.",
        explanation="Use the affected URL from the DAST finding to identify the server-side code path, patch the root cause and verify with a rerun.",
    )


def local_triage(finding: dict) -> dict:
    scan_type = (finding.get("scan_type") or "").upper()
    if scan_type == "SECRET":
        return remediate_secret(finding)
    if scan_type == "SCA":
        return remediate_sca(finding)
    if scan_type == "IAC":
        return remediate_iac(finding)
    if scan_type == "SAST":
        return remediate_sast(finding)
    if scan_type == "DAST":
        return remediate_dast(finding)

    return make_result(
        finding,
        reasoning="The finding was triaged by the local remediation engine because no specialized handler matched its exact category.",
        impact=finding.get("business_impact") or "The finding may expose the application if left unresolved.",
        after=finding.get("remediation_hint") or "Review the affected component and implement the scanner-recommended fix.",
        explanation="Apply the source-level or configuration-level change at the affected location and verify the scanner no longer reports the issue.",
    )


def build_groq_prompt(finding: dict) -> str:
    return f"""
Analyze this security finding as a senior AppSec engineer.
Return valid JSON only with keys:
classification, confidence, reasoning, code_fix, business_impact, priority_score.

Rules:
- code_fix.after must be a concrete remediation, not a placeholder.
- Never use phrases like "fixed code", "best practices", "placeholder", "replace with secure code".
- If the finding is a secret in code/config, show a concrete environment-variable or secret-store based remediation.
- If the finding is SCA, name the package and a clear upgrade action.
- If the finding is IaC, output the exact Dockerfile/workflow/config hardening step.

Finding context:
scan_type: {finding.get('scan_type')}
source_tool: {finding.get('source_tool')}
rule_id: {finding.get('rule_id')}
cve_cwe: {finding.get('cve_cwe')}
title: {finding.get('title')}
severity: {finding.get('severity')}
file: {finding.get('affected_file')}
line: {finding.get('affected_line')}
existing_remediation_hint: {finding.get('remediation_hint')}
existing_business_impact: {finding.get('business_impact')}
code_snippet: {str(finding.get('code_snippet', ''))[:2000]}
""".strip()


def validate_ai_response(ai_resp: Optional[dict]) -> bool:
    if not ai_resp or not isinstance(ai_resp, dict):
        return False
    code_fix = ai_resp.get("code_fix")
    if not isinstance(code_fix, dict):
        return False
    required = [
        ai_resp.get("classification"),
        ai_resp.get("reasoning"),
        ai_resp.get("business_impact"),
        code_fix.get("after"),
        code_fix.get("explanation"),
    ]
    if any(not value for value in required):
        return False
    haystack = " ".join(str(value).lower() for value in required if isinstance(value, str))
    return not any(pattern in haystack for pattern in PLACEHOLDER_PATTERNS)


def call_groq_api(finding: dict) -> Optional[dict]:
    if not GROQ_API_KEY:
        return None

    data = json.dumps({
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": "You are a world-class AppSec triage assistant. Always respond in valid JSON."},
            {"role": "user", "content": build_groq_prompt(finding)},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }).encode("utf-8")

    for attempt in range(5):
        try:
            # Add a small delay between requests to respect rate limits
            time.sleep(1.2)

            req = urllib.request.Request(
                "https://api.groq.com/openai/v1/chat/completions",
                data=data,
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json",
                    "User-Agent": "AegisFlow-Triage/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=40) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                content = res_data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                return parsed if validate_ai_response(parsed) else None
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8") if exc.fp else ""
            if exc.code == 429:
                wait = (attempt + 1) * 7
                print(f"  [RATE LIMIT] Groq API rate limit reached. Waiting {wait}s...")
                time.sleep(wait)
            elif exc.code == 401:
                print(f"  [AI ERROR 401] Invalid Groq API Key. Please check your key in the dashboard.")
                break
            else:
                print(f"  [AI ERROR {exc.code}] {err_body[:200]}")
                break
        except Exception as exc:
            print(f"  [AI ERROR] Unexpected error: {exc}")
            break
    return None


def triage_finding(finding: dict, target_path: str, mode: str):
    now = datetime.now(timezone.utc)
    severity = (finding.get("severity") or "MEDIUM").upper()
    ai_resp = None
    ai_model = "local-rule-engine"

    if severity in {"CRITICAL", "HIGH"} and GROQ_API_KEY:
        print(f"  [AI REAL-TIME] Analyzing high-risk finding {finding.get('id')}...")
        ai_resp = call_groq_api(finding)
        if ai_resp:
            ai_model = f"groq:{GROQ_MODEL}"

    if not ai_resp:
        ai_resp = local_triage(finding)

    cls = ai_resp.get("classification", "Needs Review")
    finding["ai_analysis"] = f"[{cls}] {ai_resp.get('reasoning', '')}"
    finding["ai_fix"] = ai_resp.get("code_fix", {})
    finding["ai_confidence"] = ai_resp.get("confidence", 70)
    finding["ai_priority_score"] = ai_resp.get("priority_score", 5)
    finding["business_impact"] = ai_resp.get("business_impact", finding.get("business_impact", ""))
    finding["status"] = "AI_TRIAGED"
    finding["ai_model"] = ai_model
    finding["ai_analyzed_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    finding["sla_deadline"] = compute_sla_deadline(severity, now)

    stats[cls] = stats.get(cls, 0) + 1
    print(f"  [AI {ai_model}] {finding.get('id')} -> {cls}")


def main() -> None:
    start_time = time.time()
    print()
    print(c("═" * 64, BOLD))
    print(c("  AI Triage Engine  –  Security Finding Analysis", BOLD, CYAN))
    print(c("═" * 64, BOLD))
    print()

    if not REPORT_FILE.exists():
        print(c(f"  [ERROR] Not found: {REPORT_FILE}", RED), file=sys.stderr)
        sys.exit(1)

    try:
        report = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        print(c(f"  [ERROR] Failed to load report: {exc}", RED))
        sys.exit(1)

    findings = report.get("findings", [])
    if not findings:
        print(c("  [WARN] No findings to analyze.", YELLOW))
    else:
        print(f"  [PARALLEL] Analyzing {len(findings)} findings using 3 concurrent workers (Throttled Mode)...")
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(triage_finding, finding, ".", "REAL") for finding in findings]
            for future in futures:
                future.result()

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(report, indent=4), encoding="utf-8")

    elapsed = round(time.time() - start_time, 1)
    print()
    print(c("  " + "─" * 32, DIM))
    print(c("  Triage Summary", BOLD))
    print(c("  " + "─" * 32, DIM))
    for cls, count in stats.items():
        if count > 0 and cls != "error":
            color = RED if "True" in cls else (GREEN if "False" in cls else YELLOW)
            print(f"    {c(cls.ljust(15), color)}: {count} findings")
    print(f"\n  ✅ Analysis complete. Results saved to {OUTPUT_FILE.name}")
    print(f"  Duration: {elapsed}s")
    print(c("═" * 64, BOLD))
    print()


if __name__ == "__main__":
    main()
