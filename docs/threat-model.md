# AegisFlow Threat Modeling

This document covers two critical aspects of threat modeling within the AegisFlow ecosystem: the security of the pipeline itself, and the threat modeling of the target application.

## 1. Security of the Pipeline (Pipeline Threat Model)
The CI/CD pipeline is a high-value target. If compromised, attackers can deploy malicious code or steal production secrets.

### Identified Threats & Mitigations
| Threat Category | Specific Risk | Impact | Mitigation in AegisFlow |
| :--- | :--- | :--- | :--- |
| **Secrets Leakage** | Hardcoded API keys (e.g., `GROQ_API_KEY`) accidentally logged to console or stored in artifacts. | Attacker steals AI service quota or gains access to external production services. | The `server.py` masks the key length and passes it securely via environment variables (`env["GROQ_API_KEY"]`), never echoing the literal value in logs. Gitleaks scans the repo to catch accidental commits. |
| **Compromised CI Runner** | An attacker gains RCE on the Docker container running the pipeline via a malicious `build` script. | Attacker can alter security scan results, forcing a "PASSED" state for vulnerable code. | The pipeline runs in isolated, ephemeral Docker containers (`docker-compose`). We enforce an Immutable Audit Log (`audit_logger.py`) with SHA-256 hashes for every run, ensuring results cannot be silently tampered with post-execution. |
| **Supply Chain Attack** | A compromised scanner dependency (e.g., a malicious NPM package used by the app) executes during the build phase. | Backdoors injected into the final application artifact. | `scan_sca.py` (Trivy) and `scan_sbom.py` (Syft) run *before* deployment to identify vulnerable or malicious dependencies. |

## 2. Secure-by-Design & App Threat Modeling
For the target applications (e.g., Web App + API + DB), AegisFlow maps findings back to secure design principles.

### Example Threats for a Web API
1. **Threat (Spoofing/Elevation of Privilege):** Attacker modifies JWT tokens or abuses Broken Access Control (BOLA/IDOR) to access other users' data.
   - *Design Control:* Implement strict Server-Side Session Validation and Role-Based Access Control (RBAC).
   - *Pipeline Check:* Semgrep SAST rules flag missing authorization checks on API routes.
2. **Threat (Tampering/Injection):** Attacker sends malicious payloads (SQLi, NoSQLi) via API parameters.
   - *Design Control:* Use ORMs/Parameterized Queries and strict input validation schemas (e.g., Zod, Joi).
   - *Pipeline Check:* DAST (Nuclei) actively fuzzes API endpoints to detect SQLi responses.
3. **Threat (Information Disclosure):** Sensitive PII is leaked via verbose error messages or insecure direct object references.
   - *Design Control:* Implement global error handlers that strip stack traces in production.
   - *Pipeline Check:* SAST rules flag the use of `console.log(error)` or returning raw error objects in HTTP responses.
