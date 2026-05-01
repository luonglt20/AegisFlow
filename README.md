# AegisFlow

AegisFlow is a local DevSecOps/AppSec framework built for the case-study submission. It uses one repository, one Docker-based environment, one pipeline, and one dashboard to orchestrate security scanning across a selected target folder.

The operator workflow is intentionally simple:
1. Start the stack with Docker Compose.
2. Open the dashboard at `http://localhost:58081`.
3. Choose the application folder to scan.
4. Click `Scan`.
5. Review findings, policy decisions, remediation guidance, SBOM data, and audit logs in the dashboard and generated report artifacts.

## Submission Mapping

This repository is structured to satisfy the mandatory submission package:

- `docker-compose.yml`: local runtime for the dashboard, pipeline controller, and demo target app.
- `DevSecOps_CaseStudy_Report.pdf`: single PDF report used for scoring.
- Supporting project files: pipeline scripts, dashboard, report generator, sample targets, and reports.

## Tasks Covered

This repo covers Task 1, Task 2, Task 3, Task 4, and Task 5.

- Task 1: CI/CD pipeline with explicit `build`, `test`, `security`, and `report` stages in [.gitlab-ci.yml](/Users/toilaluongg/Desktop/AegisFlow-main/.gitlab-ci.yml:1), [.circleci/config.yml](/Users/toilaluongg/Desktop/AegisFlow-main/.circleci/config.yml:1), and [.github/workflows/ci.yml](/Users/toilaluongg/Desktop/AegisFlow-main/.github/workflows/ci.yml:1).
- Task 2: SCA, IaC, container-oriented security, secrets scanning, and SBOM generation.
- Task 3: policy enforcement, dashboard reporting, SLA handling, exception workflow, and auditability.
- Task 4: pipeline security analysis and mitigations, including secret handling, least privilege, and supply-chain guardrails.
- Task 5: secure-by-design threat modeling for a separate payment-service system described in the report.

## Real Tools vs Fallback Logic

- SAST: `semgrep`
- SCA and image/dependency scan: `trivy`
- Secrets: `gitleaks`
- IaC: `checkov`
- DAST: `nuclei`
- SBOM: `syft`
- AI Triage: `Groq (Llama-3.3)` with deep context analysis.

## Key Features & Enhancements

- **Dynamic Security Score**: Real-time numerical risk assessment (0-100) based on vulnerability density and severity.
- **Enterprise Report Center**: Automated, professional security assessment preview with executive summary and top risk analysis.
- **AI-Powered Contextual Triage**: Eliminates false positives by analyzing code context surrounding detected vulnerabilities.
- **Glassmorphism Dashboard**: A modern, high-contrast "Single Pane of Glass" for CISO-level visibility.

For portability, some stages support controlled fallback behavior:

- `build` and `test` stages use lightweight validation when a selected target does not expose a portable build/test command.
- AI triage uses Groq when `GROQ_API_KEY` is provided; otherwise it falls back to deterministic local reasoning templates.
- DAST runs against a live URL when `TARGET_URL` is reachable; if no live target is provided, the framework documents predictive mode in the report.

These fallbacks are deliberate and are explained in the PDF report along with their limits.

## Quick Start

1. Optionally copy `.env.example` to `.env`.
2. Optionally add `GROQ_API_KEY` for live AI triage.
3. Start the stack:

```bash
docker-compose up --build
```

4. Open `http://localhost:58081`.

## Useful Commands

```bash
make up
make pipeline
make down
```

## CircleCI

This repository also includes a CircleCI pipeline in [.circleci/config.yml](/Users/toilaluongg/Desktop/AegisFlow-main/.circleci/config.yml:1).

- `build`: runs `pipeline/build_target.py`
- `test`: runs `pipeline/test_target.py`
- `security`: installs scanners and runs `pipeline/run_pipeline.sh`
- `report`: refreshes `DevSecOps_CaseStudy_Report.html`
- `policy_gate`: fails the workflow when the security policy blocks the target

The default CircleCI target is `real-apps/NodeGoat`, matching the sample report artifacts already checked into the repository.

## GitHub Actions

This repository also includes a GitHub Actions workflow in [.github/workflows/ci.yml](/Users/toilaluongg/Desktop/AegisFlow-main/.github/workflows/ci.yml:1).

- `build`: runs `pipeline/build_target.py`
- `test`: runs `pipeline/test_target.py`
- `security`: installs scanners and runs `pipeline/run_pipeline.sh`
- `report`: refreshes `DevSecOps_CaseStudy_Report.html`
- `policy_gate`: fails the workflow when the security policy blocks the target

The workflow runs on `push`, `pull_request`, and `workflow_dispatch`, and uses `real-apps/NodeGoat` as the default CI target so the generated artifacts stay aligned with the sample case-study report.

## Important Artifacts

- Dashboard: [/dashboard](/Users/toilaluongg/Desktop/AegisFlow-main/dashboard)
- Pipeline scripts: [/pipeline](/Users/toilaluongg/Desktop/AegisFlow-main/pipeline)
- Security output: [/security-results](/Users/toilaluongg/Desktop/AegisFlow-main/security-results)
- PDF report: [DevSecOps_CaseStudy_Report.pdf](/Users/toilaluongg/Desktop/AegisFlow-main/DevSecOps_CaseStudy_Report.pdf)

## Public Repo Safety

Before publishing, this repo is designed to avoid committing live secrets:

- `docker-compose.yml` reads runtime values from `.env`.
- `.env` is ignored by git.
- `.env.example` documents required variables.
