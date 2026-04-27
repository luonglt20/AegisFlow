# User Guide

## 1. Objective

This project is a local security operations framework for the case study. It lets a reviewer run one Dockerized environment, select one application folder, and execute the same DevSecOps/AppSec pipeline end to end.

## 2. Prerequisites

- Docker
- Docker Compose
- Optional: `GROQ_API_KEY` for live AI triage

## 3. Startup

1. Optionally create `.env` from `.env.example`.
2. Run:

```bash
docker-compose up --build
```

3. Open:

```text
http://localhost:58081
```

## 4. How to Demo

1. Open the `Scanner Intelligence` tab.
2. Select or enter the target folder.
3. Provide the target URL if live DAST is desired.
4. Click `Launch Integrated Security Pipeline`.
5. Review:
   - Executive risk summary
   - Action Center findings
   - Pipeline and policy status
   - SBOM output
   - Audit log
   - Generated report artifacts in the repo root and `security-results`

## 5. CI/CD Design

The case study uses one pipeline for all Task 1-4 work:

- `build`: stack-aware validation for the selected app
- `test`: lightweight or real test execution depending on detected stack
- `security`: SAST, SCA, secrets, IaC, DAST, SBOM, AI triage, policy enforcement
- `report`: HTML/PDF report generation

Reference:

- [.gitlab-ci.yml](/Users/toilaluongg/Desktop/AegisFlow-main/.gitlab-ci.yml:1)
- [pipeline/run_pipeline.sh](/Users/toilaluongg/Desktop/AegisFlow-main/pipeline/run_pipeline.sh:1)

## 6. Mock / Fallback Disclosure

The assignment allows mocked behavior if explained clearly. This repo documents each fallback:

- `build` and `test`: for multi-target portability, some applications are validated structurally instead of fully built/tested in local mode.
- AI triage: real when Groq is configured; deterministic fallback when it is not.
- DAST: live against a reachable target URL; otherwise the workflow records predictive limitations.

Limits:

- Results from fallback stages are useful for demonstrating orchestration and governance, but they are not equivalent to a production-grade CI runner with app-specific dependency caching and test setup.

## 7. Repository Layout

- [/dashboard](/Users/toilaluongg/Desktop/AegisFlow-main/dashboard): dashboard UI
- [/pipeline](/Users/toilaluongg/Desktop/AegisFlow-main/pipeline): orchestration, scanners, triage, policy, reporting
- [/real-apps](/Users/toilaluongg/Desktop/AegisFlow-main/real-apps): sample targets
- [/security-results](/Users/toilaluongg/Desktop/AegisFlow-main/security-results): generated reports
- [DevSecOps_CaseStudy_Report.pdf](/Users/toilaluongg/Desktop/AegisFlow-main/DevSecOps_CaseStudy_Report.pdf): final submission PDF
