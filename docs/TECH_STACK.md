# Technology Stack

## Runtime

- Python 3.11
- Bash
- Docker / Docker Compose
- Vanilla JavaScript dashboard

## Security Tooling

- SAST: Semgrep
- SCA: Trivy
- Secrets: Gitleaks
- IaC: Checkov
- DAST: Nuclei
- SBOM: Syft
- AI triage: Groq Llama when available, deterministic local fallback otherwise

## CI/CD Representation

- Local orchestration: [pipeline/run_pipeline.sh](/Users/toilaluongg/Desktop/AegisFlow-main/pipeline/run_pipeline.sh:1)
- CI/CD config artifact: [.gitlab-ci.yml](/Users/toilaluongg/Desktop/AegisFlow-main/.gitlab-ci.yml:1)

## Security Governance Components

- Report consolidation: [pipeline/report_generator.py](/Users/toilaluongg/Desktop/AegisFlow-main/pipeline/report_generator.py:1)
- Policy gate: [pipeline/policy_engine.py](/Users/toilaluongg/Desktop/AegisFlow-main/pipeline/policy_engine.py:1)
- Audit trail: [pipeline/audit_logger.py](/Users/toilaluongg/Desktop/AegisFlow-main/pipeline/audit_logger.py:1)
- Report generation: [pipeline/generate_report.py](/Users/toilaluongg/Desktop/AegisFlow-main/pipeline/generate_report.py:1)

## Design Note

This case study is intentionally built as a reusable framework instead of a single hard-coded demo. The dashboard controls one pipeline that can scan different local targets while preserving the same governance, reporting, and policy model.
