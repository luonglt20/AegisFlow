<p align="center">
  <img src="assets/hero-banner.png" alt="AegisFlow Hero" width="40%" style="border-radius: 12px;">
</p>

<h1 align="center">🛡️ AegisFlow</h1>
<p align="center">
  <strong>Autonomous Enterprise ASPM & AI-Powered DevSecOps Orchestrator</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Security-Semgrep-blueviolet?style=for-the-badge" alt="Semgrep">
  <img src="https://img.shields.io/badge/AI-Llama--3-orange?style=for-the-badge" alt="AI">
  <img src="https://img.shields.io/badge/UI-Glassmorphism-blue?style=for-the-badge" alt="UI">
  <img src="https://img.shields.io/badge/Platform-Docker-0db7ed?style=for-the-badge" alt="Docker">
</p>

---

## 🌟 Overview

**AegisFlow** is a next-generation **Application Security Posture Management (ASPM)** platform designed to simplify complex security workflows. It unifies high-fidelity scanning tools (SAST, SCA, DAST, Secrets, IaC) into a single, autonomous pipeline, visualized through a stunning premium dashboard.

Built for the modern security engineer, AegisFlow doesn't just find vulnerabilities—it uses **AI-driven triage** to classify findings and provide automated remediation guidance, reducing MTTR (Mean Time To Remediate) by up to 70%.

---

## ✨ Core Pillars

### 🚀 1. Autonomous Pipeline Orchestration
One-click execution of the industry's best-in-class security toolchain:
- **SAST**: `Semgrep` for deep semantic code analysis.
- **SCA**: `Trivy` for dependency and vulnerability detection.
- **Secrets**: `Gitleaks` for high-accuracy credential hunting.
- **IaC**: `Checkov` for infrastructure misconfiguration (K8s, Terraform, Docker).
- **DAST**: `Nuclei` for intelligent runtime vulnerability probing.

### 🧠 2. AI Triage Engine (Groq/Llama-3)
Eliminate manual triage fatigue. AegisFlow integrates an LLM-powered engine that:
- **Auto-Classifies**: Context-aware True Positive vs. False Positive detection.
- **Business Impact**: Evaluates risk based on application criticality.
- **AI Remediation**: Provides drop-in code fixes and hardening suggestions.

### 💎 3. Premium Glassmorphism Dashboard
A state-of-the-art UI experience designed for clarity and impact:
- **Real-time Telemetry**: Watch the pipeline work with interactive status animations.
- **Executive Overview**: KPI-driven insights for C-level reporting.
- **Security Scoring**: Instant health metrics based on vulnerability density and SLA.

---

## 🏗️ System Architecture

```mermaid
graph TD
    User((Security Analyst)) --> Dashboard[AegisFlow Dashboard]
    Dashboard --> Server[Python API Server]
    Server --> Orchestrator[Pipeline Engine]
    
    subgraph "Scanning Layer"
        Orchestrator --> SAST[Semgrep]
        Orchestrator --> SCA[Trivy]
        Orchestrator --> Secret[Gitleaks]
        Orchestrator --> DAST[Nuclei]
    end
    
    Orchestrator --> AI_Engine[AI Triage Hub]
    AI_Engine --> Data[(PostgreSQL / JSON)]
    Data --> Dashboard
    Data --> Reports[PDF/Excel Reports]
```

---

## 🚀 Quick Start (Production Mode)

Ensure you have **Docker Desktop** installed, then run:

```bash
# 1. Clone & Enter
git clone https://github.com/luonglt20/AegisFlow.git && cd AegisFlow

# 2. Launch (One Command)
./run_mac.sh
```

> **Note**: For AI-powered triage, add your `GROQ_API_KEY` to the `.env` file or input it directly in the Dashboard.

---

## 📂 Repository Layout

- `dashboard/`: Premium React-style Vanilla JS frontend & API layer.
- `pipeline/`: The "Brain" of the scanning and AI integration.
- `demo-targets/`: Curated vulnerable applications (NodeGoat, PyGoat, WebGoat).
- `docs/`: Technical threat models, API specs, and compliance mappings.
- `assets/`: Project visual identity and hero banners.

---

## 🛡️ Roadmap & Safety

- [x] Multi-language support (Java, Python, JS).
- [x] Real-time WebSocket-like UI polling.
- [x] AI-Powered Remediation Plans.
- [ ] **Coming Soon**: Multi-tenant RBAC support.
- [ ] **Coming Soon**: Jira & Slack Integration.

**Safety First**: AegisFlow is a powerful security tool. Only scan targets you are authorized to test.

---

<p align="center">
  Developed with ❤️ for the DevSecOps Community.<br>
  &copy; 2026 <strong>AegisFlow Enterprise</strong>
</p>
