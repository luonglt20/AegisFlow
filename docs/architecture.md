# AegisFlow System Architecture

## High-Level Overview
AegisFlow is divided into three main architectural pillars:
1. **The Orchestration Engine & Server** (`server.py`)
2. **The Pipeline & Scanning Logic** (`pipeline/`)
3. **The User Interface** (`dashboard/`)

These pillars communicate via JSON-based file synchronization within a shared Docker volume, ensuring decoupling between the backend heavy-lifting and the frontend rendering.

## Directory Structure
```text
AegisFlow/
├── dashboard/               # Frontend UI (HTML, CSS, JS)
│   ├── index.html           # Main UI View
│   ├── app.js               # UI Logic and API polling
│   └── data/                # Copied from security-results/ for UI rendering
├── docs/                    # Architecture and AI Context Documentation
├── pipeline/                # Core Python orchestration scripts
│   ├── run_pipeline.sh      # Master shell orchestrator
│   ├── scan_*.py            # Bridges to specific security tools
│   ├── report_generator.py  # Aggregates raw outputs to full_report.json
│   ├── ai_triage_engine.py  # Groq/LLaMA integration for smart triage
│   ├── policy_engine.py     # Enforcement logic (Pass/Fail)
│   └── audit_logger.py      # Immutable logging
├── security-results/        # Ephemeral directory for raw and processed JSONs
├── server.py                # Python HTTP Server acting as the API and Agent
├── docker-compose.yml       # Infrastructure definition
└── Dockerfile               # Execution environment containing all tools
```

## Component Details

### 1. The Server (`server.py`)
- Acts as a lightweight API gateway and static file server for the Dashboard.
- Receives HTTP POST requests on `/api/scan` containing the target directory and optional API keys.
- Spawns a background subprocess (`bash pipeline/run_pipeline.sh`) to execute the pipeline without blocking the UI.
- Periodically syncs files from `security-results/` to `dashboard/data/` so the frontend can poll for updates.

### 2. The Pipeline (`pipeline/`)
- **Execution Strategy:** A linear execution model initiated by `run_pipeline.sh`.
- **Bridges:** Python scripts (e.g., `scan_sast.py`) that wrap external CLI tools (Semgrep, Trivy, etc.). They handle tool execution, capture stdout/stderr, and format the output.
- **Data Normalization:** `report_generator.py` parses disparate formats (SARIF, checkov JSON, Trivy JSON) into a unified, normalized `full_report.json` schema.
- **AI Triage:** Enhances `full_report.json` by adding AI-generated reasoning, mitigation strategies, and code fixes, saving it as `full_report_triaged.json`.
- **Policy Engine:** Reads the triaged report and evaluates it against risk thresholds (e.g., CRITICAL > 0 blocks the build). Generates `policy_result.json`.

### 3. The Dashboard (`dashboard/`)
- A pure vanilla JavaScript, HTML, and CSS application.
- Uses long-polling (via `fetch`) to retrieve `status.json`, `full_report_triaged.json`, and `policy_result.json`.
- Dynamically updates UI components (Progress bars, Donut charts, Finding cards) based on the state of the JSON data.

## Data Flow
1. User clicks "Scan" in Dashboard → POST to `server.py`.
2. `server.py` initializes empty placeholder files in `security-results/` and launches `run_pipeline.sh`.
3. Dashboard begins polling `dashboard/data/status.json`.
4. `run_pipeline.sh` executes each scanner sequentially. Scanners write raw outputs to `security-results/`.
5. `report_generator.py` merges raw files into `full_report.json`.
6. `ai_triage_engine.py` enriches findings and creates `full_report_triaged.json`.
7. `policy_engine.py` evaluates the report and writes `policy_result.json`.
8. `server.py` copies all final JSONs to `dashboard/data/`.
9. Dashboard polls the updated data, rendering the final executive summary and detailed findings.
