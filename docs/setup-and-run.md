# AegisFlow Setup & Execution

This document details how to configure and run AegisFlow. It is designed to run entirely locally using Docker, ensuring that no external SAAS dependencies (other than the optional LLM API) are required.

## 1. Environment Requirements
- **Docker & Docker Compose:** Required to run the AegisFlow core container and the target applications.
- **Environment Variables:**
  - `GROQ_API_KEY`: (Optional but recommended) Used to enable the AI Triage Engine. If absent, the system falls back to a local rules engine.
  - `SCAN_TARGET`: The path to the application you want to scan (e.g., `./real-apps/juice-shop`).
  - `TARGET_URL`: (Optional) The live URL for DAST scanning (e.g., `http://juice-shop:3000`).

## 2. Helper Script: `run_mac.sh`
For macOS users, a robust wrapper script is provided to manage the lifecycle of the application.

**Execution:**
```bash
# Standard run (defaults to Juice Shop)
bash run_mac.sh

# Run with custom target and Groq API key
export GROQ_API_KEY="your_key"
export SCAN_TARGET="./real-apps/my-app"
bash run_mac.sh
```

**What `run_mac.sh` does:**
1. Validates Docker daemon status.
2. Cleans up old dangling containers and volumes (`aegisflow-core`, `juice-shop`, etc.).
3. Exports the environment variables so `docker-compose.yml` can read them.
4. Executes `docker-compose up --build -d`.
5. Streams the logs of the `aegisflow-core` container to the terminal so you can monitor the internal Python server.

## 3. The Docker Compose Architecture
The `docker-compose.yml` spins up:
- **`aegisflow` service:** Built from `Dockerfile`. It contains Python 3.11, Node.js, Go, and all security CLI tools (Semgrep, Trivy, Checkov, Nuclei). It mounts the local directory `./` to `/app` inside the container, allowing live code reloading and outputting reports back to the host filesystem. It exposes port `58081` for the Dashboard.
- **Target Application services (e.g., `juice-shop`):** Spins up the vulnerable target application on the same bridge network (`aegis-net`) so that Nuclei DAST scans can reach it via internal Docker DNS.

## 4. Viewing the Dashboard
Once the container is running:
1. Open your browser to `http://localhost:58081` (The Dashboard UI).
2. Click the "INITIATE PIPELINE SCAN" button.
3. This sends an API request to `server.py`, which kicks off `pipeline/run_pipeline.sh`.
4. Watch the UI automatically update as the pipeline completes its 13 stages.
