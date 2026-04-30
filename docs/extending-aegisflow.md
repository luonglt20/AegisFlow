# Extending AegisFlow (Adding New Scanners)

AegisFlow is designed to be highly extensible. If you want to add a new security tool (e.g., SonarQube, Snyk, Bandit), follow this standard 3-step process.

## Step 1: Add the CLI Tool to the Dockerfile
AegisFlow runs all scanners locally within the `aegisflow` container.
Modify the `Dockerfile` to install the binary:
```dockerfile
# Example: Adding Bandit (Python SAST)
RUN pip install --no-cache-dir bandit
```

## Step 2: Create a Bridge Script
Create a new file in the `pipeline/` directory, e.g., `pipeline/scan_bandit.py`.
This script should:
1. Run the external tool as a subprocess.
2. Tell the tool to output results in JSON format.
3. Save the raw JSON to `security-results/bandit_raw.json`.

```python
import subprocess
from pathlib import Path

TARGET = Path(os.environ.get("SCAN_TARGET", "."))
OUT_FILE = Path("security-results/bandit_raw.json")

subprocess.run(["bandit", "-r", str(TARGET), "-f", "json", "-o", str(OUT_FILE)], check=False)
```

## Step 3: Parse and Normalize the Output
Open `pipeline/report_generator.py` and write a new parser function to map the raw JSON into the AegisFlow `full_report.json` schema.

```python
def parse_bandit(data: dict, start_idx: int) -> list[dict]:
    findings = []
    idx = start_idx
    for issue in data.get("results", []):
        f = make_finding(
            idx, "Bandit", "SAST",
            issue.get("test_id"), issue.get("issue_text"),
            issue.get("issue_severity"), 5.0, "CWE-0", issue.get("test_id"),
            extra={
                "affected_file": issue.get("filename"),
                "affected_line": issue.get("line_number"),
                "code_snippet": issue.get("code")
            }
        )
        findings.append(f)
        idx += 1
    return findings
```
Then, register this parser in the `main()` function of `report_generator.py` so it executes when `bandit_raw.json` is detected.

## Step 4: Add to Orchestrator
Update `pipeline/run_pipeline.sh` to execute your new bridge script at the correct stage:
```bash
echo "Running Bandit SAST..."
python3 pipeline/scan_bandit.py
```

## Conclusion
Because the `report_generator.py` normalizes everything into `full_report.json`, **you do not need to modify the UI, the AI Triage Engine, or the Policy Engine**. The rest of the system will automatically pick up your new findings, display them on the dashboard, send them to Groq for AI triage, and evaluate them against the security policies.
