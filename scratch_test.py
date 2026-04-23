import json
from pathlib import Path

def identify_type(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except:
        return "UNKNOWN"

    if "runs" in data and isinstance(data["runs"], list):
        if len(data["runs"]) > 0 and "tool" in data["runs"][0] and "driver" in data["runs"][0]["tool"]:
            if data["runs"][0]["tool"]["driver"].get("name") == "semgrep":
                return "SAST_SEMGREP"

    if "ArtifactType" in data and data["ArtifactType"] == "container_image":
        return "CONTAINER_TRIVY"

    if "ArtifactName" in data and "Results" in data:
        return "SCA_TRIVY"

    if "check_type" in data or "results" in data:
        if isinstance(data.get("results"), dict) and "failed_checks" in data["results"]:
            return "IAC_CHECKOV"

    if isinstance(data, list) and len(data) > 0:
        if "fuzzer" in data[0]:
            return "API"
        if "host" in data[0] and "port" in data[0]:
            return "NETWORK"
        if "reporter" in data[0] and "type" in data[0]:
            return "MANUAL"
        if "Description" in data[0] and "Match" in data[0]:
            return "SECRET_GITLEAKS"

    if isinstance(data, list):
        # check if it's zap?
        pass

    if isinstance(data, dict):
        if "site" in data:
            return "DAST_ZAP"

    # Nuclei format? It's jsonl so usually array if we load it

    filename = path.name.lower()
    if filename.startswith("sast_"): return "SAST"
    if filename.startswith("sca_"): return "SCA"
    if filename.startswith("iac_"): return "IAC"
    if filename.startswith("secret_"): return "SECRET"
    if filename.startswith("dast_"): return "DAST"
    if filename.startswith("container_"): return "CONTAINER"
    if filename.startswith("network_"): return "NETWORK"
    if filename.startswith("api_"): return "API"
    if filename.startswith("manual_"): return "MANUAL"
    if filename.startswith("nuclei_"): return "NUCLEI"

    return "UNKNOWN"

for f in Path("mock-data").glob("*.json"):
    print(f"{f.name}: {identify_type(f)}")
