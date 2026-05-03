import http.server
import socketserver
import json
import subprocess
import os
import threading
import shutil
from urllib.parse import urlsplit, urlunsplit

PORT = 58081
DIRECTORY = "dashboard"
IS_SCANNING = False


def write_dashboard_file(filename, content):
    file_path = os.path.join(os.getcwd(), "dashboard", "data", filename)
    with open(file_path, "w") as f:
        json.dump(content, f)


def normalize_target_url(target_url):
    if not target_url:
        return ""
    normalized = str(target_url).strip()
    parsed = urlsplit(normalized)

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invalid target URL. Only absolute http/https URLs are allowed.")

    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path or "",
        parsed.query or "",
        "",
    ))


def normalize_target_path(target):
    if not target:
        return ""
    return str(target).strip()


def infer_target_url_for_target(target):
    normalized_target = normalize_target_path(target).replace("\\", "/").lower()
    if "juice-shop" in normalized_target:
        return "http://juice-shop:3000"
    return ""


def get_allowed_target_urls(target):
    allowed_urls = set()
    inferred_url = infer_target_url_for_target(target)
    if inferred_url:
        allowed_urls.add(inferred_url)

    raw_allowlist = os.environ.get("AEGIS_ALLOWED_DAST_TARGETS", "")
    for item in raw_allowlist.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            allowed_urls.add(normalize_target_url(candidate))
        except ValueError:
            continue

    return allowed_urls


def resolve_target_url(target, requested_target_url):
    requested_url = normalize_target_url(requested_target_url)
    inferred_url = infer_target_url_for_target(target)

    if not requested_url:
        return inferred_url

    if requested_url not in get_allowed_target_urls(target):
        raise ValueError(
            "Target URL is not approved for live DAST. "
            "Use a server-recognized demo target or configure AEGIS_ALLOWED_DAST_TARGETS."
        )

    return requested_url


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

class AegisHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        # Extract base path without query params
        base_path = self.path.split('?')[0]

        if base_path == '/api/status':
            status_file = os.path.join(os.getcwd(), "dashboard/data/status.json")
            data = {"is_scanning": IS_SCANNING}
            if os.path.exists(status_file):
                try:
                    with open(status_file, "r") as f:
                        data.update(json.load(f))
                except: pass

            # Ensure global sync
            data["is_scanning"] = IS_SCANNING

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        else:
            super().do_GET()

    def do_POST(self):
        global IS_SCANNING
        if self.path == '/api/scan':
            if IS_SCANNING:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Scan already in progress"}).encode())
                return

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            params = json.loads(post_data)

            target = normalize_target_path(params.get('target', ''))
            use_ai = params.get('use_ai', True)
            api_key = params.get('groq_key', '')
            scanners = params.get('scanners', ['sast', 'sca', 'sbom', 'secret', 'iac', 'dast'])

            if not target:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing scan target"}).encode())
                return

            # Validate the target path actually exists
            target_abs = os.path.join(os.getcwd(), target.lstrip('./'))
            if not os.path.exists(target_abs):
                # Try to suggest valid targets
                demo_dir = os.path.join(os.getcwd(), 'demo-targets')
                suggestions = []
                if os.path.isdir(demo_dir):
                    suggestions = [f"./demo-targets/{d}" for d in os.listdir(demo_dir)
                                   if os.path.isdir(os.path.join(demo_dir, d)) and not d.startswith('.')]
                hint = f" Available targets: {', '.join(suggestions)}" if suggestions else ""
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": f"Target path not found: '{target}'.{hint}"
                }).encode())
                return
            try:
                target_url = resolve_target_url(target, params.get('target_url', ''))
            except ValueError as exc:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(exc)}).encode())
                return

            IS_SCANNING = True
            thread = threading.Thread(target=self.run_scan, args=(target, target_url, use_ai, api_key, scanners))
            thread.start()

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "SCAN_STARTED"}).encode())
        else:
            self.send_error(404)

    def run_scan(self, target, target_url, use_ai, api_key, scanners):
        global IS_SCANNING
        print(f"[AGENT] Starting Enterprise Pipeline on: {target} (URL: {target_url}, AI: {use_ai}, Scanners: {scanners})")

        env = os.environ.copy()
        env["SCAN_TARGET"] = target
        env["TARGET_URL"] = target_url
        env["ENABLED_SCANNERS"] = ",".join(scanners)

        if use_ai and api_key:
            env["GROQ_API_KEY"] = api_key
            print(f"[AGENT] Groq API Key received (length: {len(api_key)})")
        else:
            env["GROQ_API_KEY"] = ""
            print("[AGENT] Groq API Key NOT received or AI disabled")

        print(f"[AGENT] Preparing clean environment for: {target}")
        for folder in ["security-results", "dashboard/data", "ingest"]:
            folder_path = os.path.join(os.getcwd(), folder)
            if os.path.exists(folder_path):
                shutil.rmtree(folder_path)
            os.makedirs(folder_path, exist_ok=True)

        empty_files = {
            "audit_log.json": [],
            "build_report.json": {"stage": "build", "status": "pending", "mode": "pending", "details": []},
            "test_report.json": {"stage": "test", "status": "pending", "mode": "pending", "details": []},
            "sbom.json": {},
            "policy_result.json": {"passed": True, "details": [], "status": "RUNNING"},
            "status.json": {
                "is_scanning": True,
                "target": target,
                "target_url": target_url,
                "pipeline_state": "RUNNING",
                "build": "running",
                "test": "pending",
                "sast": "pending" if "sast" in scanners else "skipped",
                "sca": "pending" if "sca" in scanners else "skipped",
                "sbom": "pending" if "sbom" in scanners else "skipped",
                "secret": "pending" if "secret" in scanners else "skipped",
                "iac": "pending" if "iac" in scanners else "skipped",
                "dast": "pending" if "dast" in scanners else "skipped",
                "policy": "pending",
                "audit": "pending",
                "report": "pending"
            }
        }
        for filename, content in empty_files.items():
            write_dashboard_file(filename, content)

        try:
            process = subprocess.Popen(
                ["bash", "pipeline/run_pipeline.sh"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            for line in process.stdout:
                print(f"[SHELL] {line.strip()}")
            process.wait()

            print("[AGENT] Syncing results to dashboard/data...")
            subprocess.run(["cp", "-r", "security-results/.", "dashboard/data/"], check=False)

            policy_path = os.path.join(os.getcwd(), "security-results", "policy_result.json")
            if process.returncode == 0:
                print("[AGENT] Pipeline completed successfully.")
            elif os.path.exists(policy_path):
                print(f"[AGENT] Pipeline finished with policy exit code {process.returncode}; preserving policy result.")
            else:
                print(f"[ERROR] Pipeline exited with code {process.returncode}")
                write_dashboard_file("status.json", {
                    "is_scanning": False,
                    "target": target,
                    "target_url": target_url,
                    "pipeline_state": "FAILED",
                    "build": "unknown",
                    "test": "unknown",
                    "sast": "unknown",
                    "sca": "unknown",
                    "sbom": "unknown",
                    "secret": "unknown",
                    "iac": "unknown",
                    "dast": "unknown",
                    "policy": "failed",
                    "audit": "unknown",
                    "report": "unknown"
                })
                write_dashboard_file("policy_result.json", {
                    "passed": False,
                    "status": "FAILED",
                    "pipeline_status": "FAILED",
                    "block_reason": f"Pipeline execution failed with exit code {process.returncode}. Check container logs."
                })

        except Exception as e:
            print(f"[ERROR] Pipeline failed: {e}")
            write_dashboard_file("status.json", {
                "is_scanning": False,
                "target": target,
                "target_url": target_url,
                "pipeline_state": "FAILED"
            })
            write_dashboard_file("policy_result.json", {
                "passed": False,
                "status": "FAILED",
                "pipeline_status": "FAILED",
                "block_reason": f"Pipeline controller error: {e}"
            })
        finally:
            global IS_SCANNING
            IS_SCANNING = False

if __name__ == "__main__":
    # Ensure we are in the project root
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    os.chdir(BASE_DIR)

    # Create data directory and seed default files if missing
    DATA_DIR = os.path.join(BASE_DIR, "dashboard", "data")
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    # Seed default files to prevent 404
    default_files = {
        "full_report_triaged.json": {"scan_metadata": {"app_name": "AegisFlow Skeleton", "pipeline_run_id": "init"}, "findings": []},
        "policy_result.json": {"status": "INITIALIZED", "violated_policies": []},
        "build_report.json": {"stage": "build", "status": "pending", "mode": "pending", "details": []},
        "test_report.json": {"stage": "test", "status": "pending", "mode": "pending", "details": []},
        "sbom.json": {},
        "audit_log.json": []
    }

    for filename, content in default_files.items():
        file_path = os.path.join(DATA_DIR, filename)
        if not os.path.exists(file_path):
            with open(file_path, "w") as f:
                json.dump(content, f)
            print(f"[*] Seeded default file: {filename}")

    with ReusableThreadingTCPServer(("", PORT), AegisHandler) as httpd:
        print(f"🚀 AegisFlow Hub running at http://localhost:{PORT}")
        httpd.serve_forever()
