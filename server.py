import http.server
import socketserver
import json
import subprocess
import os
import threading
import shutil

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
    return str(target_url).strip()


def normalize_target_path(target):
    if not target:
        return ""
    return str(target).strip()


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
            target_url = normalize_target_url(params.get('target_url', ''))
            use_ai = params.get('use_ai', True)
            api_key = params.get('groq_key', '')

            if not target:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing scan target"}).encode())
                return

            IS_SCANNING = True
            thread = threading.Thread(target=self.run_scan, args=(target, target_url, use_ai, api_key))
            thread.start()

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "SCAN_STARTED"}).encode())
        else:
            self.send_error(404)

    def run_scan(self, target, target_url, use_ai, api_key):
        global IS_SCANNING
        print(f"[AGENT] Starting Enterprise Pipeline on: {target} (URL: {target_url}, AI: {use_ai})")

        env = os.environ.copy()
        env["SCAN_TARGET"] = target
        env["TARGET_URL"] = target_url

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
            "policy_result.json": {"passed": True, "details": [], "status": "RUNNING"},
            "status.json": {
                "is_scanning": True,
                "target": target,
                "target_url": target_url,
                "pipeline_state": "RUNNING",
                "sast": "running",
                "sca": "pending",
                "sbom": "pending",
                "secret": "pending",
                "iac": "pending",
                "dast": "pending"
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

            if process.returncode == 0:
                print("[AGENT] Syncing results to dashboard/data...")
                subprocess.run(["cp", "-r", "security-results/.", "dashboard/data/"], check=False)
                print("[AGENT] Pipeline completed successfully.")
            else:
                print(f"[ERROR] Pipeline exited with code {process.returncode}")
                write_dashboard_file("status.json", {
                    "is_scanning": False,
                    "target": target,
                    "target_url": target_url,
                    "pipeline_state": "FAILED",
                    "sast": "unknown",
                    "sca": "unknown",
                    "sbom": "unknown",
                    "secret": "unknown",
                    "iac": "unknown",
                    "dast": "unknown"
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
