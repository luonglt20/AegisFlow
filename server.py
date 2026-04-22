import http.server
import socketserver
import json
import subprocess
import os
import threading

PORT = 58082
DIRECTORY = "dashboard"
IS_SCANNING = False # [NEW] Global scan status

class AegisHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        if self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"is_scanning": IS_SCANNING}).encode())
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

            target = params.get('target', './test-target-app')
            api_key = params.get('api_key', '')

            IS_SCANNING = True
            thread = threading.Thread(target=self.run_scan, args=(target, api_key))
            thread.start()

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "SCAN_STARTED"}).encode())
        else:
            self.send_error(404)

    def run_scan(self, target, api_key):
        global IS_SCANNING
        print(f"[AGENT] Starting scan on: {target}")
        env = os.environ.copy()
        if api_key:
            env["GROQ_API_KEY"] = api_key

        try:
            process = subprocess.Popen(
                ["bash", "pipeline/run_real_scanners.sh", target],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            for line in process.stdout:
                print(f"[SHELL] {line.strip()}")
            process.wait()
            print("[AGENT] Scan completed.")
        except Exception as e:
            print(f"[ERROR] Scan failed: {e}")
        finally:
            IS_SCANNING = False

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    with socketserver.TCPServer(("", PORT), AegisHandler) as httpd:
        httpd.allow_reuse_address = True
        print(f"🚀 AegisFlow Enterprise Dashboard running at http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.shutdown()
