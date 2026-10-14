"""Local synthetic UI fixture, not deployment or cryptographic validation."""
import argparse
import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import sleep
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_coverage_dashboard import fixture_documents
from tests.test_dashboard import snapshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", required=True)
    parser.add_argument("--node-modules", required=True)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--api-port", type=int, default=38750)
    parser.add_argument("--ui-port", type=int, default=38751)
    parser.add_argument("--output", default=str(ROOT/"docs/novelty-roadmap/evidence/N8/visual"))
    args = parser.parse_args()
    documents = fixture_documents()
    state = {"requests": 0, "outage": False}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/_fixture/stats":
                body, code = state.copy(), 200
            else:
                state["requests"] += 1
                body, code = {}, 503 if state["outage"] else 200
                if path == "/api/snapshot":
                    body = snapshot()
                elif path.startswith("/api/coverage/"):
                    body = dict(documents.get(path[len("/api/coverage/"):], {}))
                else:
                    code = 404
                body["observed_at"] = datetime.now(timezone.utc).isoformat()
            encoded = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        def do_POST(self):
            if self.path != "/_fixture/outage":
                self.send_error(404)
                return
            state["outage"] = True
            self.send_response(204)
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", args.api_port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = os.environ.copy()
    env.update(MONITORING_API_URL=f"http://127.0.0.1:{args.api_port}", NODE_PATH=args.node_modules,
               DASHBOARD_COVERAGE_ENABLED="true")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    app = subprocess.Popen([sys.executable, "-m", "streamlit", "run", str(ROOT/"dashboard/app.py"),
        "--server.address=127.0.0.1", f"--server.port={args.ui_port}", "--server.headless=true",
        "--browser.gatherUsageStats=false"], env=env, cwd=ROOT, creationflags=flags,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        url = f"http://127.0.0.1:{args.ui_port}"
        for _ in range(80):
            if app.poll() is not None:
                raise RuntimeError("UI fixture failed to start")
            try:
                urlopen(url+"/_stcore/health", timeout=1).close()
                break
            except OSError:
                sleep(.25)
        result = subprocess.run([args.node, str(ROOT/"scripts/verify_n8_browser.cjs"), url,
            str(args.api_port), args.output, args.browser], env=env, cwd=ROOT, check=False,
            timeout=180, creationflags=flags, capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        return result.returncode
    finally:
        app.terminate()
        app.wait(timeout=15)
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
