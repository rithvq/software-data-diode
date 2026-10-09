"""Integration verification against an explicitly named, isolated audit stack."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import Request, urlopen
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.docker_support import docker_executable


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--outages", action="store_true")
    args = parser.parse_args()
    docker = docker_executable()
    compose = [docker, "compose", "-p", "software-data-diode-audit", "--profile", "full"]
    results = []

    def command(*arguments):
        return subprocess.check_output(compose + list(arguments), cwd=ROOT, text=True, timeout=90).strip()

    def inside(service, code):
        return command("exec", "-T", service, "python", "-c", code)

    def check(name, condition, evidence):
        results.append({"check": name, "passed": bool(condition), "evidence": evidence,
                        "timestamp": datetime.now(timezone.utc).isoformat()})
        print(f"{'PASS' if condition else 'FAIL'} {name}", flush=True)

    def url(service, port, path):
        binding = command("port", service, str(port)).splitlines()[0]
        return f"http://{binding}{path}"

    def status(target):
        try:
            with urlopen(target, timeout=12) as response:
                return response.status
        except OSError:
            return 0

    def snapshot():
        return json.loads(inside("dashboard", "import requests,json; r=requests.get('http://monitoring-api:8000/api/snapshot',timeout=15); r.raise_for_status(); print(r.text)"))

    gateway = url("edge-gateway", 8000, "")
    try:
        for service, port, path in (("edge-gateway", 8000, "/ready"), ("dashboard", 8501, "/_stcore/health"),
                                    ("prometheus-edge", 9090, "/-/ready"), ("prometheus-fog", 9090, "/-/ready"),
                                    ("grafana", 3000, "/api/health")):
            code = status(url(service, port, path))
            check(service + " readiness", code == 200, code)
        data = snapshot()
        check("five active Edge devices", data["overview"]["active_edge_nodes"] == 5, data["overview"])
        check("analytics and alerts persisted", bool(data["analytics"]["latest_anomalies"]) and bool(data["analytics"]["active_alerts"]),
              {"anomalies": len(data["analytics"]["latest_anomalies"]), "alerts": len(data["analytics"]["active_alerts"])})
        for service in ("prometheus-edge", "prometheus-fog"):
            with urlopen(url(service, 9090, "/api/v1/targets"), timeout=10) as response:
                targets = json.load(response)["data"]["activeTargets"]
            check(service + " scrape targets", bool(targets) and all(t["health"] == "up" for t in targets),
                  [{"url": t["scrapeUrl"], "health": t["health"]} for t in targets])
        memberships = {}
        for service in ("edge-gateway", "fog-receiver", "dashboard"):
            identifier = command("ps", "-q", service)
            memberships[service] = json.loads(subprocess.check_output(
                [docker, "inspect", "--format", "{{json .NetworkSettings.Networks}}", identifier], text=True))
        edge_ip = memberships["edge-gateway"]["software-data-diode-audit_edge-network"]["IPAddress"]
        check("Fog and dashboard have no Edge network membership",
              not (set(memberships["edge-gateway"]) & set(memberships["fog-receiver"])) and
              not (set(memberships["edge-gateway"]) & set(memberships["dashboard"])),
              {key: list(value) for key, value in memberships.items()})
        probe = """import socket,json
result={}
for host in HOSTS:
    try:
        connection=socket.create_connection((host,8000),timeout=1)
        connection.close()
        result[host]='connected'
    except OSError:
        result[host]='blocked'
print(json.dumps(result))
""".replace("HOSTS", repr(["edge-gateway", "edge-device-01", edge_ip]))
        blocked = json.loads(inside("fog-receiver", probe))
        check("Fog reverse connections blocked", all(v == "blocked" for v in blocked.values()), blocked)
        reverse = inside("fog-receiver", "import httpx; r=httpx.post('http://data-diode:8000/ingest',json={},timeout=3); print(r.status_code)")
        check("Fog cannot submit to diode ingress", reverse == "403", reverse)
        for service in ("edge-gateway", "data-diode", "fog-receiver"):
            names = json.loads(inside(service, "from pathlib import Path; import json; print(json.dumps([p.name for p in Path('/logs').iterdir()]))"))
            others = {"edge-gateway", "data-diode", "fog-receiver"} - {service}
            check(service + " sees only its runtime files", bool(names) and not any(name.startswith(other) for name in names for other in others), names)
            audit = inside(service, f"from shared.security.audit import verify_audit_log; import json; print(json.dumps(verify_audit_log('/logs/{service}-audit.jsonl')))")
            check(service + " migrated audit chain valid", json.loads(audit)[0], json.loads(audit)[1])
        if args.outages:
            for dependency in ("fog-receiver", "postgres"):
                marker = "audit-recovery-" + uuid4().hex
                command("stop", "-t", "10", dependency)
                try:
                    check(dependency + " failure propagates readiness", status(gateway + "/ready") != 200, "readiness unavailable")
                    message = {"device_id": marker, "timestamp": datetime.now(timezone.utc).isoformat(),
                               "temperature": 45, "humidity": 50, "status": "critical", "event_type": "attack"}
                    request = Request(gateway + "/telemetry", data=json.dumps(message).encode(),
                                      headers={"Content-Type": "application/json"})
                    with urlopen(request, timeout=10) as response:
                        check(dependency + " outage ingress bounded and responsive", response.status == 200, json.load(response))
                finally:
                    command("start", dependency)
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline and status(gateway + "/ready") != 200:
                    time.sleep(1)
                check(dependency + " readiness recovered", status(gateway + "/ready") == 200, "dependency restarted")
                query = ("import os,psycopg; c=psycopg.connect(os.environ['DATABASE_URL']); "
                         "print(c.execute('SELECT count(*) FROM accepted_telemetry WHERE device_id=%s',(" + repr(marker) + ",)).fetchone()[0])")
                count = "0"
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    count = inside("monitoring-api", query)
                    if count == "1":
                        break
                    time.sleep(1)
                check(dependency + " outage message delivered once after recovery", count == "1", count)
    except Exception as exc:
        check("runtime audit completed", False, str(exc))
    finally:
        path = ROOT / "audit-results/runtime.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return int(not all(item["passed"] for item in results))


if __name__ == "__main__":
    raise SystemExit(main())
