"""N11 local operator controls. No global stop, prune, key rotation or volume deletion."""
import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.docker_support import docker_executable
from scripts.run_n9_validation import (
    REVERSE_IP_PROBE,
    REVERSE_PROBE,
    allocate_test_subnets,
    baseline_identity,
    protected_files,
)
from shared.edge.demo import SCENARIOS, demo_project

SERVICES = ("postgres", "edge-gateway", "data-diode", "fog-receiver", "event-processor",
            "fog-analytics", "alert-engine", "monitoring-api", "dashboard")
DEVICES = tuple(f"edge-device-{i:02}" for i in range(1, 6))


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, default=str)
        handle.flush()
        os.fsync(handle.fileno())


class LocalProject:
    def __init__(self, project, docker=None):
        self.project = demo_project(project)
        self.docker = docker or docker_executable()
        self.output = ROOT/".local"/"n11"/project
        self.env = dict(os.environ)
        self.command = [self.docker, "compose", "--env-file", str(self.output/"empty.env"), "--project-directory", str(ROOT), "-p", project,
                        "-f", str(self.output/"compose.json")]

    def call(self, args, *, compose=True, timeout=120, check=True, input_text=None):
        result = subprocess.run((self.command if compose else [self.docker])+args, cwd=ROOT,
            env=self.env, input=input_text, text=True, encoding="utf-8", errors="replace",
            capture_output=True, timeout=timeout, check=False)
        if check and result.returncode:
            # Never print resolved Compose configurations/DB passwords.
            raise RuntimeError("Docker operation failed: "+" ".join(args[:4])+"\n"+result.stderr[-2000:])
        return result

    def containers(self, own=True):
        args = ["ps", "-aq"]
        if own:
            args += ["--filter", "label=com.docker.compose.project="+self.project]
        ids = self.call(args, compose=False).stdout.split()
        return json.loads(self.call(["inspect", *ids], compose=False).stdout) if ids else []

    def guard(self, check_isolation=True):
        containers = self.containers()
        edge_writes, fog_writes = set(), set()
        for c in containers:
            labels = c["Config"]["Labels"]
            if labels.get("org.rccd.n11") != self.project:
                raise ValueError("Existing research deployment is not N11-owned; left untouched. Use a fresh N11 validation project.")
            for mount in c["Mounts"]:
                if mount["Type"] == "volume" and not mount["Name"].startswith(self.project+"_"):
                    raise ValueError("foreign volume refused")
                if mount["Type"] == "volume" and mount.get("RW", False):
                    target = edge_writes if labels.get("com.docker.compose.service") in {"validation-init", "edge-gateway", "data-diode", *DEVICES} else fog_writes
                    target.add(mount["Name"])
            for network in c["NetworkSettings"]["Networks"]:
                if network != "none" and not network.startswith(self.project+"_"):
                    raise ValueError("foreign network refused")
            for bindings in (c["HostConfig"].get("PortBindings") or {}).values():
                if any(b["HostIp"] != "127.0.0.1" for b in bindings or []):
                    raise ValueError("non-loopback publication refused")
        if check_isolation and edge_writes & fog_writes:
            raise ValueError("Edge/Fog shared writable state refused")
        return containers

    def setup(self, cached=None, port=38501):
        self.guard()
        self.output.mkdir(parents=True, exist_ok=True)
        target = self.output/"compose.json"
        if target.exists():
            saved = json.loads((self.output/"settings.json").read_bytes())
            if saved["project"] != self.project or saved["dashboard_port"] != port:
                raise ValueError("existing N11 settings differ; no state replaced")
            print("N11 setup already exists; credentials, keys and state preserved")
            return
        # Resolve the existing standalone test service patterns, not the main .env.
        self.env.update(N9_PROJECT_NAME=self.project, N9_RUN_ID="n11-local",
                        N9_DB_PASSWORD=secrets.token_hex(24), N9_OUTPUT_DIR=str(self.output))
        model = json.loads(self.call(["compose", "--env-file", str(self.empty_env()), "-p", self.project,
            "-f", "docker-compose.n9.yml", "config", "--format", "json"], compose=False).stdout)
        model["services"].pop("security-test-client")
        services = model["services"]
        policy = json.loads((ROOT/"config/information_policy.json").read_bytes())
        policy.update(messages_per_second=1, max_queue_size=64)
        policy_path = self.output/"demo-policy.json"
        if not policy_path.exists():
            write_new(policy_path, policy)
        elif json.loads(policy_path.read_bytes()) != policy:
            raise ValueError("existing demo policy differs; no overwrite")
        for mount in services["edge-gateway"]["volumes"]:
            if mount["target"] == "/app/config/information_policy.json":
                mount["source"] = str(policy_path)
        for name, definition in services.items():
            definition["labels"] = {"org.rccd.n11": self.project}
            env = definition.setdefault("environment", {})
            env.pop("N9_PROJECT_NAME", None)
            env.pop("N9_RUN_ID", None)
            env.update(N11_PROJECT=self.project, N11_DEMO_ENABLED="true")
            if definition.get("build"):
                definition.setdefault("volumes", []).append({"type": "bind", "source": str(ROOT/"shared"),
                    "target": "/app/shared", "read_only": True})
                app = ROOT/name/"app"
                if app.is_dir():
                    definition["volumes"].append({"type": "bind", "source": str(app), "target": "/app/app", "read_only": True})
                definition["image"] = self.image(name, cached) if cached else self.project+"-"+name
            if name in DEVICES:
                definition["command"] = ["python", "-c", "import time; time.sleep(2147483647)"]
            for mount in definition.get("volumes", []):
                if mount.get("type") == "volume" and mount["source"] == "audit":
                    key = "audit-"+name
                    mount["source"] = key
                    model["volumes"][key] = {"name": self.project+"_"+key}
        model["volumes"].pop("audit")
        init = services["validation-init"]
        init.update(command=["python", "-m", "shared.coverage.demo_provision"], user="0:0",
                    cap_add=["CHOWN", "SETUID", "SETGID"])
        model["volumes"]["audit-init"] = {"name": self.project+"_audit-init"}
        init["volumes"].append({"type": "volume", "source": "audit-init", "target": "/logs"})
        db_url = services["fog-receiver"]["environment"]["DATABASE_URL"]
        health = services["fog-receiver"]["healthcheck"]
        for name in ("monitoring-api", "dashboard"):
            service = {k: services["event-processor"][k] for k in (
                "read_only", "init", "cap_drop", "security_opt", "tmpfs", "pids_limit", "logging")}
            service.update(build={"context": str(ROOT), "dockerfile": name+"/Dockerfile"},
                image=self.image(name, cached) if cached else self.project+"-"+name,
                user="10001:10001", mem_limit="768m" if name == "dashboard" else "384m", cpus="1.0",
                labels={"org.rccd.n11": self.project}, networks=["fog-services-network"],
                depends_on={"fog-receiver": {"condition": "service_healthy"}},
                environment={}, volumes=[], healthcheck=health)
            if name == "monitoring-api":
                service["environment"] = {"DATABASE_URL": db_url, "COVERAGE_DASHBOARD_ENABLED": "true",
                    "COVERAGE_CONTRACT_PATH": "/app/config/rule_coverage.json"}
                service["volumes"] = [self.bind("shared", "/app/shared"), self.bind(name+"/app", "/app/app"),
                    self.bind("config/rule_coverage.json", "/app/config/rule_coverage.json")]
            else:
                service["environment"] = {"MONITORING_API_URL": "http://monitoring-api:8000", "DASHBOARD_COVERAGE_ENABLED": "true"}
                service["volumes"] = [self.bind("dashboard/app.py", "/app/app.py"),
                    self.bind("dashboard/.streamlit", "/app/.streamlit")]
                service["ports"] = [{"target": 8501, "published": str(port), "host_ip": "127.0.0.1", "protocol": "tcp"}]
                service["healthcheck"] = {**health, "test": ["CMD", "python", "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health',timeout=2)"]}
                service["depends_on"] = {"monitoring-api": {"condition": "service_healthy"}}
            services[name] = service
        original_command = list(self.command)
        allocate_test_subnets(self)
        allocated = json.loads((self.output/"allocated-networks.yml").read_bytes())
        for name, value in allocated["networks"].items():
            model["networks"][name].update(value)
        import ipaddress
        chosen = json.loads((self.output/"network-allocation.json").read_bytes())["chosen"]
        subnet = list(ipaddress.ip_network(chosen).subnets(new_prefix=28))[4]
        model["networks"]["fog-host-network"] = {"name": self.project+"_fog-host-network",
            "driver": "bridge", "ipam": {"config": [{"subnet": str(subnet)}]}}
        services["dashboard"]["networks"].append("fog-host-network")
        self.command = original_command
        # This file is still private setup material, never a report artifact.
        write_new(target, model)
        write_new(self.output/"settings.json", {"project": self.project, "dashboard_port": port,
            "cached_images_from": cached, "mode": "BOUNDED_N11_DEMO_NOT_BASELINE", "created": datetime.now(timezone.utc).isoformat()})
        print("N11 setup ready; isolated credentials retained under .local/n11 (do not publish)")

    def empty_env(self):
        path = self.output/"empty.env"
        if not path.exists():
            path.touch(exist_ok=False)
        return path

    def bind(self, source, target):
        return {"type": "bind", "source": str(ROOT/source), "target": target, "read_only": True}

    def image(self, service, source):
        import re
        if not re.fullmatch(r"software-data-diode-n9-[a-f0-9]{12}", source):
            raise ValueError("cached images require an explicit earlier N9 source")
        tag = source+"-"+("edge-gateway" if service == "validation-init" else service)
        if service in {"dashboard", "monitoring-api"}:
            tag = "software-data-diode-coverage-"+service
        rows = json.loads(self.call(["image", "inspect", tag], compose=False).stdout)
        return rows[0]["Id"]

    def start(self, build=False):
        self.guard()
        if not (self.output/"settings.json").exists():
            raise ValueError("Run setup first")
        validate_model(json.loads((self.output/"compose.json").read_bytes()), self.project)
        if build:
            self.call(["build"], timeout=900)
        self.call(["up", "-d", "--no-build", "--pull", "never", "--no-recreate"], timeout=240)
        self.ready()
        print("Ready: http://127.0.0.1:"+str(self.settings()["dashboard_port"])+" (Evidence Coverage)")
        print("Devices idle until demo. Stop after demonstration; signing history is finite (256 entries).")

    def settings(self):
        return json.loads((self.output/"settings.json").read_bytes())

    def ready(self):
        end = time.monotonic()+120
        while time.monotonic() < end:
            rows = self.guard()
            states = {c["Config"]["Labels"]["com.docker.compose.service"]: c["State"] for c in rows}
            if all(states.get(s, {}).get("Health", {}).get("Status") == "healthy" for s in SERVICES):
                if not all(states.get(s, {}).get("Running") for s in DEVICES):
                    raise RuntimeError("five device containers are not running")
                return
            time.sleep(2)
        raise RuntimeError("N11 readiness timed out. Use status and project-scoped logs; do not delete volumes.")

    def local(self, service, code):
        return json.loads(self.call(["exec", "-T", service, "python", "-c", code]).stdout)

    def runtime(self, service):
        route = "/research/status" if service == "fog-receiver" else "/metrics/runtime"
        return self.local(service, "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000"+route+"',timeout=3).read().decode())")

    def status(self):
        rows = self.guard()
        print(self.call(["ps", "-a"]).stdout)
        return {c["Config"]["Labels"]["com.docker.compose.service"]: {
            "state": c["State"]["Status"], "health": c["State"].get("Health", {}).get("Status"),
            "user": c["Config"]["User"], "networks": sorted(c["NetworkSettings"]["Networks"]),
            "ports": c["HostConfig"].get("PortBindings")} for c in rows}

    def stop(self):
        self.guard(check_isolation=False)
        if (self.output/"settings.json").exists():
            self.call(["stop", "--timeout", "30"], timeout=180)
        print("N11 stopped; volumes, keys, epochs and PostgreSQL retained")

    def db_snapshot(self, start, end):
        return self.local("fog-receiver", DB_SNAPSHOT.replace("START", str(start)).replace("END", str(end)))

    def verify(self):
        self.ready()
        output = ROOT/"docs/novelty-roadmap/evidence/N11"/("checks-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
        output.mkdir(parents=True, exist_ok=False)
        containers = self.guard()
        by_service = {c["Config"]["Labels"]["com.docker.compose.service"]: c for c in containers}
        names = sorted({n for c in containers for n in c["NetworkSettings"]["Networks"] if n != "none"})
        networks = json.loads(self.call(["network", "inspect", *names], compose=False).stdout)
        write_new(output/"networks.json", networks)
        reverse = self.local("fog-receiver", REVERSE_PROBE)
        addresses = {s: [n["IPAddress"] for n in by_service[s]["NetworkSettings"]["Networks"].values()] for s in (*DEVICES, "edge-gateway")}
        reverse += self.local("fog-receiver", REVERSE_IP_PROBE+"\nprobe("+repr(addresses)+")")
        write_new(output/"reverse-path.json", reverse)
        migrations = {p.name: p.read_text(encoding="utf-8") for p in sorted((ROOT/"database/migrations").glob("*.sql"))}
        bundle = base64.b64encode(json.dumps(migrations).encode()).decode()
        for phase, suffix in (("n6", "persistence"), ("n7", "rules")):
            source = (ROOT/f"scripts/verify_{phase}_{suffix}.py").read_text(encoding="utf-8")
            code = "import sys; sys.argv=['check','--migration-bundle',"+repr(bundle)+"]; exec(compile("+repr(source)+",'n11-postgres-check','exec'))"
            result = json.loads(self.call(["exec", "-T", "fog-receiver", "python", "-"], input_text=code, timeout=90).stdout)
            write_new(output/(phase+"-repository.json"), result)
        profile_before = self.local("edge-gateway", "import json; from pathlib import Path; print(Path('/run/coverage/profile.json').read_text())")
        self.call(["run", "--rm", "--no-deps", "validation-init"], timeout=45)
        profile_after = self.local("edge-gateway", "import json; from pathlib import Path; print(Path('/run/coverage/profile.json').read_text())")
        permission = {}
        for name, directory in {"edge-gateway": "/state/coverage-ledger", "data-diode": "/logs",
                                 "fog-receiver": "/state/research-replay",
                                 **{d: "/state/research-device" for d in DEVICES}}.items():
            permission[name] = self.local(name, "import json,os; from pathlib import Path; p=Path("+repr(directory)+")/'n11-permission-probe'; p.touch(exist_ok=False); p.unlink(); print(json.dumps({'uid':os.getuid(),'writable':True}))")
        url = "http://127.0.0.1:"+str(self.settings()["dashboard_port"])+"/_stcore/health"
        with urllib.request.urlopen(url, timeout=5) as response:
            health = {"url": url, "status": response.status, "body": response.read(64).decode()}
        fog = self.runtime("fog-receiver")
        stats = self.call(["stats", "--no-stream", "--format", "{{json .}}", *[c["Id"] for c in containers if c["State"]["Running"]]], compose=False, timeout=30)
        write_new(output/"resources.json", [json.loads(r) for r in stats.stdout.splitlines()])
        result = {"project": self.project, "reverse_failures": all(r["failed"] for r in reverse),
            "profile_unchanged": profile_before == profile_after, "permissions": permission,
            "dashboard": health, "fog_socket_audit": fog["socket_audit"], "services": self.status()}
        write_new(output/"checks.json", result)
        if not (result["reverse_failures"] and result["profile_unchanged"] and health["status"] == 200
                and all(p["uid"] == 10001 for p in permission.values()) and fog["socket_audit"]["udp_send_calls"] == 0):
            raise AssertionError("N11 deployment checks failed; see "+str(output))
        print("N11 deployment checks passed: "+str(output))

    def run_devices(self, start, output, recovery=False):
        def send(device):
            result = self.call(["exec", "-T", device, "python", "-m", "shared.edge.demo", "--start", str(start),
                                *(["--recovery"] if recovery else [])], timeout=90)
            value = json.loads(result.stdout)
            write_new(output/(device+("-recovery" if recovery else "")+".json"), value)
            return value
        with ThreadPoolExecutor(max_workers=5) as workers:
            return list(workers.map(send, DEVICES))

    def demo(self):
        self.ready()
        history = self.local("edge-gateway", "import json,sqlite3; db=sqlite3.connect('file:/state/coverage-ledger/observations.sqlite3?mode=ro',uri=True); print(json.dumps({'sealed':db.execute('SELECT COUNT(*) FROM sealed_capsules').fetchone()[0]})); db.close()")
        if history["sealed"] > 136:
            raise ValueError("Insufficient bounded signing history for another demo. Preserve this state; use a fresh validation namespace for a new experiment, never reset its epoch.")
        output = ROOT/"docs/novelty-roadmap/evidence/N11"/(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+secrets.token_hex(3))
        output.mkdir(parents=True, exist_ok=False)
        before = protected_files()
        baseline = baseline_identity([c for c in self.containers(False)
            if c["Config"]["Labels"].get("com.docker.compose.project") != self.project])
        write_new(output/"start.json", {"project": self.project, "protected_sha256": before,
            "baseline": baseline, "source": source_hashes(), "services": self.status(),
            "demo_policy": json.loads((self.output/"demo-policy.json").read_bytes())})
        start = (int(time.time())//10+3)*10
        plan = {"start": start, "run_id": output.name}
        self.call(["exec", "-T", "data-diode", "python", "-c",
            "from pathlib import Path; Path('/logs/n11-plan.json').write_text("+repr(json.dumps(plan))+")"])
        write_new(output/"plan.json", {**plan, "scenarios": SCENARIOS,
            "timing": "six aligned ingress windows; faults affect subsequent evidence closure; no feedback"})
        print("Running five real devices through native admission/UDP. Evidence: "+str(output), flush=True)
        try:
            self.run_devices(start, output)
            time.sleep(max(0, start+86-time.time()))
            database = self.db_snapshot(start//10, start//10+5)
            write_new(output/"received.json", database)
            write_new(output/"diode.json", self.runtime("data-diode"))
            write_new(output/"fog.json", self.runtime("fog-receiver"))
            write_new(output/"gateway.json", self.runtime("edge-gateway"))
            first = self.local("edge-gateway", LEDGER_IDENTITY)
            # Restart only this research project's stateful services, never the baseline.
            self.call(["restart", "--timeout", "30", "edge-gateway", "fog-receiver", "postgres"], timeout=150)
            self.ready()
            second = self.local("edge-gateway", LEDGER_IDENTITY)
            if first["epoch"] != second["epoch"] or first["devices"] != second["devices"]:
                raise AssertionError("restart lost accepted identity/counters")
            recovery_start = (int(time.time())//10+3)*10
            self.run_devices(recovery_start, output, recovery=True)
            time.sleep(max(0, recovery_start+16-time.time()))
            recovery = self.db_snapshot(recovery_start//10, recovery_start//10)
            write_new(output/"recovery.json", {"before": first, "after": second, "received": recovery})
            results = assess(database, recovery, start//10, recovery_start//10, output)
            oracle = oracle_checks(output, database, recovery)
            write_new(output/"oracle.json", oracle)
            if oracle["wrong_definite"]:
                raise AssertionError("received definite answer contradicts accepted-ingress oracle")
            write_new(output/"results.json", results)
            import csv
            with (output/"results.csv").open("x", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(results[0]))
                writer.writeheader()
                writer.writerows(results)
            if not all(r["passed"] for r in results):
                raise AssertionError("N11 outcome mismatch; retained results explain failures")
            print("N11 scenarios passed: "+str(output))
        except (RuntimeError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
            write_new(output/"failure.json", {"type": type(error).__name__, "reason": str(error)[:2000]})
            raise
        finally:
            self.call(["exec", "-T", "data-diode", "python", "-c",
                "from pathlib import Path; Path('/logs/n11-plan.json').unlink(missing_ok=True)"], check=False)
            after = baseline_identity([c for c in self.containers(False)
                if c["Config"]["Labels"].get("com.docker.compose.project") != self.project])
            preserved = before == protected_files() and baseline == after
            write_new(output/"preservation.json", {"preserved": preserved, "baseline_count": len(baseline)})
            if not preserved:
                raise AssertionError("baseline/protected file audit differs")


LEDGER_IDENTITY = """
import json,sqlite3,os
with sqlite3.connect('file:/state/coverage-ledger/observations.sqlite3?mode=ro',uri=True) as db:
 print(json.dumps({'epoch':db.execute("SELECT value FROM metadata WHERE key='epoch'").fetchone()[0],
  'devices':list(db.execute('SELECT device,ingress,retry_highwater FROM devices ORDER BY device')),'uid':os.getuid()}))
"""

DB_SNAPSHOT = """
import json,os,psycopg
from psycopg.rows import dict_row
with psycopg.connect(os.environ['DATABASE_URL'],row_factory=dict_row,connect_timeout=3) as db:
 db.execute('SET statement_timeout=5000')
 queries={
 'capsules':"SELECT artifact_digest,scope_id,body,verification,received_at_us FROM coverage_capsules WHERE (body->>'window_index')::bigint BETWEEN START AND END ORDER BY scope_id LIMIT 100",
 'verdicts':"SELECT rule_id,window_index,verdict,result,revision FROM coverage_rule_verdicts WHERE window_index BETWEEN START AND END ORDER BY window_index,rule_id LIMIT 100",
 'raw':"SELECT device_id,payload FROM accepted_telemetry ORDER BY received_at DESC LIMIT 500",
 'outcomes':"SELECT reason_code,details FROM coverage_outcomes ORDER BY timestamp_us DESC LIMIT 500",
 'tables':"SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"}
 print(json.dumps({k:list(db.execute(q)) for k,q in queries.items()},default=str))
"""


def assess(database, recovery, first, last, output):
    def verdict(db, window, rule):
        return next((r for r in db["verdicts"] if r["window_index"] == window and r["rule_id"] == rule), {})
    cases = [(SCENARIOS[0], first, "environmental-threshold", "FALSE"),
             (SCENARIOS[1], first+1, "environmental-threshold", "TRUE"),
             (SCENARIOS[2], first+2, "incident-correlation", "TRUE"),
             (SCENARIOS[3], first+3, "incident-correlation", "TRUE"),
             (SCENARIOS[4], first+4, "environmental-threshold", "UNKNOWN"),
             (SCENARIOS[5], first+5, "environmental-threshold", "UNKNOWN"),
             ("recovery", last, "incident-correlation", "TRUE")]
    rows = []
    for name, window, rule, expected in cases:
        db = recovery if name == "recovery" else database
        row = verdict(db, window, rule)
        passed = row.get("verdict") == expected
        if name == "tampering":
            passed &= any(r["reason_code"] == "INVALID_SIGNED_PART" for r in db["outcomes"])
        if name == "normal-reduction":
            passed &= any(c["body"]["reduction_accounting"]["reduced_raw"]+
                          c["body"]["reduction_accounting"]["dropped_raw"] > 0
                          for c in db["capsules"] if c["body"]["window_index"] == window)
        scopes = [c for c in db["capsules"] if c["body"]["window_index"] == window]
        if expected in {"TRUE", "FALSE"}:
            passed &= len(scopes) == 5 and all(c["body"]["accepted_observation_count"] == 5 for c in scopes)
        if name == "raw-loss":
            passed &= not any(r["payload"].get("attributes", {}).get("n11_scenario") == "raw-loss" for r in db["raw"])
        if name == "evidence-loss":
            passed &= not scopes and any(r["payload"].get("attributes", {}).get("n11_scenario") == "evidence-loss" for r in db["raw"])
        rows.append({"scenario": name, "window_index": window, "rule_id": rule, "expected": expected,
            "actual": row.get("verdict", "NOT_PERSISTED"), "passed": bool(passed),
            "reason": json.dumps(row.get("result", {}).get("reason_codes", [])),
            "evidence_file": "recovery.json" if name == "recovery" else "received.json"})
    return rows


def oracle_checks(output, database, recovery):
    from shared.coverage.contracts import load_contract
    from shared.coverage.models import IngressObservation, MetricReading
    from shared.coverage.oracle import trace_oracle
    from shared.security.crypto import canonical_bytes
    contract = load_contract(ROOT/"config/rule_coverage.json")
    observations = []
    for device in DEVICES:
        definition = next(d for d in contract.devices if d.device_id == device)
        for suffix in ("", "-recovery"):
            for entry in json.loads((output/(device+suffix+".json")).read_bytes())["observations"]:
                raw, receipt = entry["original"], entry["receipt"]
                if hashlib.sha256(canonical_bytes(raw)).hexdigest() != receipt["input_hash"]:
                    raise AssertionError("original fixture does not match native accepted-input hash")
                readings = tuple(MetricReading(path=m.path, value=(raw["measurements"].get(m.path.split(".", 1)[1])
                    if m.path.startswith("measurements.") else raw.get(m.path))) for m in definition.metrics)
                # The native ledger receipt, not the device's timestamp, fixes ingress scope.
                observations.append(IngressObservation(ledger_epoch=receipt["ledger_epoch"], device_id=device,
                    ingress_sequence=receipt["ingress_sequence"], ingress_utc_us=receipt["window_index"]*10000000+1,
                    telemetry_type=raw["telemetry_type"], metrics=readings))
    rows = []
    for row in database["verdicts"]+recovery["verdicts"]:
        expected = trace_oracle(contract, row["rule_id"], ledger_epoch=observations[0].ledger_epoch,
            window_index=row["window_index"], observations=observations)
        actual = row["verdict"]
        rows.append({"rule_id": row["rule_id"], "window_index": row["window_index"], "oracle": str(expected),
                     "received": actual, "wrong_definite": actual != "UNKNOWN" and actual != expected})
    return {"scope": "ACKNOWLEDGED_NATIVE_GATEWAY_INGRESS", "ingress_time_precision": "RECEIPT_WINDOW_MEMBERSHIP_ONLY_NOT_EXACT_ARRIVAL_INSTANT", "rows": rows,
            "wrong_definite": sum(r["wrong_definite"] for r in rows)}


def source_hashes():
    files = [Path(__file__), ROOT/"docker-compose.n9.yml", *sorted((ROOT/"shared/coverage").glob("*.py")),
             ROOT/"shared/edge/demo.py", ROOT/"shared/edge/coverage_client.py",
             *sorted((ROOT/"config").glob("rule_coverage*.json"))]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def validate_model(model, project):
    expected = {*SERVICES, *DEVICES, "database-migrator", "validation-init"}
    if model.get("name") != project or set(model["services"]) != expected:
        raise ValueError("unexpected N11 project/service set")
    for name, definition in model["services"].items():
        if definition.get("privileged") or definition.get("network_mode") not in (None, "none"):
            raise ValueError("unsafe demo namespace")
        for port in definition.get("ports", []):
            if name != "dashboard" or port.get("host_ip") != "127.0.0.1":
                raise ValueError("only loopback dashboard publication allowed")
        for mount in definition.get("volumes", []):
            if mount["type"] == "volume":
                volume = model["volumes"][mount["source"]]
                if volume.get("external") or not volume["name"].startswith(project+"_"):
                    raise ValueError("foreign demo volume")
                if mount["source"] in {"ledger", "private"} and name not in {"validation-init", "edge-gateway"}:
                    raise ValueError("Edge private state visible outside gateway")
            elif mount["type"] == "bind":
                source = Path(mount["source"]).resolve()
                if not source.is_relative_to(ROOT) or not mount.get("read_only") or "secrets" in source.parts:
                    raise ValueError("unexpected writable/private host bind")
            else:
                raise ValueError("unsupported demo mount")
    edge = set(model["services"]["edge-gateway"]["networks"])
    fog = set(model["services"]["fog-receiver"]["networks"])
    if edge & fog:
        raise ValueError("Edge/Fog share application network")
    for name, network in model["networks"].items():
        if network.get("external") or not network["name"].startswith(project+"_"):
            raise ValueError("foreign network")
        if name != "fog-host-network" and not network.get("internal"):
            raise ValueError("non-internal application zone")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "start", "status", "demo", "stop", "restart", "verify"))
    parser.add_argument("--project", default="software-data-diode-coverage")
    parser.add_argument("--cached-images-from")
    parser.add_argument("--dashboard-port", type=int, default=38501, choices=range(1024, 65536), metavar="PORT")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    project = LocalProject(args.project)
    project.call(["info", "--format", "{{.ServerVersion}}"], compose=False)
    if args.action == "setup":
        project.setup(args.cached_images_from, args.dashboard_port)
    elif args.action == "start":
        project.start(args.build)
    elif args.action == "status":
        print(json.dumps(project.status(), indent=2))
    elif args.action == "stop":
        project.stop()
    elif args.action == "restart":
        project.stop()
        project.start(args.build)
    elif args.action == "verify":
        project.verify()
    else:
        project.demo()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, AssertionError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
