"""Read-only N5 observation plus optional bounded faults/outage on its project only."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.docker_support import docker_executable

PROJECT = "software-data-diode-coverage"


def run(arguments):
    result = subprocess.run([docker_executable(), *arguments], cwd=ROOT, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("Docker check failed: "+result.stderr[-2000:])
    return result.stdout


def compose(*arguments):
    return run(["compose", "-p", PROJECT, "-f", "docker-compose.yml", "-f", "docker-compose.coverage.yml", "--profile", "coverage", *arguments])


def get(service, path):
    code = "import json,urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000"+path+"',timeout=3).read().decode())"
    return json.loads(compose("exec", "-T", service, "python", "-c", code))


def inspect():
    ids = compose("ps", "-q").split()
    records = json.loads(run(["inspect", *ids]))
    memberships = {}
    for container in records:
        if container["Config"]["Labels"].get("com.docker.compose.project") != PROJECT:
            raise RuntimeError("foreign project container")
        service = container["Config"]["Labels"]["com.docker.compose.service"]
        memberships[service] = {"networks": sorted(container["NetworkSettings"]["Networks"]),
            "addresses": {name: network["IPAddress"] for name, network in container["NetworkSettings"]["Networks"].items()},
            "ports": container["HostConfig"]["PortBindings"],
            "volumes": [{"name": m.get("Name"), "target": m["Destination"], "writable": m["RW"]}
                        for m in container["Mounts"] if m["Type"] == "volume"]}
    assert not any("edge" in network or "diode-network" in network for network in memberships["fog-receiver"]["networks"])
    assert not any("coverage-ledger" in mount["name"] for mount in memberships["fog-receiver"]["volumes"])
    names = run(["network", "ls", "--filter", "label=com.docker.compose.project="+PROJECT, "--format", "{{.Name}}"] ).split()
    networks = json.loads(run(["network", "inspect", *names]))
    return {"containers": memberships, "networks": [{"name": n["Name"], "internal": n["Internal"],
        "members": sorted(c["Name"] for c in n["Containers"].values())} for n in networks]}


def reverse_checks(memberships):
    code = """
import json,socket,sys
result=[]
for name in ['edge-gateway','edge-device-01','edge-device-02','edge-device-03','edge-device-04','edge-device-05']:
    entry={'service':name,'resolved':False,'connected':False}
    try:
        entry['address']=socket.gethostbyname(name);entry['resolved']=True
        with socket.create_connection((name,8000),timeout=.5):entry['connected']=True
    except OSError:pass
    result.append(entry)
for service,addresses in json.loads(sys.argv[1]).items():
    for address in addresses:
        entry={'service':service,'known_ip':address,'connected':False}
        try:
            with socket.create_connection((address,8000),timeout=.5):entry['connected']=True
        except OSError:pass
        result.append(entry)
print(json.dumps(result))
"""
    addresses = {name: list(record["addresses"].values()) for name, record in memberships.items() if name.startswith("edge-")}
    rows = json.loads(compose("exec", "-T", "fog-receiver", "python", "-c", code, json.dumps(addresses)))
    assert all(not r.get("resolved", False) and not r["connected"] for r in rows)
    return rows


def faults():
    code = """
import os,socket,sqlite3,json
from shared.coverage.transport import SeededFaultAdapter
from shared.coverage.parts import split_artifact
from shared.security import load_private_key
db=sqlite3.connect('file:'+os.environ['COVERAGE_LEDGER_PATH']+'?mode=ro',uri=True)
body=db.execute('SELECT body FROM sealed_capsules ORDER BY idx DESC LIMIT 1').fetchone()[0];db.close()
parts=split_artifact(body,load_private_key(os.environ['EDGE_PRIVATE_KEY_PATH']))
adapter=SeededFaultAdapter(571,drop=.2,duplicate=.5,max_delay_steps=3,max_pending=64)
destination=(socket.gethostbyname('data-diode'),9001);s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sent=0;total=0
for cycle in range(12):
    for part in parts:
        for frame in adapter.feed(part):s.sendto(frame,destination);sent+=1;total+=len(frame)+28
s.close();print(json.dumps({'seed':571,'injected_datagrams':sent,'injected_wire_bytes':total,'scope':'test copies, not N4 scheduled work'}))
"""
    return json.loads(compose("exec", "-T", "edge-gateway", "python", "-c", code))


def verify(with_faults=False, with_outage=False):
    memberships = inspect()
    document = {"project": PROJECT, "memberships": memberships, "reverse_path": reverse_checks(memberships["containers"])}
    for _ in range(40):
        fog = get("fog-receiver", "/research/status")
        if fog.get("verified_artifacts", 0) >= 5 and not fog["edge_state_stale"]:
            break
        time.sleep(1)
    else:
        raise RuntimeError("research intake did not observe bounded signed work/state")
    if with_faults:
        document["seeded_faults"] = faults()
        time.sleep(7)
    if with_outage:
        document["before_outage_fog"] = get("fog-receiver", "/research/status")
        assert document["before_outage_fog"]["socket_audit"]["udp_send_calls"] == 0
        before = get("edge-gateway", "/metrics/runtime")["coverage_admission"]["modeled_scheduled_bytes"]
        try:
            compose("stop", "fog-receiver")
            time.sleep(4)
            assert get("edge-gateway", "/ready")["status"] == "ready"
            assert get("data-diode", "/ready")["status"] == "ready"
            after = get("edge-gateway", "/metrics/runtime")["coverage_admission"]["modeled_scheduled_bytes"]
            assert after > before
            document["fog_outage"] = {"before_scheduled_bytes": before, "after_scheduled_bytes": after,
                "sender_progress": True, "fog_receipt_during_outage": "NOT_OBSERVED"}
        finally:
            run(["start", PROJECT+"-fog-receiver-1"])
        time.sleep(6)
    document["gateway"] = get("edge-gateway", "/metrics/runtime")
    document["diode"] = get("data-diode", "/metrics/runtime")
    document["fog"] = get("fog-receiver", "/research/status")
    assert document["fog"]["socket_audit"]["installed"]
    assert document["fog"]["socket_audit"]["udp_send_calls"] == 0
    assert document["diode"]["socket_audit"]["udp_send_calls"] > 0
    assert document["gateway"]["coverage_udp"]["socket_audit"]["udp_send_calls"] > 0
    document["assurance"] = "Tested CPython UDP send instrumentation and memberships; not physical/privileged-host enforcement"
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--faults", action="store_true")
    parser.add_argument("--outage", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing to overwrite previous evidence")
    result = verify(args.faults, args.outage)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
    print("N5 local transport checks passed: "+str(args.output))


if __name__ == "__main__":
    main()
