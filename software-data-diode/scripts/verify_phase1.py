"""Verify the running, isolated Phase 1 Compose project without targeting the full stack."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "edge-device": {"edge-network"},
    "edge-gateway": {"edge-network", "gateway-network"},
    "unidirectional-gateway": {"gateway-network", "fog-network"},
    "fog-receiver": {"fog-network"},
}


def find_docker():
    executable = shutil.which("docker")
    if executable:
        return executable
    candidate = Path(os.getenv("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe"
    return str(candidate) if candidate.is_file() else "docker"


def main(phase=1, extra_checks=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default=find_docker())
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--output", type=Path, default=ROOT / f"phase{phase}-results")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    compose_file = f"docker-compose.phase{phase}.yml"
    compose = ["compose", "-f", str(ROOT / compose_file)]

    def docker(*parts, input_text=None):
        process = subprocess.run([args.docker, *parts], cwd=ROOT, input=input_text,
                                 capture_output=True, text=True, timeout=30)
        if process.returncode:
            raise RuntimeError(process.stderr.strip() or process.stdout.strip())
        return process.stdout.strip()

    def local_json(service, endpoint):
        code = ("import urllib.request; "
                f"print(urllib.request.urlopen('http://127.0.0.1:8000/{endpoint}', timeout=3).read().decode())")
        return json.loads(docker(*compose, "exec", "-T", service, "python", "-c", code))

    def check(name, passed, detail):
        results.append({"check": name, "passed": bool(passed), "detail": detail})

    def received_count():
        metrics = local_json("fog-receiver", "metrics/runtime")
        return metrics["received_messages"] if phase == 1 else metrics["security"].get("accepted_messages", 0)

    started = datetime.now(timezone.utc).isoformat()
    try:
        docker("info", "--format", "{{.ServerVersion}}")
        containers = {}
        network_ids = set()
        for service in EXPECTED:
            identifier = docker(*compose, "ps", "-q", service)
            if not identifier:
                raise RuntimeError(f"{service} is not running; start {compose_file} first")
            data = json.loads(docker("inspect", identifier))[0]
            containers[service] = data
            network_ids.update(n["NetworkID"] for n in data["NetworkSettings"]["Networks"].values())
        networks = json.loads(docker("network", "inspect", *sorted(network_ids)))
        (args.output / "network-inspection.json").write_text(json.dumps(networks, indent=2), encoding="utf-8")
        labels = {n["Id"]: n.get("Labels", {}).get("com.docker.compose.network") for n in networks}
        check("Three private application networks", len(networks) == 3 and all(n["Internal"] for n in networks),
              list(labels.values()))
        for service, spec in containers.items():
            actual = {labels[n["NetworkID"]] for n in spec["NetworkSettings"]["Networks"].values()}
            check(f"Membership {service}", actual == EXPECTED[service], sorted(actual))
            check(f"No published ports {service}", not spec["HostConfig"].get("PortBindings"),
                  spec["HostConfig"].get("PortBindings"))

        initial = received_count()
        deadline = time.monotonic() + args.timeout
        current = initial
        while time.monotonic() < deadline:
            current = received_count()
            if current >= initial + 10:
                break
            time.sleep(1)
        check("Continuous forward delivery", current >= initial + 10,
              {"start_count": initial, "end_count": current, "required_new_messages": 10})
        messages = local_json("fog-receiver", "messages")[-10:]
        check("One traceable Edge device", len(messages) >= 10 and
              {m["device_id"] for m in messages} == {"edge-device-01"}, len(messages))
        sequences = [m["sequence_number"] for m in messages]
        check("Contiguous FIFO sequence", len(sequences) >= 10 and
              all(b == a + 1 for a, b in zip(sequences, sequences[1:])), sequences)
        identifiers = {m["message_id"] for m in messages}
        check("Unique received IDs", len(identifiers) == len(messages), len(identifiers))
        for service in ("edge-gateway", "unidirectional-gateway"):
            records = local_json(service, "metrics/runtime")["recent_records"]
            sent = {r["message_id"]: r for r in records if r["event"] == "transmitted"}
            valid = identifiers.issubset(sent)
            for identifier in identifiers & sent.keys():
                r = sent[identifier]
                stamps = [datetime.fromisoformat(r[field]) for field in
                          ("arrival_timestamp", "queue_entry_timestamp", "transmission_timestamp")]
                valid = valid and stamps == sorted(stamps) and r["message_size_bytes"] > 0 and r["queue_length"] >= 0
            check(f"Forward trace and instrumentation {service}", valid,
                  {"matched_ids": len(identifiers & sent.keys()), "received_ids": len(identifiers)})

        # A successful Edge-side request establishes the target is actually listening.
        control = docker(*compose, "exec", "-T", "edge-device", "python", "-c",
                         "import urllib.request; print(urllib.request.urlopen('http://edge-gateway:8000/health', timeout=3).status)")
        check("Edge Gateway reachable from Edge (control)", control == "200", control)
        targets = [{"service": service, "ip": network["IPAddress"]}
                   for service in ("edge-device", "edge-gateway")
                   for network in containers[service]["NetworkSettings"]["Networks"].values()]
        probes = docker(*compose, "exec", "-T", "fog-receiver", "python", "-m", "phase1.probe",
                        input_text=json.dumps({"targets": targets}))
        results.extend(json.loads(probes))
        if extra_checks:
            extra_checks(docker, compose, containers, check, args.output)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        check("Verification execution", False, str(exc))
    report = {"started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
              "project": f"software-data-diode-phase{phase}", "checks": results,
              "passed": bool(results) and all(r["passed"] for r in results)}
    destination = args.output / "verification.json"
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for result in results:
        print(f"{'PASS' if result['passed'] else 'FAIL'} {result['check']}: {result['detail']}")
    print(f"Report: {destination}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
