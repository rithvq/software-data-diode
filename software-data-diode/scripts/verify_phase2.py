"""Phase 2 extends the Phase 1 live delivery/isolation checks with local security probes."""

import csv
import json
import time

from verify_phase1 import main


def security_checks(docker, compose, containers, check, output):
    for role in ("edge-device", "unidirectional-gateway", "fog-receiver"):
        mounts = containers[role]["Mounts"]
        check(f"No private volume {role}", not any(m["Destination"] == "/private" for m in mounts),
              [m["Destination"] for m in mounts])
    mounts = containers["fog-receiver"]["Mounts"]
    check("Fog public key mount is read-only", any(m["Destination"] == "/public" and not m["RW"] for m in mounts),
          "public verification volume only")
    for result in json.loads(docker(*compose, "exec", "-T", "fog-receiver", "python", "-m", "phase2.probe", "public")):
        check(result["check"], result["passed"], result["detail"])
    attacks = json.loads(docker(*compose, "exec", "-T", "edge-gateway", "python", "-m", "phase2.probe", "attacks"))
    (output / "security-results.json").write_text(json.dumps(attacks, indent=2), encoding="utf-8")
    with (output / "security-results.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(attacks[0]))
        writer.writeheader()
        writer.writerows(attacks)
    for result in attacks:
        check(result["scenario"], result["detected"], result["actual_result"])
    for role in ("edge-gateway", "unidirectional-gateway", "fog-receiver"):
        for result in json.loads(docker(*compose, "exec", "-T", role, "python", "-m", "phase2.probe", "audit")):
            check(f"{role}: {result['check']}", result["passed"], result["detail"])
    code = "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/metrics/runtime').read().decode())"
    def count():
        metrics = json.loads(docker(*compose, "exec", "-T", "fog-receiver", "python", "-c", code))
        return metrics["security"].get("accepted_messages", 0)
    before = count()
    time.sleep(3)
    after = count()
    check("Valid delivery continues after probes", after > before, {"before": before, "after": after})
    metrics = json.loads(docker(*compose, "exec", "-T", "unidirectional-gateway", "python", "-c", code))
    check("Queue remains bounded", metrics["queue_length"] <= metrics["capacity"], metrics["queue_length"])


if __name__ == "__main__":
    raise SystemExit(main(phase=2, extra_checks=security_checks))
