"""Capture reproducible, credential-free N0 evidence without changing services."""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from scripts.docker_support import docker_executable

SOURCE_DIRS = (
    "shared", "edge-device", "edge-gateway", "data-diode", "fog-receiver",
    "event-processor", "fog-analytics", "alert-engine", "monitoring-api",
    "dashboard", "security-test-client", "phase1", "phase2", "scripts",
    "tests", "config", "database", "observability", "experiments", "docs",
)
EXCLUDED_DIRS = {"__pycache__", ".venv", ".pytest_cache", "results", "evidence", "reports"}
SUFFIXES = {".py", ".json", ".sql", ".yml", ".yaml", ".md", ".toml", ".ini", ".txt"}
PUBLIC_CONFIG_NAMES = {"Dockerfile", ".dockerignore", ".gitignore", ".coveragerc"}
PUBLIC_SETTINGS = (
    "INFORMATION_POLICY_ENABLED", "INFORMATION_POLICY_CONFIG", "SCHEDULER_MODE",
    "MAX_QUEUE_SIZE", "MAX_PAYLOAD_BYTES", "MAX_MESSAGES_PER_SECOND",
    "EGRESS_MESSAGES_PER_SECOND", "FORWARD_TIMEOUT_SECONDS",
    "DASHBOARD_REFRESH_SECONDS", "EDGE_GATEWAY_PORT", "DASHBOARD_PORT",
    "GRAFANA_PORT", "PROMETHEUS_EDGE_PORT", "PROMETHEUS_FOG_PORT",
)


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def source_fingerprints(root: Path) -> dict:
    candidates = [item for item in root.iterdir() if item.is_file()]
    for name in SOURCE_DIRS:
        directory = root / name
        if directory.exists():
            candidates.extend(directory.rglob("*"))
    rows = []
    for path in sorted(set(candidates)):
        relative = path.relative_to(root)
        if path.is_symlink() or any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if not path.is_file() or (path.suffix not in SUFFIXES and path.name not in PUBLIC_CONFIG_NAMES):
            continue
        if path.name.startswith(".env") and path.name != ".env.example":
            continue
        data = path.read_bytes()
        rows.append({"path": relative.as_posix(), "size_bytes": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()})
    rows.sort(key=lambda item: item["path"])
    return {"algorithm": "SHA-256", "files": rows, "file_count": len(rows),
            "aggregate_sha256": canonical_digest(rows),
            "exclusions": "Secrets, real .env files, runtime/generated results, evidence and reports; symlinks are not followed."}


def environment_summary(root: Path) -> dict:
    values = {}
    path = root / ".env"
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    return {
        "env_file_present": path.exists(),
        "public_settings": {name: values[name] for name in PUBLIC_SETTINGS if name in values},
        "required_secret_present": {name: bool(values.get(name)) for name in
                                    ("POSTGRES_PASSWORD", "OBSERVABILITY_TOKEN", "GRAFANA_ADMIN_PASSWORD")},
        "signing_key_files_present": {name: (root / "secrets" / name).is_file() for name in
                                      ("edge_private_key.pem", "edge_public_key.pem")},
        "secret_values_and_digests_exported": False,
    }


def dependency_summary(root: Path) -> dict:
    installed = sorted(({"name": item.metadata["Name"], "version": item.version}
                        for item in metadata.distributions() if item.metadata.get("Name")),
                       key=lambda item: item["name"].lower())
    normalize = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    versions = {normalize(item["name"]): item["version"] for item in installed}
    pins = []
    for line in (root / "constraints.txt").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+)", line.strip())
        if match:
            name, expected = match.groups()
            actual = versions.get(normalize(name))
            pins.append({"name": name, "pinned": expected, "installed": actual,
                         "matches": expected == actual})
    return {"installed": installed, "direct_constraint_comparison": pins,
            "direct_constraint_mismatches": [row["name"] for row in pins if not row["matches"]]}


def test_summary(path: Path | None) -> dict:
    if path is None:
        return {"status": "not_supplied"}
    suites = ET.parse(path).getroot()
    cases = list(suites.iter("testcase"))
    counts = {"tests": len(cases), "failures": 0, "errors": 0, "skipped": 0}
    for case in cases:
        for key, tag in (("failures", "failure"), ("errors", "error"), ("skipped", "skipped")):
            counts[key] += int(case.find(tag) is not None)
    counts["passed"] = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    return {"status": "passed" if cases and not (counts["failures"] or counts["errors"]) else "not_passed",
            "junit_file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "counts": counts, "test_cases": [{"class": case.get("classname"), "name": case.get("name")}
                                             for case in cases]}


def compose_summary(root: Path) -> dict:
    documents = {}
    for path in sorted(root.glob("docker-compose*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        services = {}
        for name, value in document.get("services", {}).items():
            networks = value.get("networks", [])
            services[name] = {"profiles": value.get("profiles", []),
                              "networks": list(networks), "ports": value.get("ports", []),
                              "has_healthcheck": bool(value.get("healthcheck")),
                              "has_build": bool(value.get("build")), "image": value.get("image")}
        documents[path.name] = {"services": services, "networks": document.get("networks", {}),
                                "volumes": list(document.get("volumes", {}))}
    return documents


def entrypoint_summary(root: Path) -> dict:
    entries = {}
    for path in sorted(root.glob("*/app/main.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        routes = []
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr in {"get", "post", "put", "delete", "patch"}
                        and decorator.args and isinstance(decorator.args[0], ast.Constant)):
                    routes.append({"method": decorator.func.attr.upper(), "path": decorator.args[0].value,
                                   "function": node.name, "line": node.lineno})
        entries[path.relative_to(root).as_posix()] = routes
    return entries


def run_readonly(command: list[str], *, root: Path, timeout: int = 20) -> str:
    result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout, check=False)
    if result.returncode:
        # Docker/Compose stderr can contain expanded configuration; do not export it.
        raise RuntimeError(f"read-only command exited with code {result.returncode}")
    return result.stdout


def sanitize_container(item: dict) -> dict:
    labels = item.get("Config", {}).get("Labels") or {}
    state = item.get("State") or {}
    return {
        "name": item.get("Name", "").lstrip("/"),
        "project": labels.get("com.docker.compose.project"),
        "service": labels.get("com.docker.compose.service"),
        "image_id": item.get("Image"),
        "state": state.get("Status"), "running": state.get("Running"), "exit_code": state.get("ExitCode"),
        "health_status": (state.get("Health") or {}).get("Status"),
        "configured_networks": sorted((item.get("NetworkSettings", {}).get("Networks") or {}).keys()),
        "port_bindings": item.get("HostConfig", {}).get("PortBindings"),
        "named_volume_mounts": [{"name": mount.get("Name"), "destination": mount.get("Destination"),
                                  "read_write": mount.get("RW")}
                                 for mount in item.get("Mounts", []) if mount.get("Type") == "volume"],
    }


def docker_summary(root: Path, executable: str | None) -> dict:
    observation = {"mode": "read-only", "status": "unavailable", "operations": []}
    try:
        cli = executable or docker_executable()
        version = json.loads(run_readonly([cli, "version", "--format", "{{json .}}"], root=root))
        observation.update(status="available", client_version=version.get("Client", {}).get("Version"),
                           engine_version=version.get("Server", {}).get("Version"),
                           context=version.get("Client", {}).get("Context"))
        observation["compose_version"] = run_readonly([cli, "compose", "version", "--short"], root=root).strip()
        observation["operations"].extend(["version", "compose version"])
        rows = run_readonly([cli, "ps", "-a", "--filter", "label=com.docker.compose.project",
                             "--format", "{{json .}}"], root=root)
        candidates = [json.loads(line) for line in rows.splitlines() if line.strip()]
        ids = [row["ID"] for row in candidates
               if re.fullmatch(r"software-data-diode(?:-[A-Za-z0-9_-]+)?", row.get("Names", ""))]
        observation["operations"].append("ps -a (project containers selected)")
        containers = json.loads(run_readonly([cli, "inspect", *ids], root=root)) if ids else []
        observation["containers"] = [sanitize_container(item) for item in containers]
        observation["operations"].append("inspect (selected container fields exported)")
        names = run_readonly([cli, "network", "ls", "--filter", "name=software-data-diode",
                              "--format", "{{.Name}}"], root=root).splitlines()
        names = [name for name in names if re.fullmatch(r"software-data-diode(?:[-_][A-Za-z0-9_-]+)?", name)]
        networks = json.loads(run_readonly([cli, "network", "inspect", *names], root=root)) if names else []
        observation["networks"] = [{"name": item["Name"], "internal": item.get("Internal"),
                                    "driver": item.get("Driver"), "subnets": item.get("IPAM", {}).get("Config", []),
                                    "active_container_names": sorted(value.get("Name", "") for value in
                                                                     (item.get("Containers") or {}).values())}
                                   for item in networks]
        observation["operations"].extend(["network ls", "network inspect"])
        observation["running_project_container_count"] = sum(bool(row["running"]) for row in observation["containers"])
        run_readonly([cli, "compose", "-p", "software-data-diode", "--profile", "full",
                      "config", "--quiet"], root=root)
        observation["compose_validation"] = "passed"
        observation["operations"].append("compose config --quiet")
    except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        observation["status"] = "partial" if observation["status"] == "available" else "unavailable"
        observation["error_type"] = type(exc).__name__
        observation["reason"] = "Read-only Docker access was unavailable, timed out, or returned an error; no service mutation was attempted."
    return observation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--test-report", type=Path)
    parser.add_argument("--phase-test-report", type=Path)
    parser.add_argument("--docker-path")
    parser.add_argument("--skip-docker", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.relative_to(PROJECT_ROOT)
    if output.exists():
        raise SystemExit("Refusing to overwrite an existing baseline manifest")
    started_at = datetime.now(timezone.utc).isoformat()
    checks = []
    for arguments in ([], ["--example"]):
        run_readonly([sys.executable, "scripts/validate_config.py", *arguments], root=PROJECT_ROOT)
        checks.append({"command": [".venv/Scripts/python.exe", "scripts/validate_config.py", *arguments],
                       "exit_code": 0})
    git = {}
    try:
        git = {"head": run_readonly(["git", "rev-parse", "HEAD"], root=PROJECT_ROOT).strip(),
               "project_status": run_readonly(["git", "status", "--porcelain", "--", "."], root=PROJECT_ROOT).splitlines()}
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        git = {"status": "unavailable"}
    document = {
        "schema_version": 1, "phase": "N0", "project": "software-data-diode",
        "started_at_utc": started_at, "client_timezone": "Asia/Calcutta",
        "python": {"version": platform.python_version(), "platform": platform.platform()},
        "git": git, "fingerprints": source_fingerprints(PROJECT_ROOT),
        "environment": environment_summary(PROJECT_ROOT), "dependencies": dependency_summary(PROJECT_ROOT),
        "configuration_checks": checks, "test_evidence": test_summary(args.test_report),
        "n0_tool_test_evidence": test_summary(args.phase_test_report),
        "compose_inventory": compose_summary(PROJECT_ROOT), "service_routes": entrypoint_summary(PROJECT_ROOT),
        "docker": {"status": "skipped", "mode": "read-only"} if args.skip_docker else docker_summary(PROJECT_ROOT, args.docker_path),
        "runtime_features_added": [], "completed_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print(json.dumps({"manifest": str(output.relative_to(PROJECT_ROOT)),
                      "source_files": document["fingerprints"]["file_count"],
                      "tests": document["test_evidence"].get("counts"),
                      "constraint_mismatches": document["dependencies"]["direct_constraint_mismatches"],
                      "docker_status": document["docker"]["status"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
