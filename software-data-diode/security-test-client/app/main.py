from __future__ import annotations

import asyncio
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import time
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from shared.models import PriorityLevel, SecureTelemetryEnvelope, TelemetryPayload
from shared.security import compute_payload_hash, load_private_key, sign_envelope, verify_audit_log


PERMITTED_TARGET_HOSTS = {"fog-receiver", "data-diode"}
CSV_FIELDS = (
    "scenario",
    "attack_type",
    "expected_result",
    "actual_result",
    "detected",
    "response_time",
    "timestamp",
)


@dataclass
class ScenarioResult:
    scenario: str
    attack_type: str
    expected_result: str
    actual_result: str
    detected: bool
    response_time: float
    timestamp: str


def validate_target_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in PERMITTED_TARGET_HOSTS:
        raise ValueError(f"security test target is not permitted: {url}")
    return url


def write_csv_report(path: str | Path, results: list[ScenarioResult]) -> None:
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.DictWriter(report_file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for result in results:
            row = asdict(result)
            row["detected"] = str(result.detected).lower()
            writer.writerow(row)


def tamper_audit_copy(source: str | Path, destination: str | Path) -> tuple[int, str]:
    source_path = Path(source)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_path, destination_path)

    lines = destination_path.read_text(encoding="utf-8").splitlines()
    tampered_line = 0
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        record = json.loads(line)
        record["result"] = "TAMPERED_BY_CONTROLLED_TEST"
        lines[index] = json.dumps(record, sort_keys=True)
        tampered_line = index + 1
        break
    if tampered_line == 0:
        raise ValueError("audit log contains no records to tamper with")

    destination_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    valid, reason = verify_audit_log(destination_path)
    if valid:
        raise RuntimeError("tampered audit copy unexpectedly passed verification")
    return tampered_line, reason


class SecurityTestRunner:
    def __init__(self) -> None:
        self.fog_url = validate_target_url(
            os.getenv("FOG_RECEIVER_URL", "http://fog-receiver:8000/receive")
        )
        self.diode_url = validate_target_url(
            os.getenv("DATA_DIODE_URL", "http://data-diode:8000/ingest")
        )
        self.reverse_path_url = validate_target_url(
            os.getenv(
                "REVERSE_PATH_URL",
                "http://fog-receiver:8000/security-test/reverse-path",
            )
        )
        self.runtime_url = validate_target_url(
            os.getenv("DIODE_RUNTIME_URL", "http://data-diode:8000/metrics/runtime")
        )
        self.private_key = load_private_key(
            os.getenv("EDGE_PRIVATE_KEY_PATH", "/run/secrets/edge_private_key.pem")
        )
        self.report_dir = Path(os.getenv("REPORT_DIR", "/reports"))
        self.audit_log_path = Path(
            os.getenv("FOG_AUDIT_LOG_PATH", "/logs/fog-receiver-audit.jsonl")
        )
        self.flood_requests = int(os.getenv("FLOOD_REQUESTS", "160"))
        self.expected_max_queue = int(os.getenv("EXPECTED_MAX_QUEUE_SIZE", "20"))
        self.run_id = uuid4().hex[:10]
        self.results: list[ScenarioResult] = []
        self.valid_attempts = 0
        self.valid_rejections = 0

    def envelope(
        self,
        device_suffix: str,
        sequence: int,
        *,
        priority: PriorityLevel = PriorityLevel.LOW,
        created_at: datetime | None = None,
        attributes: dict[str, str | int | float | bool] | None = None,
    ) -> SecureTelemetryEnvelope:
        payload = TelemetryPayload(
            temperature=25.0,
            humidity=50.0,
            status="controlled-security-test",
            event_type="security_validation",
            attributes=attributes or {},
        )
        envelope = SecureTelemetryEnvelope(
            message_id=uuid4(),
            device_id=f"security-test-{self.run_id}-{device_suffix}",
            created_at=created_at or datetime.now(timezone.utc),
            sequence_number=sequence,
            priority=priority,
            payload=payload,
            payload_hash=compute_payload_hash(payload),
            signature="unsigned",
        )
        return envelope.model_copy(update={"signature": sign_envelope(envelope, self.private_key)})

    async def post(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        json_body: object | None = None,
        content: str | None = None,
    ) -> tuple[httpx.Response | None, float, str]:
        started = time.perf_counter()
        try:
            response = await client.post(url, json=json_body, content=content)
        except httpx.HTTPError as exc:
            elapsed = time.perf_counter() - started
            return None, elapsed, f"CLIENT_ERROR:{type(exc).__name__}"
        elapsed = time.perf_counter() - started
        return response, elapsed, response_result(response)

    def add_result(
        self,
        scenario: str,
        attack_type: str,
        expected: str,
        actual: str,
        detected: bool,
        elapsed: float,
    ) -> None:
        self.results.append(
            ScenarioResult(
                scenario=scenario,
                attack_type=attack_type,
                expected_result=expected,
                actual_result=actual,
                detected=detected,
                response_time=round(elapsed, 6),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

    async def expect_response(
        self,
        client: httpx.AsyncClient,
        scenario: str,
        attack_type: str,
        expected: str,
        *,
        url: str | None = None,
        body: object | None = None,
        content: str | None = None,
    ) -> httpx.Response | None:
        response, elapsed, actual = await self.post(
            client,
            url or self.fog_url,
            json_body=body,
            content=content,
        )
        self.add_result(
            scenario,
            attack_type,
            expected,
            actual,
            actual == expected,
            elapsed,
        )
        return response

    async def valid_control(
        self,
        client: httpx.AsyncClient,
        suffix: str,
        sequence: int = 1,
    ) -> tuple[bool, float]:
        self.valid_attempts += 1
        response, elapsed, actual = await self.post(
            client,
            self.fog_url,
            json_body=self.envelope(suffix, sequence).model_dump(mode="json"),
        )
        accepted = response is not None and response.status_code == 200 and actual == "ACCEPTED"
        if not accepted:
            self.valid_rejections += 1
        return accepted, elapsed

    async def run_validation_attacks(self, client: httpx.AsyncClient) -> None:
        accepted, elapsed = await self.valid_control(client, "baseline")
        self.add_result(
            "valid_baseline",
            "VALID_CONTROL",
            "ACCEPTED",
            "ACCEPTED" if accepted else "REJECTED",
            accepted,
            elapsed,
        )

        tampered = self.envelope("tamper", 1).model_dump(mode="json")
        tampered["payload"]["temperature"] = 999.0
        await self.expect_response(
            client,
            "payload_tampering",
            "PAYLOAD_TAMPERING",
            "HASH_MISMATCH",
            body=tampered,
        )

        bad_signature = self.envelope("signature", 1).model_copy(update={"signature": "AAAA"})
        await self.expect_response(
            client,
            "signature_tampering",
            "SIGNATURE_TAMPERING",
            "INVALID_SIGNATURE",
            body=bad_signature.model_dump(mode="json"),
        )

        first_replay = self.envelope("replay", 100)
        self.valid_attempts += 1
        first_response, _, first_actual = await self.post(
            client, self.fog_url, json_body=first_replay.model_dump(mode="json")
        )
        if first_response is None or first_response.status_code != 200:
            self.valid_rejections += 1
        replay = self.envelope("replay", 99)
        replay_response = await self.expect_response(
            client,
            "replay_attack",
            "SEQUENCE_REPLAY",
            "REPLAY_DETECTED",
            body=replay.model_dump(mode="json"),
        )
        if first_actual != "ACCEPTED" and replay_response is not None:
            self.results[-1].detected = False
            self.results[-1].actual_result = f"SETUP_{first_actual}"

        duplicate = self.envelope("duplicate", 1)
        self.valid_attempts += 1
        first_response, _, first_actual = await self.post(
            client, self.fog_url, json_body=duplicate.model_dump(mode="json")
        )
        if first_response is None or first_response.status_code != 200:
            self.valid_rejections += 1
        duplicate_response = await self.expect_response(
            client,
            "duplicate_injection",
            "DUPLICATE_UUID",
            "DUPLICATE_MESSAGE",
            body=duplicate.model_dump(mode="json"),
        )
        if first_actual != "ACCEPTED" and duplicate_response is not None:
            self.results[-1].detected = False
            self.results[-1].actual_result = f"SETUP_{first_actual}"

        stale = self.envelope(
            "stale",
            1,
            created_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        await self.expect_response(
            client,
            "timestamp_manipulation",
            "STALE_TIMESTAMP",
            "EXPIRED_MESSAGE",
            body=stale.model_dump(mode="json"),
        )

        await self.expect_response(
            client,
            "schema_violation",
            "INVALID_SCHEMA",
            "INVALID_SCHEMA",
            body={"device_id": "missing-required-envelope-fields"},
        )

        oversized = self.envelope(
            "oversized",
            1,
            attributes={"padding": "X" * 20_000},
        )
        await self.expect_response(
            client,
            "oversized_payload",
            "OVERSIZED_PAYLOAD",
            "PAYLOAD_TOO_LARGE",
            url=self.diode_url,
            body=oversized.model_dump(mode="json"),
        )

    async def run_flood(self, client: httpx.AsyncClient) -> dict[str, float | int | bool]:
        baseline = await self.runtime_snapshot(client)
        baseline_low_drops = priority_metric(baseline, "LOW", "dropped_count")
        flood_started = time.perf_counter()
        flood_done = asyncio.Event()
        max_queue_observed = 0

        async def send_low(index: int) -> tuple[int, str]:
            await asyncio.sleep(index / max(self.flood_requests, 1))
            envelope = self.envelope(f"flood-{index}", 1, priority=PriorityLevel.LOW)
            response, _, actual = await self.post(
                client, self.diode_url, json_body=envelope.model_dump(mode="json")
            )
            return (response.status_code if response is not None else 0, actual)

        async def monitor_queue() -> None:
            nonlocal max_queue_observed
            while not flood_done.is_set():
                snapshot = await self.runtime_snapshot(client)
                queue = snapshot.get("queue", {}) if isinstance(snapshot, dict) else {}
                max_queue_observed = max(max_queue_observed, int(queue.get("queue_length", 0)))
                await asyncio.sleep(0.02)

        flood_task = asyncio.gather(
            *(send_low(index) for index in range(self.flood_requests))
        )
        monitor_task = asyncio.create_task(monitor_queue())

        await asyncio.sleep(0.2)
        valid_started = time.perf_counter()
        valid_results = await asyncio.gather(
            *(self.valid_control(client, f"during-flood-{index}") for index in range(10))
        )
        valid_elapsed = max(time.perf_counter() - valid_started, 0.000001)

        critical = self.envelope("critical", 1, priority=PriorityLevel.CRITICAL)
        critical_started = time.perf_counter()
        critical_status = "NOT_ACCEPTED"
        critical_accepted = False
        while time.perf_counter() - critical_started < 5:
            response, _, critical_status = await self.post(
                client, self.diode_url, json_body=critical.model_dump(mode="json")
            )
            if response is not None and response.status_code == 200:
                critical_accepted = True
                break
            await asyncio.sleep(0.05)

        flood_responses = await flood_task
        flood_done.set()
        await monitor_task
        critical_delivered = False
        if critical_accepted:
            critical_delivered = await wait_for_audit_message(
                self.audit_log_path,
                str(critical.message_id),
                timeout_seconds=8,
            )
        critical_latency = time.perf_counter() - critical_started

        final_snapshot = await self.runtime_snapshot(client)
        max_queue_observed = max(
            max_queue_observed,
            int(final_snapshot.get("queue", {}).get("queue_length", 0)),
        )
        final_low_drops = priority_metric(final_snapshot, "LOW", "dropped_count")
        status_counts: dict[int, int] = {}
        reason_counts: dict[str, int] = {}
        for status_code, reason in flood_responses:
            status_counts[status_code] = status_counts.get(status_code, 0) + 1
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

        rate_limited = reason_counts.get("RATE_LIMIT_EXCEEDED", 0)
        queue_full = reason_counts.get("QUEUE_FULL", 0)
        low_drops = max(final_low_drops - baseline_low_drops, 0)
        bounded = max_queue_observed <= self.expected_max_queue
        queue_pressured = queue_full > 0 or low_drops > 0
        flood_detected = rate_limited > 0 and bounded and queue_pressured
        flood_elapsed = time.perf_counter() - flood_started
        self.add_result(
            "message_flooding",
            "RATE_LIMIT_FLOOD",
            "RATE_LIMITED_AND_QUEUE_BOUNDED",
            (
                f"rate_limited={rate_limited};queue_full={queue_full};"
                f"max_queue={max_queue_observed};bounded={str(bounded).lower()}"
            ),
            flood_detected,
            flood_elapsed,
        )

        critical_progress = critical_accepted and critical_delivered and queue_pressured
        self.add_result(
            "low_priority_queue_exhaustion",
            "LOW_PRIORITY_EXHAUSTION",
            "CRITICAL_PROGRESS",
            (
                f"accepted={str(critical_accepted).lower()};"
                f"delivered={str(critical_delivered).lower()};"
                f"low_drops={low_drops};submit_result={critical_status}"
            ),
            critical_progress,
            critical_latency,
        )

        valid_accepted = sum(1 for accepted, _ in valid_results if accepted)
        self.add_result(
            "valid_traffic_during_attack",
            "VALID_CONTROL",
            "ACCEPTED",
            f"accepted={valid_accepted}/10",
            valid_accepted == 10,
            valid_elapsed,
        )
        return {
            "flood_requests": self.flood_requests,
            "rate_limited_requests": rate_limited,
            "queue_full_requests": queue_full,
            "maximum_queue_size_observed": max_queue_observed,
            "configured_queue_capacity": self.expected_max_queue,
            "low_priority_drops": low_drops,
            "valid_traffic_throughput_during_attack": valid_accepted / valid_elapsed,
            "critical_traffic_latency_during_flood_seconds": critical_latency,
            "critical_delivered": critical_delivered,
        }

    async def runtime_snapshot(self, client: httpx.AsyncClient) -> dict[str, object]:
        try:
            response = await client.get(self.runtime_url)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError):
            return {}

    async def reverse_path_test(self, client: httpx.AsyncClient) -> dict[str, object]:
        started = time.perf_counter()
        try:
            response = await client.post(self.reverse_path_url)
            response.raise_for_status()
            evidence = response.json()
            detected = bool(evidence.get("all_blocked"))
            actual = "REVERSE_PATH_BLOCKED" if detected else "REVERSE_PATH_REACHABLE"
        except (httpx.HTTPError, ValueError) as exc:
            evidence = {"error": type(exc).__name__}
            detected = False
            actual = "PROBE_FAILED"
        self.add_result(
            "reverse_path_validation",
            "FOG_TO_EDGE_CONNECTIVITY",
            "REVERSE_PATH_BLOCKED",
            actual,
            detected,
            time.perf_counter() - started,
        )
        return evidence

    def audit_attack(self) -> None:
        started = time.perf_counter()
        try:
            line, reason = tamper_audit_copy(
                self.audit_log_path,
                self.report_dir / "tampered-fog-receiver-audit.jsonl",
            )
            expected = f"HASH_CHAIN_BREAK_AT_LINE_{line}"
            detected = reason.startswith(f"line {line}:")
            actual = reason
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            expected = "HASH_CHAIN_BREAK"
            detected = False
            actual = f"AUDIT_TEST_ERROR:{type(exc).__name__}"
        self.add_result(
            "audit_log_tampering",
            "AUDIT_HASH_CHAIN_MODIFICATION",
            expected,
            actual,
            detected,
            time.perf_counter() - started,
        )

    async def run(self) -> bool:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        async with httpx.AsyncClient(timeout=10.0, limits=httpx.Limits(max_connections=200)) as client:
            await self.run_validation_attacks(client)
            flood_metrics = await self.run_flood(client)
            reverse_evidence = await self.reverse_path_test(client)
        self.audit_attack()

        attacks = [result for result in self.results if result.attack_type != "VALID_CONTROL"]
        detection_latencies = [result.response_time for result in attacks if result.detected]
        metrics = {
            "run_id": self.run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_detection_rate": (
                sum(1 for result in attacks if result.detected) / len(attacks) if attacks else 0.0
            ),
            "false_rejection_rate": (
                self.valid_rejections / self.valid_attempts if self.valid_attempts else 0.0
            ),
            "average_detection_latency_seconds": (
                sum(detection_latencies) / len(detection_latencies)
                if detection_latencies
                else 0.0
            ),
            "valid_attempts": self.valid_attempts,
            "valid_rejections": self.valid_rejections,
            **flood_metrics,
        }
        write_csv_report(self.report_dir / "security-test-results.csv", self.results)
        (self.report_dir / "security-metrics.json").write_text(
            json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (self.report_dir / "reverse-path-results.json").write_text(
            json.dumps(reverse_evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"results": [asdict(item) for item in self.results], "metrics": metrics}))
        return all(result.detected for result in self.results)


def response_result(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"HTTP_{response.status_code}"
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict) and detail.get("reason"):
        return str(detail["reason"])
    if isinstance(body, dict) and body.get("status"):
        return str(body["status"]).upper()
    return f"HTTP_{response.status_code}"


def priority_metric(snapshot: dict[str, object], priority: str, metric: str) -> int:
    traffic = snapshot.get("traffic", {})
    if not isinstance(traffic, dict):
        return 0
    by_priority = traffic.get("by_priority", {})
    if not isinstance(by_priority, dict):
        return 0
    values = by_priority.get(priority, {})
    return int(values.get(metric, 0)) if isinstance(values, dict) else 0


async def wait_for_audit_message(path: Path, message_id: str, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with path.open("r", encoding="utf-8") as audit_file:
                for line in audit_file:
                    if message_id in line and '"result": "ACCEPTED"' in line:
                        return True
        except OSError:
            pass
        await asyncio.sleep(0.05)
    return False


async def async_main() -> int:
    runner = SecurityTestRunner()
    return 0 if await runner.run() else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))
