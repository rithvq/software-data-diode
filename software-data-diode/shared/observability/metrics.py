from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST


LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)


class ServiceMetrics:
    """An isolated Prometheus registry safe for repeated service-module tests."""

    def __init__(self, service: str) -> None:
        self.service = service
        self.registry = CollectorRegistry()
        self.messages_received = Counter(
            "messages_received_total",
            "Messages accepted at a service boundary.",
            ("service", "device_id", "priority"),
            registry=self.registry,
        )
        self.messages_forwarded = Counter(
            "messages_forwarded_total",
            "Messages forwarded to the next service.",
            ("service", "device_id", "priority"),
            registry=self.registry,
        )
        self.messages_rejected = Counter(
            "messages_rejected_total",
            "Messages rejected by reason.",
            ("service", "reason", "device_id"),
            registry=self.registry,
        )
        self.queue_size = Gauge(
            "queue_size", "Current bounded queue size.", ("service",), registry=self.registry
        )
        self.policy_actions = Counter(
            "information_policy_actions_total", "Explainable local information policy decisions.",
            ("service", "action"), registry=self.registry,
        )
        self.predicted_queue = Gauge(
            "predicted_queue_size", "Forecast local queue length before reductions.",
            ("service",), registry=self.registry,
        )
        self.information_utility = Histogram(
            "information_utility_score", "Information utility at local policy decisions.",
            ("service", "priority"), buckets=(-10, -1, 0, 1, 2, 4, 8, 16, 32, 64),
            registry=self.registry,
        )
        self.queue_wait = Histogram(
            "queue_wait_seconds",
            "Time spent waiting in the scheduler queue.",
            ("service", "priority"),
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.end_to_end_latency = Histogram(
            "end_to_end_latency_seconds",
            "Observed end-to-end processing latency.",
            ("service", "priority"),
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.signature_failures = Counter(
            "signature_failures_total",
            "Signature verification failures.",
            ("service",),
            registry=self.registry,
        )
        self.replay_attempts = Counter(
            "replay_attempts_total",
            "Replay and duplicate attempts.",
            ("service", "reason"),
            registry=self.registry,
        )
        self.filtered_bytes = Counter(
            "filtered_bytes_total",
            "Bytes removed by Edge filtering.",
            ("service", "device_id"),
            registry=self.registry,
        )
        self.transmitted_bytes = Counter(
            "transmitted_bytes_total",
            "Bytes transmitted to the next tier.",
            ("service",),
            registry=self.registry,
        )
        self.scheduler_score = Histogram(
            "scheduler_score",
            "Adaptive scheduler score distribution.",
            ("service", "priority"),
            buckets=(0, 5, 10, 20, 40, 80, 160, 320, 640),
            registry=self.registry,
        )
        self.dropped_messages = Counter(
            "dropped_messages_total",
            "Messages dropped by queue or forwarding controls.",
            ("service", "priority"),
            registry=self.registry,
        )
        self.service_health = Gauge(
            "service_health", "Service health (1 healthy, 0 unhealthy).", ("service",), registry=self.registry
        )
        self.audit_log_valid = Gauge(
            "audit_log_valid", "Audit hash chain state (1 valid, 0 invalid).", ("service",), registry=self.registry
        )
        self.service_health.labels(service).set(1)

    def received(self, device_id: str = "", priority: object = "") -> None:
        self.messages_received.labels(self.service, device_id, str(priority)).inc()

    def forwarded(self, device_id: str = "", priority: object = "") -> None:
        self.messages_forwarded.labels(self.service, device_id, str(priority)).inc()

    def rejected(self, reason: object, device_id: str = "") -> None:
        self.messages_rejected.labels(self.service, str(reason), device_id).inc()

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST
