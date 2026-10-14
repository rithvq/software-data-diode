"""Fixed-cardinality persisted coverage gauges, refreshed on every scrape."""
from prometheus_client import Gauge


class CoverageMetrics:
    def __init__(self, registry):
        self.available = Gauge("coverage_metrics_available", "1 when Fog persistence was queried successfully.", registry=registry)
        self.bytes = Gauge("coverage_evidence_received_bytes", "Persisted unique complete part payload bytes; excludes repeats lost in transit.", registry=registry)
        self.pending = Gauge("coverage_pending_reserved_bytes", "Latest signed sender reserved bytes, not an Edge query.", registry=registry)
        self.obligations = Gauge("coverage_pending_obligations", "Latest signed sender evidence obligations with reserved bytes.", registry=registry)
        self.sender_age = Gauge("coverage_sender_state_age_seconds", "Age of latest persisted signed sender state.", registry=registry)
        self.fraction = Gauge("coverage_evidence_forward_fraction", "Matched modeled local-grant bytes since N8 accounting start; not receipt.", registry=registry)
        self.verdicts = Gauge("coverage_rule_windows", "Historical latest rule-window verdict totals.", ("truth",), registry=registry)
        self.failures = Gauge("coverage_verification_failures", "Persisted non-valid verification outcomes; not unique attackers.", registry=registry)
        self.unavailable()

    def update(self, document):
        from datetime import datetime, timezone
        self.available.set(1)
        self.bytes.set(document["cost"]["received_evidence_bytes"])
        counts = document["counts"]
        for truth, name in (("TRUE", "positive"), ("FALSE", "negative"), ("UNKNOWN", "unknown")):
            self.verdicts.labels(truth).set(counts[name])
        sender = document["sender"]
        self.pending.set(sender["pending_reserved_bytes"] if sender["pending_reserved_bytes"] is not None else float("nan"))
        self.obligations.set(sender["pending_obligations"] if sender["pending_obligations"] is not None else float("nan"))
        self.fraction.set(sender["evidence_fraction"] if sender["evidence_fraction"] is not None else float("nan"))
        stamp = sender.get("reported_at")
        if isinstance(stamp, str):
            stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        self.sender_age.set(max(0, (datetime.now(timezone.utc)-stamp).total_seconds()) if stamp else float("nan"))
        self.failures.set(document["verification_failures"])

    def unavailable(self):
        self.available.set(0)
        for metric in (self.bytes, self.pending, self.obligations, self.sender_age, self.fraction, self.failures):
            metric.set(float("nan"))
        for truth in ("TRUE", "FALSE", "UNKNOWN"):
            self.verdicts.labels(truth).set(float("nan"))
