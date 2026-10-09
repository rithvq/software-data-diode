"""Deterministic information preservation using Edge-local observations only.

No transport client, receiver response, or Fog metric is accepted by this module.
The same engine is used by the live gateway and the discrete-event experiments.
"""
from __future__ import annotations

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
import math
from pathlib import Path
from typing import Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shared.models import AggregationSummary, EdgeTelemetryMessage, PriorityLevel


class PolicyAction(StrEnum):
    SEND = "SEND"
    DELAY = "DELAY"
    AGGREGATE = "AGGREGATE"
    SAMPLE = "SAMPLE"
    SUPERSEDE = "SUPERSEDE"
    DROP = "DROP"


class UtilityWeights(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    priority: float = Field(default=4, ge=0)
    novelty: float = Field(default=3, ge=0)
    freshness: float = Field(default=1, ge=0)
    security_risk: float = Field(default=4, ge=0)
    waiting_age: float = Field(default=1, ge=0)
    starvation: float = Field(default=2, ge=0)
    transmission_cost: float = Field(default=0.2, ge=0)
    obsolescence: float = Field(default=2, ge=0)


class InformationPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    weights: UtilityWeights = Field(default_factory=UtilityWeights)
    strategy: Literal["fifo", "priority", "utility", "density_under_pressure"] = "utility"
    reduction_enabled: bool = True
    prediction_enabled: bool = True
    max_queue_size: int = Field(default=250, gt=0)
    link_bytes_per_second: float = Field(default=16384, gt=0)
    messages_per_second: float = Field(default=25, gt=0)
    envelope_overhead_bytes: int = Field(default=512, ge=0)
    max_message_bytes: int = Field(default=8192, gt=0)
    window_seconds: float = Field(default=10, ge=1)
    prediction_horizon_seconds: float = Field(default=5, gt=0)
    freshness_seconds: float = Field(default=120, gt=0)
    starvation_seconds: float = Field(default=15, gt=0)
    low_novelty_threshold: float = Field(default=0.15, ge=0, le=1)
    preserve_novelty_threshold: float = Field(default=0.75, gt=0, le=1)
    elevated_threshold: float = Field(default=0.5, gt=0, lt=1)
    congested_threshold: float = Field(default=0.75, gt=0, lt=1)
    critical_threshold: float = Field(default=0.9, gt=0, le=1)
    sample_every: int = Field(default=4, ge=1)
    aggregation_max_samples: int = Field(default=5, ge=2, le=100)
    max_streams: int = Field(default=1024, ge=1)
    security_events: tuple[str, ...] = ("intrusion", "attack", "intrusion_detected")
    routine_events: tuple[str, ...] = (
        "telemetry", "resource", "network", "security", "industrial_process",
        "environmental_telemetry", "system_telemetry", "network_telemetry",
        "security_telemetry", "industrial_telemetry",
    )
    security_scales: dict[str, float] = Field(default_factory=lambda: {
        "failed_logins": 5, "blocked_connections": 10,
    })
    novelty_scales: dict[str, dict[str, float]] = Field(default_factory=lambda: {
        "environmental": {"temperature": 5, "humidity": 10, "air_quality_index": 50},
        "system": {"cpu_usage": 20, "memory_usage": 20, "load_average": 3},
        "network": {"packets_per_second": 3000, "network_latency_ms": 100,
                    "packet_loss_percent": 2},
        "security": {"failed_logins": 3, "blocked_connections": 5},
        "industrial": {"pressure_bar": 4, "vibration_mm_s": 3, "rpm": 300},
    })

    @model_validator(mode="after")
    def validate_scales(self):
        if not self.elevated_threshold < self.congested_threshold < self.critical_threshold:
            raise ValueError("congestion thresholds must be strictly increasing")
        if self.low_novelty_threshold >= self.preserve_novelty_threshold:
            raise ValueError("low novelty must be below preservation threshold")
        for scales in [self.security_scales, *self.novelty_scales.values()]:
            if any(not math.isfinite(x) or x <= 0 for x in scales.values()):
                raise ValueError("metric scales must be finite and positive")
        if set(self.novelty_scales) != {"environmental", "system", "network", "security", "industrial"}:
            raise ValueError("novelty scales must cover all five telemetry types")
        return self

    @classmethod
    def from_file(cls, path: str | Path):
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))


@dataclass
class Candidate:
    message_id: str
    message: EdgeTelemetryMessage
    priority: PriorityLevel
    enqueued_at: float
    generated_at: float
    size_bytes: int
    protected: bool
    source_ids: tuple[str, ...]
    generated_bytes: int


def serialized_size(message: EdgeTelemetryMessage) -> int:
    return len(message.model_dump_json().encode("utf-8"))


def numeric_values(message: EdgeTelemetryMessage) -> dict[str, float]:
    values = dict(message.measurements)
    for name in ("temperature", "humidity", "cpu_usage", "memory_usage"):
        value = getattr(message, name)
        if value is not None:
            values[name] = float(value)
    return values


class LocalStateEstimator:
    def __init__(self, config: InformationPolicyConfig) -> None:
        self.config = config
        # One-second buckets keep state bounded even during a flood.
        self.buckets: OrderedDict[int, Counter] = OrderedDict()
        self.started_at: float | None = None
        self.previous_queue: tuple[float, int] | None = None
        self.queue_growth = 0.0

    def record(self, now: float, kind: str, size: int = 0, priority: str = "", service: float = 0) -> None:
        if self.started_at is None:
            self.started_at = now
        bucket = self.buckets.setdefault(math.floor(now), Counter())
        bucket[kind] += 1
        bucket[f"{kind}_bytes"] += size
        if kind == "arrival":
            bucket[f"priority_{priority}"] += 1
        if kind == "dispatch":
            bucket["service_seconds"] += service
        self._prune(now)

    def _prune(self, now: float) -> None:
        while self.buckets and next(iter(self.buckets)) < math.floor(now - self.config.window_seconds):
            self.buckets.popitem(last=False)

    def snapshot(self, now: float, queue_length: int) -> dict[str, object]:
        self._prune(now)
        total = Counter()
        recent = Counter()
        for second, bucket in self.buckets.items():
            total.update(bucket)
            if second >= math.floor(now - 1):
                recent.update(bucket)
        elapsed = max(1.0, min(self.config.window_seconds, now - (self.started_at if self.started_at is not None else now)))
        arrivals = total["arrival"]
        mean_size = total["arrival_bytes"] / arrivals if arrivals else 512.0
        capacity = min(self.config.messages_per_second, self.config.link_bytes_per_second / max(mean_size, 1))
        arrival_rate = arrivals / elapsed
        drain_rate = total["dispatch"] / elapsed
        burst_rate = recent["arrival"] / min(elapsed, 2.0)
        growth = max(arrival_rate - capacity, burst_rate - capacity, self.queue_growth, 0.0)
        predicted = queue_length + growth * self.config.prediction_horizon_seconds
        utilization = queue_length / self.config.max_queue_size
        pressure = max(utilization, predicted / self.config.max_queue_size) if self.config.prediction_enabled else utilization
        state = "NORMAL"
        for threshold, label in (
            (self.config.elevated_threshold, "ELEVATED"),
            (self.config.congested_threshold, "CONGESTED"),
            (self.config.critical_threshold, "CRITICAL"),
        ):
            if pressure >= threshold:
                state = label
        return {
            "arrival_rate": arrival_rate, "drain_rate": drain_rate,
            "configured_service_rate": capacity, "queue_length": queue_length,
            "queue_growth_rate": self.queue_growth, "queue_utilization": utilization,
            "average_message_size": mean_size,
            "service_time_seconds": total["service_seconds"] / max(total["dispatch"], 1),
            "burst_intensity": burst_rate / max(arrival_rate, 0.001),
            "predicted_queue_length": predicted, "congestion_state": state,
            "drop_rate": total["drop"] / elapsed,
            "aggregation_rate": total["aggregate"] / elapsed,
            "priority_distribution": {p.value: total[f"priority_{p.value}"] / max(arrivals, 1) for p in PriorityLevel},
        }

    def observe_queue(self, now: float, queue_length: int) -> None:
        if self.previous_queue is not None and now > self.previous_queue[0]:
            self.queue_growth = (queue_length - self.previous_queue[1]) / max(now - self.previous_queue[0], 1.0)
        self.previous_queue = (now, queue_length)


class InformationEngine:
    def __init__(self, config: InformationPolicyConfig, on_decision: Callable[[dict], None] | None = None):
        self.config = config
        self.local = LocalStateEstimator(config)
        self.queue: list[Candidate] = []
        self.last_dispatched: OrderedDict[tuple, EdgeTelemetryMessage] = OrderedDict()
        self.sample_counts: OrderedDict[tuple, int] = OrderedDict()
        self.next_dispatch_at = 0.0
        self.decisions: deque[dict] = deque(maxlen=100)
        self.action_counts: Counter = Counter()
        self.generated_bytes = 0
        self.dispatched_bytes = 0
        self.on_decision = on_decision

    def configure_local_link(self, bytes_per_second: float) -> None:
        """Apply an operator/testbed link setting, never a receiver recommendation."""
        document = self.config.model_dump()
        document["link_bytes_per_second"] = bytes_per_second
        self.config = InformationPolicyConfig.model_validate(document)
        self.local.config = self.config

    @staticmethod
    def stream(message: EdgeTelemetryMessage) -> tuple:
        return (message.device_id, message.telemetry_type.value, message.event_type,
                tuple(sorted(message.attributes.items())))

    def novelty(self, message: EdgeTelemetryMessage) -> float:
        previous = self.last_dispatched.get(self.stream(message))
        if previous is None:
            return 1.0
        if message.status != previous.status:
            return 1.0
        values, old = numeric_values(message), numeric_values(previous)
        if values.keys() != old.keys():
            return 1.0
        scales = self.config.novelty_scales[message.telemetry_type.value]
        return min(1.0, max((abs(values[k] - old[k]) / scales.get(k, max(abs(old[k]), 1.0)) for k in values), default=0.0))

    def security_risk(self, message: EdgeTelemetryMessage) -> float:
        text = f"{message.event_type} {message.status}".lower()
        if any(event.lower() in text for event in self.config.security_events):
            return 1.0
        return min(1.0, max((message.measurements.get(k, 0) / scale for k, scale in self.config.security_scales.items()), default=0))

    def utility(self, item: Candidate, now: float, obsolete: bool = False) -> dict[str, object]:
        waiting = max(now - item.enqueued_at, 0)
        age = max(now - item.generated_at, 0)
        service = max(1 / self.config.messages_per_second, item.size_bytes / self.config.link_bytes_per_second)
        terms = {
            "priority": {PriorityLevel.LOW: 0.25, PriorityLevel.MEDIUM: 0.5, PriorityLevel.HIGH: 0.75, PriorityLevel.CRITICAL: 1}[item.priority],
            "novelty": self.novelty(item.message),
            "freshness": 1.0 if item.protected else math.exp(-age / self.config.freshness_seconds),
            "security_risk": self.security_risk(item.message),
            "waiting_age": waiting / self.config.starvation_seconds,
            "starvation": max(waiting / self.config.starvation_seconds - 1, 0),
            "transmission_cost": service,
            "obsolescence": float(obsolete or (not item.protected and age > self.config.freshness_seconds)),
        }
        contributions = {key: value * getattr(self.config.weights, key) * (-1 if key in {"transmission_cost", "obsolescence"} else 1) for key, value in terms.items()}
        score = sum(contributions.values())
        return {"score": score, "density": score / service, "terms": terms, "contributions": contributions}

    def _decision(self, item: Candidate, action: PolicyAction, reason: str, now: float, state: dict, **extra) -> dict:
        self.local.observe_queue(now, len(self.queue))
        utility = self.utility(item, now, obsolete=action == PolicyAction.SUPERSEDE)
        record = {
            "message_id": item.message_id, "device_id": item.message.device_id,
            "priority": item.priority.value, "estimated_size_bytes": item.size_bytes,
            "local_time": now, "action": action.value, "reason": reason,
            "utility_score": utility["score"], "utility_density": utility["density"],
            "components": utility["terms"], "weighted_components": utility["contributions"],
            "congestion_state": state["congestion_state"], "local_state": state,
            "source_ids": list(item.source_ids), **extra,
        }
        self.decisions.append(record)
        self.action_counts[action.value] += 1
        if action in {PolicyAction.DROP, PolicyAction.SAMPLE, PolicyAction.SUPERSEDE}:
            self.local.record(now, "drop")
        if action == PolicyAction.AGGREGATE:
            self.local.record(now, "aggregate")
        if self.on_decision:
            self.on_decision(record)
        return record

    def submit(self, message: EdgeTelemetryMessage, priority: PriorityLevel, now: float,
               wall_time: datetime, message_id: str | None = None) -> dict:
        if any(not math.isfinite(value) for value in numeric_values(message).values()):
            raise ValueError("telemetry values must be finite")
        stamp = message.timestamp.replace(tzinfo=timezone.utc) if message.timestamp.tzinfo is None else message.timestamp
        stamp = stamp.astimezone(timezone.utc)
        message = message.model_copy(update={"timestamp": stamp})
        if wall_time.tzinfo is None:
            wall_time = wall_time.replace(tzinfo=timezone.utc)
        initial_age = max((wall_time - stamp).total_seconds(), 0)
        size = serialized_size(message) + self.config.envelope_overhead_bytes
        identifier = message_id or str(uuid4())
        protected = (
            message.aggregation is not None
            or priority in {PriorityLevel.HIGH, PriorityLevel.CRITICAL}
            or message.event_type.lower() not in self.config.routine_events
            or message.status.lower() not in {"normal", "ok"}
            or self.security_risk(message) >= 1
            or self.novelty(message) >= self.config.preserve_novelty_threshold
        )
        item = Candidate(identifier, message, priority, now, now - initial_age, size, protected, (identifier,), size)
        self.generated_bytes += size
        self.local.record(now, "arrival", size, priority.value)
        state = self.local.snapshot(now, len(self.queue))
        if size > self.config.max_message_bytes:
            return self._decision(item, PolicyAction.DROP, "candidate exceeds configured serialized size bound", now, state)
        if initial_age > self.config.freshness_seconds and not protected and self.config.reduction_enabled:
            return self._decision(item, PolicyAction.DROP, "obsolete routine measurement", now, state)

        pressure = state["congestion_state"]
        key = self.stream(message)
        if self.config.reduction_enabled and not protected and pressure in {"CONGESTED", "CRITICAL"}:
            if pressure == "CRITICAL" and self.novelty(message) <= self.config.low_novelty_threshold:
                count = self.sample_counts.get(key, 0) + 1
                self._remember(self.sample_counts, key, count)
                if (count - 1) % self.config.sample_every:
                    return self._decision(item, PolicyAction.SAMPLE, "deterministic low-novelty sample omitted", now, state, retained=False)
            matches = [old for old in self.queue if not old.protected and self.stream(old.message) == key and old.priority == priority]
            if matches:
                previous = matches[-1]
                if (self.novelty(message) <= self.config.low_novelty_threshold
                        and len(previous.source_ids) < self.config.aggregation_max_samples
                        and message.timestamp >= previous.message.timestamp
                        and numeric_values(previous.message).keys() == numeric_values(message).keys()):
                    aggregate = replace(item)
                    self._aggregate(previous, aggregate)
                    if aggregate.size_bytes <= self.config.max_message_bytes:
                        self.queue[self.queue.index(previous)] = aggregate
                        return self._decision(aggregate, PolicyAction.AGGREGATE, "low-novelty routine samples summarized before signing", now, state)
                if previous.message.aggregation is None and message.timestamp >= previous.message.timestamp:
                    self.queue.remove(previous)
                    item.enqueued_at = previous.enqueued_at
                    self._decision(previous, PolicyAction.SUPERSEDE, "newer routine state replaces queued reading", now, state, replacement_id=item.message_id)

        if len(self.queue) >= self.config.max_queue_size:
            victims = [old for old in self.queue if not old.protected]
            if item.priority == PriorityLevel.CRITICAL:
                # At hard capacity, critical admission may displace lower-priority
                # state. Such loss is audited as overflow, never supersession.
                victims = [old for old in self.queue if old.priority != PriorityLevel.CRITICAL]
            if self.config.strategy == "fifo" and not self.config.reduction_enabled:
                victims = []
            victim = min(victims, key=lambda old: self.utility(old, now)["score"], default=None)
            if victim is None or (not item.protected and self.utility(item, now)["score"] <= self.utility(victim, now)["score"]):
                return self._decision(item, PolicyAction.DROP, "bounded queue admission exhausted", now, state)
            self.queue.remove(victim)
            self._decision(victim, PolicyAction.DROP, "lower-utility state evicted at hard capacity", now, state, replacement_id=item.message_id)
        self.queue.append(item)
        return self._decision(item, PolicyAction.DELAY, "admitted to local shaped transmission queue", now, state)

    def _aggregate(self, previous: Candidate, item: Candidate) -> None:
        count = len(previous.source_ids)
        old_values, new_values = numeric_values(previous.message), numeric_values(item.message)
        means = {k: (old_values[k] * count + value) / (count + 1) for k, value in new_values.items()}
        prior = previous.message.aggregation
        minima = prior.metric_minima if prior else old_values
        maxima = prior.metric_maxima if prior else old_values
        summary = AggregationSummary(
            average_temperature=means["temperature"], average_humidity=means["humidity"],
            minimum_temperature=min(previous.message.aggregation.minimum_temperature if prior else old_values["temperature"], new_values["temperature"]),
            maximum_temperature=max(previous.message.aggregation.maximum_temperature if prior else old_values["temperature"], new_values["temperature"]),
            sample_count=count + 1, metric_averages=means,
            metric_minima={k: min(minima[k], new_values[k]) for k in new_values},
            metric_maxima={k: max(maxima[k], new_values[k]) for k in new_values},
            source_message_ids=list(previous.source_ids + item.source_ids),
            window_start=prior.window_start if prior else previous.message.timestamp,
            window_end=item.message.timestamp,
        )
        item.message = item.message.model_copy(update={
            **{k: means[k] for k in ("temperature", "humidity", "cpu_usage", "memory_usage") if k in means},
            "measurements": {k: means[k] for k in item.message.measurements}, "aggregation": summary,
        })
        item.enqueued_at = previous.enqueued_at
        item.generated_at = previous.generated_at
        item.source_ids = previous.source_ids + item.source_ids
        item.generated_bytes += previous.generated_bytes
        item.size_bytes = serialized_size(item.message) + self.config.envelope_overhead_bytes

    def pop(self, now: float) -> Candidate | None:
        if now < self.next_dispatch_at:
            return None
        state = self.local.snapshot(now, len(self.queue))
        for item in list(self.queue):
            if (self.config.reduction_enabled and not item.protected
                    and now - item.generated_at > self.config.freshness_seconds):
                self.queue.remove(item)
                self._decision(item, PolicyAction.DROP, "routine measurement expired while queued", now, state)
        if not self.queue:
            return None
        overdue = [item for item in self.queue if now - item.enqueued_at >= self.config.starvation_seconds]
        if self.config.strategy == "fifo":
            selected = self.queue[0]
        elif overdue:
            selected = min(overdue, key=lambda item: item.enqueued_at)
        elif self.config.strategy == "priority":
            selected = max(self.queue, key=lambda item: self.utility(item, now)["terms"]["priority"])
        else:
            use_density = self.config.strategy == "density_under_pressure" and state["congestion_state"] == "CRITICAL"
            selected = max(self.queue, key=lambda item: self.utility(item, now)["density" if use_density else "score"])
        self.queue.remove(selected)
        service = max(1 / self.config.messages_per_second, selected.size_bytes / self.config.link_bytes_per_second)
        self.next_dispatch_at = now + service
        self._decision(selected, PolicyAction.SEND, "oldest overdue candidate" if overdue and self.config.strategy != "fifo" else "selected by " + self.config.strategy, now, state)
        self._remember(self.last_dispatched, self.stream(selected.message), selected.message)
        self.local.record(now, "dispatch", selected.size_bytes, service=service)
        self.dispatched_bytes += selected.size_bytes
        return selected

    def _remember(self, mapping: OrderedDict, key: tuple, value) -> None:
        mapping[key] = value
        mapping.move_to_end(key)
        while len(mapping) > self.config.max_streams:
            mapping.popitem(last=False)

    def snapshot(self, now: float) -> dict:
        return {
            "strategy": self.config.strategy, "local_state": self.local.snapshot(now, len(self.queue)),
            "actions": dict(self.action_counts), "recent_decisions": list(self.decisions),
            "generated_bytes": self.generated_bytes, "dispatched_bytes": self.dispatched_bytes,
            "pending_generated_bytes": sum(item.generated_bytes for item in self.queue),
            "config": self.config.model_dump(mode="json"),
        }
