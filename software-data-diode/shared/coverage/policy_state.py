"""Bounded JSON checkpoints for the existing engine; no pickle or replayed code."""
from collections import Counter, OrderedDict, deque
import math
from uuid import UUID

from shared.models import EdgeTelemetryMessage, PriorityLevel
from shared.security.crypto import canonical_bytes
from shared.traffic.information import Candidate, InformationEngine, PolicyAction, serialized_size


def freeze(value):
    return tuple(freeze(item) for item in value) if isinstance(value, list) else value


def candidate_document(item):
    return {**item.__dict__, "message": item.message.model_dump(mode="json"),
            "priority": item.priority.value, "source_ids": list(item.source_ids)}


def checkpoint(engine):
    return canonical_bytes({
        "version": 1, "queue": [candidate_document(item) for item in engine.queue],
        "last": [[key, value.model_dump(mode="json")] for key, value in engine.last_dispatched.items()],
        "samples": list(engine.sample_counts.items()), "next": engine.next_dispatch_at,
        "decisions": list(engine.decisions), "actions": dict(engine.action_counts),
        "generated": engine.generated_bytes, "dispatched": engine.dispatched_bytes,
        "buckets": [[key, dict(value)] for key, value in engine.local.buckets.items()],
        "started": engine.local.started_at, "previous": engine.local.previous_queue,
        "growth": engine.local.queue_growth})


def restore(encoded, config, guard=None):
    from shared.http import strict_json
    state = strict_json(encoded)
    expected = {"version", "queue", "last", "samples", "next", "decisions", "actions", "generated",
                "dispatched", "buckets", "started", "previous", "growth"}
    if set(state) != expected or state["version"] != 1:
        raise ValueError("invalid policy checkpoint schema")
    def finite(value):
        if isinstance(value, (int, float)) and not isinstance(value, bool) and not math.isfinite(value):
            raise ValueError("nonfinite policy state")
        if isinstance(value, dict):
            for item in value.values():
                finite(item)
        elif isinstance(value, list):
            for item in value:
                finite(item)
    def count(value):
        if type(value) is not int or value < 0:
            raise ValueError("invalid policy counter")
    finite(state)
    for name in ("generated", "dispatched"):
        count(state[name])
    if (not isinstance(state["next"], (int, float)) or state["next"] < 0
            or not set(state["actions"]) <= {action.value for action in PolicyAction}):
        raise ValueError("invalid policy scalar state")
    for value in state["actions"].values():
        count(value)
    if (len(state["queue"]) > config.max_queue_size or len(state["last"]) > config.max_streams
            or len(state["samples"]) > config.max_streams or len(state["decisions"]) > 100
            or len(state["buckets"]) > int(config.window_seconds)+2):
        raise ValueError("policy checkpoint cardinality exceeded")
    engine = InformationEngine(config, before_action=guard)
    for value in state["queue"]:
        value = dict(value)
        value["message"] = EdgeTelemetryMessage.model_validate(value["message"])
        value["priority"] = PriorityLevel(value["priority"])
        value["source_ids"] = tuple(value["source_ids"])
        if not 1 <= len(value["source_ids"]) <= config.aggregation_max_samples:
            raise ValueError("invalid source cardinality")
        if (len(set(value["source_ids"])) != len(value["source_ids"])
                or type(value["protected"]) is not bool
                or value["message_id"] != value["source_ids"][-1]
                or value["size_bytes"] != serialized_size(value["message"]) + config.envelope_overhead_bytes
                or not 0 <= value["enqueued_at"] or value["generated_at"] > value["enqueued_at"]):
            raise ValueError("invalid policy candidate")
        count(value["generated_bytes"])
        for identifier in value["source_ids"]:
            if str(UUID(identifier)) != identifier:
                raise ValueError("invalid observation reference")
        engine.queue.append(Candidate(**value))
    if len({item.message_id for item in engine.queue}) != len(engine.queue):
        raise ValueError("duplicate policy candidate")
    engine.last_dispatched = OrderedDict((freeze(key), EdgeTelemetryMessage.model_validate(value)) for key, value in state["last"])
    engine.sample_counts = OrderedDict((freeze(key), value) for key, value in state["samples"])
    if len(engine.last_dispatched) != len(state["last"]) or len(engine.sample_counts) != len(state["samples"]):
        raise ValueError("duplicate policy stream")
    for key, value in engine.last_dispatched.items():
        if engine.stream(value) != key:
            raise ValueError("invalid policy stream binding")
    for value in engine.sample_counts.values():
        count(value)
    engine.next_dispatch_at = state["next"]
    engine.decisions = deque(state["decisions"], maxlen=100)
    engine.action_counts = Counter(state["actions"])
    engine.generated_bytes, engine.dispatched_bytes = state["generated"], state["dispatched"]
    engine.local.buckets = OrderedDict((key, Counter(value)) for key, value in state["buckets"])
    if len(engine.local.buckets) != len(state["buckets"]):
        raise ValueError("duplicate local time bucket")
    for key, values in engine.local.buckets.items():
        count(key)
        if any(not isinstance(value, (int, float)) or value < 0 for value in values.values()):
            raise ValueError("invalid local time bucket")
    if state["previous"] is not None:
        if len(state["previous"]) != 2 or state["previous"][0] < 0:
            raise ValueError("invalid local queue state")
        count(state["previous"][1])
    engine.local.started_at, engine.local.queue_growth = state["started"], state["growth"]
    engine.local.previous_queue = tuple(state["previous"]) if state["previous"] is not None else None
    if checkpoint(engine) != encoded:
        raise ValueError("noncanonical policy checkpoint")
    return engine
