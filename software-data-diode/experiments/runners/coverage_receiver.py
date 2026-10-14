"""Offline experiment observer; no value from this module enters sender decisions."""

import json
from collections import defaultdict
from datetime import datetime, timezone

from shared.analytics import AnomalyDetector, CorrelationEngine, DetectionConfig
from shared.coverage.capsules import parse_artifact
from shared.coverage.contracts import contract_hash
from shared.coverage.evaluation import condition_facts, evaluate_rule
from shared.coverage.models import ConditionFacts, CoverageLimitation, WindowIdentity
from shared.coverage.transport import PartAssembler
from shared.coverage.verification import FogEvidenceVerifier
from shared.models import FogEvent, SecureTelemetryEnvelope

from .coverage_common import ROOT, normalize_original


class Observer:
    def __init__(self, framer, arm):
        self.framer, self.arm = framer, arm
        self.now = 0.0
        self.assembler = PartAssembler(framer, monotonic=lambda: self.now)
        self.scopes = {}
        self.simple_scopes = {}
        self.barriers = {}
        self.originals = defaultdict(dict)
        self.raw_receipts = []
        self.seen = set()
        self.rejections = 0
        self.detector = AnomalyDetector(
            DetectionConfig.from_file(ROOT / "config/anomaly_rules.json")
        )
        self.correlator = CorrelationEngine.from_file(
            ROOT / "config/correlation_rules.json"
        )
        self.native_anomalies, self.native_alerts = 0, 0
        self.revision = 0
        self.cache = {}

    def restart(self, durable):
        self.assembler = PartAssembler(self.framer, monotonic=lambda: self.now)
        if not durable:
            self.scopes.clear()
            self.simple_scopes.clear()
            self.barriers.clear()
            self.originals.clear()
            self.seen.clear()
        self.revision += 1

    def receive(self, frame, at):
        self.now = at
        try:
            artifact = self.assembler.add(frame)
            if (
                artifact is None
                or (artifact.kind, artifact.identity, artifact.encoded) in self.seen
            ):
                return
            self.seen.add((artifact.kind, artifact.identity, artifact.encoded))
            self.revision += 1
            if artifact.kind == "EVIDENCE":
                body = parse_artifact(artifact.encoded).body
                record = FogEvidenceVerifier(self.framer).verify(
                    artifact.encoded,
                    received_us=round(at * 1e6) + self.base_us,
                    frames=artifact.frames,
                )
                self.scopes[(body.window_index, body.device_id)] = (body, record)
            elif artifact.kind == "STATE":
                document = json.loads(artifact.encoded)
                summary = document["metrics"].get("n10_predicate_summary")
                if summary:
                    expected = {
                        "protocol",
                        "epoch",
                        "device",
                        "window",
                        "contract",
                        "n",
                        "first",
                        "last",
                        "limitations",
                        "facts",
                    }
                    if (
                        set(summary) != expected
                        or summary["protocol"] != "n10-predicate-summary-v1"
                        or summary["epoch"] != self.framer.profile.ledger_epoch
                        or summary["contract"] != self.framer.profile.contract_hash
                    ):
                        raise ValueError("invalid signed compact summary context")
                    atoms = {
                        a.condition_id
                        for a in self.framer.contract.conditions
                        if a.device_id == summary["device"]
                    }
                    counts = summary["facts"]
                    if (
                        not atoms
                        or len(counts) != len(atoms)
                        or {c[0] for c in counts} != atoms
                        or any(len(c) != 4 for c in counts)
                    ):
                        raise ValueError("invalid compact condition cardinality")
                    n = summary["n"]
                    if (
                        type(n) is not int
                        or not 0 <= n <= 1000
                        or (
                            n
                            and (
                                type(summary["first"]) is not int
                                or type(summary["last"]) is not int
                                or summary["last"] - summary["first"] + 1 != n
                            )
                        )
                        or (
                            not n
                            and (
                                summary["first"] is not None
                                or summary["last"] is not None
                            )
                        )
                    ):
                        raise ValueError("invalid compact ingress range")
                    window = WindowIdentity(
                        ledger_epoch=summary["epoch"],
                        device_id=summary["device"],
                        window_index=summary["window"],
                        contract_hash=summary["contract"],
                    )
                    limits = tuple(
                        CoverageLimitation(v) for v in summary["limitations"]
                    )
                    self.simple_scopes[(window.window_index, window.device_id)] = {
                        c[0]: ConditionFacts(
                            window=window,
                            condition_id=c[0],
                            accepted_count=n,
                            matching_count=c[1],
                            nonmatching_count=c[2],
                            unresolved_count=c[3],
                            population_complete=not limits,
                            closed=True,
                            limitations=limits,
                        )
                        for c in counts
                    }
                barrier = document["metrics"].get("n10_barrier")
                if barrier:
                    expected = {
                        "protocol",
                        "ledger_epoch",
                        "device_id",
                        "contract_hash",
                        "window_index",
                        "accepted_count",
                        "first_seq",
                        "last_seq",
                        "limitations",
                    }
                    if (
                        set(barrier) != expected
                        or barrier["protocol"] != "n10-ingress-barrier-v1"
                        or barrier["ledger_epoch"] != self.framer.profile.ledger_epoch
                        or barrier["contract_hash"] != self.framer.profile.contract_hash
                    ):
                        raise ValueError("invalid signed barrier context")
                    n = barrier["accepted_count"]
                    if (
                        type(n) is not int
                        or not 1 <= n <= 1000
                        or barrier["last_seq"] - barrier["first_seq"] + 1 != n
                    ):
                        raise ValueError("invalid signed barrier range")
                    self.barriers[(barrier["window_index"], barrier["device_id"])] = (
                        barrier
                    )
            else:
                envelope = SecureTelemetryEnvelope.model_validate_json(artifact.encoded)
                attrs = envelope.payload.attributes
                epoch = attrs.get("_n10_epoch")
                sequence = attrs.get("_n10_seq")
                stamp = attrs.get("_n10_ingress_us")
                if (
                    epoch != self.framer.profile.ledger_epoch
                    or type(sequence) is not int
                    or type(stamp) is not int
                ):
                    raise ValueError("raw provenance absent/ambiguous")
                message = envelope.payload.model_dump(mode="json")
                message["attributes"] = {
                    k: v for k, v in attrs.items() if not k.startswith("_n10_")
                }
                message.update(
                    device_id=envelope.device_id,
                    timestamp=attrs["_n10_original_timestamp"],
                )
                exact = envelope.payload.aggregation is None
                receipt = {
                    "device_id": envelope.device_id,
                    "ingress_sequence": sequence,
                    "ingress_utc_us": stamp,
                    "ledger_epoch": epoch,
                    "message": message,
                    "at_seconds": at,
                    "priority": envelope.priority.value,
                    "exact": exact,
                }
                self.raw_receipts.append(receipt)
                if exact:
                    self.originals[(stamp // 10000000, envelope.device_id)][
                        sequence
                    ] = receipt
                if self.arm == "legacy":
                    event = FogEvent(
                        received_at=datetime.fromtimestamp(
                            (self.base_us / 1e6) + at, tz=timezone.utc
                        ),
                        envelope=envelope,
                    )
                    self.native_anomalies += len(self.detector.detect(event))
                    self.native_alerts += len(self.correlator.process(event)[1])
        except (ValueError, RecursionError):
            self.rejections += 1

    def facts(self, index):
        contract = self.framer.contract
        facts = []
        for atom in contract.conditions:
            key = (index, atom.device_id)
            window = WindowIdentity(
                ledger_epoch=self.framer.profile.ledger_epoch,
                device_id=atom.device_id,
                window_index=index,
                contract_hash=contract_hash(contract),
            )
            rows = list(self.originals.get(key, {}).values())
            observations = [normalize_original(contract, r) for r in rows]
            barrier = self.barriers.get(key)
            complete = bool(
                barrier
                and set(self.originals.get(key, {}))
                == set(range(barrier["first_seq"], barrier["last_seq"] + 1))
            )
            limits = (
                tuple(CoverageLimitation(v) for v in barrier["limitations"])
                if barrier
                else ()
            )
            raw = condition_facts(
                contract,
                atom.condition_id,
                window,
                observations,
                population_complete=complete,
                limitations=limits,
            )
            if key in self.simple_scopes:
                facts.append(self.simple_scopes[key][atom.condition_id])
                continue
            capsule = self.scopes.get(key)
            if capsule:
                body, verified = capsule
                declared = next(
                    f
                    for f in body.per_condition_facts
                    if f.condition_id == atom.condition_id
                )
                scoped = [
                    r
                    for r in rows
                    if body.ingress_first_sequence is not None
                    and body.ingress_first_sequence
                    <= r["ingress_sequence"]
                    <= body.ingress_last_sequence
                ]
                witnessed = condition_facts(
                    contract,
                    atom.condition_id,
                    window,
                    [normalize_original(contract, r) for r in scoped],
                    population_complete=False,
                )
                contradiction = any(
                    getattr(witnessed, name) > getattr(declared, name)
                    for name in (
                        "matching_count",
                        "nonmatching_count",
                        "unresolved_count",
                    )
                )
                if not contradiction:
                    facts.append(
                        ConditionFacts(
                            window=window,
                            condition_id=atom.condition_id,
                            accepted_count=body.accepted_observation_count,
                            matching_count=declared.matching_count,
                            nonmatching_count=declared.nonmatching_count,
                            unresolved_count=declared.unresolved_count,
                            closed=True,
                            population_complete=body.population_complete
                            and verified.status == "VALID",
                            limitations=body.coverage_limitations,
                        )
                    )
                    continue
            facts.append(raw)
        return facts

    def verdicts(self, index):
        if self.arm == "always_unknown":
            return {r.rule_id: "UNKNOWN" for r in self.framer.contract.rules}
        if index in self.cache and self.cache[index][0] == self.revision:
            return self.cache[index][1]
        facts = self.facts(index)
        result = {
            r.rule_id: evaluate_rule(
                self.framer.contract,
                r.rule_id,
                ledger_epoch=self.framer.profile.ledger_epoch,
                window_index=index,
                facts=facts,
            ).truth.value
            for r in self.framer.contract.rules
        }
        self.cache[index] = (self.revision, result)
        return result
