"""Independent reference on original ingress traces, not production facts.

Only immutable input models are shared. Do not import evaluation/policy helpers.
"""
import math
from collections.abc import Iterable

from .models import CoverageLimitation, IngressObservation, RuleContract, Truth


def trace_oracle(contract: RuleContract, rule_id: str, *, ledger_epoch: str, window_index: int,
                 observations: Iterable[IngressObservation], closed: bool = True,
                 population_complete: bool = True,
                 limitations: tuple[CoverageLimitation, ...] = ()) -> Truth:
    if type(window_index) is not int or type(closed) is not bool or type(population_complete) is not bool:
        raise ValueError("oracle scope and closure flags require exact types")
    limitations = tuple(CoverageLimitation(item) for item in limitations)
    rule = next((item for item in contract.rules if item.rule_id == rule_id), None)
    if rule is None:
        raise ValueError("unregistered oracle rule")
    trace = tuple(observations)
    devices = {item.device_id: item for item in contract.devices}
    identities = set()
    for record in trace:
        identity = (record.ledger_epoch, record.device_id, record.ingress_sequence)
        if identity in identities:
            raise ValueError("duplicate original observation identity")
        identities.add(identity)
    answers = {}
    for atom in contract.conditions:
        hits = uncertain = samples = 0
        for record in trace:
            if (record.ledger_epoch != ledger_epoch or record.device_id != atom.device_id
                    or record.ingress_utc_us // 10000000 != window_index):
                continue
            samples += 1
            original = next((reading.value for reading in record.metrics if reading.path == atom.metric_path), None)
            if record.telemetry_type != devices[atom.device_id].telemetry_type or type(original) not in (int, float):
                uncertain += 1
                continue
            try:
                number = float(original)
            except OverflowError:
                uncertain += 1
                continue
            if not math.isfinite(number):
                uncertain += 1
                continue
            if atom.inequality == ">":
                hit = number > atom.threshold
            elif atom.inequality == ">=":
                hit = number >= atom.threshold
            elif atom.inequality == "<":
                hit = number < atom.threshold
            else:
                hit = number <= atom.threshold
            hits += int(hit)
        if CoverageLimitation.CLOCK_DISCONTINUITY in limitations:
            answers[atom.condition_id] = Truth.UNKNOWN
        elif hits >= atom.k:
            answers[atom.condition_id] = Truth.TRUE
        elif not closed or not population_complete or limitations or samples < atom.minimum_samples:
            answers[atom.condition_id] = Truth.UNKNOWN
        elif hits + uncertain < atom.k:
            answers[atom.condition_id] = Truth.FALSE
        else:
            answers[atom.condition_id] = Truth.UNKNOWN

    # Explicit tables keep reference composition independent of production branching.
    tables = {
        "AND": ((Truth.TRUE, Truth.FALSE, Truth.UNKNOWN),
                (Truth.FALSE, Truth.FALSE, Truth.FALSE),
                (Truth.UNKNOWN, Truth.FALSE, Truth.UNKNOWN)),
        "OR": ((Truth.TRUE, Truth.TRUE, Truth.TRUE),
               (Truth.TRUE, Truth.FALSE, Truth.UNKNOWN),
               (Truth.TRUE, Truth.UNKNOWN, Truth.UNKNOWN)),
    }
    ordinal = {Truth.TRUE: 0, Truth.FALSE: 1, Truth.UNKNOWN: 2}

    def interpret(node):
        if node.kind == "ATOM":
            return answers[node.condition_id]
        operands = [interpret(child) for child in node.children]
        result = operands[0]
        for operand in operands[1:]:
            result = tables[node.kind][ordinal[result]][ordinal[operand]]
        return result

    return interpret(rule.expression)
