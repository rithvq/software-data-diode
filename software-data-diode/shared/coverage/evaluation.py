"""Pure trusted-fact semantics; cryptographic verification is a later phase."""
import math
import operator
from collections.abc import Iterable, Mapping

from .contracts import contract_hash
from .models import (AtomicCondition, AtomicVerdict, ConditionFacts, CoverageLimitation, IngressObservation,
                     RuleContract, RuleExpression, RuleVerdict, Truth, WindowIdentity)


COMPARISONS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le}


def kleene_and(left: Truth, right: Truth) -> Truth:
    left, right = Truth(left), Truth(right)
    if Truth.FALSE in (left, right):
        return Truth.FALSE
    return Truth.TRUE if left == right == Truth.TRUE else Truth.UNKNOWN


def kleene_or(left: Truth, right: Truth) -> Truth:
    left, right = Truth(left), Truth(right)
    if Truth.TRUE in (left, right):
        return Truth.TRUE
    return Truth.FALSE if left == right == Truth.FALSE else Truth.UNKNOWN


def condition_facts(contract: RuleContract, condition_id: str, window: WindowIdentity,
                    observations: Iterable[IngressObservation], *, closed: bool = True,
                    population_complete: bool = True,
                    limitations: tuple[CoverageLimitation, ...] = ()) -> ConditionFacts:
    condition = next((item for item in contract.conditions if item.condition_id == condition_id), None)
    if condition is None or window.device_id != condition.device_id or window.contract_hash != contract_hash(contract):
        raise ValueError("condition/window scope does not match contract")
    device = next(item for item in contract.devices if item.device_id == condition.device_id)
    matching = nonmatching = unresolved = 0
    seen = set()
    for observation in observations:
        identity = (observation.ledger_epoch, observation.device_id, observation.ingress_sequence)
        if identity in seen:
            raise ValueError("duplicate original observation identity")
        seen.add(identity)
        if (observation.device_id != window.device_id or observation.ledger_epoch != window.ledger_epoch
                or not window.start_utc_us <= observation.ingress_utc_us < window.end_utc_us):
            continue
        values = {item.path: item.value for item in observation.metrics}
        value = values.get(condition.metric_path)
        if observation.telemetry_type != device.telemetry_type or type(value) not in (int, float):
            unresolved += 1
            continue
        try:
            value = float(value)
        except OverflowError:
            unresolved += 1
            continue
        if not math.isfinite(value):
            unresolved += 1
        elif COMPARISONS[condition.inequality](value, condition.threshold):
            matching += 1
        else:
            nonmatching += 1
    return ConditionFacts(window=window, condition_id=condition_id, accepted_count=matching + nonmatching + unresolved,
                          matching_count=matching, nonmatching_count=nonmatching,
                          unresolved_count=unresolved, closed=closed,
                          population_complete=population_complete, limitations=limitations)


def evaluate_condition(condition: AtomicCondition, facts: ConditionFacts | None) -> AtomicVerdict:
    complete = False
    if facts is None:
        truth, reason = Truth.UNKNOWN, "MISSING_FACTS"
    elif facts.condition_id != condition.condition_id or facts.window.device_id != condition.device_id:
        raise ValueError("facts do not belong to condition")
    elif CoverageLimitation.CLOCK_DISCONTINUITY in facts.limitations:
        truth, reason = Truth.UNKNOWN, "UNCERTAIN_TIME_SCOPE"
    else:
        complete = (facts.closed and facts.population_complete and not facts.limitations
                    and facts.unresolved_count == 0 and facts.accepted_count >= condition.minimum_samples)
        if facts.matching_count >= condition.k:
            truth, reason = Truth.TRUE, "MATCHING_LOWER_BOUND"
        elif not facts.closed or not facts.population_complete or facts.limitations:
            truth, reason = Truth.UNKNOWN, "INCOMPLETE_SCOPE"
        elif facts.accepted_count < condition.minimum_samples:
            truth, reason = Truth.UNKNOWN, "INSUFFICIENT_OBSERVATIONS"
        elif facts.matching_count + facts.unresolved_count < condition.k:
            truth, reason = Truth.FALSE, "MATCHING_UPPER_BOUND"
        else:
            truth, reason = Truth.UNKNOWN, "UNRESOLVED_MEASUREMENTS"
    return AtomicVerdict(condition_id=condition.condition_id, truth=truth,
                         reason=reason, coverage_complete=complete)


def _expression_result(expression: RuleExpression, answers: Mapping[str, AtomicVerdict]):
    if expression.kind == "ATOM":
        answer = answers[expression.condition_id]
        return answer.truth, (answer.condition_id,) if answer.truth != Truth.UNKNOWN else ()
    children = [_expression_result(child, answers) for child in expression.children]
    deciding = Truth.FALSE if expression.kind == "AND" else Truth.TRUE
    for truth, basis in children:
        if truth == deciding:
            return truth, basis
    combine = kleene_and if expression.kind == "AND" else kleene_or
    result = Truth.TRUE if expression.kind == "AND" else Truth.FALSE
    for truth, _ in children:
        result = combine(result, truth)
    return result, tuple(item for _, basis in children for item in basis) if result != Truth.UNKNOWN else ()


def evaluate_rule(contract: RuleContract, rule_id: str, *, ledger_epoch: str, window_index: int,
                  facts: Iterable[ConditionFacts]) -> RuleVerdict:
    rule = next((item for item in contract.rules if item.rule_id == rule_id), None)
    if rule is None:
        raise ValueError("unregistered rule")
    digest = contract_hash(contract)
    supplied = {}
    conditions = {item.condition_id: item for item in contract.conditions}
    for item in facts:
        if (item.condition_id not in conditions or item.window.contract_hash != digest
                or item.window.ledger_epoch != ledger_epoch or item.window.window_index != window_index
                or item.window.device_id != conditions[item.condition_id].device_id):
            raise ValueError("mixed or invalid fact scope")
        if item.condition_id in supplied:
            raise ValueError("duplicate condition facts; do not add overlapping scopes")
        supplied[item.condition_id] = item
    references = []
    stack = [rule.expression]
    while stack:
        node = stack.pop()
        if node.kind == "ATOM":
            references.append(node.condition_id)
        stack.extend(reversed(node.children))
    answers = {name: evaluate_condition(conditions[name], supplied.get(name)) for name in references}
    truth, basis = _expression_result(rule.expression, answers)
    return RuleVerdict(contract_hash=digest, ledger_epoch=ledger_epoch, window_index=window_index,
                       rule_id=rule_id, truth=truth, conditions=tuple(answers.values()),
                       supporting_conditions=basis,
                       unknown_conditions=tuple(name for name, answer in answers.items() if answer.truth == Truth.UNKNOWN),
                       coverage_complete=all(answer.coverage_complete for answer in answers.values()))
