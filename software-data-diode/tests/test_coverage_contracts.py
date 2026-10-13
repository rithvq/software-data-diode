from copy import deepcopy
from datetime import datetime, timedelta, timezone
import itertools
import json
import math
from pathlib import Path

import pytest
from pydantic import ValidationError

from shared.coverage import (ConditionFacts, CoverageLimitation, IngressObservation,
    MetricReading, RuleContract, Truth, WindowIdentity, WindowSchedule, condition_facts,
    contract_bytes, contract_hash, evaluate_condition, evaluate_rule, kleene_and, kleene_or,
    load_contract, parse_contract, trace_oracle, utc_microseconds, window_identity)


ROOT = Path(__file__).resolve().parents[1]
GOLDEN_HASH = "5ac9d246d40fc6a333c68fe984025d7f6169bec2fe3e85589c5af3cee51204bd"


def contract_data(inequality=">=", predicate="EXISTS"):
    return {
        "contract_id": "test-v1",
        "devices": [{"device_id": device, "telemetry_type": "system",
                     "metrics": [{"path": "cpu_usage", "unit": "percent"}]} for device in ("d1", "d2")],
        "conditions": [{"condition_id": condition, "device_id": device, "metric_path": "cpu_usage",
                        "unit": "percent", "predicate": predicate, "inequality": inequality,
                        "threshold": 1, "k": 2 if predicate == "COUNT_GE" else 1}
                       for condition, device in (("c1", "d1"), ("c2", "d2"))],
        "rules": [{"rule_id": "single", "expression": {"kind": "ATOM", "condition_id": "c1"}},
                  *[{"rule_id": kind.lower(), "expression": {"kind": kind, "children": [
                     {"kind": "ATOM", "condition_id": "c1"}, {"kind": "ATOM", "condition_id": "c2"}]}}
                    for kind in ("AND", "OR")]],
    }


@pytest.fixture
def contract():
    return RuleContract.model_validate(contract_data())


def observation(device="d1", value=0, sequence=1, at=1, epoch="epoch", telemetry_type="system"):
    readings = () if value is None else (MetricReading(path="cpu_usage", value=value),)
    return IngressObservation(ledger_epoch=epoch, device_id=device, ingress_sequence=sequence,
        ingress_utc_us=at, telemetry_type=telemetry_type, metrics=readings)


def facts(contract, condition_id="c1", observations=(), **kwargs):
    device = next(item.device_id for item in contract.conditions if item.condition_id == condition_id)
    window = WindowIdentity(ledger_epoch="epoch", device_id=device,
                            window_index=0, contract_hash=contract_hash(contract))
    return condition_facts(contract, condition_id, window, observations, **kwargs)


def test_demo_golden_hash_defaults_order_and_roundtrip():
    contract = load_contract(ROOT / "config/rule_coverage.json")
    assert contract_hash(contract) == GOLDEN_HASH
    assert len(contract_bytes(contract)) == 3835
    raw = json.loads((ROOT / "config/rule_coverage.json").read_text())
    assert contract_hash(parse_contract(json.dumps(dict(reversed(list(raw.items())))))) == GOLDEN_HASH
    assert contract_hash(parse_contract(contract_bytes(contract))) == GOLDEN_HASH
    assert contract.observation_scope == "accepted_normalized_gateway_ingress"
    assert contract.purpose == "synthetic_demonstration"
    assert len(contract.devices) == 5


@pytest.mark.parametrize("section,key,value", [
    ("root", "contract_id", "test-v2"), ("root", "purpose", "research"),
    ("condition", "threshold", 1.01), ("condition", "inequality", ">"),
    ("condition", "minimum_samples", 3), ("limits", "evidence_repetitions", 2),
    ("limits", "clock_jump_tolerance_us", 0), ("limits", "max_devices", 2),
    ("limits", "max_datagram_payload_bytes", 1000),
])
def test_resolved_semantic_changes_affect_hash(contract, section, key, value):
    document = contract.model_dump(mode="json")
    target = document if section == "root" else document["conditions"][0] if section == "condition" else document["limits"]
    target[key] = value
    assert contract_hash(RuleContract.model_validate(document)) != contract_hash(contract)


def test_units_and_expression_structure_are_hashed(contract):
    document = contract.model_dump(mode="json")
    document["devices"][0]["metrics"][0]["unit"] = "fraction"
    document["conditions"][0]["unit"] = "fraction"
    assert contract_hash(RuleContract.model_validate(document)) != contract_hash(contract)
    document = contract.model_dump(mode="json")
    document["rules"][1]["expression"]["kind"] = "OR"
    assert contract_hash(RuleContract.model_validate(document)) != contract_hash(contract)


@pytest.mark.parametrize("bad", [float("inf"), float("nan"), -float("inf"), "1", True, 10**400])
def test_threshold_rejects_nonfinite_and_ambiguous_numbers(bad):
    data = contract_data()
    data["conditions"][0]["threshold"] = bad
    with pytest.raises(ValueError):
        RuleContract.model_validate(data)


def test_negative_zero_has_same_numeric_identity():
    data = contract_data()
    data["conditions"][0]["threshold"] = -0.0
    first = RuleContract.model_validate(data)
    data["conditions"][0]["threshold"] = 0
    assert contract_hash(first) == contract_hash(RuleContract.model_validate(data))


@pytest.mark.parametrize("body", [b'{"contract_id":"x","contract_id":"y"}',
    b'{"threshold":NaN}', b'{"threshold":Infinity}', b'[]', b'null', b'{}', b'{' , b' ' * 65537],
    ids=["duplicate-key", "nan", "infinity", "array", "null", "empty", "malformed", "oversized"])
def test_contract_parser_rejects_invalid_ambiguous_or_oversized_json(body):
    with pytest.raises(ValueError):
        parse_contract(body)


@pytest.mark.parametrize("mutation", [
    "duplicate-device", "duplicate-condition", "duplicate-rule", "ambiguous-id", "unknown-device",
    "unknown-reference", "duplicate-reference", "wrong-unit", "unknown-metric", "duplicate-metric",
    "unsupported-comparison", "unsupported-predicate", "exists-k", "boolean-count", "zero-count",
    "executable", "not", "empty-and", "atom-children", "extra-field", "wrong-window", "wrong-time",
    "cardinality", "depth", "nodes", "hard-device-limit",
])
def test_configuration_failures_are_visible(mutation):
    data = contract_data()
    condition, expression = data["conditions"][0], data["rules"][1]["expression"]
    if mutation.startswith("duplicate-") and mutation.split("-")[1] in ("device", "condition", "rule"):
        group = {"device": "devices", "condition": "conditions", "rule": "rules"}[mutation.split("-")[1]]
        data[group].append(deepcopy(data[group][0]))
    elif mutation == "ambiguous-id": condition["condition_id"] = "d1"
    elif mutation == "unknown-device": condition["device_id"] = "other"
    elif mutation == "unknown-reference": expression["children"][0]["condition_id"] = "missing"
    elif mutation == "duplicate-reference": expression["children"][1]["condition_id"] = "c1"
    elif mutation == "wrong-unit": condition["unit"] = "degC"
    elif mutation == "unknown-metric": condition["metric_path"] = "measurements.other"
    elif mutation == "duplicate-metric": data["devices"][0]["metrics"] *= 2
    elif mutation == "unsupported-comparison": condition["inequality"] = "=="
    elif mutation == "unsupported-predicate": condition["predicate"] = "DURATION"
    elif mutation == "exists-k": condition["k"] = 2
    elif mutation == "boolean-count": condition["k"] = True
    elif mutation == "zero-count": condition["minimum_samples"] = 0
    elif mutation == "executable": data["rules"][0]["expression"] = "__import__('os').system('x')"
    elif mutation == "not": expression["kind"] = "NOT"
    elif mutation == "empty-and": expression["children"] = []
    elif mutation == "atom-children": data["rules"][0]["expression"]["children"] = expression["children"]
    elif mutation == "extra-field": data["continuous_time"] = True
    elif mutation == "wrong-window": data["window_seconds"] = 30
    elif mutation == "wrong-time": data["time_basis"] = "source_timestamp"
    elif mutation == "cardinality": data["limits"] = {"max_devices": 1}
    elif mutation == "depth": data["limits"] = {"max_expression_depth": 1}
    elif mutation == "nodes": data["limits"] = {"max_expression_nodes": 2}
    elif mutation == "hard-device-limit": data["devices"] = [deepcopy(data["devices"][0])] * 17
    with pytest.raises(ValueError):
        RuleContract.model_validate(data)


def test_immutable_models_and_nested_values(contract):
    with pytest.raises(ValidationError):
        contract.contract_id = "changed"
    with pytest.raises(ValidationError):
        contract.conditions[0].threshold = 999
    assert isinstance(contract.devices, tuple)
    assert isinstance(contract.rules[1].expression.children, tuple)
    assert isinstance(contract.devices[0].metrics, tuple)


@pytest.mark.parametrize("left,right", itertools.product(Truth, repeat=2))
def test_all_kleene_table_cells(left, right):
    order = [Truth.TRUE, Truth.FALSE, Truth.UNKNOWN]
    expected_and = [[Truth.TRUE, Truth.FALSE, Truth.UNKNOWN], [Truth.FALSE]*3,
                    [Truth.UNKNOWN, Truth.FALSE, Truth.UNKNOWN]]
    expected_or = [[Truth.TRUE]*3, [Truth.TRUE, Truth.FALSE, Truth.UNKNOWN],
                   [Truth.TRUE, Truth.UNKNOWN, Truth.UNKNOWN]]
    assert kleene_and(left, right) == expected_and[order.index(left)][order.index(right)]
    assert kleene_or(left, right) == expected_or[order.index(left)][order.index(right)]


@pytest.mark.parametrize("inequality,expected", [(">", [False, False, True]),
    (">=", [False, True, True]), ("<", [True, False, False]), ("<=", [True, True, False])])
def test_binary64_immediate_threshold_neighbors(inequality, expected):
    contract = RuleContract.model_validate(contract_data(inequality))
    for value, answer in zip([math.nextafter(1.0, -math.inf), 1.0, math.nextafter(1.0, math.inf)], expected):
        result = evaluate_condition(contract.conditions[0], facts(contract, observations=[observation(value=value)]))
        assert result.truth == (Truth.TRUE if answer else Truth.FALSE)


@pytest.mark.parametrize("value", [None, True, False, "5"])
def test_missing_or_wrong_metric_is_unresolved(contract, value):
    result = facts(contract, observations=[observation(value=value)])
    assert result.unresolved_count == 1
    assert evaluate_condition(contract.conditions[0], result).truth == Truth.UNKNOWN


def test_zero_samples_wrong_type_and_count_bounds(contract):
    assert evaluate_condition(contract.conditions[0], facts(contract)).reason == "INSUFFICIENT_OBSERVATIONS"
    wrong = facts(contract, observations=[observation(value=2, telemetry_type="network")])
    assert wrong.unresolved_count == 1
    counted = RuleContract.model_validate(contract_data(predicate="COUNT_GE"))
    incomplete = facts(counted, observations=[observation(value=None)])
    result = evaluate_condition(counted.conditions[0], incomplete)
    assert result.truth == Truth.FALSE and not result.coverage_complete
    uncertain = facts(counted, observations=[observation(value=2), observation(value=None, sequence=2)])
    assert evaluate_condition(counted.conditions[0], uncertain).truth == Truth.UNKNOWN
    certain = facts(counted, observations=[observation(value=2), observation(value=3, sequence=2)], closed=False)
    assert evaluate_condition(counted.conditions[0], certain).truth == Truth.TRUE


@pytest.mark.parametrize("options", [{"closed": False}, {"population_complete": False},
    {"limitations": (CoverageLimitation.STARTUP_PARTIAL,)}, {"limitations": (CoverageLimitation.INTERRUPTED,)}])
def test_incomplete_scopes_cannot_establish_negative_but_keep_witness(contract, options):
    assert evaluate_condition(contract.conditions[0], facts(contract, observations=[observation()], **options)).truth == Truth.UNKNOWN
    assert evaluate_condition(contract.conditions[0], facts(contract, observations=[observation(value=2)], **options)).truth == Truth.TRUE


def test_uncertain_time_invalidates_even_positive_scope(contract):
    result = facts(contract, observations=[observation(value=2)], limitations=(CoverageLimitation.CLOCK_DISCONTINUITY,))
    assert evaluate_condition(contract.conditions[0], result).truth == Truth.UNKNOWN


def test_false_and_is_not_global_health_or_complete_coverage(contract):
    verdict = evaluate_rule(contract, "and", ledger_epoch="epoch", window_index=0,
                            facts=[facts(contract, observations=[observation()])])
    assert verdict.truth == Truth.FALSE
    assert verdict.supporting_conditions == ("c1",)
    assert verdict.unknown_conditions == ("c2",)
    assert not verdict.coverage_complete
    assert verdict.artifact_verification == "NOT_PERFORMED"
    assert verdict.device_health == "NOT_ASSESSED"


@pytest.mark.parametrize("change", [{"ledger_epoch": "other"}, {"window_index": 1},
    {"contract_hash": "0" * 64}, {"device_id": "d2"}])
def test_mixed_fact_scope_is_rejected(contract, change):
    document = facts(contract, observations=[observation()]).model_dump()
    document["window"].update(change)
    with pytest.raises(ValueError, match="scope"):
        evaluate_rule(contract, "single", ledger_epoch="epoch", window_index=0,
                      facts=[ConditionFacts.model_validate(document)])


def test_counts_and_duplicates_are_not_silently_combined(contract):
    first = facts(contract, observations=[observation()])
    with pytest.raises(ValueError, match="partition"):
        ConditionFacts.model_validate({**first.model_dump(), "accepted_count": 0})
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_rule(contract, "single", ledger_epoch="epoch", window_index=0, facts=[first, first])
    duplicated = [observation(), observation(at=20000000)]
    with pytest.raises(ValueError, match="duplicate"):
        facts(contract, observations=duplicated)
    with pytest.raises(ValueError, match="duplicate"):
        trace_oracle(contract, "single", ledger_epoch="epoch", window_index=0, observations=duplicated)


def test_device_epoch_and_half_open_window_scoping(contract):
    raw = [observation(value=2, at=0), observation(value=2, sequence=2, at=10000000),
           observation(device="d2", value=2), observation(epoch="other", value=2)]
    result = facts(contract, observations=raw)
    assert result.accepted_count == result.matching_count == 1


@pytest.mark.parametrize("inequality", [">", ">=", "<", "<="])
@pytest.mark.parametrize("predicate", ["EXISTS", "COUNT_GE"])
def test_exhaustive_small_two_device_traces_against_independent_oracle(inequality, predicate):
    contract = RuleContract.model_validate(contract_data(inequality, predicate))
    traces = [values for size in range(3) for values in itertools.product((0, 1, 2, None), repeat=size)]
    for left, right in itertools.product(traces, repeat=2):
        raw = tuple(observation(device=device, value=value, sequence=index+1)
                    for device, values in (("d1", left), ("d2", right)) for index, value in enumerate(values))
        computed = [facts(contract, name, raw) for name in ("c1", "c2")]
        for rule_id in ("single", "and", "or"):
            expected = trace_oracle(contract, rule_id, ledger_epoch="epoch", window_index=0, observations=raw)
            actual = evaluate_rule(contract, rule_id, ledger_epoch="epoch", window_index=0, facts=computed)
            assert actual.truth == expected, (predicate, inequality, left, right, rule_id)
            if raw and all(value is not None for value in (*left, *right)) and left:
                compare = {">": lambda x: x > 1, ">=": lambda x: x >= 1,
                           "<": lambda x: x < 1, "<=": lambda x: x <= 1}[inequality]
                if rule_id == "single":
                    boolean = sum(compare(value) for value in left) >= (2 if predicate == "COUNT_GE" else 1)
                    assert actual.truth == (Truth.TRUE if boolean else Truth.FALSE)


def test_oracle_detects_injected_production_comparison_bug(contract, monkeypatch):
    import shared.coverage.evaluation as production
    monkeypatch.setitem(production.COMPARISONS, ">=", lambda value, threshold: False)
    raw = [observation(value=2)]
    assert evaluate_condition(contract.conditions[0], facts(contract, observations=raw)).truth == Truth.FALSE
    assert trace_oracle(contract, "single", ledger_epoch="epoch", window_index=0, observations=raw) == Truth.TRUE


def test_oracle_has_no_evaluator_or_policy_imports():
    import ast
    tree = ast.parse((ROOT / "shared/coverage/oracle.py").read_text())
    imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any("evaluation" in name or "traffic" in name for name in imports)


def test_explicit_paths_cannot_be_overridden_by_measurement_name(contract):
    raw = observation(value=0).model_dump(mode="json")
    raw["metrics"].append({"path": "measurements.cpu_usage", "value": 99})
    sample = IngressObservation.model_validate(raw)
    assert facts(contract, observations=[sample]).matching_count == 0
    assert trace_oracle(contract, "single", ledger_epoch="epoch", window_index=0, observations=[sample]) == Truth.FALSE
    raw["metrics"].append({"path": "cpu_usage", "value": 99})
    with pytest.raises(ValueError, match="ambiguous"):
        IngressObservation.model_validate(raw)


def test_minimum_population_restricts_negatives_not_known_positives():
    data = contract_data()
    data["conditions"][0]["minimum_samples"] = 3
    contract = RuleContract.model_validate(data)
    for value, expected in ((0, Truth.UNKNOWN), (2, Truth.TRUE)):
        raw = [observation(value=value)]
        assert evaluate_condition(contract.conditions[0], facts(contract, observations=raw)).truth == expected
        assert trace_oracle(contract, "single", ledger_epoch="epoch", window_index=0, observations=raw) == expected


def test_nested_composition_has_minimal_support_and_unknowns():
    data = contract_data()
    data["conditions"].append({**data["conditions"][1], "condition_id": "c3", "threshold": -1})
    data["rules"].append({"rule_id": "nested", "expression": {"kind": "AND", "children": [
        {"kind": "ATOM", "condition_id": "c1"}, {"kind": "OR", "children": [
            {"kind": "ATOM", "condition_id": "c2"}, {"kind": "ATOM", "condition_id": "c3"}]}]}})
    contract = RuleContract.model_validate(data)
    raw = [observation(value=2), observation(device="d2", value=0)]
    computed = [facts(contract, name, raw) for name in ("c1", "c2", "c3")]
    result = evaluate_rule(contract, "nested", ledger_epoch="epoch", window_index=0, facts=computed)
    assert result.truth == Truth.TRUE
    assert result.supporting_conditions == ("c1", "c3")
    assert trace_oracle(contract, "nested", ledger_epoch="epoch", window_index=0, observations=raw) == result.truth


def test_unknown_rule_and_nonfinite_observation_fail_visibly(contract):
    with pytest.raises(ValueError, match="unregistered"):
        evaluate_rule(contract, "absent", ledger_epoch="epoch", window_index=0, facts=[])
    with pytest.raises(ValueError, match="unregistered"):
        trace_oracle(contract, "absent", ledger_epoch="epoch", window_index=0, observations=[])
    with pytest.raises(ValueError):
        MetricReading(path="cpu_usage", value=math.inf)
    with pytest.raises(ValueError):
        kleene_and("INVALID", Truth.TRUE)
    with pytest.raises(ValueError, match="exact types"):
        trace_oracle(contract, "single", ledger_epoch="epoch", window_index=0, observations=[], closed="false")
    result = facts(contract, observations=[observation()])
    verdict = evaluate_rule(contract, "single", ledger_epoch="epoch", window_index=0, facts=[result])
    for model, attribute, value in ((result, "accepted_count", 2),
                                     (result.window, "window_index", 1), (verdict, "truth", Truth.TRUE)):
        with pytest.raises(ValidationError):
            setattr(model, attribute, value)


class FakeClock:
    def __init__(self, microseconds=0):
        self.utc = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)
        self.ns = 0

    def utc_now(self): return self.utc
    def monotonic_ns(self): return self.ns
    def advance(self, microseconds, wall_delta=None):
        self.ns += microseconds * 1000
        self.utc += timedelta(microseconds=microseconds if wall_delta is None else wall_delta)


def test_utc_integer_precision_offset_and_boundary():
    for microseconds, index in ((-1, -1), (0, 0), (9999999, 0), (10000000, 1)):
        clock = FakeClock(microseconds)
        window = window_identity(ledger_epoch="epoch", device_id="d1", contract_hash="0"*64, ingress_time=clock.utc)
        assert window.window_index == index
        assert utc_microseconds(clock.utc.astimezone(timezone(timedelta(hours=5, minutes=30)))) == microseconds
    with pytest.raises(ValueError, match="aware"):
        utc_microseconds(datetime(2026, 10, 13))


def test_monotonic_closure_and_normal_delayed_poll():
    clock = FakeClock()
    schedule = WindowSchedule(clock)
    assert schedule.deadline_ns == 10000000000
    clock.advance(9999999)
    assert schedule.poll().closed_window is None
    clock.advance(6)
    update = schedule.poll()
    assert update.active_window_index == 1
    assert update.closed_window.window_index == 0 and update.closed_window.eligible_for_negative
    clock.advance(10000000)
    assert schedule.poll().closed_window.eligible_for_negative


def test_partial_start_interruption_and_no_fabricated_history():
    clock = FakeClock(5000000)
    schedule = WindowSchedule(clock, interrupted=True)
    assert schedule.deadline_ns == 5000000000
    clock.advance(5000000)
    closed = schedule.poll().closed_window
    assert set(closed.limitations) == {CoverageLimitation.STARTUP_PARTIAL, CoverageLimitation.INTERRUPTED}
    clock.advance(35000000)
    update = schedule.poll()
    assert update.skipped_window_count == 2
    assert update.closed_window.window_index == 1
    assert not update.closed_window.eligible_for_negative
    assert update.active_window_index == 4
    assert schedule.interrupt().active_window_index is None
    with pytest.raises(ValueError, match="halted"):
        schedule.poll()


@pytest.mark.parametrize("wall_delta", [2000000, -2000000])
def test_wall_clock_jump_halts_and_cannot_reopen(wall_delta):
    clock = FakeClock()
    schedule = WindowSchedule(clock)
    clock.advance(1000000, wall_delta=wall_delta)
    update = schedule.poll()
    assert update.active_window_index is None
    assert CoverageLimitation.CLOCK_DISCONTINUITY in update.closed_window.limitations
    with pytest.raises(ValueError, match="recovery"):
        schedule.poll()


def test_monotonic_regression_and_clock_setting_validation():
    clock = FakeClock()
    clock.ns = 2000
    schedule = WindowSchedule(clock)
    clock.ns = 1000
    assert schedule.poll().active_window_index is None
    with pytest.raises(ValueError):
        WindowSchedule(clock, jump_tolerance_us=True)
