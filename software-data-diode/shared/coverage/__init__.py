"""Opt-in pure research contracts. Not wired into live service entry points."""
from .contracts import contract_bytes, contract_hash, load_contract, parse_contract
from .evaluation import condition_facts, evaluate_condition, evaluate_rule, kleene_and, kleene_or
from .models import (ArtifactVerification, AtomicCondition, ConditionFacts, ContractLimits,
                     CoverageLimitation, DeviceScope, IngressObservation, MetricDefinition,
                     MetricReading, RuleContract, RuleDefinition, RuleExpression, RuleVerdict,
                     Truth, WindowIdentity)
from .oracle import trace_oracle
from .windows import Clock, SystemClock, WindowSchedule, utc_microseconds, window_identity

__all__ = [
    "ArtifactVerification", "AtomicCondition", "ConditionFacts", "ContractLimits", "CoverageLimitation",
    "DeviceScope", "IngressObservation", "MetricDefinition", "MetricReading", "RuleContract",
    "RuleDefinition", "RuleExpression", "RuleVerdict", "Truth", "WindowIdentity", "Clock",
    "SystemClock", "WindowSchedule", "contract_bytes", "contract_hash", "load_contract",
    "parse_contract", "condition_facts", "evaluate_condition", "evaluate_rule", "kleene_and",
    "kleene_or", "trace_oracle", "utc_microseconds", "window_identity",
]
