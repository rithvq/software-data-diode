"""Policy and scheduling contracts contain no HTTP or Docker dependencies."""
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from .models import Telemetry


@dataclass(frozen=True)
class LocalState:
    arrivals: int
    dispatch_attempts: int
    queue_length: int
    received_bytes: int


@dataclass(frozen=True)
class QueuedMessage:
    message: Telemetry
    body: bytes
    arrival_timestamp: datetime
    queue_entry_timestamp: datetime


@dataclass(frozen=True)
class PolicyDecision:
    admit: bool = True
    reason: str = "phase1 pass-through admission"


class InformationAnalyzer(Protocol):
    def analyze(self, message: Telemetry) -> dict[str, float]: ...


class StateEstimator(Protocol):
    def observe_arrival(self, message_size_bytes: int) -> None: ...
    def observe_dispatch(self) -> None: ...
    def snapshot(self, queue_length: int) -> LocalState: ...


class CongestionPredictor(Protocol):
    def predict(self, state: LocalState) -> str: ...


class PolicyEngine(Protocol):
    def decide(self, message: Telemetry, information: dict[str, float],
               state: LocalState, prediction: str) -> PolicyDecision: ...


class Scheduler(Protocol):
    def enqueue(self, item: QueuedMessage) -> None: ...
    def select(self, state: LocalState) -> QueuedMessage | None: ...
    def __len__(self) -> int: ...


@dataclass
class PipelineComponents:
    analyzer: InformationAnalyzer
    estimator: StateEstimator
    predictor: CongestionPredictor
    policy: PolicyEngine
    scheduler: Scheduler
