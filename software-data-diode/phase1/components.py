from collections import deque

from .interfaces import LocalState, PipelineComponents, PolicyDecision, QueuedMessage


class PassThroughInformationAnalyzer:
    def analyze(self, message):
        return {}


class CountingStateEstimator:
    def __init__(self):
        self.arrivals = 0
        self.dispatch_attempts = 0
        self.received_bytes = 0

    def observe_arrival(self, message_size_bytes):
        self.arrivals += 1
        self.received_bytes += message_size_bytes

    def observe_dispatch(self):
        self.dispatch_attempts += 1

    def snapshot(self, queue_length):
        return LocalState(self.arrivals, self.dispatch_attempts, queue_length, self.received_bytes)


class NoOpCongestionPredictor:
    def predict(self, state):
        return "NORMAL"


class PassThroughPolicyEngine:
    def decide(self, message, information, state, prediction):
        return PolicyDecision()


class FifoScheduler:
    def __init__(self):
        self._items = deque()

    def enqueue(self, item: QueuedMessage):
        self._items.append(item)

    def select(self, state: LocalState):
        return self._items.popleft() if self._items else None

    def __len__(self):
        return len(self._items)


def default_components() -> PipelineComponents:
    return PipelineComponents(
        PassThroughInformationAnalyzer(), CountingStateEstimator(),
        NoOpCongestionPredictor(), PassThroughPolicyEngine(), FifoScheduler(),
    )
