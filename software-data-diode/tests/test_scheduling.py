from datetime import datetime, timezone

from shared.models import CongestionState, PriorityLevel
from shared.traffic import AdaptiveScheduler, BoundedMessageQueue, CongestionMonitor, SchedulerWeights
from shared.traffic.scheduling import ScheduledMessage, new_simulated_envelope


def scheduled(priority: PriorityLevel, enqueued_at: float, sequence: int) -> ScheduledMessage:
    return ScheduledMessage(
        envelope=new_simulated_envelope(
            priority,
            datetime.now(timezone.utc),
            sequence,
            estimated_transmission_cost=100,
        ),
        enqueued_at=enqueued_at,
        size_bytes=100,
        arrival_index=sequence,
    )


def test_adaptive_scheduler_prioritizes_critical_messages() -> None:
    scheduler = AdaptiveScheduler(SchedulerWeights())
    low = scheduled(PriorityLevel.LOW, enqueued_at=0.0, sequence=1)
    critical = scheduled(PriorityLevel.CRITICAL, enqueued_at=1.0, sequence=2)

    selected = scheduler.choose([low, critical], now=1.0, congestion_state=CongestionState.NORMAL)

    assert selected.envelope.priority == PriorityLevel.CRITICAL


def test_aging_and_starvation_boost_can_promote_old_low_priority_messages() -> None:
    scheduler = AdaptiveScheduler(SchedulerWeights())
    old_low = scheduled(PriorityLevel.LOW, enqueued_at=0.0, sequence=1)
    fresh_high = scheduled(PriorityLevel.HIGH, enqueued_at=100.0, sequence=2)

    low_score = scheduler.score(old_low, now=100.0, congestion_state=CongestionState.NORMAL)
    high_score = scheduler.score(fresh_high, now=100.0, congestion_state=CongestionState.NORMAL)

    assert low_score > high_score


def test_fifo_and_adaptive_can_choose_different_messages() -> None:
    scheduler = AdaptiveScheduler(SchedulerWeights())
    queue = BoundedMessageQueue(max_queue_size=10)
    low = new_simulated_envelope(PriorityLevel.LOW, datetime.now(timezone.utc), 1)
    critical = new_simulated_envelope(PriorityLevel.CRITICAL, datetime.now(timezone.utc), 2)

    queue.push(low, size_bytes=100, now=0.0)
    queue.push(critical, size_bytes=100, now=0.1)
    fifo_choice = queue.pop_fifo()

    queue = BoundedMessageQueue(max_queue_size=10)
    queue.push(low, size_bytes=100, now=0.0)
    queue.push(critical, size_bytes=100, now=0.1)
    adaptive_choice = queue.pop_adaptive(scheduler, now=0.1, congestion_state=CongestionState.NORMAL)

    assert fifo_choice is not None
    assert adaptive_choice is not None
    assert fifo_choice.envelope.priority == PriorityLevel.LOW
    assert adaptive_choice.envelope.priority == PriorityLevel.CRITICAL


def test_congestion_state_transitions() -> None:
    monitor = CongestionMonitor(
        elevated_threshold=0.5,
        congested_threshold=0.75,
        critical_threshold=0.9,
    )

    assert monitor.state(0, 100) == CongestionState.NORMAL
    assert monitor.state(50, 100) == CongestionState.ELEVATED
    assert monitor.state(75, 100) == CongestionState.CONGESTED
    assert monitor.state(90, 100) == CongestionState.CRITICAL


def test_queue_overflow_retains_higher_priority_messages() -> None:
    queue = BoundedMessageQueue(max_queue_size=2)
    low_one = new_simulated_envelope(PriorityLevel.LOW, datetime.now(timezone.utc), 1)
    low_two = new_simulated_envelope(PriorityLevel.LOW, datetime.now(timezone.utc), 2)
    critical = new_simulated_envelope(PriorityLevel.CRITICAL, datetime.now(timezone.utc), 3)

    assert queue.push(low_one, 100, now=0.0).accepted is True
    assert queue.push(low_two, 100, now=0.1).accepted is True
    result = queue.push(critical, 100, now=0.2)

    assert result.accepted is True
    assert result.dropped is not None
    assert result.dropped.envelope.priority == PriorityLevel.LOW
    assert any(item.envelope.priority == PriorityLevel.CRITICAL for item in queue.snapshot())


def test_full_queue_drops_incoming_low_priority_message() -> None:
    queue = BoundedMessageQueue(max_queue_size=1)
    first_low = new_simulated_envelope(PriorityLevel.LOW, datetime.now(timezone.utc), 1)
    second_low = new_simulated_envelope(PriorityLevel.LOW, datetime.now(timezone.utc), 2)

    assert queue.push(first_low, 100, now=0.0).accepted is True
    result = queue.push(second_low, 100, now=0.1)

    assert result.accepted is False
    assert result.dropped is not None
    assert result.dropped.envelope.sequence_number == 2
