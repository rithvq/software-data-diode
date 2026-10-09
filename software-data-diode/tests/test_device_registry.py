from concurrent.futures import ThreadPoolExecutor

from shared.edge import DeviceRegistry
from shared.models import DeviceHealth, PriorityLevel


def test_concurrent_devices_have_independent_sequences_and_statistics() -> None:
    registry = DeviceRegistry()

    def send(device_number: int) -> None:
        device_id = f"edge-device-{device_number:02d}"
        for _ in range(200):
            registry.record_received(device_id, PriorityLevel.LOW)
            registry.next_sequence(device_id)
            registry.record_forwarded(device_id)

    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(send, range(1, 6)))

    snapshots = registry.snapshots()
    assert len(snapshots) == 5
    assert all(snapshot.health == DeviceHealth.ACTIVE for snapshot in snapshots)
    assert all(snapshot.last_sequence_number == 200 for snapshot in snapshots)
    assert all(snapshot.received_count == 200 for snapshot in snapshots)
    assert all(snapshot.forwarded_count == 200 for snapshot in snapshots)


def test_sequence_numbers_survive_gateway_restart(tmp_path) -> None:
    state_path = tmp_path / "gateway-sequences.json"
    first = DeviceRegistry(sequence_state_path=state_path)
    assert first.next_sequence("edge-device-01") == 1
    assert first.next_sequence("edge-device-01") == 2
    assert first.next_sequence("edge-device-02") == 1

    restarted = DeviceRegistry(sequence_state_path=state_path)

    assert restarted.next_sequence("edge-device-01") == 3
    assert restarted.next_sequence("edge-device-02") == 2


def test_filtering_and_priority_statistics_are_kept_per_device() -> None:
    registry = DeviceRegistry()
    registry.record_received("edge-device-01", PriorityLevel.LOW)
    registry.record_filtered("edge-device-01", "unchanged")
    registry.record_received("edge-device-02", PriorityLevel.CRITICAL)

    first = registry.snapshot("edge-device-01")
    second = registry.snapshot("edge-device-02")

    assert first is not None and first.filtering_statistics == {"unchanged": 1}
    assert first.priority_statistics[PriorityLevel.LOW] == 1
    assert second is not None and second.filtered_count == 0
    assert second.priority_statistics[PriorityLevel.CRITICAL] == 1
