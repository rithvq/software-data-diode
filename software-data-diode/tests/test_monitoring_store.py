from __future__ import annotations

import importlib.util
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STORE_PATH = PROJECT_ROOT / "monitoring-api" / "app" / "store.py"


def load_store_module():
    spec = importlib.util.spec_from_file_location("monitoring_store_test_module", STORE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {STORE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_audit_verification_runs_in_background_and_is_cached(monkeypatch, tmp_path) -> None:
    module = load_store_module()
    clock = [100.0]
    verification_calls = []
    deferred_threads = []

    class DeferredThread:
        def __init__(self, *, target, name, daemon) -> None:
            self.target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            deferred_threads.append(self)

    def fake_verify(path: Path) -> tuple[bool, str]:
        verification_calls.append(path.name)
        return True, "audit log hash chain is valid"

    monkeypatch.setattr(module, "Thread", DeferredThread)
    monkeypatch.setattr(module, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "verify_audit_log", fake_verify)

    store = module.MonitoringStore(
        "postgresql://unused",
        str(tmp_path),
        audit_verification_interval_seconds=30,
    )

    initial = store._audit_states()
    assert {item["valid"] for item in initial} == {None}
    assert len(deferred_threads) == 1
    assert verification_calls == []

    deferred_threads[0].target()
    cached = store._audit_states()
    assert {item["valid"] for item in cached} == {True}
    assert len(deferred_threads) == 1
    assert len(verification_calls) == 3

    clock[0] = 131.0
    stale = store._audit_states()
    assert {item["valid"] for item in stale} == {True}
    assert len(deferred_threads) == 2
    assert len(verification_calls) == 3


def test_monitoring_api_offloads_blocking_store_calls() -> None:
    source = (PROJECT_ROOT / "monitoring-api" / "app" / "main.py").read_text(encoding="utf-8")

    assert "await asyncio.to_thread(store.healthcheck)" in source
    assert "await asyncio.to_thread(store.snapshot)" in source
