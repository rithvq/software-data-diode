from pathlib import Path
from unittest.mock import Mock

import requests
from streamlit.testing.v1 import AppTest


APP = Path(__file__).resolve().parents[1] / "dashboard/app.py"


def snapshot():
    timestamp = "2026-09-23T07:00:00Z"
    return {
        "observed_at": timestamp,
        "overview": {"generated_messages": 10, "accepted_messages": 8},
        "architecture": {"edge_devices": [{"device_id": "edge-device-01", "health": "ACTIVE", "last_seen": timestamp}]},
        "scheduler": {
            "by_priority": [{"priority": "LOW", "throughput": 1, "average_latency": 0.1,
                             "average_queue_wait": 0.02, "p95_latency": 0.2, "delivered": 8, "dropped": 0}],
            "score_distribution": {"LOW": [1, 2, 3]},
        },
        "security": {"counts": {"invalid_signatures": 1}, "audit_logs": [{"service": "fog", "valid": True, "detail": "valid"}]},
        "analytics": {
            "latest_anomalies": [{"timestamp": timestamp, "device_id": "edge-device-01", "detector": "threshold",
                                  "metric": "temperature", "observed_value": 45, "severity": "HIGH"}],
            "active_alerts": [{"timestamp": timestamp, "alert_type": "ANOMALY_THRESHOLD", "severity": "HIGH",
                               "source_devices": ["edge-device-01"]}],
            "anomaly_timeline": [{"timestamp": timestamp, "severity": "HIGH", "count": 1}],
            "telemetry_trends": [{"timestamp": timestamp, "telemetry_type": "environmental", "messages": 8}],
            "alert_severity": [{"severity": "HIGH", "count": 1}],
        },
    }


def test_dashboard_views_filters_and_refresh_controls(monkeypatch):
    monkeypatch.setattr(requests, "get", Mock(return_value=Mock(json=snapshot, raise_for_status=lambda: None)))
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    assert not app.exception
    for seconds in (5, 10, 30, 3):
        app.button_group(key="refresh_interval_seconds").set_value(seconds).run()
        assert app.session_state["refresh_interval_seconds"] == seconds
        assert any(f"Every {seconds}s" in element.value for element in app.markdown)
        assert not app.exception
    app.toggle(key="auto_refresh_enabled").set_value(False).run()
    assert app.button_group(key="refresh_interval_seconds").disabled
    assert any("Paused" in element.value for element in app.markdown)
    for view in ("Scheduler", "Security", "Fog analytics", "Architecture"):
        app.button_group(key="dashboard_view").set_value(view).run()
        assert not app.exception
        for widget in list(app.multiselect):
            widget.set_value([]).run()
            assert not app.exception


def test_dashboard_retains_snapshot_during_outage(monkeypatch):
    get = Mock(return_value=Mock(json=snapshot, raise_for_status=lambda: None))
    monkeypatch.setattr(requests, "get", get)
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    get.side_effect = requests.ConnectionError("offline")
    app.run()
    assert not app.exception
    assert app.session_state["last_good_snapshot"]["overview"]["accepted_messages"] == 8
    assert any("last received snapshot" in element.value for element in app.warning)
    assert any("Stale" in element.value for element in app.markdown)


def test_dashboard_initial_outage_does_not_crash(monkeypatch):
    monkeypatch.setattr(requests, "get", Mock(side_effect=requests.Timeout("offline")))
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    assert not app.exception
    assert len(app.warning) == 1
