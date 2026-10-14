import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock
from uuid import UUID

import pytest
import requests
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry, generate_latest
from streamlit.testing.v1 import AppTest

from shared.observability.coverage import CoverageMetrics
from shared.persistence.coverage_queries import CoverageQuery, predicate, sender_accounting, verdict_page, witnesses
from tests.test_coverage_transport import coupled, framer
from tests.test_dashboard import APP, snapshot


ROOT = Path(__file__).resolve().parents[1]
IDENTITY = "11111111-1111-5111-8111-111111111111"
DIGEST = "a"*64


@pytest.fixture(autouse=True)
def research_dashboard_enabled(monkeypatch):
    monkeypatch.setenv("DASHBOARD_COVERAGE_ENABLED", "true")


def fixture_documents():
    row = {"decision_id": IDENTITY, "window_index": 179190000, "rule_id": "incident-correlation",
           "verdict": "UNKNOWN", "revision": 2, "contract_hash": DIGEST, "result": {
               "truth": "UNKNOWN", "reason_codes": ["MISSING_EVIDENCE"], "conditions": [],
               "supporting_artifacts": [DIGEST], "coverage_health": {"state": "DEGRADED"}}}
    overview = {"observed_at": "2026-10-14T00:00:00Z", "rules": ["incident-correlation"],
        "contract": {"devices": [{"device_id": "edge-device-02"}]},
        "counts": {"opportunities": 1, "definite_yield": 0, "unknown_rate": 1},
        "cost": {"received_evidence_bytes": 1200}, "sender": {"evidence_fraction": None},
        "devices": [{"device_id": "edge-device-02", "coverage": "MISSING"}]}
    body = {"device_id": "edge-device-02", "accepted_observation_count": 5,
            "per_condition_facts": [{"unresolved_count": 2}], "reduction_accounting": {"selected_raw": 1, "reduced_raw": 4}}
    detail = {"decision": row, "capsules": [{"artifact_digest": DIGEST, "body": body,
        "verification": {"assurance_level": "AUTHENTICATED_SUMMARY", "continuity": "GAP"}}],
        "history": [{"revision": 1, "record": {"verdict": "UNKNOWN"}}], "alerts": [{"active": False}]}
    return {"overview": overview, "verdicts": {"items": [row], "next_cursor": None},
            "decisions/"+IDENTITY: detail,
            "capsules/"+DIGEST: {"signed_artifact": {"body": body}, "verification": detail["capsules"][0]["verification"]},
            "capsules/"+DIGEST+"/witnesses": {"items": [], "next_sequence": None}}


def responses(documents, calls):
    def get(url, **kwargs):
        calls.append((url, kwargs))
        value = snapshot() if url.endswith("/api/snapshot") else documents[url.split("/api/coverage/")[1]]
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(value).encode()
        return response
    return get


def test_coverage_controls_pause_manual_timeout_and_downloads(monkeypatch):
    documents, calls = fixture_documents(), []
    get = Mock(side_effect=responses(documents, calls))
    monkeypatch.setattr(requests, "get", get)
    app = AppTest.from_file(str(APP), default_timeout=20).run()
    app.button_group(key="dashboard_view").set_value("Evidence Coverage").run()
    assert not app.exception
    assert app.session_state["coverage_selected"] == IDENTITY
    assert any("NOT RUN" in e.value for e in app.markdown)
    downloads = app.get("download_button")
    assert len(downloads) >= 6
    assert any(e.proto.url for e in downloads)
    app.selectbox(key="coverage_rule").select("incident-correlation").run()
    app.selectbox(key="coverage_device").select("edge-device-02").run()
    app.selectbox(key="coverage_hours").set_value(24).run()
    assert calls[-1][1]["timeout"] == 2
    assert any(c[1].get("params", {}).get("device_id") == "edge-device-02" for c in calls)
    app.toggle(key="auto_refresh_enabled").set_value(False).run()
    before = len(calls)
    app.run()
    assert len(calls) == before
    assert any("Paused" in e.value for e in app.markdown)
    next(b for b in app.button if b.label == "Refresh now").click().run()
    assert len(calls) > before and not app.exception
    get.side_effect = requests.Timeout("controlled outage")
    next(b for b in app.button if b.label == "Refresh now").click().run()
    assert not app.exception
    assert app.session_state["coverage_selected"] == IDENTITY
    assert any("Last good data retained" in e.value for e in app.warning)
    assert any("MISSING_EVIDENCE" in e.value for e in app.markdown)
    app.selectbox(key="coverage_rule").select("All").run()
    assert any("No evidence is inferred" in e.value for e in app.warning)


def test_empty_results_and_large_paginated_results(monkeypatch):
    documents, calls = fixture_documents(), []
    documents["verdicts"]["items"] = []
    monkeypatch.setattr(requests, "get", responses(documents, calls))
    app = AppTest.from_file(str(APP), default_timeout=20).run()
    app.button_group(key="dashboard_view").set_value("Evidence Coverage").run()
    assert not app.exception and len(app.info) == 1
    rows = [dict(fixture_documents()["verdicts"]["items"][0], decision_id=str(UUID(int=n+100)),
                 window_index=179190000-n) for n in range(25)]
    for row in rows:
        documents["decisions/"+row["decision_id"]] = dict(fixture_documents()["decisions/"+IDENTITY], decision=row)
    documents["verdicts"] = {"items": rows, "next_cursor": {"before_window": rows[-1]["window_index"], "before_id": rows[-1]["decision_id"]}}
    app.run()
    app.button(key="coverage_next").click().run()
    assert app.session_state["coverage_cursor"]["before_id"] == rows[-1]["decision_id"]
    assert not app.exception
    app.button(key="coverage_previous").click().run()
    assert app.session_state["coverage_cursor"] is None
    for seconds in (5, 10, 30, 3):
        app.button_group(key="refresh_interval_seconds").set_value(seconds).run()
        assert not app.exception
        assert app.session_state["coverage_selected"] == rows[0]["decision_id"]


def api_module(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("COVERAGE_DASHBOARD_ENABLED", "false")
    path = ROOT / "monitoring-api/app/main.py"
    spec = importlib.util.spec_from_file_location("n8_api_test", path, submodule_search_locations=[str(path.parent)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_api_bounds_disabled_missing_timeout_and_scrape(monkeypatch):
    module = api_module(monkeypatch)
    client = TestClient(module.app)
    assert client.get("/api/coverage/overview").status_code == 404
    module.store.coverage_enabled = True
    module.store.coverage = Mock(return_value={"items": []})
    for query in ("limit=101", "limit=0", "truth=MAYBE", "start_window=-1", "extra=1",
                  "before_window=1", "before_id="+IDENTITY, "start_window=2&end_window=1"):
        assert client.get("/api/coverage/verdicts?"+query).status_code == 422
    assert client.get("/api/coverage/capsules/not-a-digest").status_code == 422
    assert client.get(f"/api/coverage/capsules/{DIGEST}/witnesses?limit=17").status_code == 422
    assert client.get("/api/coverage/decisions/not-a-uuid").status_code == 422
    assert client.get("/api/coverage/verdicts?limit=25").status_code == 200
    query = module.store.coverage.call_args.args[1]
    assert isinstance(query, CoverageQuery)
    module.store.coverage.return_value = None
    assert client.get(f"/api/coverage/decisions/{IDENTITY}").status_code == 404
    module.store.coverage.side_effect = RuntimeError("private SQL and credentials")
    response = client.get("/api/coverage/overview")
    assert response.status_code == 503 and "private" not in response.text
    assert "coverage_metrics_available 0.0" in client.get("/metrics").text


def test_keyset_query_parameterization_and_witness_bounds():
    query = CoverageQuery(rule_id="x", device_id="edge-01", limit=2, before_window=50, before_id=UUID(IDENTITY))
    where, params = predicate(query, page=True)
    assert "edge-01" not in where and "edge-01" in params
    assert "<(%s,%s)" in where
    records = [{"decision_id": UUID(int=n), "window_index": n} for n in (49, 48, 47)]
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = records
    page = verdict_page(connection, query)
    assert len(page["items"]) == 2 and page["next_cursor"]["before_window"] == 48
    assert cursor.execute.call_args.args[1][-1] == 3
    cursor.fetchall.return_value = [{"ingress_sequence": n, "canonical_input": b'{}'} for n in range(1, 4)]
    result = witnesses(connection, DIGEST, limit=2)
    assert result["next_sequence"] == 2 and len(result["items"]) == 2
    assert result["items"][0]["canonical_input_base64"] == "e30="


@pytest.mark.parametrize("bad", [None, {}, {"total": 5}, {"scope": "other"}])
def test_unmatched_byte_fraction_is_unavailable(bad):
    assert sender_accounting({"metrics": {"forward_byte_accounting": bad}})["evidence_fraction"] is None


def test_matched_byte_scopes_and_fixed_label_metrics():
    sender = sender_accounting({"timestamp": None, "metrics": {"forward_byte_accounting": {
        "scope": "N8_LOCAL_GRANTS_SINCE_START", "total": 100, "RAW": 60, "EVIDENCE": 30, "STATE": 10},
        "reserved_wire_bytes": 1200}})
    assert sender["evidence_fraction"] == .3 and sender["receipt"] == "NOT_OBSERVED"
    registry = CollectorRegistry()
    metrics = CoverageMetrics(registry)
    metrics.update({"sender": sender, "counts": {"positive": 1, "negative": 2, "unknown": 3},
                    "cost": {"received_evidence_bytes": 2500}, "verification_failures": 2})
    text = generate_latest(registry).decode()
    assert 'coverage_rule_windows{truth="UNKNOWN"} 3.0' in text
    assert "coverage_evidence_forward_fraction 0.3" in text
    assert "device_id" not in text and "contract_hash" not in text
    metrics.unavailable()
    assert "coverage_evidence_received_bytes NaN" in generate_latest(registry).decode()


def test_read_only_fog_wiring():
    source = (ROOT/"monitoring-api/app/store.py").read_text()
    assert "REPEATABLE READ READ ONLY" in source
    assert "NOT i.active" in source
    query_source = (ROOT/"shared/persistence/coverage_queries.py").read_text()
    assert "requests.get" not in query_source and "sqlite" not in query_source
    assert "coverage-ledger" not in (ROOT/"docker-compose.coverage.yml").read_text().split("  monitoring-api:")[1].split("  dashboard:")[0]


def test_byte_counters_atomic_matched_repeats_and_restart(tmp_path, framer):
    from collections import Counter

    from shared.coverage.admission import CoupledAdmission
    from shared.coverage.ledger import ObservationLedger
    from shared.coverage.transport import ResearchFramer
    from tests.test_coverage_ledger import CONTRACT, FakeClock, message

    controller = coupled(tmp_path, framer)
    try:
        controller.admit(message(), expected_epoch=controller.ledger.epoch, retry_sequence=1)
        controller.publish_forward_state()
        sums = Counter()
        for _ in range(1400):
            lease = controller.lease_frame()
            if lease:
                sums[lease.kind] += lease.modeled_wire_bytes
                controller.complete_local_attempt(lease.lease_id)
            controller.ledger.clock.advance(.01)
        accounting = controller.status()["forward_byte_accounting"]
        assert set(sums) == {"RAW", "STATE", "EVIDENCE"}
        assert all(accounting[k] == sums[k] for k in sums)
        assert accounting["total"] == sum(sums.values()) == controller.status()["modeled_scheduled_bytes"]
        assert controller.status()["pending_evidence_obligations"] == 0
        path, profile, key = controller.ledger.path, controller.framer.profile, controller.key
        controller.ledger.close()
        store = ObservationLedger(path, CONTRACT, clock=FakeClock(20))
        current = ResearchFramer(profile, key.public_key(), CONTRACT, private_key=key)
        controller = CoupledAdmission(store, profile.gateway_id, profile.signing_key_id, key, framer=current)
        assert controller.status()["forward_byte_accounting"] == accounting
        controller.publish_forward_state()
        store.clock.advance(1)
        def fault(stage, db):
            if stage == "before_service_commit":
                raise RuntimeError("injected rollback")
        store.fault = fault
        with pytest.raises(RuntimeError, match="rollback"):
            controller.lease_frame()
        assert controller.status()["forward_byte_accounting"] == accounting
        store.fault = lambda *args: None
        lease = controller.lease_frame()
        assert lease
        charged = controller.status()["forward_byte_accounting"]
        controller.retire_uncertain_lease()
        assert controller.status()["forward_byte_accounting"] == charged
    finally:
        controller.ledger.close()
