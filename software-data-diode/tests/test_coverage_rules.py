from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import itertools
import json
from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest

from shared.coverage.capsules import InputRecord, build_capsule, sign_artifact, artifact_digest, EvidenceError
from shared.coverage.contracts import contract_hash
from shared.coverage.models import CoverageLimitation, WindowIdentity, IngressObservation, MetricReading
from shared.coverage.monitoring import MonitoringConfig, CoverageMonitor, RulePolicy
from shared.models.fog import CoverageAlertDelivery as AlertDelivery
from shared.coverage.oracle import trace_oracle
from shared.coverage.parts import split_artifact
from shared.coverage.rules import VerifiedScope, checked_witnesses, evaluate_window
from shared.coverage.verification import FogEvidenceVerifier
from shared.security.crypto import canonical_bytes
from tests.test_coverage_transport import framer as framer
from tests.conftest import load_service_module
from shared.models import EdgeTelemetryMessage, AlertSeverity


def scope_fixture(framer, device="edge-device-01", values=(45,), *, index=100, complete=True, limitations=(), previous=None):
    contract, records = framer.contract, []
    device_scope = next(d for d in contract.devices if d.device_id == device)
    path = device_scope.metrics[0].path
    window = WindowIdentity(ledger_epoch=framer.profile.ledger_epoch,device_id=device,window_index=index,contract_hash=contract_hash(contract))
    for seq, value in enumerate(values,1):
        kwargs = {"temperature":25,"humidity":50,"status":"normal","device_id":device,"telemetry_type":device_scope.telemetry_type,
            "timestamp":datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(microseconds=window.start_utc_us+seq)}
        if value is not None:
            if path.startswith("measurements."):
                kwargs["measurements"] = {path.split(".",1)[1]:value}
            else:
                kwargs[path] = value
        raw = canonical_bytes(EdgeTelemetryMessage(**kwargs).model_dump(mode="json"))
        records.append(InputRecord(ledger_epoch=window.ledger_epoch,device_id=device,ingress_sequence=index*100+seq,
            ingress_utc_us=window.start_utc_us+seq,canonical_input=raw,input_hash=hashlib.sha256(raw).hexdigest()))
    body = build_capsule(contract=contract,window=window,records=records,gateway_id=framer.profile.gateway_id,
        signing_key_id=framer.profile.signing_key_id,created_at_utc_us=window.end_utc_us,previous_digest=previous,
        population_complete=complete,limitations=limitations,
        closure_reason="CLOCK_DISCONTINUITY" if CoverageLimitation.CLOCK_DISCONTINUITY in limitations else "INTERRUPTED" if limitations else "WINDOW_END")
    encoded = sign_artifact(body,framer.private_key)
    frames = split_artifact(encoded,framer.private_key)
    verification = FogEvidenceVerifier(framer).verify(encoded,received_us=window.end_utc_us,frames=frames)
    return VerifiedScope(body,artifact_digest(encoded),verification), tuple(records), encoded, frames


def decisions(framer, scopes=(), index=100):
    return {r["rule_id"]:r for r in evaluate_window(framer.contract,gateway_id=framer.profile.gateway_id,
        ledger_epoch=framer.profile.ledger_epoch,window_index=index,scopes=scopes)}


def oracle_original(record, contract):
    # Independent normalization from canonical originals, not N7 witness helpers.
    document = json.loads(record.canonical_input)
    device = next(d for d in contract.devices if d.device_id == record.device_id)
    readings = []
    for metric in device.metrics:
        if metric.path.startswith("measurements."):
            value = document["measurements"].get(metric.path[len("measurements."):])
        else:
            value = document.get(metric.path)
        readings.append(MetricReading(path=metric.path,value=value))
    return IngressObservation(ledger_epoch=record.ledger_epoch,device_id=record.device_id,ingress_sequence=record.ingress_sequence,
        ingress_utc_us=record.ingress_utc_us,telemetry_type=document["telemetry_type"],metrics=tuple(readings))


def test_positive_partial_negative_complete_and_coverage_not_global(framer):
    positive,*_ = scope_fixture(framer,complete=False)
    result = decisions(framer,[positive])["process-attention"]
    assert result["truth"] == "TRUE" and not result["coverage_complete"]
    assert result["unknown_conditions"] == ["industrial-vibration"]
    negative,*_ = scope_fixture(framer,values=(25,))
    result = decisions(framer,[negative])["process-correlation"]
    assert result["truth"] == "FALSE" and not result["coverage_complete"]
    assert result["supporting_conditions"] == ["environmental-hot"]
    assert result["coverage_health"]["state"] == "DEGRADED"
    local = decisions(framer,[negative])["environmental-threshold"]
    assert local["coverage_complete"] and not local["coverage_health"]["complete"]


def test_empty_missing_no_input_and_clock_uncertainty(framer):
    assert all(r["truth"] == "UNKNOWN" for r in decisions(framer).values())
    empty,*_ = scope_fixture(framer,values=())
    assert decisions(framer,[empty])["environmental-threshold"]["truth"] == "UNKNOWN"
    discontinuous,*_ = scope_fixture(framer,limitations=(CoverageLimitation.CLOCK_DISCONTINUITY,))
    assert decisions(framer,[discontinuous])["environmental-threshold"]["truth"] == "UNKNOWN"


def test_count_lower_upper_missing_metrics_and_original_not_double_counted(framer):
    one,records,*_ = scope_fixture(framer,"edge-device-04",(5,))
    one = replace(one,originals=records)
    result = decisions(framer,[one])["repeated-security-observations"]
    assert result["truth"] == "FALSE" and result["condition_bounds"]["security-repeat"] == {"lower":1,"upper":1}
    assert result["checked_original_witnesses"]
    two,*_ = scope_fixture(framer,"edge-device-04",(5,5),complete=False)
    assert decisions(framer,[two])["repeated-security-observations"]["truth"] == "TRUE"
    unknown,*_ = scope_fixture(framer,"edge-device-04",(5,None))
    assert decisions(framer,[unknown])["repeated-security-observations"]["truth"] == "UNKNOWN"
    bounded,*_ = scope_fixture(framer,"edge-device-04",(None,))
    result = decisions(framer,[bounded])["repeated-security-observations"]
    assert result["truth"] == "FALSE" and not result["coverage_complete"]


def test_correlation_real_paths_quantifier_and_different_windows(framer):
    scopes = [scope_fixture(framer,d,(v,))[0] for d,v in (("edge-device-02",90),("edge-device-03",8000),("edge-device-04",5))]
    result = decisions(framer,scopes)["incident-correlation"]
    assert result["truth"] == "TRUE" and "physical simultaneity is not asserted" in result["quantifier"]
    next_window,*_ = scope_fixture(framer,"edge-device-04",(5,),index=101)
    assert decisions(framer,[*scopes[:2],next_window])["incident-correlation"]["truth"] == "UNKNOWN"


def test_conflicting_scope_and_gap_are_distinct(framer):
    a,*_ = scope_fixture(framer)
    fork,*_ = scope_fixture(framer,values=(25,))
    assert decisions(framer,[a,fork])["environmental-threshold"]["truth"] == "UNKNOWN"
    assert decisions(framer,[a,fork])["environmental-threshold"]["verification_status"] == "CONFLICT_PRESENT"
    assert decisions(framer,[replace(a,verification=a.verification.model_copy(update={"continuity_status":"GAP"}))])["environmental-threshold"]["truth"] == "TRUE"
    assert decisions(framer,[replace(a,retired=True)])["environmental-threshold"]["truth"] == "UNKNOWN"


def test_contract_epoch_device_and_record_mismatch_never_supply_facts(framer):
    a,*_ = scope_fixture(framer)
    wrong = replace(a,verification=a.verification.model_copy(update={"contract_hash":"f"*64}))
    assert decisions(framer,[wrong])["environmental-threshold"]["truth"] == "UNKNOWN"
    other,*_ = scope_fixture(framer,index=101)
    assert decisions(framer,[other])["environmental-threshold"]["truth"] == "UNKNOWN"


def test_unrelated_disclosure_cannot_authenticate_an_original_witness(framer):
    a,records,*_ = scope_fixture(framer)
    other,changed,*_ = scope_fixture(framer,values=(25,))
    with pytest.raises(EvidenceError,match="UNAUTHENTICATED"):
        checked_witnesses(replace(a,originals=changed),framer.contract)
    with pytest.raises(EvidenceError,match="DUPLICATE"):
        checked_witnesses(replace(a,originals=(*records,*records)),framer.contract)
    assert checked_witnesses(replace(a,originals=records),framer.contract)


def test_exhaustive_finite_scoped_decisions_against_independent_oracle(framer):
    # Production sees arbitrary subsets/limited evidence. Reference sees the
    # original ingress trace, and never calls the evaluator or reduction engine.
    fixtures = {}
    for device in ("edge-device-01","edge-device-05"):
        threshold = 38 if device.endswith("01") else 8
        for value in (threshold-1,threshold,threshold+1):
            fixtures[device,value] = scope_fixture(framer,device,(value,))
    comparisons = 0
    for left,right in itertools.product((37,38,39),(7,8,9)):
        a,ar,*_ = fixtures["edge-device-01",left]
        b,br,*_ = fixtures["edge-device-05",right]
        trace = [oracle_original(r,framer.contract) for r in (*ar,*br)]
        for observed in ([],[a],[b],[a,b],[replace(a,quarantined=True),b],[replace(a,verification=a.verification.model_copy(update={"status":"LIMITED"})),b]):
            for name in ("environmental-threshold","industrial-threshold","process-correlation","process-attention"):
                answer = decisions(framer,observed)[name]["truth"]
                oracle = trace_oracle(framer.contract,name,ledger_epoch=framer.profile.ledger_epoch,window_index=100,observations=trace)
                if answer != "UNKNOWN":
                    assert answer == oracle
                comparisons += 1
    assert comparisons == 216


def test_exhaustive_count_traces_and_partial_observation_against_oracle(framer):
    for n in range(4):
        for values in itertools.product((0,5,None),repeat=n):
            scope,records,*_ = scope_fixture(framer,"edge-device-04",values)
            reference = trace_oracle(framer.contract,"repeated-security-observations",ledger_epoch=framer.profile.ledger_epoch,
                window_index=100,observations=[oracle_original(r,framer.contract) for r in records])
            for available in ([],[scope],[replace(scope,verification=scope.verification.model_copy(update={"status":"LIMITED"}))]):
                actual = decisions(framer,available)["repeated-security-observations"]["truth"]
                assert actual == "UNKNOWN" or actual == reference


def test_monitor_policy_validation_and_alert_revision_request(framer):
    policies = tuple(RulePolicy(rule_id=r.rule_id,severity=AlertSeverity.HIGH) for r in framer.contract.rules)
    monitor = CoverageMonitor(framer,MonitoringConfig(policies=policies),now_us=lambda:1020000000)
    assert monitor.now() == 1020000000
    with pytest.raises(ValueError,match="rule set"):
        CoverageMonitor(framer,MonitoringConfig(policies=policies[:-1]))
    with pytest.raises(ValueError):
        AlertDelivery(alert_id="bad",revision=0)


def test_alert_engine_revision_delivery_is_opt_in_off_loop_and_durable(monkeypatch):
    service = load_service_module("alert-engine")
    client = TestClient(service.app)
    payload = {"alert_id":"38da3eab-5a7f-4f02-ae01-ef403c0ba557","revision":1}
    monkeypatch.setattr(service,"COVERAGE_ALERTS_ENABLED",False)
    assert client.post("/coverage-alerts",json=payload).status_code == 404
    monkeypatch.setattr(service,"COVERAGE_ALERTS_ENABLED",True)
    repository = Mock()
    repository.deliver_coverage_alert.return_value = "STORED"
    monkeypatch.setattr(service,"repository",repository)
    assert client.post("/coverage-alerts",json=payload).json()["status"] == "STORED"
    repository.deliver_coverage_alert.side_effect = OSError("database down")
    assert client.post("/coverage-alerts",json=payload).status_code == 503


def test_readonly_rule_history_query_is_fog_local(monkeypatch):
    service = load_service_module("fog-receiver")
    client = TestClient(service.app)
    assert client.get("/research/rules").status_code == 404
    monkeypatch.setattr(service,"_research_udp",Mock())
    repository = Mock()
    repository.coverage_rules.return_value = []
    monkeypatch.setattr(service,"repository",repository)
    assert client.get("/research/rules?limit=101").status_code == 422
    assert client.get("/research/rules?history=true").json()["decisions"] == []
    repository.coverage_rules.assert_called_once_with(20,True)


def test_boundary_uses_ingress_not_original_source_timestamp(framer):
    original,records,*_ = scope_fixture(framer,values=(45,))
    boundary_record = records[0].model_copy(update={"ingress_utc_us":original.body.window_end_utc_us})
    next_window = WindowIdentity(ledger_epoch=framer.profile.ledger_epoch,device_id="edge-device-01",window_index=101,contract_hash=contract_hash(framer.contract))
    body = build_capsule(contract=framer.contract,window=next_window,records=[boundary_record],gateway_id=framer.profile.gateway_id,
        signing_key_id=framer.profile.signing_key_id,created_at_utc_us=next_window.end_utc_us)
    encoded = sign_artifact(body,framer.private_key)
    record = FogEvidenceVerifier(framer).verify(encoded,received_us=next_window.end_utc_us,frames=split_artifact(encoded,framer.private_key))
    scope = VerifiedScope(body,artifact_digest(encoded),record)
    assert decisions(framer,[scope],100)["environmental-threshold"]["truth"] == "UNKNOWN"
    assert decisions(framer,[scope],101)["environmental-threshold"]["truth"] == "TRUE"


def test_exhaustive_cross_device_correlation_against_full_ingress_oracle(framer):
    for cpu,network,login in itertools.product((10,90,None),(1,8000,None),(0,5,None)):
        fixtures = [scope_fixture(framer,d,(v,)) for d,v in (("edge-device-02",cpu),("edge-device-03",network),("edge-device-04",login))]
        trace = [oracle_original(r,framer.contract) for f in fixtures for r in f[1]]
        expected = trace_oracle(framer.contract,"incident-correlation",ledger_epoch=framer.profile.ledger_epoch,window_index=100,observations=trace)
        for mask in range(8):
            observed = [f[0] for i,f in enumerate(fixtures) if mask & (1<<i)]
            answer = decisions(framer,observed)["incident-correlation"]["truth"]
            assert answer == "UNKNOWN" or answer == expected


def test_decision_identity_and_supporting_basis_stay_stable(framer):
    a,*_ = scope_fixture(framer,values=(25,))
    industrial,*_ = scope_fixture(framer,"edge-device-05",(9,))
    fork,*_ = scope_fixture(framer,"edge-device-05",(1,))
    initial = decisions(framer,[a])["process-correlation"]
    changed = decisions(framer,[a,industrial,fork])["process-correlation"]
    assert initial["decision_id"] == changed["decision_id"]
    assert changed["truth"] == "FALSE" and changed["verification_status"] == "CONFLICT_PRESENT"
    assert changed["supporting_artifacts"] == [a.digest] and not changed["coverage_health"]["complete"]
