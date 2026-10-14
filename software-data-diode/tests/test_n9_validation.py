import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from shared.coverage.contracts import load_contract
from shared.security.n9_cases import reject_campaign, finite_campaign, seeded_campaign, failure_campaign, flood_campaign
from shared.security.n9_support import TargetAllowlist, test_project as validate_project, fixture_framer, Result, export_results
from shared.security.n9_crash import crash_campaign


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = load_contract(ROOT/"config/rule_coverage.json")


def test_n9_rejects_external_baseline_loopback_and_rebound_targets():
    run = "012345abcdef"
    document={"project":"software-data-diode-n9-"+run,"run_id":run,"targets":{
        "edge-gateway":{"address":"172.20.0.2","ports":[8000]},"fog-receiver":{"address":"172.22.0.2","ports":[9002]}}}
    allow = TargetAllowlist(document, resolver=lambda name: document["targets"][name]["address"])
    assert allow.endpoint("fog-receiver",9002)==("172.22.0.2",9002)
    for target,port in (("localhost",8501),("host.docker.internal",8000),("8.8.8.8",53),("edge-gateway",9002)):
        with pytest.raises(ValueError): allow.endpoint(target,port)
    with pytest.raises(ValueError): allow.gateway_url("/configuration")
    allow.resolve=lambda name:"172.20.0.99"
    with pytest.raises(ValueError): allow.endpoint("edge-gateway",8000)
    for name in ("software-data-diode","software-data-diode-coverage","software-data-diode-n9-nope"):
        with pytest.raises(ValueError): validate_project(name,run)
    document["targets"]["edge-gateway"]["address"]="127.0.0.1"
    with pytest.raises(ValueError): TargetAllowlist(document)


def test_n9_mutations_and_independent_finite_and_seeded_oracle():
    key=Ed25519PrivateKey.generate()
    rejected=reject_campaign(fixture_framer(CONTRACT,key))
    assert len(rejected)==10 and all(r.passed for r in rejected)
    finite=finite_campaign(CONTRACT,key)
    assert finite.passed and finite.queue_data["comparisons"]==9216 and finite.queue_data["wrong_definite"]==0
    random=seeded_campaign(CONTRACT,key,trials=12)
    assert random.passed and random.queue_data["comparisons"]==108


def test_n9_failures_and_undetectable_cases_are_separated(tmp_path):
    results=failure_campaign(fixture_framer(CONTRACT,Ed25519PrivateKey.generate()),tmp_path)
    assert all(r.passed for r in results)
    outside=[r for r in results if r.scope.startswith("OUT_OF_SCOPE")]
    assert len(outside)==2 and all(r.detected is None for r in outside)
    assert "HIDDEN_ORACLE_TRUE" in outside[0].actual_result


def test_n9_flood_and_compaction_bounds(tmp_path):
    results=flood_campaign(tmp_path,CONTRACT,Ed25519PrivateKey.generate())
    assert len(results)==4 and all(r.passed for r in results)
    for row in results[:1]+results[2:3]:
        assert row.queue_data["critical_local_grant_latency_seconds"]
        assert row.queue_data["refused"]>0 and row.queue_data["granted_bytes"]["EVIDENCE"]>0


def test_n9_exports_unknown_and_out_of_scope_without_detection_credit(tmp_path):
    rows=[Result("unknown","LOSS","UNKNOWN","UNKNOWN",True,None,"IN_SCOPE_FAILURE"),
          Result("lie","SIGNER","UNDETECTABLE","UNDETECTABLE",True,None,"OUT_OF_SCOPE_TRUSTED_SIGNER")]
    document=export_results(tmp_path,rows,{"seed":909})
    assert document["detected_in_scope"]==0 and document["in_scope_attack_cases"]==0
    assert "NOT_APPLICABLE" in (tmp_path/"results.csv").read_text()
    assert json.loads((tmp_path/"results.json").read_text())["passed"]
    with pytest.raises(ValueError): export_results(tmp_path,rows,{})


def test_n9_real_process_crash_recovery(tmp_path):
    results=crash_campaign(tmp_path,ROOT/"config/rule_coverage.json")
    assert len(results)==19 and all(r.passed for r in results)


def test_n9_test_project_has_no_host_ports_or_user_secrets():
    import yaml
    document=yaml.safe_load((ROOT/"docker-compose.n9.yml").read_text())
    assert all(n["internal"] for n in document["networks"].values())
    for service in document["services"].values():
        assert not service.get("ports")
        assert not any("./secrets" in volume or "docker.sock" in volume for volume in service.get("volumes",[]))
    assert document["services"]["security-test-client"]["network_mode"]=="service:data-diode"
    assert document["services"]["edge-gateway"]["tmpfs"]==["/tmp:size=128m,mode=1777"]
    assert not any("ledger:" in volume or "private:" in volume for volume in document["services"]["fog-receiver"]["volumes"])
    for service in ("edge-gateway","fog-receiver","security-test-client"):
        configured=document["services"][service]
        targets={v.split(":")[-2] for v in configured["volumes"] if v.endswith(":ro")}
        for key in ("COVERAGE_CONTRACT_PATH","COVERAGE_TRANSPORT_CONFIG"):
            assert configured["environment"][key] in targets


def test_n9_cleanup_rejects_foreign_state_and_baseline_comparison_is_order_independent(tmp_path):
    from scripts.run_n9_validation import Campaign, baseline_identity
    campaign=Campaign("not-executed","012345abcdef",tmp_path)
    item={"Id":"test-id","Image":"test-image","Config":{"Labels":{"com.docker.compose.project":campaign.project}},
        "State":{"StartedAt":"fixed","Status":"running"},"HostConfig":{"PortBindings":{}},
        "Mounts":[{"Type":"volume","Name":"existing-user-data","Destination":"/state"}],
        "NetworkSettings":{"Networks":{}}}
    campaign.ids=lambda own=False:["test-id"]
    campaign.inspect=lambda ids:[item]
    with pytest.raises(ValueError,match="foreign state volume"): campaign.guard()
    item["Mounts"]=[{"Destination":"/b"},{"Destination":"/a"}]
    before=baseline_identity([item])
    item["Mounts"].reverse()
    assert before==baseline_identity([item])


def test_n9_gateway_transport_dataflow_has_no_receiver_client(monkeypatch):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import Mock
    import shared.coverage.udp_runtime as runtime
    calls=[]
    class Sender:
        counts={}
        def __init__(self,*args): pass
        def attempt(self,frame): calls.append(("attempt",frame))
        async def close(self): pass
    class Controller:
        def retire_uncertain_lease(self): calls.append(("recover",None))
        def publish_forward_state(self): calls.append(("local-state",None))
        def lease_frame(self):
            if any(c[0]=="attempt" for c in calls): return None
            return SimpleNamespace(payload=b"local-frame",lease_id="charged-lease")
        def complete_local_attempt(self,identity): calls.append(("complete",identity))
    monkeypatch.setattr(runtime,"SendOnlyUDP",Sender)
    monkeypatch.setattr(runtime.httpx,"AsyncClient",Mock(side_effect=AssertionError("receiver feedback client forbidden")))
    async def exercise():
        gateway=runtime.GatewayUDP(Controller(),SimpleNamespace(state_interval_seconds=10,datagram_bytes=1200))
        try:
            for _ in range(400):
                if any(c[0]=="complete" for c in calls): break
                await asyncio.sleep(.005)
            assert ("complete","charged-lease") in calls
            assert gateway.status()["confirmed_receipt"]=="NOT_OBSERVED"
        finally: await gateway.close()
    asyncio.run(exercise())
