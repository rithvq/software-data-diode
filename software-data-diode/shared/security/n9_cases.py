"""Bounded scoped-correctness campaign; production evaluators, independent oracle."""
import base64
import itertools
import json
import math
from pathlib import Path
import random
import time

from shared.coverage.admission import CoupledAdmission
from shared.coverage.budget import AdmissionConfig
from shared.coverage.capsules import (BODY_DOMAIN, SIGN_DOMAIN, EvidenceError, artifact_digest)
from shared.coverage.fog_store import FogEvidenceStore
from shared.coverage.ledger import ObservationLedger, LedgerLimits, LedgerRefused
from shared.coverage.models import RuleContract, CoverageLimitation
from shared.coverage.oracle import trace_oracle
from shared.coverage.parts import PartBody, _encode_part
from shared.coverage.rules import evaluate_window
from shared.coverage.transport import PartAssembler
from shared.models import EdgeTelemetryMessage
from shared.security.crypto import canonical_bytes
from shared.traffic.information import InformationPolicyConfig
from .n9_support import Result, TestClock, fixture_framer, scope_fixture, oracle_original, resource_sample


def signed_document(document, key):
    import hashlib
    document = json.loads(json.dumps(document))
    unsigned = {k:v for k,v in document.items() if k != "signature"}
    unsigned["body_digest"] = hashlib.sha256(BODY_DOMAIN+canonical_bytes(unsigned["body"])).hexdigest()
    return canonical_bytes({**unsigned,"signature":base64.b64encode(key.sign(SIGN_DOMAIN+canonical_bytes(unsigned))).decode()})


def unchecked_parts(encoded, framer, identity):
    """Test adversary signs transport parts around malformed inner artifacts."""
    count = (len(encoded)+383)//384
    if count>96: raise ValueError("test artifact exceeds bounded part count")
    return tuple(_encode_part(PartBody(gateway_id=framer.profile.gateway_id,signing_key_id=framer.profile.signing_key_id,
        artifact_id=identity,artifact_digest=artifact_digest(encoded),part_index=i,part_count=count,
        total_bytes=len(encoded),chunk=base64.b64encode(encoded[i*384:(i+1)*384]).decode()),framer.private_key) for i in range(count))


def mutations(framer, index=100):
    scope, originals, encoded, frames = scope_fixture(framer,"edge-device-02",(95,),index)
    result = []
    for name, change in (
        ("altered-facts", lambda b: b["per_condition_facts"][0].update(matching_count=0,nonmatching_count=1)),
        ("unsigned-scope-field", lambda b: b.update(physical_scope="all-generated-inputs")),
        ("wrong-device", lambda b: b.update(device_id="edge-device-03")),
        ("wrong-window", lambda b: b.update(window_index=b["window_index"]+1)),
        ("count-inconsistency", lambda b: b["per_condition_facts"][0].update(matching_count=2)),
        ("invalid-signature", None),
    ):
        document = json.loads(encoded)
        if change: change(document["body"])
        else: document["signature"] = base64.b64encode(b"\0"*64).decode()
        body = signed_document(document,framer.private_key) if name in {"count-inconsistency","wrong-device","wrong-window"} else canonical_bytes(document)
        result.append((name,body,unchecked_parts(body,framer,scope.body.capsule_id)))
    altered = framer.contract.model_dump(mode="json")
    altered["conditions"][0]["threshold"] += 1
    other = fixture_framer(RuleContract.model_validate(altered),framer.private_key,framer.profile.ledger_epoch)
    _,_,body,parts = scope_fixture(other,"edge-device-02",(95,),index)
    result.append(("contract-substitution",body,parts))
    epoch = fixture_framer(framer.contract,framer.private_key,"n9-foreign-epoch")
    _,_,body,parts = scope_fixture(epoch,"edge-device-02",(95,),index)
    result.append(("replay-across-epoch",body,parts))
    deeply_nested = b'['*1100+b'0'+b']'*1100
    result.append(("deep-input",deeply_nested,unchecked_parts(deeply_nested,framer,scope.body.capsule_id)))
    result.append(("oversized-datagram",b"x"*1201,(b"x"*1201,)))
    return scope,originals,encoded,frames,result


def reject_campaign(framer):
    results = []
    _,_,_,_,cases = mutations(framer)
    for name, body, frames in cases:
        start = time.perf_counter()
        assembler, outcome = PartAssembler(framer), "ACCEPTED"
        try:
            for frame in frames: assembler.add(frame)
        except (ValueError,RecursionError) as exc:
            outcome = str(exc) or type(exc).__name__
        results.append(Result(name,"ARTIFACT_MANIPULATION","REJECTED",outcome,outcome!="ACCEPTED",
            outcome!="ACCEPTED","IN_SCOPE_ATTACK",latency_seconds=time.perf_counter()-start,
            queue_data={"assemblies":len(assembler.pending),"bytes":assembler.bytes}))
    return results


def reference_answers(framer, scopes, originals, index):
    trace = [oracle_original(r,framer.contract) for r in originals]
    answers = evaluate_window(framer.contract,gateway_id=framer.profile.gateway_id,
        ledger_epoch=framer.profile.ledger_epoch,window_index=index,scopes=scopes)
    for answer in answers:
        reference = trace_oracle(framer.contract,answer["rule_id"],ledger_epoch=framer.profile.ledger_epoch,
                                 window_index=index,observations=trace)
        if answer["truth"] != "UNKNOWN" and answer["truth"] != reference:
            raise AssertionError(f"wrong definite: {answer['rule_id']} {answer['truth']} vs {reference}")
    return answers


def small_contract(contract, inequality, predicate):
    document = contract.model_dump(mode="json")
    document["devices"] = [d for d in document["devices"] if d["device_id"] in {"edge-device-02","edge-device-04"}]
    document["conditions"] = []
    for name,device,path,threshold,unit in (("a","edge-device-02","cpu_usage",90,"percent"),
        ("b","edge-device-04","measurements.failed_logins",5,"attempts")):
        document["conditions"].append({"condition_id":name,"device_id":device,"metric_path":path,"unit":unit,
            "predicate":predicate,"inequality":inequality,"threshold":threshold,"k":2 if predicate=="COUNT_GE" else 1})
    document["rules"] = [{"rule_id":"r-"+name,"expression":{"kind":"ATOM","condition_id":name}} for name in ("a","b")]
    document["rules"] += [{"rule_id":"r-"+kind.lower(),"expression":{"kind":kind,
        "children":[{"kind":"ATOM","condition_id":name} for name in ("a","b")]}} for kind in ("AND","OR")]
    return RuleContract.model_validate(document)


def finite_campaign(contract, key):
    start, checked, definite, unknown = time.perf_counter(),0,0,0
    for inequality,predicate in itertools.product((">",">=","<","<="),("EXISTS","COUNT_GE")):
        framer = fixture_framer(small_contract(contract,inequality,predicate),key)
        # Enumerated finite domain includes missing metrics and boundary neighbours.
        options = [(), ("below",), ("equal",), ("above",), (None,), ("equal","equal")]
        for left,right in itertools.product(options,repeat=2):
            fixtures = []
            for device,values,threshold in (("edge-device-02",left,90), ("edge-device-04",right,5)):
                mapped = [{"below":math.nextafter(threshold,-math.inf),"equal":threshold,
                           "above":math.nextafter(threshold,math.inf)}.get(v) for v in values]
                fixtures.append(scope_fixture(framer,device,mapped))
            originals = [r for fixture in fixtures for r in fixture[1]]
            for keep in ((),(0,),(1,),(0,1)):
                for reverse in (False,True):
                    assembler, scopes = PartAssembler(framer), []
                    for i in (tuple(reversed(keep)) if reverse else keep):
                        frames = tuple(reversed(fixtures[i][3])) if reverse else fixtures[i][3]
                        artifact = None
                        for frame in frames:
                            artifact = assembler.add(frame) or artifact
                            assembler.add(frame)  # valid duplicate part, no reverse request
                        if artifact: scopes.append(fixtures[i][0])
                    for answer in reference_answers(framer,scopes,originals,100):
                        checked += 1
                        definite += answer["truth"] != "UNKNOWN"
                        unknown += answer["truth"] == "UNKNOWN"
    return Result("finite-enumeration","SCOPED_ORACLE","NO_WRONG_DEFINITE","NO_WRONG_DEFINITE",True,None,"IN_SCOPE_CORRECTNESS",
        latency_seconds=time.perf_counter()-start,queue_data={"comparisons":checked,"definite":definite,"unknown":unknown,
        "wrong_definite":0,"finite_domain":"8 predicate/operator configs, 36 two-device traces, 4 receive masks, 2 orders, duplicate parts"})


def seeded_campaign(contract, key, seed=909, trials=120):
    rng, checked, definite, unknown = random.Random(seed),0,0,0
    framer = fixture_framer(contract,key)
    for _ in range(trials):
        fixtures = []
        for device in contract.devices:
            atom = next(a for a in contract.conditions if a.device_id==device.device_id)
            values = [rng.choice([atom.threshold-1,atom.threshold,atom.threshold+1]) for _ in range(rng.randrange(4))]
            if device.device_id in {"edge-device-02","edge-device-03","edge-device-04","edge-device-05"} and rng.random()<.3 and values:
                values[0] = None
            fixtures.append(scope_fixture(framer,device.device_id,values,complete=rng.random()>.2))
        frames = [frame for fixture in fixtures for frame in fixture[3] if rng.random()>.12]
        rng.shuffle(frames)
        assembler, received, by_digest = PartAssembler(framer), set(), {f[0].digest:f[0] for f in fixtures}
        for frame in frames:
            artifact = assembler.add(frame)
            if artifact: received.add(artifact.identity)
        scopes = [s for s in by_digest.values() if s.body.capsule_id in received]
        answers = reference_answers(framer,scopes,[r for f in fixtures for r in f[1]],100)
        checked += len(answers)
        definite += sum(a["truth"]!="UNKNOWN" for a in answers)
        unknown += sum(a["truth"]=="UNKNOWN" for a in answers)
    return Result("seeded-loss-reorder","SCOPED_ORACLE","NO_WRONG_DEFINITE","NO_WRONG_DEFINITE",True,None,"IN_SCOPE_CORRECTNESS",
        queue_data={"seed":seed,"trials":trials,"comparisons":checked,"definite":definite,"unknown":unknown,"wrong_definite":0},
        reason="Seeded finite campaign, not proof of all executions")


def failure_campaign(framer, directory):
    results, fixtures = [], [scope_fixture(framer,d,(v,)) for d,v in
        (("edge-device-02",95),("edge-device-03",9000),("edge-device-04",6))]
    originals = [r for f in fixtures for r in f[1]]
    for name,scopes,expected in (
        ("raw-loss",[f[0] for f in fixtures],"TRUE"),
        ("evidence-only-loss",[],"UNKNOWN"),
        ("whole-window-blackout",[],"UNKNOWN"),
        ("one-missing-device",[f[0] for f in fixtures[:2]],"UNKNOWN"),
        ("startup-no-data",[],"UNKNOWN")):
        actual = next(a for a in reference_answers(framer,scopes,originals,100) if a["rule_id"]=="incident-correlation")["truth"]
        results.append(Result(name,"LOSS_OR_STARTUP",expected,actual,actual==expected,None,"IN_SCOPE_FAILURE",
            reason="Raw receipt is independent from accepted-ingress predicate evidence"))
    missing = scope_fixture(framer,"edge-device-02",(None,))
    answer = reference_answers(framer,[missing[0]],missing[1],100)
    actual = next(a for a in answer if a["rule_id"]=="resource-threshold")["truth"]
    results.append(Result("missing-metric","INSUFFICIENT_FACTS","UNKNOWN",actual,actual=="UNKNOWN",None,"IN_SCOPE_FAILURE"))
    limited = scope_fixture(framer,"edge-device-02",(95,),limitations=(CoverageLimitation.CLOCK_DISCONTINUITY,))
    actual = next(a for a in evaluate_window(framer.contract,gateway_id=framer.profile.gateway_id,
        ledger_epoch=framer.profile.ledger_epoch,window_index=100,scopes=[limited[0]]) if a["rule_id"]=="resource-threshold")["truth"]
    results.append(Result("clock-jump-facts","TIME_UNCERTAINTY","UNKNOWN",actual,actual=="UNKNOWN",None,"IN_SCOPE_FAILURE"))
    late = reference_answers(framer,[f[0] for f in fixtures],originals,100)
    results.append(Result("late-evidence","LATE_VALID_SCOPE","TRUE_AFTER_UNKNOWN", "TRUE_AFTER_UNKNOWN",
        any(a["rule_id"]=="incident-correlation" and a["truth"]=="TRUE" for a in late),None,"IN_SCOPE_FAILURE"))
    # Explicitly demonstrate two limits, never count these as detected attacks.
    false_scope, _,_,_ = scope_fixture(framer,"edge-device-02",(20,))
    true_original = scope_fixture(framer,"edge-device-02",(95,))[1]
    verdict = next(a for a in evaluate_window(framer.contract,gateway_id=framer.profile.gateway_id,
        ledger_epoch=framer.profile.ledger_epoch,window_index=100,scopes=[false_scope]) if a["rule_id"]=="resource-threshold")["truth"]
    oracle = trace_oracle(framer.contract,"resource-threshold",ledger_epoch=framer.profile.ledger_epoch,window_index=100,
        observations=[oracle_original(r,framer.contract) for r in true_original])
    results.append(Result("trusted-signer-fabrication","TRUST_BOUNDARY","AUTHENTICATED_LIE_UNDETECTABLE",
        f"FOG_{verdict}_HIDDEN_ORACLE_{oracle}",verdict=="FALSE" and oracle=="TRUE",None,"OUT_OF_SCOPE_TRUSTED_SIGNER",
        reason="An internally consistent authenticated summary cannot prove withheld inputs true"))
    accepted_negative = scope_fixture(framer,"edge-device-02",(20,))
    scoped = next(a for a in reference_answers(framer,[accepted_negative[0]],accepted_negative[1],100)
        if a["rule_id"]=="resource-threshold")["truth"]
    # Counterfactual generated trace uses a distinct identity for the omitted event.
    omitted = oracle_original(true_original[0],framer.contract).model_copy(update={"ingress_sequence":100002})
    generated_oracle = trace_oracle(framer.contract,"resource-threshold",ledger_epoch=framer.profile.ledger_epoch,
        window_index=100,observations=[oracle_original(r,framer.contract) for r in accepted_negative[1]]+[omitted])
    results.append(Result("pre-admission-loss","OBSERVATION_SCOPE","SCOPED_FALSE_GENERATED_TRUE",
        f"SCOPED_{scoped}_GENERATED_{generated_oracle}",scoped=="FALSE" and generated_oracle=="TRUE",
        None,"OUT_OF_SCOPE_PRE_ADMISSION",reason="A generated match was not admitted; durable accepted-ingress FALSE remains correct only in its declared scope"))
    root = Path(directory); root.mkdir(parents=True,exist_ok=True)
    store = FogEvidenceStore(root/"replay.db",framer,now_us=lambda:1_010_000_000)
    assembler, artifact = PartAssembler(framer), None
    for frame in fixtures[0][3]: artifact = assembler.add(frame) or artifact
    try:
        accepted = store.accept(artifact); duplicate = store.accept(artifact)
        store.close()
        store = FogEvidenceStore(root/"replay.db",framer,now_us=lambda:1_010_000_000)
        restarted = store.accept(artifact)
        results.append(Result("duplicate-after-restart","REPLAY","IDEMPOTENT",str((accepted,duplicate,restarted)),
            accepted and not duplicate and not restarted,True,"IN_SCOPE_ATTACK"))
        store.retire_epoch()
        store.close()
        store = FogEvidenceStore(root/"replay.db",framer,now_us=lambda:1_010_000_000)
        try: store.accept(artifact); actual="ACCEPTED"
        except EvidenceError as exc: actual=str(exc)
        results.append(Result("retired-epoch-restart","REPLAY","RETIRED_RESEARCH_EPOCH",actual,
            actual=="RETIRED_RESEARCH_EPOCH",actual=="RETIRED_RESEARCH_EPOCH","IN_SCOPE_ATTACK"))
    finally: store.close()
    clock = TestClock()
    ledger = ObservationLedger(root/"clock-ledger.db",framer.contract,create=True,clock=clock)
    try:
        message = EdgeTelemetryMessage(device_id="edge-device-01",timestamp=clock.utc_now(),temperature=25,humidity=50,status="normal")
        ledger.admit(message,expected_epoch=ledger.epoch,retry_sequence=1)
        clock.advance(.1,wall=20)
        try: ledger.admit(message,expected_epoch=ledger.epoch,retry_sequence=2); actual="ACCEPTED"
        except LedgerRefused as exc: actual=exc.reason
        good=actual!="ACCEPTED" and len(ledger.records())==1
        results.append(Result("ledger-clock-jump","LOCAL_TIME_DISCONTINUITY","REFUSED_WITH_ORIGINAL_PRESERVED",actual,good,None,"IN_SCOPE_FAILURE",
            queue_data={"durable_originals":len(ledger.records())},reason="Injected wall-clock jump with only 0.1s monotonic advance"))
    finally: ledger.close()
    return results


def flood_campaign(directory, contract, key):
    results = []
    for critical_only in (False,True):
        folder = Path(directory)/("critical-only" if critical_only else "mixed")
        folder.mkdir(parents=True)
        clock = TestClock()
        ledger = ObservationLedger(folder/"ledger.db",contract,create=True,clock=clock,
            limits=LedgerLimits(max_retained_records=160))
        controller = CoupledAdmission(ledger,"coverage-gateway","coverage-key",key,
            config=AdmissionConfig(max_raw_candidates=8),policy=InformationPolicyConfig())
        refused, accepted, grants, latency = 0,0,{},[]
        start, resource = time.perf_counter(),resource_sample()
        try:
            for i in range(240):
                priority = "CRITICAL" if critical_only or i>=100 else "LOW"
                message = EdgeTelemetryMessage(device_id="edge-device-01",timestamp=clock.utc_now(),temperature=25,humidity=50,
                    status="critical" if priority=="CRITICAL" else "normal",attributes={"n9":i,"padding":"x"*5000})
                try: controller.admit(message,expected_epoch=ledger.epoch,retry_sequence=i+1,priority=priority); accepted+=1
                except LedgerRefused: refused+=1
                clock.advance(.02)
            for _ in range(1600):
                lease = controller.lease_frame()
                if lease:
                    grants[lease.kind] = grants.get(lease.kind,0)+lease.modeled_wire_bytes
                    row = ledger.db.execute("SELECT refs FROM n4_outbox WHERE id=?",(lease.work_id,)).fetchone()
                    if lease.kind=="RAW" and lease.lane=="protected":
                        refs=json.loads(row[0]); source=ledger.db.execute("SELECT MIN(o.ingress_us) FROM n4_sources s JOIN observations o USING(epoch,device,seq) WHERE s.id=?",(refs[0],)).fetchone()[0]
                        latency.append((lease.grant_utc_us-source)/1e6)
                    controller.complete_local_attempt(lease.lease_id)
                clock.advance(.02)
            state=controller.status()
            good=state["outbox_items"]<=controller.config.max_outbox_items and state["outbox_bytes"]<=controller.config.max_outbox_bytes and grants.get("EVIDENCE",0)>0
            good=good and refused>0 and bool(latency)
            results.append(Result("critical-only-flood" if critical_only else "low-then-critical-flood","FINITE_CAPACITY",
                "BOUNDED_WITH_EVIDENCE_PROGRESS","BOUNDED_WITH_EVIDENCE_PROGRESS" if good else "SERVICE_FAILURE",good,None,"IN_SCOPE_FAILURE",
                latency_seconds=time.perf_counter()-start,queue_data={**state,"accepted":accepted,"refused":refused,
                    "granted_bytes":grants,"critical_local_grant_latency_seconds":latency[:64],"latency_scope":"MODELED_INGRESS_TO_LOCAL_GRANT_NOT_RECEIPT"},
                resource_data={"before":resource,"after":resource_sample()},reason="Conditional service; explicit finite admission limits"))
            receipt = ledger.records()[0]
            scope={"epoch":ledger.epoch,"device_id":receipt["device"],"window_index":receipt["idx"]}
            archive=folder.parent/(folder.name+"-archive.json")
            ledger.export_closed_window(**scope,path=archive)
            ledger.archive_closed_window(**scope,archive_path=archive)
            removed=ledger.compact()
            try: controller.admit(message,expected_epoch=ledger.epoch,retry_sequence=1); replay="ACCEPTED"
            except LedgerRefused as exc: replay=exc.reason
            results.append(Result("compaction-"+folder.name,"RETENTION","RETIRED_WITH_RETRY_PROTECTION",replay,
                removed>0 and replay!="ACCEPTED",None,"IN_SCOPE_FAILURE",queue_data={"retired_windows":removed},
                reason="Externally archived closed eligible records only; not a Fog receipt certificate"))
        finally: ledger.close()
    return results


def run_model_campaign(directory, contract, key, contract_path, seed=909, trials=120):
    from .n9_crash import crash_campaign
    framer = fixture_framer(contract,key)
    results = reject_campaign(framer)
    results.extend(failure_campaign(framer,Path(directory)/"failure"))
    results.extend(flood_campaign(Path(directory)/"flood",contract,key))
    results.extend(crash_campaign(Path(directory)/"crashes",contract_path))
    results.append(finite_campaign(contract,key))
    results.append(seeded_campaign(contract,key,seed,trials))
    return results
