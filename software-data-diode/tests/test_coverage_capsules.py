from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.coverage import (CoverageLimitation, RuleContract, Truth, WindowIdentity,
                             contract_hash, evaluate_condition, load_contract)
from shared.coverage.capsules import (ARTIFACT_DOMAIN, BODY_DOMAIN, INPUT_FOLD_DOMAIN,
    INPUT_LEAF_DOMAIN, INPUT_SEED_DOMAIN, MAX_ARTIFACT_BYTES, MAX_INPUT_RECORDS, SIGN_DOMAIN,
    CapsuleBody, EvidenceConflict, EvidenceError, EvidenceTracker, InputRecord, RawAccounting,
    artifact_digest, audit_capsule, authenticated_facts, build_capsule, build_transition,
    input_commitment, parse_artifact, sign_artifact, verify_artifact)
from shared.coverage.ledger import LedgerRefused, ObservationLedger
from shared.coverage.parts import (MAX_PARTS, PartBody, _encode_part, assemble_parts,
                                  split_artifact, verify_part)
from shared.coverage.sealing import CapsuleSealer, SealingLimits
from shared.models import EdgeTelemetryMessage
from shared.security.crypto import canonical_bytes
from tests.test_coverage_ledger import FakeClock, message as ledger_message


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = load_contract(ROOT/"config/rule_coverage.json")
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEYS = {("gateway-vector","test-vector-key"):KEY.public_key()}
CONTRACTS = {contract_hash(CONTRACT):CONTRACT}
VECTOR = json.loads((ROOT/"tests/fixtures/coverage_capsule_v1.json").read_text())


def window(index=0, device="edge-device-01"):
    return WindowIdentity(ledger_epoch="vector-epoch",device_id=device,
                          window_index=index,contract_hash=contract_hash(CONTRACT))


def record(value=45, sequence=1, index=0, device="edge-device-01", **values):
    kind = next(item.telemetry_type for item in CONTRACT.devices if item.device_id == device)
    m = EdgeTelemetryMessage(device_id=device,timestamp=datetime(1970,1,1,tzinfo=timezone.utc),
                             temperature=value,humidity=50,status="normal",telemetry_type=kind,**values)
    encoded = canonical_bytes(m.model_dump(mode="json"))
    return InputRecord(ledger_epoch="vector-epoch",device_id=device,ingress_sequence=sequence,
                       ingress_utc_us=index*10000000+sequence,canonical_input=encoded,
                       input_hash=hashlib.sha256(encoded).hexdigest())


def capsule(records=None, index=0, device="edge-device-01", **kwargs):
    return build_capsule(contract=CONTRACT,window=window(index,device),records=[record(index=index,device=device)] if records is None else records,
        gateway_id="gateway-vector",signing_key_id="test-vector-key",created_at_utc_us=(index+1)*10000000,**kwargs)


def test_canonical_input_commitment_signature_and_artifact_vectors():
    body = capsule()
    encoded = sign_artifact(body,KEY)
    artifact = verify_artifact(encoded,KEYS,CONTRACTS)
    assert record().input_hash == VECTOR["input_hash"]
    assert body.input_commitment.root == VECTOR["commitment"]
    assert body.capsule_id == VECTOR["capsule_id"]
    assert artifact.body_digest == VECTOR["body_digest"]
    assert artifact.signature == VECTOR["signature"]
    assert artifact_digest(encoded) == VECTOR["artifact_digest"]
    assert len(encoded) == VECTOR["artifact_bytes"]
    assert sign_artifact(body,KEY) == encoded
    doc = json.loads(encoded)
    reordered = dict(reversed(list(doc.items())))
    assert canonical_bytes(reordered) == encoded
    with pytest.raises(EvidenceError): parse_artifact(json.dumps(doc,indent=2).encode())


def test_independently_calculated_scope_seed_leaf_and_fold_vectors():
    raw = record()
    seed = hashlib.sha256(INPUT_SEED_DOMAIN+canonical_bytes(window().model_dump(mode="json"))).digest()
    leaf = hashlib.sha256(INPUT_LEAF_DOMAIN+canonical_bytes({"ledger_epoch":raw.ledger_epoch,"device_id":raw.device_id,
        "ingress_sequence":raw.ingress_sequence,"ingress_utc_us":raw.ingress_utc_us,"input_hash":raw.input_hash})).digest()
    assert hashlib.sha256(INPUT_FOLD_DOMAIN+seed+leaf).hexdigest() == VECTOR["commitment"]
    assert input_commitment(window(),[]).root == seed.hex()
    assert input_commitment(window(),[record(sequence=2,value=25),raw]) == input_commitment(window(),[raw,record(sequence=2,value=25)])


def leaves(value,path=()):
    if isinstance(value,dict):
        return list(itertools.chain.from_iterable(leaves(item,(*path,key)) for key,item in value.items()))
    if isinstance(value,list):
        return list(itertools.chain.from_iterable(leaves(item,(*path,index)) for index,item in enumerate(value)))
    return [(path,value)]


MUTATIONS = leaves(json.loads(sign_artifact(capsule(),KEY)))


@pytest.mark.parametrize("path,value",MUTATIONS,ids=[".".join(map(str,path)) for path,_ in MUTATIONS])
def test_every_meaningful_scalar_field_mutation_is_rejected(path,value):
    doc = json.loads(sign_artifact(capsule(),KEY))
    target = doc
    for element in path[:-1]: target = target[element]
    if type(value) is bool: replacement = not value
    elif type(value) is int: replacement = value+1
    elif value is None: replacement = "unexpected"
    elif isinstance(value,str) and len(value) == 64: replacement = ("a" if value[0] != "a" else "b")+value[1:]
    else: replacement = str(value)+"x"
    target[path[-1]] = replacement
    with pytest.raises(EvidenceError): verify_artifact(canonical_bytes(doc),KEYS,CONTRACTS)


def test_wrong_key_identity_contract_and_telemetry_signature_domain():
    wire = sign_artifact(capsule(),KEY)
    wrong = Ed25519PrivateKey.generate()
    with pytest.raises(EvidenceError,match="INVALID_SIGNATURE"):
        verify_artifact(wire,{next(iter(KEYS)):wrong.public_key()},CONTRACTS)
    with pytest.raises(EvidenceError,match="SIGNER"):
        verify_artifact(wire,{},CONTRACTS)
    with pytest.raises(EvidenceError,match="CONTRACT"):
        verify_artifact(wire,KEYS,{})
    doc = json.loads(wire)
    import base64
    unsigned = {name:item for name,item in doc.items() if name != "signature"}
    doc["signature"] = base64.b64encode(KEY.sign(canonical_bytes(unsigned))).decode()
    with pytest.raises(EvidenceError,match="INVALID_SIGNATURE"):
        verify_artifact(canonical_bytes(doc),KEYS,CONTRACTS)
    assert len({BODY_DOMAIN,SIGN_DOMAIN,ARTIFACT_DOMAIN,INPUT_SEED_DOMAIN,INPUT_LEAF_DOMAIN,INPUT_FOLD_DOMAIN}) == 6


def test_duplicate_keys_nonfinite_unknown_fields_and_size_are_rejected():
    wire = sign_artifact(capsule(),KEY)
    with pytest.raises(EvidenceError): parse_artifact(wire.replace(b'"algorithm":"Ed25519"',b'"algorithm":"Ed25519","algorithm":"Ed25519"'))
    with pytest.raises(EvidenceError): parse_artifact(b'{"body":NaN}')
    with pytest.raises(EvidenceError): parse_artifact(b" "*(MAX_ARTIFACT_BYTES+1))
    with pytest.raises(EvidenceError): parse_artifact(canonical_bytes({**json.loads(wire),"unknown":True}))
    data = record().model_dump()
    data["canonical_input"] += b" "
    with pytest.raises(ValueError): InputRecord.model_validate(data)


@pytest.mark.parametrize("mutation",["partition","range","duplicate-fact","extra-witness","outside-witness","accounting","overflow-subset","early-close","limit-contradiction"])
def test_count_and_scope_contradictions_fail_before_signing(mutation):
    body = capsule().model_dump(mode="json")
    if mutation == "partition": body["per_condition_facts"][0]["matching_count"] = 2
    elif mutation == "range": body["ingress_last_sequence"] = 2
    elif mutation == "duplicate-fact": body["per_condition_facts"] *= 2
    elif mutation == "extra-witness": body["per_condition_facts"][0]["witnesses"] *= 2
    elif mutation == "outside-witness": body["per_condition_facts"][0]["witnesses"][0]["ingress_sequence"] = 100
    elif mutation == "accounting": body["reduction_accounting"]["dropped_raw"] = 1
    elif mutation == "overflow-subset": body["reduction_accounting"]["queue_overflow_drops"] = 1
    elif mutation == "early-close": body["created_at_utc_us"] = 0
    else: body["closure_reason"] = "CLOCK_DISCONTINUITY"
    with pytest.raises(ValueError): CapsuleBody.model_validate(body)


def test_predicate_counts_are_original_not_aggregate_means_and_delivery_is_separate():
    originals = [record(value=45),record(value=25,sequence=2)]
    body = capsule(originals,accounting=RawAccounting(dropped_raw=2,queue_overflow_drops=2,raw_dispatch_attempts=0))
    assert (45+25)/2 < 38
    assert body.per_condition_facts[0].matching_count == 1
    assert body.reduction_accounting.confirmed_receipt_count is None
    wire = sign_artifact(body,KEY)
    assert audit_capsule(wire,KEYS,CONTRACTS,originals).status == "RECOMPUTED"
    assert evaluate_condition(CONTRACT.conditions[0],authenticated_facts(wire,KEYS,CONTRACTS)[0]).truth == Truth.TRUE
    lie = body.model_dump(mode="json")
    lie["per_condition_facts"][0].update(matching_count=0,nonmatching_count=2,witnesses=[])
    signed_lie = sign_artifact(CapsuleBody.model_validate(lie),KEY)
    assert verify_artifact(signed_lie,KEYS,CONTRACTS).body.online_assurance == "AUTHENTICATED_SUMMARY"
    assert audit_capsule(signed_lie,KEYS,CONTRACTS,originals).status == "MISMATCH"
    assert audit_capsule(wire,KEYS,CONTRACTS,originals[:1]).status == "INCOMPLETE_DISCLOSURE"


def test_offline_recomputation_is_independent_of_production_predicate_comparisons(monkeypatch):
    import shared.coverage.evaluation as production
    wire = sign_artifact(capsule(),KEY)
    monkeypatch.setitem(production.COMPARISONS,">=",lambda *args:False)
    assert audit_capsule(wire,KEYS,CONTRACTS,[record()]).status == "RECOMPUTED"


def test_empty_and_missing_metric_artifacts_do_not_certify_no_event():
    empty = sign_artifact(capsule([]),KEY)
    assert parse_artifact(empty).body.scope_kind == "NO_INPUT"
    assert evaluate_condition(CONTRACT.conditions[0],authenticated_facts(empty,KEYS,CONTRACTS)[0]).truth == Truth.UNKNOWN
    missing = record(device="edge-device-04")
    body = capsule([missing],device="edge-device-04")
    assert all(fact.unresolved_count == 1 for fact in body.per_condition_facts)
    for condition,fact in zip([c for c in CONTRACT.conditions if c.device_id==missing.device_id],authenticated_facts(sign_artifact(body,KEY),KEYS,CONTRACTS)):
        assert evaluate_condition(condition,fact).truth == (Truth.UNKNOWN if condition.k == 1 else Truth.FALSE)


def test_predecessor_gap_does_not_invalidate_later_scope_and_forks_are_detected():
    first = sign_artifact(capsule(),KEY)
    second = sign_artifact(capsule(index=1,previous_digest=artifact_digest(first)),KEY)
    tracker = EvidenceTracker(KEYS,CONTRACTS)
    result = tracker.inspect(second)
    assert result.continuity == "INCOMPLETE"
    assert evaluate_condition(CONTRACT.conditions[0],authenticated_facts(second,KEYS,CONTRACTS)[0]).truth == Truth.TRUE
    assert tracker.inspect(first).continuity == "COMPLETE"
    assert tracker.inspect(second).duplicate and tracker.inspect(second).continuity == "COMPLETE"
    changed = capsule(index=1,previous_digest=artifact_digest(first)).model_dump(mode="json")
    changed["created_at_utc_us"] += 1
    with pytest.raises(EvidenceConflict,match="SAME_SCOPE"):
        tracker.inspect(sign_artifact(CapsuleBody.model_validate(changed),KEY))
    assert tracker.inspect(second).duplicate


def test_cache_limits_invalid_traffic_and_wrong_predecessor_lineage():
    tracker = EvidenceTracker(KEYS,CONTRACTS,max_artifacts=1)
    first = sign_artifact(capsule(),KEY)
    with pytest.raises(EvidenceError): tracker.inspect(b"{}")
    assert not tracker.entries
    tracker.inspect(first)
    with pytest.raises(EvidenceError,match="CACHE_FULL"): tracker.inspect(sign_artifact(capsule(index=1),KEY))
    assert tracker.inspect(first).duplicate
    other = sign_artifact(capsule(device="edge-device-04"),KEY)
    mixed = sign_artifact(capsule(index=1,previous_digest=artifact_digest(other)),KEY)
    tracker = EvidenceTracker(KEYS,CONTRACTS)
    tracker.inspect(other)
    assert tracker.inspect(mixed).continuity == "BROKEN"


def test_contract_transition_authenticates_boundary_but_carries_no_rule_facts():
    changed = CONTRACT.model_dump(mode="json")
    changed["conditions"][0]["threshold"] = 39
    next_contract = RuleContract.model_validate(changed)
    contracts = {**CONTRACTS,contract_hash(next_contract):next_contract}
    body = build_transition(gateway_id="gateway-vector",signing_key_id="test-vector-key",ledger_epoch="vector-epoch",
        previous_contract_hash=contract_hash(CONTRACT),next_contract_hash=contract_hash(next_contract),
        effective_window_index=3,created_at_utc_us=20000000)
    wire = sign_artifact(body,KEY)
    assert verify_artifact(wire,KEYS,contracts).body.effective_start_utc_us == 30000000
    with pytest.raises(EvidenceError,match="CONTRACT"): verify_artifact(wire,KEYS,CONTRACTS)
    with pytest.raises(EvidenceError,match="NOT_RULE"): authenticated_facts(wire,KEYS,contracts)
    assert EvidenceTracker(KEYS,contracts).inspect(wire).continuity == "NOT_APPLICABLE"


def test_record_cardinality_scope_witness_and_empty_commitment_bounds():
    with pytest.raises(EvidenceError): input_commitment(window(),[record(),record()])
    with pytest.raises(EvidenceError): input_commitment(window(),[record(index=1)])
    with pytest.raises(EvidenceError): input_commitment(window(),[record(),record(sequence=3)])
    with pytest.raises(EvidenceError,match="RECORD_LIMIT"):
        input_commitment(window(),(record(sequence=index+1) for index in range(MAX_INPUT_RECORDS+1)))
    assert input_commitment(window(),[]).record_count == 0
    many = capsule([record(sequence=i+1) for i in range(10)])
    assert len(many.per_condition_facts[0].witnesses) == 2


def test_signed_parts_fit_reassemble_reorder_and_redeliver():
    wire = sign_artifact(capsule(),KEY)
    parts = split_artifact(wire,KEY)
    assert len(parts) > 1 and all(len(item) <= 1200 for item in parts)
    assert assemble_parts((*reversed(parts),parts[0]),KEYS,CONTRACTS) == wire
    assert split_artifact(wire,KEY) == parts
    with pytest.raises(EvidenceError,match="INCOMPLETE"): assemble_parts(parts[:-1],KEYS,CONTRACTS)
    with pytest.raises(EvidenceError): verify_part(parts[0]+b" "*1200,KEYS)
    with pytest.raises(EvidenceError): assemble_parts(itertools.repeat(parts[0],MAX_PARTS+1),KEYS,CONTRACTS)
    with pytest.raises(EvidenceError,match="DO_NOT_FIT"): split_artifact(wire,KEY,max_datagram_bytes=256)


def test_parts_tampering_mixing_forks_and_whole_signature_rejection():
    wire = sign_artifact(capsule(),KEY)
    parts = split_artifact(wire,KEY)
    bad = json.loads(parts[0])
    bad["body"]["part_index"] += 1
    with pytest.raises(EvidenceError): assemble_parts([canonical_bytes(bad),*parts[1:]],KEYS,CONTRACTS)
    body,chunk = verify_part(parts[0],KEYS)
    import base64
    fork = PartBody.model_validate({**body.model_dump(),"chunk":base64.b64encode(b"x"+chunk[1:]).decode()})
    with pytest.raises(EvidenceConflict): assemble_parts([parts[0],_encode_part(fork,KEY)],KEYS,CONTRACTS)
    other = split_artifact(sign_artifact(capsule(index=1),KEY),KEY)
    with pytest.raises(EvidenceConflict): assemble_parts([parts[0],other[0]],KEYS,CONTRACTS)
    unsigned = json.loads(wire)
    unsigned["signature"] = "A"*86+"=="
    corrupted = split_artifact(canonical_bytes(unsigned),KEY)
    with pytest.raises(EvidenceError,match="SIGNATURE"): assemble_parts(corrupted,KEYS,CONTRACTS)


@pytest.fixture
def store(tmp_path):
    path = tmp_path/"state"
    path.mkdir()
    ledger = ObservationLedger(path/"ledger.db",CONTRACT,create=True,clock=FakeClock())
    try: yield ledger
    finally: ledger.close()


def submit(store,retry=1):
    return store.admit(ledger_message(temperature=45),expected_epoch=store.epoch,retry_sequence=retry)


def test_sealer_only_closed_original_scope_and_immutable_redelivery_after_recovery(store,tmp_path):
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)
    receipt = submit(store)
    with pytest.raises(LedgerRefused,match="CLOSED"): signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    store.clock.advance(10)
    store.tick()
    wire = signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    assert parse_artifact(wire).body.closure_reason == "WINDOW_END"
    store.clock.advance(10)
    assert signer.seal(device_id=receipt.device_id,window_index=receipt.window_index) == wire
    path,epoch = store.path,store.epoch
    store.close()
    reopened = ObservationLedger(path,CONTRACT,clock=FakeClock(30))
    try:
        signer = CapsuleSealer(reopened,"gateway-vector","test-vector-key",KEY)
        assert signer.seal(device_id=receipt.device_id,window_index=receipt.window_index,epoch=epoch) == wire
        raw = [InputRecord.from_ledger(row) for row in reopened.records()]
        assert audit_capsule(wire,KEYS,CONTRACTS,raw).status == "RECOMPUTED"
        archive = tmp_path/"closed.json"
        args = {"epoch":epoch,"device_id":receipt.device_id,"window_index":receipt.window_index}
        reopened.export_closed_window(**args,path=archive)
        reopened.archive_closed_window(**args,archive_path=archive)
        reopened.compact()
        assert signer.seal(**args) == wire
    finally: reopened.close()


@pytest.mark.parametrize("stage",["before_capsule_commit","after_capsule_commit"])
def test_sealing_faults_at_commit_boundaries_recover_same_bytes(store,stage):
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)
    receipt = submit(store)
    store.clock.advance(10)
    store.tick()
    def fail(point,db):
        if point == stage: raise RuntimeError("lost capsule operation")
    store.fault = fail
    with pytest.raises(RuntimeError): signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    count = store.db.execute("SELECT COUNT(*) FROM sealed_capsules").fetchone()[0]
    assert count == (0 if stage == "before_capsule_commit" else 1)
    cached = store.db.execute("SELECT body FROM sealed_capsules").fetchone()
    store.fault = lambda *args:None
    wire = signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    if cached: assert wire == cached[0]
    assert store.db.execute("SELECT COUNT(*) FROM sealed_capsules").fetchone()[0] == 1


def test_recovery_discontinuity_and_legacy_closure_artifacts(store):
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)
    receipt = submit(store)
    path = store.path
    store.close()
    recovered = ObservationLedger(path,CONTRACT,clock=FakeClock(1))
    try:
        signer = CapsuleSealer(recovered,"gateway-vector","test-vector-key",KEY)
        wire = signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
        assert parse_artifact(wire).body.closure_reason == "RECOVERY"
        assert CoverageLimitation.INTERRUPTED in parse_artifact(wire).body.coverage_limitations
    finally: recovered.close()


def test_clock_discontinuous_capsule_and_unknown_semantics(store):
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)
    receipt = submit(store)
    store.clock.advance(1,wall=-1)
    with pytest.raises(LedgerRefused): submit(store,retry=2)
    wire = signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    assert parse_artifact(wire).body.closure_reason == "CLOCK_DISCONTINUITY"
    assert evaluate_condition(CONTRACT.conditions[0],authenticated_facts(wire,KEYS,CONTRACTS)[0]).truth == Truth.UNKNOWN


def test_optional_migration_preserves_old_closed_scope_and_raw_archive_shape(store):
    receipt = submit(store)
    store.clock.advance(10)
    store.tick()
    before = store._archive_bytes((store.epoch,receipt.device_id,receipt.window_index))
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)
    after = store._archive_bytes((store.epoch,receipt.device_id,receipt.window_index))
    assert before == after
    wire = signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    assert parse_artifact(wire).body.closure_reason == "LEGACY_CLOSURE"
    assert CoverageLimitation.INTERRUPTED in parse_artifact(wire).body.coverage_limitations


def test_signing_capacity_key_bindings_and_order_are_fail_closed(store):
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY,limits=SealingLimits(max_capsules=1))
    first = submit(store)
    store.clock.advance(10)
    store.tick()
    signer.seal(device_id=first.device_id,window_index=first.window_index)
    second = submit(store,retry=2)
    store.clock.advance(10)
    store.tick()
    with pytest.raises(LedgerRefused,match="CAPACITY"): signer.seal(device_id=second.device_id,window_index=second.window_index)
    assert len(store.records()) == 2
    assert store.db.execute("SELECT COUNT(*) FROM sealed_capsules").fetchone()[0] == 1
    with pytest.raises(LedgerRefused,match="KEY_ID"): CapsuleSealer(store,"gateway-vector","test-vector-key",Ed25519PrivateKey.generate())
    with pytest.raises(LedgerRefused,match="GATEWAY"): CapsuleSealer(store,"other-gateway","test-vector-key",KEY)


@pytest.mark.parametrize("inequality",[">",">=","<","<="])
def test_offline_count_ge_recomputation_in_all_numeric_directions(inequality):
    doc = CONTRACT.model_dump(mode="json")
    doc["conditions"][0].update(predicate="COUNT_GE",k=2,inequality=inequality)
    contract = RuleContract.model_validate(doc)
    original_window = WindowIdentity(ledger_epoch="vector-epoch",device_id="edge-device-01",window_index=0,contract_hash=contract_hash(contract))
    raw = [record(25),record(38,sequence=2),record(45,sequence=3)]
    body = build_capsule(contract=contract,window=original_window,records=raw,gateway_id="gateway-vector",
                         signing_key_id="test-vector-key",created_at_utc_us=10000000)
    assert audit_capsule(sign_artifact(body,KEY),KEYS,{contract_hash(contract):contract},raw).status == "RECOMPUTED"


def test_signed_bytes_body_fact_and_transport_worst_identifier_bounds():
    data = CONTRACT.model_dump(mode="json")
    data["conditions"] = [{**data["conditions"][0],"condition_id":"c"+str(index).zfill(63)} for index in range(64)]
    data["rules"] = [{"rule_id":"one-rule","expression":{"kind":"ATOM","condition_id":data["conditions"][0]["condition_id"]}}]
    contract = RuleContract.model_validate(data)
    scope = WindowIdentity(ledger_epoch="e"*64,device_id="edge-device-01",window_index=0,contract_hash=contract_hash(contract))
    r = record().model_dump()
    r["ledger_epoch"] = scope.ledger_epoch
    body = build_capsule(contract=contract,window=scope,records=[InputRecord.model_validate(r)],
        gateway_id="g"*64,signing_key_id="k"*64,created_at_utc_us=10000000)
    wire = sign_artifact(body,KEY)
    parts = split_artifact(wire,KEY)
    assert len(wire) <= MAX_ARTIFACT_BYTES and len(parts) <= MAX_PARTS
    assert all(len(part) <= 1200 for part in parts)
    assert assemble_parts(parts,{("g"*64,"k"*64):KEY.public_key()},{contract_hash(contract):contract}) == wire
    data = body.model_dump(mode="json")
    data["per_condition_facts"].append(deepcopy(data["per_condition_facts"][0]))
    with pytest.raises(ValueError): CapsuleBody.model_validate(data)


def test_input_scope_byte_and_signed_evidence_byte_limits(store):
    large = record(attributes={"large":"x"*50000})
    def records():
        for index in range(200):
            yield InputRecord.model_validate({**large.model_dump(),"ingress_sequence":index+1,"ingress_utc_us":index+1})
    with pytest.raises(EvidenceError,match="BYTE_LIMIT"):
        input_commitment(window(),records())
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY,limits=SealingLimits(max_signed_bytes=1))
    receipt = submit(store)
    store.clock.advance(10)
    store.tick()
    with pytest.raises(LedgerRefused,match="CAPACITY"):
        signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    assert store.db.execute("SELECT COUNT(*) FROM sealed_capsules").fetchone()[0] == 0


def test_corrupt_signing_journal_head_facts_and_missing_scopes_fail_visibly(store):
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)
    receipt = submit(store)
    store.clock.advance(10)
    store.tick()
    store.db.execute("UPDATE facts SET matches=0,misses=1")
    with pytest.raises(LedgerRefused,match="SEAL_FACTS"):
        signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    store.db.execute("UPDATE facts SET matches=1,misses=0")
    signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    store.db.execute("UPDATE capsule_heads SET digest=?",("f"*64,))
    with pytest.raises(LedgerRefused,match="CAPSULE_HEAD"):
        CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)
    with pytest.raises(LedgerRefused,match="CLOSED"):
        signer.seal(device_id=receipt.device_id,window_index=receipt.window_index+100)


def transition_fixture(threshold=39):
    data = CONTRACT.model_dump(mode="json")
    data["conditions"][0]["threshold"] = threshold
    contract = RuleContract.model_validate(data)
    body = build_transition(gateway_id="gateway-vector",signing_key_id="test-vector-key",ledger_epoch="vector-epoch",
        previous_contract_hash=contract_hash(CONTRACT),next_contract_hash=contract_hash(contract),
        effective_window_index=3,created_at_utc_us=20000000)
    return body,{**CONTRACTS,contract_hash(contract):contract}


TRANSITION_MUTATIONS = leaves(json.loads(sign_artifact(transition_fixture()[0],KEY)))


@pytest.mark.parametrize("path,value",TRANSITION_MUTATIONS,ids=[".".join(map(str,path)) for path,_ in TRANSITION_MUTATIONS])
def test_every_contract_transition_field_mutation_is_rejected(path,value):
    body,contracts = transition_fixture()
    document = json.loads(sign_artifact(body,KEY))
    target = document
    for key in path[:-1]: target = target[key]
    target[path[-1]] = value+1 if type(value) is int else str(value)+"x"
    with pytest.raises(EvidenceError): verify_artifact(canonical_bytes(document),KEYS,contracts)


def test_coverage_limit_list_transition_forks_and_retained_signature_corruption(store):
    document = json.loads(sign_artifact(capsule(),KEY))
    document["body"]["coverage_limitations"] = ["INTERRUPTED"]
    with pytest.raises(EvidenceError): verify_artifact(canonical_bytes(document),KEYS,CONTRACTS)
    one,contracts1 = transition_fixture(39)
    two,contracts2 = transition_fixture(40)
    assert one.transition_id == two.transition_id
    tracker = EvidenceTracker(KEYS,{**contracts1,**contracts2})
    tracker.inspect(sign_artifact(one,KEY))
    with pytest.raises(EvidenceConflict): tracker.inspect(sign_artifact(two,KEY))
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)
    receipt = submit(store)
    store.clock.advance(10)
    store.tick()
    signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
    store.db.execute("UPDATE sealed_capsules SET body=?",(b"{}",))
    with pytest.raises((EvidenceError,LedgerRefused)):
        CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)


@pytest.mark.parametrize("stage",["before_capsule_commit","after_capsule_commit"])
def test_process_death_during_signing_journal_commit(store,stage):
    signer = CapsuleSealer(store,"gateway-vector","test-vector-key",KEY)
    receipt = submit(store)
    store.clock.advance(10)
    store.tick()
    path = store.path
    store.close()
    program = """
import os,sys
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shared.coverage import load_contract
from shared.coverage.ledger import ObservationLedger
from shared.coverage.sealing import CapsuleSealer
class Clock:
    def utc_now(self): return datetime(2026,1,1,0,0,20,tzinfo=timezone.utc)
    def monotonic_ns(self): return 0
def fault(stage,db):
    if stage==sys.argv[4]: os._exit(77)
s=ObservationLedger(sys.argv[1],load_contract(sys.argv[2]),clock=Clock(),fault=fault)
publisher=CapsuleSealer(s,'gateway-vector','test-vector-key',Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
publisher.seal(device_id='edge-device-01',window_index=int(sys.argv[3]))
"""
    result = subprocess.run([sys.executable,"-c",program,str(path),str(ROOT/"config/rule_coverage.json"),str(receipt.window_index),stage],
                             cwd=ROOT,capture_output=True,text=True,timeout=20)
    assert result.returncode == 77, result.stderr
    recovered = ObservationLedger(path,CONTRACT,clock=FakeClock(30))
    try:
        cached = recovered.db.execute("SELECT body FROM sealed_capsules").fetchone()
        assert bool(cached) == (stage == "after_capsule_commit")
        signer = CapsuleSealer(recovered,"gateway-vector","test-vector-key",KEY)
        encoded = signer.seal(device_id=receipt.device_id,window_index=receipt.window_index)
        if cached: assert cached[0] == encoded
        assert verify_artifact(encoded,KEYS,CONTRACTS)
    finally: recovered.close()
