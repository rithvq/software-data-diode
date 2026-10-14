"""Actual PostgreSQL/Alert Engine checks, isolated schema and ephemeral test trust."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from uuid import uuid4

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from psycopg import sql

from shared.coverage.capsules import InputRecord, build_capsule, sign_artifact, artifact_digest, WitnessReference
from shared.coverage.contracts import load_contract, contract_hash
from shared.coverage.fog_store import FogEvidenceStore
from shared.coverage.models import WindowIdentity, IngressObservation, MetricReading
from shared.coverage.monitoring import CoverageMonitor, MonitoringConfig
from shared.coverage.oracle import trace_oracle
from shared.coverage.parts import split_artifact
from shared.coverage.rules import VerifiedScope
from shared.coverage.transport import ResearchFramer, TrustProfile, PartAssembler
from shared.coverage.verification import FogEvidenceVerifier
from shared.models import EdgeTelemetryMessage
from shared.models.fog import CoverageAlertDelivery
from shared.persistence.repository import PostgresRepository
from shared.security.crypto import canonical_bytes


def scope_fixture(framer,window,device,values):
    w = WindowIdentity(ledger_epoch=framer.profile.ledger_epoch,contract_hash=framer.profile.contract_hash,device_id=device,window_index=window)
    definition = next(d for d in framer.contract.devices if d.device_id == device)
    records = []
    for seq,value in enumerate(values,1):
        kwargs = {"device_id":device,"telemetry_type":definition.telemetry_type,"temperature":25,"humidity":50,"status":"normal",
            "timestamp":datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(microseconds=w.start_utc_us+seq)}
        path = definition.metrics[0].path
        if value is not None:
            if path.startswith("measurements."):
                kwargs["measurements"] = {path.split(".",1)[1]:value}
            else:
                kwargs[path] = value
        raw = canonical_bytes(EdgeTelemetryMessage(**kwargs).model_dump(mode="json"))
        records.append(InputRecord(ledger_epoch=w.ledger_epoch,device_id=device,ingress_sequence=window*100+seq,
            ingress_utc_us=w.start_utc_us+seq,canonical_input=raw,input_hash=hashlib.sha256(raw).hexdigest()))
    body = build_capsule(contract=framer.contract,window=w,records=records,gateway_id=framer.profile.gateway_id,
        signing_key_id=framer.profile.signing_key_id,created_at_utc_us=w.end_utc_us)
    encoded = sign_artifact(body,framer.private_key)
    frames = split_artifact(encoded,framer.private_key)
    record = FogEvidenceVerifier(framer).verify(encoded,received_us=w.end_utc_us,frames=frames)
    return VerifiedScope(body,artifact_digest(encoded),record),records,encoded,frames


def oracle_record(record,contract):
    raw = json.loads(record.canonical_input)
    definition = next(d for d in contract.devices if d.device_id == record.device_id)
    metrics = tuple(MetricReading(path=m.path,value=raw["measurements"].get(m.path[13:]) if m.path.startswith("measurements.") else raw.get(m.path)) for m in definition.metrics)
    return IngressObservation(ledger_epoch=record.ledger_epoch,device_id=record.device_id,ingress_sequence=record.ingress_sequence,
        ingress_utc_us=record.ingress_utc_us,telemetry_type=raw["telemetry_type"],metrics=metrics)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--migration-bundle",required=True)
    parser.add_argument("--http-fixture",action="store_true")
    args = parser.parse_args()
    if os.getenv("COVERAGE_PROJECT_NAME") != "software-data-diode-coverage":
        raise RuntimeError("only the isolated local coverage project is permitted")
    base = PostgresRepository(os.environ["DATABASE_URL"])
    schema = "n7_check_"+uuid4().hex
    class ScopedRepository(PostgresRepository):
        def _connect(self):
            connection = super()._connect()
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            return connection
    repository = ScopedRepository(base.database_url)
    with base._connect() as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    checks, reference_comparisons = [], 0
    def check(name,truth):
        if not truth:
            raise AssertionError(name)
        checks.append({"check":name,"passed":True})
    try:
        migrations = json.loads(base64.b64decode(args.migration_bundle,validate=True))
        with repository._connect() as connection:
            for _ in range(2):
                for name in sorted(migrations):
                    connection.execute(migrations[name],prepare=False)
        check("additive migrations repeat without deleting existing schema rows",repository.coverage_ready())
        contract = load_contract(os.environ["COVERAGE_CONTRACT_PATH"])
        key = Ed25519PrivateKey.generate()
        profile = TrustProfile(gateway_id="n7-fixture-gateway",signing_key_id="n7-fixture-key",ledger_epoch="n7-"+uuid4().hex,
            contract_hash=contract_hash(contract),public_key_sha256=hashlib.sha256(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).hexdigest())
        framer = ResearchFramer(profile,key.public_key(),contract,private_key=key)
        config = MonitoringConfig.load(os.environ["COVERAGE_RULE_MONITOR_CONFIG"])
        now = [time.time_ns()//1000]
        index = now[0]//10000000-4
        monitor = CoverageMonitor(framer,config,now_us=lambda:now[0])
        def persist(fixture):
            scope,raw,encoded,frames = fixture
            return repository.save_coverage_evidence(encoded,scope.verification,frames,.001)
        def verdict(rule="incident-correlation",window=index):
            with repository._connect() as connection:
                return connection.execute("SELECT verdict,result,revision FROM coverage_rule_verdicts WHERE rule_id=%s AND window_index=%s",(rule,window)).fetchone()
        def intent(kind="INCIDENT",rule="incident-correlation",window=index):
            with repository._connect() as connection:
                row = connection.execute("""SELECT i.alert_id,i.delivery_revision,i.active FROM coverage_alert_intents i
                    JOIN coverage_rule_verdicts v USING(decision_id) WHERE v.rule_id=%s AND v.window_index=%s AND i.kind=%s""",(rule,window,kind)).fetchone()
                return row
        def compare(trace,window):
            nonlocal reference_comparisons
            with repository._connect() as connection:
                for rule,answer in connection.execute("SELECT rule_id,verdict FROM coverage_rule_verdicts WHERE window_index=%s",(window,)).fetchall():
                    reference = trace_oracle(contract,rule,ledger_epoch=profile.ledger_epoch,window_index=window,
                        observations=[oracle_record(r,contract) for r in trace])
                    if answer != "UNKNOWN":
                        check("definite "+rule+" matches independent original-ingress oracle",answer == reference)
                    reference_comparisons += 1
        cpu = scope_fixture(framer,index,"edge-device-02",[90])
        network = scope_fixture(framer,index,"edge-device-03",[8000])
        login = scope_fixture(framer,index,"edge-device-04",[5])
        persist(cpu)
        persist(network)
        with repository._connect() as connection:
            connection.execute("""CREATE FUNCTION fail_rule_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'N7 injected rule outbox failure'; END $$;
                CREATE TRIGGER fail_rule_outbox BEFORE INSERT ON coverage_alert_intents FOR EACH ROW EXECUTE FUNCTION fail_rule_outbox();""")
        try:
            repository.process_coverage_rules(monitor)
            raise AssertionError("rule transaction fault was not injected")
        except Exception as exc:
            check("rule outbox failure occurs after decision writes","injected rule outbox failure" in str(exc))
        with repository._connect() as connection:
            check("rule transaction rolls back verdict history and publication completion",
                connection.execute("SELECT COUNT(*) FROM coverage_rule_verdicts").fetchone()[0] == 0
                and connection.execute("SELECT COUNT(*) FROM coverage_rule_history").fetchone()[0] == 0
                and connection.execute("SELECT COUNT(*) FROM coverage_publications WHERE published_revision>0").fetchone()[0] == 0)
            connection.execute("DROP TRIGGER fail_rule_outbox ON coverage_alert_intents; DROP FUNCTION fail_rule_outbox()")
        repository.process_coverage_rules(monitor)
        check("missing login evidence yields UNKNOWN with partial coverage",verdict()[0] == "UNKNOWN" and not verdict()[1]["coverage_complete"])
        assembly = PartAssembler(framer)
        for frame in login[3][:-1]:
            check("incomplete authenticated parts do not become facts",assembly.add(frame) is None)
        artifact = assembly.add(login[3][-1])
        with tempfile.TemporaryDirectory(prefix="n7-fog-spool-") as directory:
            store = FogEvidenceStore(Path(directory)/"fog.db",framer,now_us=lambda:now[0])
            try:
                check("late complete RCC commits to durable Fog spool",store.accept(artifact))
                check("spooled late facts commit to PostgreSQL",store.publish_one(repository) == "ACCEPTED")
            finally:
                store.close()
        repository.process_coverage_rules(monitor)
        check("late evidence refines UNKNOWN to TRUE",verdict()[0] == "TRUE")
        check("rule complete is not globally complete observation",verdict()[1]["coverage_complete"] and not verdict()[1]["coverage_health"]["complete"])
        with repository._connect() as connection:
            history = connection.execute("SELECT record->>'verdict' FROM coverage_rule_history WHERE decision_id=%s ORDER BY revision",(verdict()[1]["decision_id"],)).fetchall()
            check("versioned history retains UNKNOWN then TRUE",history[:2] == [("UNKNOWN",),("TRUE",)])
        compare([*cpu[1],*network[1],*login[1]],index)
        check("authenticated original witness persisted",repository.save_coverage_original_witness(framer,login[0].digest,login[1][0]))
        check("original witness retry is idempotent",not repository.save_coverage_original_witness(framer,login[0].digest,login[1][0]))
        repository.process_coverage_rules(monitor)
        check("one original and its RCC do not become two COUNT_GE hits",verdict("repeated-security-observations")[0] == "FALSE")
        check("witness references survive rule publication",bool(verdict()[1]["checked_original_witnesses"]))
        if args.http_fixture:
            print("N7_ALERT_FIXTURE_SCHEMA="+schema,flush=True)
            deadline = time.monotonic()+90
            while True:
                try:
                    if httpx.get("http://alert-engine:18007/health",timeout=1).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic()>deadline:
                    raise TimeoutError("host did not start temporary Alert Engine fixture")
                time.sleep(.2)
        def deliver(row):
            request = {"alert_id":str(row[0]),"revision":row[1]}
            if args.http_fixture:
                response = httpx.post("http://alert-engine:18007/coverage-alerts",json=request,timeout=6)
                if response.status_code != 200:
                    return "HTTP_"+str(response.status_code)
                return response.json()["status"]
            return repository.deliver_coverage_alert(CoverageAlertDelivery.model_validate(request))
        original_intent = intent()
        with repository._connect() as connection:
            connection.execute("""CREATE FUNCTION fail_alert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'N7 injected alert failure'; END $$;
                CREATE TRIGGER fail_alert BEFORE INSERT ON alerts FOR EACH ROW EXECUTE FUNCTION fail_alert();""")
        if args.http_fixture:
            check("Alert Engine DB failure returns 503 instead of receipt",deliver(original_intent) == "HTTP_503")
        else:
            try:
                deliver(original_intent)
                raise AssertionError("fault not injected")
            except Exception as exc:
                check("alert fault injected", "injected alert failure" in str(exc))
        with repository._connect() as connection:
            check("failed alert transaction leaves no stored alert or delivery receipt",connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0 and connection.execute("SELECT delivered_revision FROM coverage_alert_intents WHERE alert_id=%s",(original_intent[0],)).fetchone()[0] == 0)
            connection.execute("DROP TRIGGER fail_alert ON alerts; DROP FUNCTION fail_alert()")
        check("TRUE incident stored by Alert Engine authority",deliver(original_intent) == "STORED")
        check("delivery replay creates no second incident",deliver(original_intent) == "DUPLICATE")
        check("duplicate capsule creates no new publication",persist(login) == "DUPLICATE")
        fork = scope_fixture(framer,index,"edge-device-04",[0])
        check("signed immutable scope fork quarantined",persist(fork) == "CONFLICT")
        check("conflict immediately invalidates verdict and preserves revision",verdict()[0] == "UNKNOWN" and verdict()[2] > 2)
        check("queued old TRUE delivery is rejected after conflict",deliver(original_intent) == "SUPERSEDED")
        repository.process_coverage_rules(monitor)
        check("affected correlation stays UNKNOWN while scope quarantined",verdict()[0] == "UNKNOWN")
        check("previously delivered incident gets inactive state",deliver(intent()) == "INACTIVE")
        with repository._connect() as connection:
            check("incident row retained but retracted without duplicate",connection.execute("SELECT COUNT(*) FROM alerts WHERE alert_id=%s",(original_intent[0],)).fetchone()[0] == 1 and not connection.execute("SELECT active FROM coverage_alert_states WHERE alert_id=%s",(original_intent[0],)).fetchone()[0])
        check("visibility alert identifies degraded observation",deliver(intent("VISIBILITY")) == "STORED")
        with repository._connect() as connection:
            message = connection.execute("SELECT alert_type,severity,description,evidence FROM alerts WHERE alert_id=%s",(intent("VISIBILITY")[0],)).fetchone()
            check("visibility severity is independent from UNKNOWN status",message[0] == "COVERAGE_VISIBILITY" and message[1] == "WARNING" and message[3][0]["decision_status"] == "UNKNOWN" and "does not establish an attack" in message[2])
        restarted = CoverageMonitor(framer,config,now_us=lambda:now[0])
        revision = verdict()[2]
        repository.process_coverage_rules(restarted)
        check("monitor restart does not duplicate same rule revision",verdict()[2] == revision)
        low = scope_fixture(framer,index+1,"edge-device-02",[10])
        persist(low)
        repository.process_coverage_rules(restarted)
        check("FALSE AND does not certify missing devices observed",verdict(window=index+1)[0] == "FALSE" and not verdict(window=index+1)[1]["coverage_complete"])
        compare(low[1],index+1)
        empty = scope_fixture(framer,index+2,"edge-device-04",[])
        persist(empty)
        repository.process_coverage_rules(restarted)
        check("no-input scope stays UNKNOWN",verdict("security-threshold",index+2)[0] == "UNKNOWN")
        compare([],index+2)
        env = scope_fixture(framer,index+1,"edge-device-01",[45])
        persist(env)
        repository.process_coverage_rules(restarted)
        env2 = scope_fixture(framer,index+2,"edge-device-01",[45])
        persist(env2)
        repository.process_coverage_rules(restarted)
        check("cooldown survives independent monitor instances",intent(rule="environmental-threshold",window=index+1)[2] and not intent(rule="environmental-threshold",window=index+2)[2])
        # Reference actual accepted traces, not selected raw messages or means.
        compare([*low[1],*env[1]],index+1)
        compare(env2[1],index+2)
        bad = scope_fixture(framer,index+3,"edge-device-01",[25])
        fact = bad[0].body.per_condition_facts[0].model_copy(update={"matching_count":1,"nonmatching_count":0,
            "witnesses":(WitnessReference(ingress_sequence=bad[1][0].ingress_sequence,input_hash=bad[1][0].input_hash),)})
        bad_body = bad[0].body.model_copy(update={"per_condition_facts":(fact,)})
        bad_encoded = sign_artifact(bad_body,key)
        bad_frames = split_artifact(bad_encoded,key)
        bad_verification = FogEvidenceVerifier(framer).verify(bad_encoded,received_us=bad_body.window_end_utc_us,frames=bad_frames)
        repository.save_coverage_evidence(bad_encoded,bad_verification,bad_frames)
        check("checked original contradicting signed matching assertion quarantines scope",repository.save_coverage_original_witness(framer,artifact_digest(bad_encoded),bad[1][0]) == "QUARANTINED")
        repository.process_coverage_rules(restarted)
        check("contradictory original cannot generate a definite incident",verdict("environmental-threshold",index+3)[0] == "UNKNOWN")
        expired = scope_fixture(framer,index+3,"edge-device-05",[9])
        metadata = {k:getattr(expired[0].body,k) for k in ("gateway_id","ledger_epoch","contract_hash","device_id","window_index")}
        repository.save_coverage_outcome({"outcome_id":hashlib.sha256(b"n7-expired"+expired[2]).hexdigest(),"timestamp_us":now[0],
            "reason_code":"EXPIRED_EVIDENCE","details":{"authenticated_scope":metadata}})
        # A deadline for the missing scope, not an invented historical observation.
        now[0] += 40000000
        repository.process_coverage_rules(restarted)
        expired_decision = verdict("industrial-threshold",index+3)
        check("authenticated expiry is explained as missing observation not attack",expired_decision[0] == "UNKNOWN" and "AUTHENTICATED_EVIDENCE_EXPIRED" in expired_decision[1]["reason_codes"])
        compare([*bad[1],*expired[1]],index+3)
        changed = CoverageMonitor(framer,config.model_copy(update={"visibility_cooldown_windows":config.visibility_cooldown_windows+1}),now_us=lambda:now[0])
        try:
            repository.process_coverage_rules(changed)
            raise AssertionError("config binding changed silently")
        except ValueError as exc:
            check("persisted monitor config cannot change silently on restart","CONFIG_CHANGE" in str(exc))
        now[0] += 2000000000
        repository.process_coverage_rules(restarted)
        with repository._connect() as connection:
            check("long monitor downtime records a gap rather than historical normality",connection.execute("SELECT COUNT(*) FROM coverage_monitor_gaps WHERE reason='FOG_MONITOR_DOWNTIME'").fetchone()[0] == 1)
        now[0] -= 1
        check("Fog clock regression does not reopen completed deadlines",repository.process_coverage_rules(restarted) == "CLOCK_LIMITATION")
        queued_env = intent(rule="environmental-threshold",window=index+1)
        repository.retire_coverage_epoch(profile.gateway_id,profile.ledger_epoch)
        check("epoch retirement rejects a queued old incident revision",deliver(queued_env) == "SUPERSEDED")
        with repository._connect() as connection:
            check("retirement retains decision history and invalidates current truth",connection.execute("SELECT COUNT(*) FROM coverage_rule_history").fetchone()[0] > 9 and connection.execute("SELECT COUNT(*) FROM coverage_rule_verdicts WHERE verdict!='UNKNOWN'").fetchone()[0] == 0)
        if args.http_fixture:
            httpx.post("http://alert-engine:18007/_n7_fixture_shutdown",headers={"X-N7-Fixture":schema},timeout=3).raise_for_status()
        print(json.dumps({"phase":"N7","checks":checks,"oracle_comparisons":reference_comparisons,
            "schema":schema,"ephemeral_test_trust":True,"existing_rows_modified":False,"http_alert_engine":args.http_fixture},indent=2))
    finally:
        with base._connect() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


if __name__ == "__main__":
    main()
