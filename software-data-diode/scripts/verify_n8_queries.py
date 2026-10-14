"""Real PostgreSQL N8 checks in a disposable schema, never baseline rows."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from psycopg import sql
from psycopg.rows import dict_row

from shared.coverage.capsules import InputRecord, build_capsule, sign_artifact
from shared.coverage.contracts import contract_hash, load_contract
from shared.coverage.models import WindowIdentity
from shared.coverage.monitoring import CoverageMonitor, MonitoringConfig
from shared.coverage.parts import split_artifact
from shared.coverage.transport import ResearchFramer, TrustProfile
from shared.coverage.verification import FogEvidenceVerifier
from shared.persistence import coverage_queries as queries
from shared.persistence.repository import PostgresRepository
from shared.models import EdgeTelemetryMessage
from shared.security.crypto import canonical_bytes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--migration-bundle")
    args = parser.parse_args()
    if os.environ.get("COVERAGE_PROJECT_NAME") != "software-data-diode-coverage":
        raise RuntimeError("isolated coverage project required")
    base = PostgresRepository(os.environ["DATABASE_URL"])
    schema = "n8_check_"+uuid4().hex
    class ScopedRepository(PostgresRepository):
        def _connect(self):
            connection = super()._connect()
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            return connection
    repository = ScopedRepository(base.database_url)
    checks = []
    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append({"check": name, "passed": True})
    def query(operation, *params):
        with repository._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            connection.row_factory = dict_row
            return operation(connection, *params)
    with base._connect() as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    try:
        migrations = json.loads(base64.b64decode(args.migration_bundle)) if args.migration_bundle else {
            p.name: p.read_text() for p in Path("database/migrations").glob("*.sql")}
        with repository._connect() as connection:
            for _ in range(2):
                for name in sorted(migrations):
                    connection.execute(migrations[name], prepare=False)
        check("all additive migrations run twice", repository.coverage_ready())
        contract = load_contract(os.environ["COVERAGE_CONTRACT_PATH"])
        key = Ed25519PrivateKey.generate()
        profile = TrustProfile(gateway_id="n8-test-gateway", signing_key_id="n8-test-key", ledger_epoch=uuid4().hex,
            contract_hash=contract_hash(contract), public_key_sha256=hashlib.sha256(
                key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest())
        framer = ResearchFramer(profile, key.public_key(), contract, private_key=key)
        now_us = time.time_ns()//1000
        index = now_us//10_000_000-4
        monitor = CoverageMonitor(framer, MonitoringConfig.load(os.environ["COVERAGE_RULE_MONITOR_CONFIG"]), now_us=lambda: now_us)
        encoded_bodies = []
        for offset in range(3):
            # Honest no-input capsules exercise definite UNKNOWN, not invented negatives.
            for device in contract.devices:
                window = WindowIdentity(ledger_epoch=profile.ledger_epoch, device_id=device.device_id,
                    window_index=index-offset, contract_hash=profile.contract_hash)
                body = build_capsule(contract=contract, window=window, records=[], gateway_id=profile.gateway_id,
                    signing_key_id=profile.signing_key_id, created_at_utc_us=window.end_utc_us)
                encoded = sign_artifact(body, key)
                frames = split_artifact(encoded, key)
                verified = FogEvidenceVerifier(framer).verify(encoded, received_us=window.end_utc_us, frames=frames)
                repository.save_coverage_evidence(encoded, verified, frames, .001)
                encoded_bodies.append((body, verified.artifact_digest))
            repository.process_coverage_rules(monitor)
        query_config = queries.CoverageQuery(gateway_id=profile.gateway_id, contract_hash=profile.contract_hash,
                                            start_window=index-2, end_window=index, limit=4)
        overview = query(queries.overview, query_config, contract)
        check("historical capsule byte total equals received unique parts", overview["cost"]["capsules"] == 15 and overview["cost"]["received_evidence_bytes"]>0)
        check("no-input evidence is UNKNOWN not false safety", overview["counts"]["opportunities"] == 27 and overview["counts"]["unknown_rate"] == 1)
        check("unmatched sender fraction unavailable", overview["sender"]["evidence_fraction"] is None)
        page = query(queries.verdict_page, query_config)
        ids = set()
        while True:
            check("bounded page", len(page["items"])<=4)
            check("keyset page has no duplicates", not ids.intersection(r["decision_id"] for r in page["items"]))
            ids.update(r["decision_id"] for r in page["items"])
            if not page["next_cursor"]:
                break
            query_config = queries.CoverageQuery(**{**query_config.model_dump(), **page["next_cursor"]})
            page = query(queries.verdict_page, query_config)
        check("all latest rule-window identities traversed", len(ids)==27)
        device_query = queries.CoverageQuery(device_id="edge-device-02", rule_id="incident-correlation")
        filtered = query(queries.verdict_page, device_query)
        check("rule/device dependency filter", len(filtered["items"])==3)
        detail = query(queries.decision_detail, filtered["items"][0]["decision_id"])
        check("exact decision references and revision history", len(detail["history"])>=1 and len(detail["capsules"])==3)
        digest = detail["capsules"][0]["artifact_digest"]
        capsule = query(queries.capsule_detail, digest)
        check("signed body and complete part sizes available", capsule["signed_artifact"]["body"] == capsule["body"] and bool(capsule["parts"]))
        check("empty witness page cannot imply full recomputation", not query(queries.witnesses, digest)["items"])
        check("unknown identity returns no record", query(queries.decision_detail, uuid4()) is None)
        body = next(b for b,d in encoded_bodies if d==digest)
        fork = sign_artifact(body.model_copy(update={"created_at_utc_us": body.created_at_utc_us+1}), key)
        parts = split_artifact(fork, key)
        verification = FogEvidenceVerifier(framer).verify(fork, received_us=body.window_end_utc_us+1, frames=parts)
        repository.save_coverage_evidence(fork, verification, parts, .001)
        repository.process_coverage_rules(monitor)
        conflict = query(queries.capsule_detail, digest)
        check("conflict visible without overwriting original", conflict["quarantined"] and len(conflict["conflicts"])==1)
        for delta, value, truth in ((1, 90, "TRUE"), (2, 20, "FALSE")):
            window = WindowIdentity(ledger_epoch=profile.ledger_epoch, device_id="edge-device-02",
                window_index=index+delta, contract_hash=profile.contract_hash)
            originals = []
            for seq in (1, 2):
                raw = canonical_bytes(EdgeTelemetryMessage(device_id=window.device_id,telemetry_type="system",
                    cpu_usage=value, temperature=25, humidity=50, status="normal",
                    timestamp=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(microseconds=window.start_utc_us+seq)).model_dump(mode="json"))
                originals.append(InputRecord(ledger_epoch=profile.ledger_epoch,device_id=window.device_id,
                    ingress_sequence=window.window_index*100+seq,ingress_utc_us=window.start_utc_us+seq,
                    canonical_input=raw,input_hash=hashlib.sha256(raw).hexdigest()))
            body = build_capsule(contract=contract,window=window,records=originals,gateway_id=profile.gateway_id,
                signing_key_id=profile.signing_key_id,created_at_utc_us=window.end_utc_us)
            encoded = sign_artifact(body,key)
            parts = split_artifact(encoded,key)
            record = FogEvidenceVerifier(framer).verify(encoded,received_us=window.end_utc_us,frames=parts)
            repository.save_coverage_evidence(encoded,record,parts,.001)
            repository.process_coverage_rules(monitor)
            answers = query(queries.verdict_page, queries.CoverageQuery(rule_id="resource-threshold",
                start_window=window.window_index,end_window=window.window_index))
            check(truth+" resource verdict read from actual database", len(answers["items"])==1 and answers["items"][0]["verdict"]==truth)
            selection = query(queries.decision_detail, answers["items"][0]["decision_id"])
            check(truth+" supporting capsule is exact", selection["decision"]["result"]["supporting_artifacts"]==[record.artifact_digest])
            filtered_stats = query(queries.overview, queries.CoverageQuery(rule_id="resource-threshold",truth=truth,
                start_window=window.window_index,end_window=window.window_index),contract)
            check(truth+" filtered byte totals do not multiply rules", filtered_stats["cost"]["capsules"]==1 and filtered_stats["counts"]["definite_yield"]==1)
            if truth == "TRUE":
                for original in originals:
                    repository.save_coverage_original_witness(framer,record.artifact_digest,original)
                first = query(queries.witnesses,record.artifact_digest,0,1)
                second = query(queries.witnesses,record.artifact_digest,first["next_sequence"],1)
                check("actual canonical witnesses paginate without duplication", len(first["items"])==1 and len(second["items"])==1
                    and first["items"][0]["ingress_sequence"] != second["items"][0]["ingress_sequence"]
                    and base64.b64decode(first["items"][0]["canonical_input_base64"])==originals[0].canonical_input)
                repository.process_coverage_rules(monitor)
                newer = query(queries.decision_detail, answers["items"][0]["decision_id"])
                check("witness revisions are inspectable", len(newer["history"])>=2)
        print(json.dumps({"mode": "REAL_POSTGRES_TEMPORARY_SCHEMA", "checks": checks,
                          "source": "ephemeral signed no-input/positive/negative scopes; no production rows changed"}, indent=2))
    finally:
        with base._connect() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


if __name__ == "__main__":
    main()
