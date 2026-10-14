"""Local N6 PostgreSQL checks in a new disposable schema, never existing rows."""
import argparse
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import socket
from pathlib import Path
import tempfile
import time
from uuid import uuid4, uuid5, NAMESPACE_URL

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from shared.coverage.capsules import InputRecord, artifact_digest, build_capsule, sign_artifact
from shared.coverage.contracts import contract_hash, load_contract
from shared.coverage.fog_store import FogEvidenceStore
from shared.coverage.models import WindowIdentity
from shared.coverage.parts import split_artifact
from shared.coverage.transport import ResearchFramer, TrustProfile
from shared.coverage.verification import FogEvidenceVerifier
from shared.coverage.udp_runtime import FogUDP
from shared.models import EdgeTelemetryMessage
from shared.persistence.repository import PostgresRepository
from shared.security.crypto import canonical_bytes


def fixture_artifact(framer, index, *, value=45, previous=None, created=None, device="edge-device-01", empty=False, **scope_options):
    window = WindowIdentity(ledger_epoch=framer.profile.ledger_epoch, device_id=device,
                            window_index=index, contract_hash=framer.profile.contract_hash)
    kind = next(d.telemetry_type for d in framer.contract.devices if d.device_id == device)
    original = EdgeTelemetryMessage(device_id=window.device_id, temperature=value, humidity=50, status="normal", telemetry_type=kind,
        timestamp=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(microseconds=window.start_utc_us))
    encoded = canonical_bytes(original.model_dump(mode="json"))
    row = InputRecord(ledger_epoch=window.ledger_epoch, device_id=window.device_id, ingress_sequence=1,
        ingress_utc_us=window.start_utc_us+1, canonical_input=encoded, input_hash=hashlib.sha256(encoded).hexdigest())
    body = build_capsule(contract=framer.contract, window=window, records=[] if empty else [row], gateway_id=framer.profile.gateway_id,
        signing_key_id=framer.profile.signing_key_id, created_at_utc_us=created or window.end_utc_us,
        previous_digest=previous, **scope_options)
    encoded = sign_artifact(body, framer.private_key)
    frames = split_artifact(encoded, framer.private_key)
    return framer.decode_evidence(frames)


async def outage_check(repository, framer, check):
    class LocalIntake(FogUDP):
        async def _authorize(self):
            self.authorized.add("127.0.0.1")
            await asyncio.Event().wait()

    with tempfile.TemporaryDirectory(prefix="n6-live-spool-") as directory:
        store = FogEvidenceStore(Path(directory)/"fog.sqlite3", framer)
        runtime = LocalIntake(framer, store, repository, "")
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setblocking(False)
        try:
            await runtime.start(port=19006)
            print("N6_DB_OUTAGE_READY", flush=True)
            deadline = time.monotonic()+60
            while await asyncio.to_thread(repository.healthcheck):
                if time.monotonic() > deadline:
                    raise TimeoutError("host did not stop the isolated PostgreSQL service")
                await asyncio.sleep(.2)
            now = time.time_ns()//1000
            artifact = fixture_artifact(framer, now//10000000-1)
            for frame in reversed(artifact.frames):
                client.sendto(frame, ("127.0.0.1", 19006))
            deadline = time.monotonic()+15
            while not (await asyncio.to_thread(store.status))["pending_evidence"]:
                if time.monotonic() > deadline:
                    raise TimeoutError("UDP work was not durably spooled during outage")
                await asyncio.sleep(.05)
            check("real UDP evidence durably spooled while PostgreSQL is stopped", True)
            check("Fog intake remains locally live during DB outage", runtime.status()["live"])
            try:
                await asyncio.wait_for(asyncio.get_running_loop().sock_recv(client, 1200), .2)
                raise AssertionError("unexpected UDP application reply")
            except asyncio.TimeoutError:
                check("UDP intake sends no application reply", True)
            print("N6_DB_OUTAGE_SPOOLED", flush=True)
            deadline = time.monotonic()+60
            while (await asyncio.to_thread(store.status))["pending_evidence"]:
                if time.monotonic() > deadline:
                    raise TimeoutError("host did not restore PostgreSQL / spool did not drain")
                await asyncio.sleep(.2)
            check("database restoration drains evidence without sender feedback", True)
            for frame in artifact.frames:
                client.sendto(frame, ("127.0.0.1", 19006))
            await asyncio.sleep(.4)
            with repository._connect() as connection:
                check("live duplicate does not duplicate capsule or publication",
                    connection.execute("SELECT COUNT(*) FROM coverage_capsules WHERE scope_id=%s", (artifact.identity,)).fetchone()[0] == 1
                    and connection.execute("SELECT revision FROM coverage_publications WHERE scope_id=%s", (artifact.identity,)).fetchone()[0] == 1)
        finally:
            client.close()
            await runtime.close()
            store.close()


def main():
    import psycopg
    from psycopg import sql
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--migrations", type=Path)
    source.add_argument("--migration-bundle", help="base64 JSON of local migration file contents, for read-only containers")
    parser.add_argument("--wait-for-outage", action="store_true", help="host harness stops/starts ONLY the research PostgreSQL container")
    args = parser.parse_args()
    # Invoked only inside the isolated project by the host operator/CI harness.
    if os.getenv("COVERAGE_PROJECT_NAME") != "software-data-diode-coverage":
        raise RuntimeError("N6 checks require the isolated local coverage project")
    schema = "n6_check_"+uuid4().hex
    base = PostgresRepository(os.environ["DATABASE_URL"])
    with base._connect() as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))

    class ScopedRepository(PostgresRepository):
        def _connect(self):
            connection = super()._connect()
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            return connection

    repository = ScopedRepository(base.database_url)
    migrations = ({file.name: file.read_text() for file in args.migrations.glob("*.sql")} if args.migrations else
                  json.loads(base64.b64decode(args.migration_bundle, validate=True)))
    results = []
    def check(name, truth):
        if not truth:
            raise AssertionError(name)
        results.append({"check": name, "passed": True})

    try:
        with repository._connect() as connection:
            for _ in range(2):
                for name in sorted(migrations):
                    connection.execute(migrations[name], prepare=False)
        check("all additive migrations applied twice", repository.coverage_ready())
        contract = load_contract(os.environ["COVERAGE_CONTRACT_PATH"])
        key = Ed25519PrivateKey.generate()
        profile = TrustProfile(gateway_id="n6-test-gateway", signing_key_id="n6-test-key", ledger_epoch="n6-test-"+uuid4().hex,
            contract_hash=contract_hash(contract), public_key_sha256=hashlib.sha256(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest())
        framer = ResearchFramer(profile, key.public_key(), contract, private_key=key)
        now = time.time_ns()//1000
        index = now//10000000-4
        verifier = FogEvidenceVerifier(framer)
        a = fixture_artifact(framer, index)
        def persist(artifact):
            record = verifier.verify(artifact.encoded, received_us=now, frames=artifact.frames)
            return repository.save_coverage_evidence(artifact.encoded, record, artifact.frames, .001)

        with tempfile.TemporaryDirectory(prefix="n6-spool-") as directory:
            path = Path(directory)/"fog.sqlite3"
            store = FogEvidenceStore(path, framer, now_us=lambda: now)
            try:
                check("evidence committed to durable Fog spool", store.accept(a))
                with repository._connect() as connection:
                    connection.execute("""CREATE FUNCTION fail_fact() RETURNS trigger LANGUAGE plpgsql AS
                        $$ BEGIN RAISE EXCEPTION 'N6 injected fact failure'; END $$;
                        CREATE TRIGGER fail_fact BEFORE INSERT ON coverage_facts FOR EACH ROW EXECUTE FUNCTION fail_fact();""")
                try:
                    store.publish_one(repository)
                    raise AssertionError("transaction fault not injected")
                except psycopg.Error:
                    pass
                with repository._connect() as connection:
                    counts = [connection.execute("SELECT COUNT(*) FROM "+table).fetchone()[0]
                              for table in ("coverage_epochs", "coverage_heads", "coverage_capsules", "coverage_publications")]
                    check("failed fact transaction rolls back identity/replay/publication", counts == [0, 0, 0, 0])
                    connection.execute("DROP TRIGGER fail_fact ON coverage_facts; DROP FUNCTION fail_fact()")
                check("failed DB commit leaves durable pending evidence", store.status()["pending_evidence"] == 1)
                store.close()
                store = FogEvidenceStore(path, framer, now_us=lambda: now)
                check("restart recovers pending evidence", store.publish_one(repository) == "ACCEPTED")
                check("duplicate delivery does not repeat acceptance", persist(a) == "DUPLICATE")
                document = json.loads(a.encoded)
                document["signature"] = "A"*88
                from dataclasses import replace
                from shared.coverage.capsules import EvidenceError
                invalid = canonical_bytes(document)
                try:
                    store.accept(replace(a, encoded=invalid))
                    raise AssertionError("invalid signature accepted")
                except EvidenceError:
                    store.record_outcome("INVALID_SIGNATURE", invalid, {"claimed_scope": a.identity})
                check("invalid signature outcome committed independently", store.publish_one(repository) == "OUTCOME_COMMITTED")
                with repository._connect() as connection:
                    check("unrelated invalid injection cannot overwrite valid evidence", connection.execute(
                        "SELECT verification->>'status' FROM coverage_capsules WHERE scope_id=%s", (a.identity,)).fetchone() == ("VALID",))
                store.record_outcome("REASSEMBLY_EXPIRED", details={"received_parts": 1, "expected_parts": len(a.frames)})
                check("reassembly expiry persisted in PostgreSQL", store.publish_one(repository) == "OUTCOME_COMMITTED")
                # Simulate DB commit followed by a crash before spool completion.
                b = fixture_artifact(framer, index+1, previous=artifact_digest(a.encoded), created=now)
                check("second scope admitted", store.accept(b))
                check("DB committed before lost spool completion", persist(b) == "ACCEPTED")
                store.close()
                store = FogEvidenceStore(path, framer, now_us=lambda: now)
                check("lost completion recovery is idempotent", store.publish_one(repository) == "DUPLICATE")
            finally:
                store.close()

        fork = fixture_artifact(framer, index, value=15)
        with repository._connect() as connection:
            connection.execute("""INSERT INTO coverage_rule_verdicts VALUES (%s,%s,%s,%s,'n6-test-rule','TRUE',
                'VALID','[]'::jsonb,'[]'::jsonb,'rccd-fog-verifier-v1')""",
                (profile.gateway_id, profile.ledger_epoch, profile.contract_hash, index))
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(persist, [fork]*4))
        check("concurrent valid fork quarantined exactly once", sorted(outcomes) == ["CONFLICT", "DUPLICATE", "DUPLICATE", "DUPLICATE"])
        with repository._connect() as connection:
            status = connection.execute("SELECT verification->>'status' FROM coverage_capsules WHERE scope_id=%s", (a.identity,)).fetchall()
            check("both valid bodies are quarantined", status == [("CONFLICT",), ("CONFLICT",)])
            check("no usable facts from conflicted scope", connection.execute("SELECT COUNT(*) FROM usable_coverage_facts WHERE scope_id=%s", (a.identity,)).fetchone()[0] == 0)
            check("previously stored decisions reassessed on conflict", connection.execute("SELECT verdict,verification_status FROM coverage_rule_verdicts").fetchone() == ("UNKNOWN", "CONFLICT"))
            check("later independent facts survive predecessor conflict", connection.execute("SELECT COUNT(*) FROM usable_coverage_facts WHERE scope_id=%s", (b.identity,)).fetchone()[0] > 0)
            check("signed parts retained exactly", connection.execute("SELECT COUNT(*) FROM coverage_parts WHERE artifact_digest=%s", (artifact_digest(a.encoded),)).fetchone()[0] == len(a.frames))
            connection.execute("CREATE TABLE consumed(scope TEXT, revision BIGINT, PRIMARY KEY(scope,revision))")
            revision = connection.execute("SELECT revision FROM coverage_publications WHERE scope_id=%s", (a.identity,)).fetchone()[0]
        def broken_consumer(cursor, scope, revision):
            cursor.execute("INSERT INTO consumed VALUES (%s,%s)", (scope, revision))
            raise RuntimeError("N6 consumer crash")
        try:
            repository.consume_coverage_publication(a.identity, revision, broken_consumer)
        except RuntimeError:
            pass
        def consumer(cursor, scope, revision):
            cursor.execute("INSERT INTO consumed VALUES (%s,%s)", (scope, revision))
            cursor.execute("""INSERT INTO alerts (alert_id,timestamp,source_devices,alert_type,severity,evidence,description)
                VALUES (%s,NOW(),%s,'N6_TEST_CONSUMER','INFO','[]'::jsonb,'Synthetic publication side-effect test')""",
                (uuid5(NAMESPACE_URL, scope+":"+str(revision)), ["edge-device-01"]))
        check("publication recovers after consumer transaction rollback", repository.consume_coverage_publication(a.identity, revision, consumer))
        check("duplicate publication does not duplicate consumer effects", not repository.consume_coverage_publication(a.identity, revision, consumer))
        with repository._connect() as connection:
            check("duplicate processing creates exactly one synthetic alert", connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1)
        gap = fixture_artifact(framer, index+2, previous="f"*64, created=now)
        check("independent later window with missing predecessor accepted", persist(gap) == "ACCEPTED")
        with repository._connect() as connection:
            check("gap stored separately from scope validity", connection.execute("SELECT verification->>'continuity_status',verification->>'status' FROM coverage_capsules WHERE scope_id=%s", (gap.identity,)).fetchone() == ("GAP", "VALID"))
        from shared.coverage.models import CoverageLimitation
        stale = fixture_artifact(framer, index-100, created=now, closure_reason="RECOVERY", limitations=(CoverageLimitation.INTERRUPTED,))
        try:
            persist(stale)
            raise AssertionError("durable window floor reset")
        except ValueError as exc:
            check("new repository connection preserves durable window floor", "STALE_DURABLE" in str(exc))
        if args.wait_for_outage:
            asyncio.run(outage_check(repository, framer, check))
        inspection = repository.coverage_evidence(5)
        check("bounded evidence inspection exposes typed assurance and quarantine",
            bool(inspection) and all(item["verification"]["assurance_level"] == "AUTHENTICATED_SUMMARY" for item in inspection)
            and any(item["quarantined"] for item in inspection))
        repository.retire_coverage_epoch(profile.gateway_id, profile.ledger_epoch)
        try:
            persist(gap)
            raise AssertionError("retired epoch accepted")
        except ValueError as exc:
            check("durable epoch retirement blocks even duplicates after restart", "RETIRED" in str(exc))
        print(json.dumps({"phase": "N6", "schema": schema, "checks": results, "synthetic_keys": "ephemeral in-memory only",
                          "timestamp_us": time.time_ns()//1000, "existing_rows_modified": False}, indent=2))
    finally:
        # Only this freshly created schema can be removed; existing data/volumes
        # and credentials are never dropped, rotated or recreated.
        with base._connect() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


if __name__ == "__main__":
    main()
