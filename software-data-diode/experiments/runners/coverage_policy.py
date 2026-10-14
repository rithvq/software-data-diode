"""Test-harness adapters around deployed admission; never imported by services."""

import hashlib
import json
from dataclasses import asdict
from statistics import fmean

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from shared.coverage.admission import CoupledAdmission
from shared.coverage.budget import pack_frames
from shared.coverage.capsules import (
    CapsuleFact,
    artifact_digest,
    parse_artifact,
    sign_artifact,
)
from shared.coverage.contracts import contract_hash
from shared.coverage.service import ByteService
from shared.coverage.transport import ResearchFramer, TrustProfile
from shared.coverage.windows import utc_microseconds
from shared.security.crypto import canonical_bytes, compute_payload_hash
from shared.traffic.information import InformationEngine


class UnreservedService(ByteService):
    """Harness-only frame round robin without owned lane shares, still hard-paced."""

    def choose(self, now_us, heads, config):
        if now_us < self.next_us:
            return None
        cycle = now_us // (config.service_cycle_seconds * 1000000)
        if cycle != self.cycle:
            self.cycle = cycle
            self.spent = {lane: 0 for lane in config.quotas}
            self.owned = {lane: 0 for lane in config.quotas}
        lanes = tuple(config.quotas)
        for offset in range(len(lanes)):
            lane = lanes[(self.cursor + offset) % len(lanes)]
            if (
                lane in heads
                and sum(self.spent.values()) + heads[lane] <= config.cycle_bytes
            ):
                cost = heads[lane]
                self.spent[lane] += cost
                self.total_bytes += cost
                self.next_scaled = (
                    max(self.next_scaled, now_us * config.link_bytes_per_second)
                    + cost * 1000000
                )
                self.next_us = (
                    self.next_scaled + config.link_bytes_per_second - 1
                ) // config.link_bytes_per_second
                self.cursor = (lanes.index(lane) + 1) % len(lanes)
                return lane
        return None


def framer_for(ledger, key):
    profile = TrustProfile(
        gateway_id="coverage-gateway",
        signing_key_id="coverage-key",
        ledger_epoch=ledger.epoch,
        contract_hash=contract_hash(ledger.contract),
        public_key_sha256=hashlib.sha256(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).hexdigest(),
    )
    return ResearchFramer(profile, key.public_key(), ledger.contract, private_key=key)


class HarnessAdmission(CoupledAdmission):
    """N4 core + external N5 binary framing and explicit experimental raw provenance.

    Production refuses attaching the N5 framer to its fixed-summary mode. Both
    arms therefore use the N4 chunk/header interface here, with an external N5
    encoder whose exact 128-byte headers are charged. This is not a live gateway.
    """

    def __init__(self, ledger, key, arm, config, policy):
        self.arm = arm
        self.encoder = framer_for(ledger, key)
        mode = (
            "coupled"
            if arm
            in {"rccd", "no_semantics", "no_service", "no_repeats", "no_recovery"}
            else "fixed_summary_no_reservation"
        )
        super().__init__(
            ledger,
            "coverage-gateway",
            "coverage-key",
            key,
            config=config,
            policy=policy,
            mode=mode,
        )

    def _service(self):
        service = super()._service()
        return (
            UnreservedService(**asdict(service))
            if self.arm == "no_service"
            else service
        )

    def _envelope(self, item, sequence, created_at, message_id):
        envelope = super()._envelope(item, sequence, created_at, message_id)
        source = self._sources(item)[-1]
        attributes = {
            **envelope.payload.attributes,
            "_n10_epoch": source["epoch"],
            "_n10_seq": source["seq"],
            "_n10_ingress_us": source["ingress_us"],
            "_n10_original_timestamp": item.message.timestamp.isoformat(),
        }
        payload = envelope.payload.model_copy(update={"attributes": attributes})
        return envelope.model_copy(
            update={"payload": payload, "payload_hash": compute_payload_hash(payload)}
        )

    def _state_frames(self, metrics, timestamp_us):
        db = self.ledger.db
        row = db.execute(
            "SELECT value FROM n4_state WHERE key='n10_state_seq'"
        ).fetchone()
        seq = int(row[0]) + 1 if row else 1
        db.execute(
            "INSERT INTO n4_state VALUES ('n10_state_seq',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(seq),),
        )
        body = canonical_bytes(
            {
                "protocol": "rccd-state-v1",
                "kind": "EDGE_STATE",
                "profile": self.encoder.profile.model_dump(mode="json"),
                "sequence": seq,
                "timestamp_us": timestamp_us,
                "metrics": metrics,
            }
        )
        return body, self.encoder.frames(
            body, self.encoder.state_identity(seq), b"RCS1"
        )

    def _add_state(self, metrics, timestamp_us, kind="STATE"):
        body, frames = self._state_frames(metrics, timestamp_us)
        packed = pack_frames(frames)
        self.ledger.db.execute(
            "INSERT INTO n4_outbox VALUES (?,?,?, ?,?,0,?,0,'[]',?)",
            (
                artifact_digest(body),
                kind,
                "evidence",
                packed,
                hashlib.sha256(packed).hexdigest(),
                self.config.evidence_repeats,
                self._now(),
            ),
        )
        self._assert_bounds()

    def common_state(self):
        if self.arm == "always_unknown":
            return
        with self.ledger._mutex, self.ledger._transaction():
            self._add_state(
                {
                    "n10_local_state": {
                        "accepted": self.ledger.db.execute(
                            "SELECT COUNT(*) FROM observations"
                        ).fetchone()[0],
                        "queue": len(self.engine.queue),
                    }
                },
                utc_microseconds(self.ledger.clock.utc_now()),
            )

    def _stage_scope(self, key):
        if self.arm in {
            "rccd",
            "fixed_summary",
            "no_advance",
            "no_service",
            "no_repeats",
            "no_recovery",
            "no_semantics",
        }:
            super()._stage_scope(key)
            return
        window = self.ledger.db.execute(
            "SELECT * FROM windows WHERE epoch=? AND device=? AND idx=?", key
        ).fetchone()
        if window is None or window["obligation"] not in {"UNSIZED", "RESERVED"}:
            return
        if self.arm == "compact_summary":
            counts = self.ledger.db.execute(
                "SELECT * FROM facts WHERE epoch=? AND device=? AND idx=? ORDER BY condition",
                key,
            ).fetchall()
            summary = {
                "protocol": "n10-predicate-summary-v1",
                "epoch": key[0],
                "device": key[1],
                "window": key[2],
                "contract": self.ledger.digest,
                "n": window["accepted"],
                "first": window["first_seq"],
                "last": window["last_seq"],
                "limitations": json.loads(window["limitations"]),
                "facts": [
                    [r["condition"], r["matches"], r["misses"], r["unresolved"]]
                    for r in counts
                ],
            }
            self._add_state(
                {"n10_predicate_summary": summary},
                (key[2] + 1) * 10000000,
                kind="STATE",
            )
        if self.arm in {"fifo_gap", "heartbeat"}:
            barrier = {
                "protocol": "n10-ingress-barrier-v1",
                "ledger_epoch": key[0],
                "device_id": key[1],
                "contract_hash": self.ledger.digest,
                "window_index": key[2],
                "accepted_count": window["accepted"],
                "first_seq": window["first_seq"],
                "last_seq": window["last_seq"],
                "limitations": json.loads(window["limitations"]),
            }
            self._add_state({"n10_barrier": barrier}, (key[2] + 1) * 10000000)
        self.ledger.db.execute(
            "UPDATE windows SET obligation='LOCAL_ATTEMPTED',reserved_bytes=0 WHERE epoch=? AND device=? AND idx=?",
            key,
        )

    def corrupt_summary_means(self, original_seal):
        """Intentionally unsafe aggregate-mean-as-original-facts ablation, test only."""

        def seal(**kwargs):
            encoded = original_seal(**kwargs)
            body = parse_artifact(encoded).body
            records = self.ledger.db.execute(
                "SELECT body FROM observations WHERE epoch=? AND device=? AND idx=?",
                (body.ledger_epoch, body.device_id, body.window_index),
            ).fetchall()
            facts = []
            for fact in body.per_condition_facts:
                atom = next(
                    a
                    for a in self.ledger.contract.conditions
                    if a.condition_id == fact.condition_id
                )
                values = []
                for row in records:
                    message = json.loads(row[0])
                    value = (
                        message.get("measurements", {}).get(
                            atom.metric_path.split(".", 1)[1]
                        )
                        if atom.metric_path.startswith("measurements.")
                        else message.get(atom.metric_path)
                    )
                    if value is not None:
                        values.append(value)
                from shared.coverage.evaluation import COMPARISONS

                hits = (
                    len(values)
                    if values
                    and COMPARISONS[atom.inequality](fmean(values), atom.threshold)
                    else 0
                )
                facts.append(
                    CapsuleFact(
                        condition_id=fact.condition_id,
                        matching_count=hits,
                        nonmatching_count=len(values) - hits,
                        unresolved_count=body.accepted_observation_count - len(values),
                    )
                )
            damaged = body.model_copy(update={"per_condition_facts": tuple(facts)})
            # Keep accounting/journal storage bounded and make repeated bytes immutable.
            altered = sign_artifact(damaged, self.key)
            self.ledger.db.execute(
                "UPDATE sealed_capsules SET body=?,digest=? WHERE identity=?",
                (altered, artifact_digest(altered), body.capsule_id),
            )
            self.ledger.db.execute(
                "UPDATE capsule_heads SET digest=? WHERE device=? AND idx=?",
                (artifact_digest(altered), body.device_id, body.window_index),
            )
            return altered

        return seal

    def volatile_restart(self):
        """Modeled loss of unsent obligations; oracle originals remain in audit storage."""
        with self.ledger._mutex, self.ledger._transaction():
            self.ledger.db.execute("DELETE FROM n4_inflight")
            self.ledger.db.execute("DELETE FROM n4_outbox")
            self.ledger.db.execute(
                "UPDATE observations SET disposition='DROPPED_RAW' WHERE disposition IN ('SELECTED_RAW','REDUCED_RAW','PENDING_POLICY')"
            )
            self.ledger.db.execute(
                "UPDATE windows SET obligation='UNSUPPORTED',reserved_bytes=0 WHERE closed=0"
            )
            engine = InformationEngine(self.policy)
            from shared.coverage.policy_state import checkpoint

            self._set_state("engine", checkpoint(engine))
            self.engine = self._load_engine()

    def install_ablation(self):
        if self.arm == "no_semantics":
            self.sealer.seal = self.corrupt_summary_means(self.sealer.seal)
