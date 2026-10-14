"""Versioned authenticated datagrams and bounded, receive-only reassembly."""
import hashlib
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, NAMESPACE_URL, uuid5

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import Field

from shared.http import strict_json
from shared.models import SecureTelemetryEnvelope
from shared.security.crypto import canonical_bytes, compute_payload_hash, verify_envelope_signature
from .capsules import EvidenceError, verify_artifact
from .contracts import load_contract
from .models import Digest, FrozenModel, Identifier
from .parts import MAX_PARTS, assemble_parts, verify_part

HEADER = struct.Struct("!4s16s32sHHI4s64s")
assert HEADER.size == 128
PART_DOMAIN = b"RCCD-BINARY-PART-V1\x00"


class TransportConfig(FrozenModel):
    datagram_bytes: int = Field(default=1200, strict=True, ge=512, le=1200)
    state_bytes: int = Field(default=8192, strict=True, ge=1024, le=8192)
    state_interval_seconds: int = Field(default=10, strict=True, ge=10, le=60)
    queue_frames: int = Field(default=256, strict=True, ge=1, le=1024)
    partial_artifacts: int = Field(default=32, strict=True, ge=1, le=128)
    partial_bytes: int = Field(default=1024*1024, strict=True, ge=32768, le=4*1024*1024)
    assembly_timeout_seconds: int = Field(default=5, strict=True, ge=1, le=30)
    replay_width: int = Field(default=128, strict=True, ge=8, le=256)
    replay_records: int = Field(default=1024, strict=True, ge=32, le=4096)
    replay_bytes: int = Field(default=16*1024*1024, strict=True, ge=128*1024, le=32*1024*1024)
    freshness_seconds: int = Field(default=300, strict=True, ge=10, le=600)

    @classmethod
    def load(cls, path):
        encoded = Path(path).read_bytes()
        if len(encoded) > 65536:
            raise ValueError("transport configuration too large")
        return cls.model_validate(strict_json(encoded))


class TrustProfile(FrozenModel):
    protocol: str = "rccd-udp-v1"
    gateway_id: Identifier
    signing_key_id: Identifier
    ledger_epoch: Identifier
    contract_hash: Digest
    public_key_sha256: Digest


@dataclass(frozen=True)
class ReceivedArtifact:
    kind: str
    identity: str
    device: str
    sequence: int
    stamp_us: int
    encoded: bytes


class ResearchFramer:
    def __init__(self, profile, public_key, contract, *, config=None, private_key=None):
        self.profile, self.public_key, self.contract = profile, public_key, contract
        self.config, self.private_key = config or TransportConfig(), private_key
        from .contracts import contract_hash
        fingerprint = hashlib.sha256(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()
        if (profile.protocol != "rccd-udp-v1" or profile.public_key_sha256 != fingerprint
                or profile.contract_hash != contract_hash(contract)):
            raise ValueError("unprovisioned UDP signer/contract/profile")
        if private_key and private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != public_key.public_bytes(Encoding.Raw, PublicFormat.Raw):
            raise ValueError("wrong local signing key")
        self.context = canonical_bytes(profile.model_dump(mode="json"))
        self.tag = hashlib.sha256(self.context).digest()[:4]
        self.keys = {(profile.gateway_id, profile.signing_key_id): public_key}
        self.contracts = {profile.contract_hash: contract}

    @property
    def state_wire_bound(self):
        chunk = self.config.datagram_bytes-HEADER.size
        return ((self.config.state_bytes+chunk-1)//chunk)*(self.config.datagram_bytes+28)

    @property
    def state_storage_bound(self):
        from .budget import pack_frames
        return len(pack_frames([b"x"*self.config.datagram_bytes]*((self.config.state_bytes+self.config.datagram_bytes-129)//(self.config.datagram_bytes-128))))

    def frames(self, encoded, identity, magic):
        if self.private_key is None or magic not in {b"RCR1", b"RCS1"}:
            raise ValueError("local encoder requires its provisioned key")
        limit = self.config.state_bytes if magic == b"RCS1" else 32768
        if not 1 <= len(encoded) <= limit:
            raise EvidenceError("RESEARCH_ARTIFACT_BOUND")
        chunk = self.config.datagram_bytes-128
        count = (len(encoded)+chunk-1)//chunk
        if count > MAX_PARTS:
            raise EvidenceError("RESEARCH_PART_COUNT")
        digest, identifier = hashlib.sha256(encoded).digest(), UUID(identity).bytes
        result = []
        for index in range(count):
            payload = encoded[index*chunk:(index+1)*chunk]
            unsigned = HEADER.pack(magic, identifier, digest, index, count, len(encoded), self.tag, b"\0"*64)[:64]
            signature = self.private_key.sign(PART_DOMAIN+self.context+unsigned+payload)
            result.append(unsigned+signature+payload)
        return tuple(result)

    def raw_frames(self, encoded):
        envelope = SecureTelemetryEnvelope.model_validate(strict_json(encoded))
        return self.frames(encoded, str(envelope.message_id), b"RCR1")

    def inspect_part(self, datagram):
        if not 128 < len(datagram) <= self.config.datagram_bytes:
            raise EvidenceError("RESEARCH_DATAGRAM_BOUND")
        magic, identity, digest, index, count, total, tag, signature = HEADER.unpack(datagram[:128])
        limit = self.config.state_bytes if magic == b"RCS1" else 32768
        if magic not in {b"RCR1", b"RCS1"} or tag != self.tag or not 0 <= index < count <= MAX_PARTS or not 1 <= total <= limit:
            raise EvidenceError("INVALID_RESEARCH_PART_SCOPE")
        try:
            self.public_key.verify(signature, PART_DOMAIN+self.context+datagram[:64]+datagram[128:])
        except Exception as exc:
            raise EvidenceError("INVALID_RESEARCH_PART_SIGNATURE") from exc
        return (magic.decode(), str(UUID(bytes=identity)), digest.hex(), count, total), index, datagram[128:]

    def decode_binary(self, frames):
        chunks, metadata = {}, None
        for frame in frames:
            scope, index, chunk = self.inspect_part(frame)
            if metadata is not None and scope != metadata:
                raise EvidenceError("MIXED_RESEARCH_PARTS")
            metadata = scope
            if index in chunks and chunks[index] != chunk:
                raise EvidenceError("RESEARCH_PART_FORK")
            chunks[index] = chunk
        if metadata is None or len(chunks) != metadata[3]:
            raise EvidenceError("INCOMPLETE_RESEARCH_ARTIFACT")
        encoded = b"".join(chunks[index] for index in range(metadata[3]))
        if len(encoded) != metadata[4] or hashlib.sha256(encoded).hexdigest() != metadata[2]:
            raise EvidenceError("RESEARCH_BODY_DIGEST_MISMATCH")
        from .windows import utc_microseconds
        if metadata[0] == "RCR1":
            envelope = SecureTelemetryEnvelope.model_validate(strict_json(encoded))
            if (canonical_bytes(envelope.model_dump(mode="json")) != encoded or str(envelope.message_id) != metadata[1]
                    or not verify_envelope_signature(envelope, self.public_key)
                    or compute_payload_hash(envelope.payload) != envelope.payload_hash
                    or envelope.device_id not in {d.device_id for d in self.contract.devices}):
                raise EvidenceError("INVALID_RESEARCH_RAW")
            return ReceivedArtifact("RAW", metadata[1], envelope.device_id, envelope.sequence_number,
                                    utc_microseconds(envelope.created_at), encoded)
        body = strict_json(encoded)
        expected = {"protocol", "kind", "profile", "sequence", "timestamp_us", "metrics"}
        if (set(body) != expected or body["protocol"] != "rccd-state-v1" or body["kind"] != "EDGE_STATE"
                or body["profile"] != self.profile.model_dump(mode="json") or type(body["sequence"]) is not int
                or not 1 <= body["sequence"] <= 2**63-1 or type(body["timestamp_us"]) is not int
                or not isinstance(body["metrics"], dict) or canonical_bytes(body) != encoded
                or metadata[1] != self.state_identity(body["sequence"])):
            raise EvidenceError("INVALID_RESEARCH_STATE")
        return ReceivedArtifact("STATE", metadata[1], self.profile.gateway_id, body["sequence"], body["timestamp_us"], encoded)

    def state_identity(self, sequence):
        return str(uuid5(NAMESPACE_URL, self.context.decode()+":state:"+str(sequence)))

    def decode_evidence(self, frames):
        encoded = assemble_parts(frames, self.keys, self.contracts, max_datagram_bytes=self.config.datagram_bytes)
        body = verify_artifact(encoded, self.keys, self.contracts).body
        if body.artifact_kind != "RCC" or body.ledger_epoch != self.profile.ledger_epoch:
            raise EvidenceError("UNAPPROVED_RESEARCH_EPOCH")
        return ReceivedArtifact("EVIDENCE", body.capsule_id, body.device_id, body.window_index, body.created_at_utc_us, encoded)


class PartAssembler:
    def __init__(self, framer, *, monotonic=time.monotonic):
        self.framer, self.clock, self.pending = framer, monotonic, {}
        self.expired = 0

    @property
    def bytes(self):
        return sum(sum(len(frame) for frame in entry[1].values()) for entry in self.pending.values())

    def expire(self):
        now = self.clock()
        for key, (started, _) in list(self.pending.items()):
            if now-started >= self.framer.config.assembly_timeout_seconds:
                del self.pending[key]
                self.expired += 1

    def add(self, frame):
        self.expire()
        if len(frame) > self.framer.config.datagram_bytes:
            raise EvidenceError("OVERSIZED_DATAGRAM")
        binary = frame[:4] in {b"RCR1", b"RCS1"}
        if binary:
            scope, index, _ = self.framer.inspect_part(frame)
        else:
            body, _ = verify_part(frame, self.framer.keys, max_datagram_bytes=self.framer.config.datagram_bytes)
            scope = ("RCC", body.artifact_id, body.artifact_digest, body.part_count, body.total_bytes)
            index = body.part_index
        key = scope
        if key not in self.pending:
            if len(self.pending) >= self.framer.config.partial_artifacts:
                raise EvidenceError("PARTIAL_ARTIFACT_CAPACITY")
            self.pending[key] = (self.clock(), {})
        parts = self.pending[key][1]
        if index in parts:
            if parts[index] != frame:
                del self.pending[key]
                raise EvidenceError("RESEARCH_PART_FORK")
            return None
        if self.bytes+len(frame) > self.framer.config.partial_bytes:
            raise EvidenceError("PARTIAL_BYTE_CAPACITY")
        parts[index] = frame
        if len(parts) != scope[3]:
            return None
        del self.pending[key]
        return self.framer.decode_binary(tuple(parts.values())) if binary else self.framer.decode_evidence(tuple(parts.values()))


class SeededFaultAdapter:
    """Bounded test-only network faults; extra injected copies are not scheduled bytes."""
    def __init__(self, seed, *, drop=0, duplicate=0, max_delay_steps=0, max_pending=256):
        import random
        if not 0 <= drop <= 1 or not 0 <= duplicate <= 1 or not 0 <= max_delay_steps <= 100 or not 1 <= max_pending <= 1024:
            raise ValueError("invalid bounded test fault settings")
        self.rng, self.drop, self.duplicate = random.Random(seed), drop, duplicate
        self.delay, self.limit, self.pending, self.step = max_delay_steps, max_pending, [], 0

    def feed(self, frame):
        self.step += 1
        if self.rng.random() >= self.drop:
            for _ in range(1+int(self.rng.random() < self.duplicate)):
                if len(self.pending) < self.limit:
                    self.pending.append((self.step+self.rng.randint(0, self.delay), frame))
        ready = [frame for due, frame in self.pending if due <= self.step]
        self.pending = [(due, frame) for due, frame in self.pending if due > self.step]
        self.rng.shuffle(ready)
        return ready


def load_framer(profile_path, key, contract_path, config_path):
    encoded = Path(profile_path).read_bytes()
    if len(encoded) > 8192:
        raise ValueError("trust profile too large")
    profile = TrustProfile.model_validate(strict_json(encoded))
    return ResearchFramer(profile, key, load_contract(contract_path), config=TransportConfig.load(config_path))
