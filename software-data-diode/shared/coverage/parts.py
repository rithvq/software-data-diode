"""Finite signed-part batches for future transport; no network/assembly daemon."""
import base64

from pydantic import Field
from typing import Literal

from cryptography.exceptions import InvalidSignature

from shared.http import strict_json
from shared.security.crypto import canonical_bytes

from .capsules import (CapsuleBody, EvidenceConflict, EvidenceError, MAX_ARTIFACT_BYTES,
                       Signature, artifact_digest, parse_artifact, verify_artifact)
from .models import Digest, FrozenModel, Identifier


MAX_PARTS = 96
CHUNK_BYTES = 384
PART_DOMAIN = b"RCCD-TRANSPORT-PART-SIGN-V1\x00"


class PartBody(FrozenModel):
    protocol_version: Literal["rccd-part-v1"] = "rccd-part-v1"
    artifact_kind: Literal["RCC_PART"] = "RCC_PART"
    gateway_id: Identifier
    signing_key_id: Identifier
    artifact_id: Digest
    artifact_digest: Digest
    part_index: int = Field(strict=True,ge=0,lt=MAX_PARTS)
    part_count: int = Field(strict=True,ge=1,le=MAX_PARTS)
    total_bytes: int = Field(strict=True,ge=1,le=MAX_ARTIFACT_BYTES)
    chunk: str = Field(strict=True,min_length=4,max_length=512)


class SignedPart(FrozenModel):
    body: PartBody
    signature: Signature


def _encode_part(body, key):
    signature = base64.b64encode(key.sign(PART_DOMAIN+canonical_bytes(body.model_dump(mode="json")))).decode("ascii")
    return canonical_bytes(SignedPart(body=body,signature=signature).model_dump(mode="json"))


def split_artifact(encoded, private_key, *, max_datagram_bytes=1200):
    if type(max_datagram_bytes) is not int or not 256 <= max_datagram_bytes <= 1200:
        raise EvidenceError("INVALID_DATAGRAM_LIMIT")
    artifact = parse_artifact(encoded)
    body = artifact.body
    identity = body.capsule_id if isinstance(body,CapsuleBody) else body.transition_id
    digest = artifact_digest(encoded)
    for chunk_size in range(CHUNK_BYTES,0,-16):
        count = (len(encoded)+chunk_size-1)//chunk_size
        if count > MAX_PARTS:
            break
        result = []
        for index in range(count):
            part = PartBody(gateway_id=body.gateway_id,signing_key_id=body.signing_key_id,
                artifact_id=identity,artifact_digest=digest,part_index=index,part_count=count,total_bytes=len(encoded),
                chunk=base64.b64encode(encoded[index*chunk_size:(index+1)*chunk_size]).decode("ascii"))
            result.append(_encode_part(part,private_key))
        if all(len(part) <= max_datagram_bytes for part in result):
            return tuple(result)
    raise EvidenceError("SIGNED_PARTS_DO_NOT_FIT_DATAGRAM_LIMIT")


def verify_part(encoded, public_keys, *, max_datagram_bytes=1200):
    if type(max_datagram_bytes) is not int or not 256 <= max_datagram_bytes <= 1200:
        raise EvidenceError("INVALID_DATAGRAM_LIMIT")
    if len(encoded) > max_datagram_bytes:
        raise EvidenceError("OVERSIZED_PART")
    try:
        part = SignedPart.model_validate(strict_json(encoded))
        if canonical_bytes(part.model_dump(mode="json")) != encoded:
            raise EvidenceError("NONCANONICAL_PART")
        key = public_keys.get((part.body.gateway_id,part.body.signing_key_id))
        if key is None:
            raise EvidenceError("UNPROVISIONED_SIGNER")
        signature = base64.b64decode(part.signature,validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != part.signature:
            raise ValueError("noncanonical signature")
        key.verify(signature,PART_DOMAIN+canonical_bytes(part.body.model_dump(mode="json")))
        chunk = base64.b64decode(part.body.chunk,validate=True)
        if (not 1 <= len(chunk) <= CHUNK_BYTES or base64.b64encode(chunk).decode("ascii") != part.body.chunk
                or part.body.part_index >= part.body.part_count):
            raise ValueError("invalid chunk/index")
        return part.body, chunk
    except (ValueError,RecursionError,InvalidSignature) as exc:
        raise EvidenceError("INVALID_SIGNED_PART") from exc


def assemble_parts(parts, public_keys, contracts, *, max_datagram_bytes=1200):
    by_index, metadata, total, seen = {}, None, 0, 0
    for encoded in parts:
        seen += 1
        if seen > MAX_PARTS:
            raise EvidenceError("PART_BATCH_LIMIT")
        body, chunk = verify_part(encoded,public_keys,max_datagram_bytes=max_datagram_bytes)
        current = (body.gateway_id,body.signing_key_id,body.artifact_id,body.artifact_digest,body.part_count,body.total_bytes)
        if metadata is None:
            metadata = current
        elif metadata != current:
            raise EvidenceConflict("MIXED_SIGNED_ARTIFACT_PARTS")
        if body.part_index in by_index:
            if by_index[body.part_index] != chunk:
                raise EvidenceConflict("SAME_PART_DIFFERENT_SIGNED_CONTENT")
            continue
        by_index[body.part_index] = chunk
        total += len(chunk)
        if total > MAX_ARTIFACT_BYTES or total > body.total_bytes:
            raise EvidenceError("REASSEMBLY_BYTE_LIMIT")
    if metadata is None or len(by_index) != metadata[4] or total != metadata[5]:
        raise EvidenceError("INCOMPLETE_ARTIFACT")
    encoded = b"".join(by_index[index] for index in range(metadata[4]))
    if artifact_digest(encoded) != metadata[3]:
        raise EvidenceError("WHOLE_ARTIFACT_DIGEST_MISMATCH")
    artifact = verify_artifact(encoded,public_keys,contracts)
    body = artifact.body
    identity = body.capsule_id if isinstance(body,CapsuleBody) else body.transition_id
    if (body.gateway_id,body.signing_key_id,identity) != metadata[:3]:
        raise EvidenceError("PART_ARTIFACT_IDENTITY_MISMATCH")
    return encoded
