import base64
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from shared.models import SecureTelemetryEnvelope, TelemetryPayload


def canonical_json(data: Any) -> str:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(data: Any) -> bytes:
    return canonical_json(data).encode("utf-8")


def compute_payload_hash(payload: TelemetryPayload | dict[str, Any]) -> str:
    if isinstance(payload, TelemetryPayload):
        payload_data = payload.model_dump(mode="json")
    else:
        payload_data = payload
    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonical_bytes(payload_data))
    return digest.finalize().hex()


def build_signing_document(envelope: SecureTelemetryEnvelope | dict[str, Any]) -> dict[str, Any]:
    if isinstance(envelope, SecureTelemetryEnvelope):
        data = envelope.model_dump(mode="json")
    else:
        data = dict(envelope)
    data.pop("signature", None)
    return data


def sign_envelope(
    envelope_without_signature: SecureTelemetryEnvelope | dict[str, Any],
    private_key: Ed25519PrivateKey,
) -> str:
    signature = private_key.sign(canonical_bytes(build_signing_document(envelope_without_signature)))
    return base64.b64encode(signature).decode("ascii")


def verify_envelope_signature(
    envelope: SecureTelemetryEnvelope,
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        signature = base64.b64decode(envelope.signature.encode("ascii"), validate=True)
        public_key.verify(signature, canonical_bytes(build_signing_document(envelope)))
        return True
    except (InvalidSignature, ValueError):
        return False


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key_data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("private key must be an Ed25519 private key")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    key_data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(key_data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("public key must be an Ed25519 public key")
    return key
