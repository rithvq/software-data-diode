import base64
from datetime import datetime, timezone
import hashlib
import json

from cryptography.exceptions import InvalidSignature

from shared.security.crypto import canonical_bytes, sign_envelope
from .models import SecureEnvelope, SourceMessage


class Rejected(Exception):
    def __init__(self, reason, status=400):
        super().__init__(reason)
        self.reason, self.status = reason, status


def canonical(data) -> bytes:
    # Same sorted-key UTF-8 profile as the existing system, with nonfinite values forbidden.
    json.dumps(data, allow_nan=False)
    return canonical_bytes(data)


def parse_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("nonfinite JSON number")

    return json.loads(body, object_pairs_hook=pairs, parse_constant=invalid_constant)


def fingerprint(message):
    return hashlib.sha256(canonical(message.model_dump(mode="json"))).hexdigest()


def validate_payload(message, limit):
    payload = canonical(message.payload)
    if len(payload) > limit:
        raise Rejected("PAYLOAD_TOO_LARGE", 413)
    if message.payload_size != len(payload):
        raise Rejected("PAYLOAD_SIZE_MISMATCH", 422)
    return hashlib.sha256(payload).hexdigest()


def sign(message: SourceMessage, private_key) -> SecureEnvelope:
    document = message.model_dump(mode="json")
    document.update(schema_version="2.0", payload_hash=hashlib.sha256(canonical(message.payload)).hexdigest())
    document["signature"] = sign_envelope(document, private_key)
    return SecureEnvelope.model_validate(document)


def verify(message: SecureEnvelope, public_key, payload_limit=4096):
    payload_hash = validate_payload(message, payload_limit)
    if payload_hash != message.payload_hash:
        raise Rejected("HASH_MISMATCH")
    document = message.model_dump(mode="json")
    signature = document.pop("signature")
    try:
        public_key.verify(base64.b64decode(signature, validate=True), canonical(document))
    except (InvalidSignature, ValueError):
        raise Rejected("INVALID_SIGNATURE")


def freshness(message, window=120, future_skew=10, now=None):
    age = ((now or datetime.now(timezone.utc)) - message.created_at).total_seconds()
    if age > window or age < -future_skew:
        raise Rejected("EXPIRED_MESSAGE")
