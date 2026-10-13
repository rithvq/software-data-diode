"""Local provisioning only. Hash every resolved field, including defaults."""
import hashlib
from pathlib import Path

from shared.http import strict_json
from shared.security.crypto import canonical_bytes

from .models import RuleContract


MAX_CONTRACT_BYTES = 65536


def parse_contract(body: bytes | str) -> RuleContract:
    encoded = body.encode("utf-8") if isinstance(body, str) else body
    if len(encoded) > MAX_CONTRACT_BYTES:
        raise ValueError("contract exceeds 65536 bytes")
    try:
        return RuleContract.model_validate(strict_json(encoded))
    except RecursionError as exc:
        raise ValueError("contract structure is too deep") from exc


def load_contract(path: str | Path) -> RuleContract:
    with Path(path).open("rb") as handle:
        return parse_contract(handle.read(MAX_CONTRACT_BYTES + 1))


def contract_bytes(contract: RuleContract) -> bytes:
    return canonical_bytes(contract.model_dump(mode="json"))


def contract_hash(contract: RuleContract) -> str:
    return hashlib.sha256(contract_bytes(contract)).hexdigest()
