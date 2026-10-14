"""Provision only project-scoped local volumes; never generate or rotate keys."""
import hashlib
import os
import sqlite3
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from shared.security import load_public_key
from shared.security.crypto import canonical_bytes
from shared.http import strict_json
from shared.security.runtime_state import initialize as initialize_logs
from .contracts import load_contract, contract_hash
from .runtime_state import initialize
from .transport import TrustProfile
from .ledger import PROJECT_NAME


def provision(directory, trust_directory, contract_path, public_key_path, project):
    if project != PROJECT_NAME:
        raise ValueError("isolated research project required")
    directory = Path(directory).absolute()
    path = directory/"observations.sqlite3"
    contract = load_contract(contract_path)
    if path.exists():
        anchor = Path(str(path)+".anchor.json")
        if any(p.is_symlink() for p in (directory, path, anchor)):
            raise ValueError("research state must not be symlinked")
        identity = strict_json(anchor.read_bytes())
        with sqlite3.connect(path.as_uri()+"?mode=ro", uri=True) as db:
            metadata = dict(db.execute("SELECT key,value FROM metadata"))
        if metadata["store_id"] != identity["store_id"] or metadata["contract_hash"] != contract_hash(contract):
            raise ValueError("existing research ledger identity/contract differs")
        state = {"epoch": metadata["epoch"]}
    else:
        state = initialize(directory, Path(contract_path), project)
    trust = Path(trust_directory)
    if trust.is_symlink():
        raise ValueError("trust directory cannot be symlinked")
    trust.mkdir(parents=True, exist_ok=True)
    key = load_public_key(public_key_path)
    profile = TrustProfile(gateway_id="coverage-gateway", signing_key_id="coverage-key",
        ledger_epoch=state["epoch"], contract_hash=contract_hash(contract),
        public_key_sha256=hashlib.sha256(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest())
    target, encoded = trust/"profile.json", canonical_bytes(profile.model_dump(mode="json"))
    if target.exists():
        if target.read_bytes() != encoded:
            raise ValueError("existing trust profile differs; operator migration required")
    else:
        with target.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    return profile


if __name__ == "__main__":
    initialize_logs(Path("/logs"))
    profile = provision("/state/coverage-ledger", "/state/coverage-trust",
        os.environ["COVERAGE_CONTRACT_PATH"], "/run/secrets/edge_public_key.pem", os.environ["COVERAGE_PROJECT_NAME"])
    print("Isolated research state preserved/provisioned; epoch="+profile.ledger_epoch)
