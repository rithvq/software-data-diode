"""Idempotent N11-only trust provisioning; no main credentials are mounted."""
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from shared.edge.demo import require_demo
from shared.security.crypto import canonical_bytes

from .contracts import contract_hash, load_contract
from .ledger import ObservationLedger
from .transport import TrustProfile


def initialize():
    project = require_demo()
    directories = (Path("/state/coverage-trust"), Path("/state/n9-key"),
                   Path("/state/coverage-ledger"), Path("/logs"))
    # Only this short bootstrap has CHOWN/SETUID/SETGID; runtime stays 10001.
    if os.getuid() == 0:
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            os.chown(directory, 10001, 10001)
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    trust, private, ledger_dir, _ = directories
    contract = load_contract(os.environ["COVERAGE_CONTRACT_PATH"])
    marker = trust/"n11.json"
    identity = {"project": project, "contract_hash": contract_hash(contract)}
    targets = (private/"private.pem", trust/"public.pem", trust/"profile.json")
    if marker.exists():
        if json.loads(marker.read_bytes()) != identity or not all(p.is_file() for p in targets):
            raise ValueError("N11 trust identity differs or is incomplete; operator review required")
        # Validate persisted identity without opening a writer or closing windows.
        import sqlite3
        path = ledger_dir/"observations.sqlite3"
        with sqlite3.connect(path.as_uri()+"?mode=ro", uri=True) as db:
            metadata = dict(db.execute("SELECT key,value FROM metadata"))
        profile = TrustProfile.model_validate_json(targets[2].read_bytes())
        anchor = json.loads(Path(str(path)+".anchor.json").read_bytes())
        if (metadata["epoch"] != profile.ledger_epoch or metadata["contract_hash"] != identity["contract_hash"]
                or metadata["store_id"] != anchor["store_id"]):
            raise ValueError("N11 durable identity mismatch")
        return
    if any(p.exists() for p in (*targets, ledger_dir/"observations.sqlite3")):
        raise ValueError("refusing partial initialization; never replace keys or reset epochs")
    key = Ed25519PrivateKey.generate()
    ledger = ObservationLedger(ledger_dir/"observations.sqlite3", contract, create=True)
    try:
        public = key.public_key()
        profile = TrustProfile(gateway_id="coverage-gateway", signing_key_id="coverage-key",
            ledger_epoch=ledger.epoch, contract_hash=contract_hash(contract),
            public_key_sha256=hashlib.sha256(public.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest())
        values = (key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
                  public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
                  canonical_bytes(profile.model_dump(mode="json")))
        for path, value in (*zip(targets, values), (marker, canonical_bytes(identity))):
            with path.open("xb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            path.chmod(0o600 if path == targets[0] else 0o644)
    finally:
        ledger.close()


if __name__ == "__main__":
    initialize()
    print("N11 research trust preserved/provisioned; no baseline credentials mounted")
