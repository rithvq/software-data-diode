"""Create disposable N9 credentials in new project volumes, never user secrets."""
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from shared.coverage.contracts import load_contract, contract_hash
from shared.coverage.ledger import ObservationLedger
from shared.coverage.transport import TrustProfile
from shared.security.crypto import canonical_bytes
from .n9_support import test_project


def initialize():
    run = os.environ["N9_RUN_ID"]
    project = test_project(os.environ["N9_PROJECT_NAME"], run)
    trust, private = Path("/state/coverage-trust"), Path("/state/n9-key")
    marker = trust/"n9.json"
    identity = {"project": project, "run_id": run}
    targets = (private/"private.pem", trust/"public.pem", trust/"profile.json")
    if marker.exists():
        if json.loads(marker.read_bytes()) != identity or not all(p.is_file() for p in targets):
            raise ValueError("existing N9 provisioning differs or is incomplete")
        return
    if any(p.exists() for p in targets):
        raise ValueError("refusing to replace existing keys/profile")
    trust.mkdir(parents=True, exist_ok=True)
    private.mkdir(parents=True, exist_ok=True)
    contract = load_contract(os.environ["COVERAGE_CONTRACT_PATH"])
    key = Ed25519PrivateKey.generate()
    ledger = ObservationLedger("/state/coverage-ledger/observations.sqlite3", contract, create=True)
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
    print("Disposable N9 project initialized; no user credentials mounted")
