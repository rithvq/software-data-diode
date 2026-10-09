from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from shared.security.crypto import load_private_key, load_public_key


def main(secrets_dir: Path | None = None) -> None:
    secrets_dir = secrets_dir or PROJECT_ROOT / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)

    private_path = secrets_dir / "edge_private_key.pem"
    public_path = secrets_dir / "edge_public_key.pem"
    if private_path.exists():
        private_key = load_private_key(private_path)
    else:
        if public_path.exists():
            raise ValueError("Public key exists without private key; refusing implicit key rotation")
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with private_path.open("xb") as stream:
            stream.write(private_bytes)
        private_path.chmod(0o600)
    public_key = private_key.public_key()
    if public_path.exists():
        if load_public_key(public_path).public_bytes_raw() != public_key.public_bytes_raw():
            raise ValueError("Existing signing keys do not match")
    else:
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with public_path.open("xb") as stream:
            stream.write(public_bytes)

    print("Signing keys ready; existing signing identity preserved")
    print("Mount the private key only into edge-gateway (and the isolated security-test profile).")
    print("Mount only the public key into fog-receiver.")


if __name__ == "__main__":
    main()
