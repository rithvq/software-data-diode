"""Initialize separate private/public volumes without rotating an existing key."""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.security.crypto import load_private_key, load_public_key


def initialize(private_path: Path, public_path: Path):
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    if private_path.exists():
        key = load_private_key(private_path)
    else:
        if public_path.exists():
            raise ValueError("public key exists without private key; refusing implicit key rotation")
        key = Ed25519PrivateKey.generate()
        with private_path.open("xb") as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        private_path.chmod(0o600)
    public = key.public_key()
    if public_path.exists():
        if load_public_key(public_path).public_bytes_raw() != public.public_bytes_raw():
            raise ValueError("existing key pair does not match")
    else:
        with public_path.open("xb") as stream:
            stream.write(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        public_path.chmod(0o644)
    print("Phase 2 key pair ready; existing signing identity preserved")


if __name__ == "__main__":
    initialize(Path("/private/edge_private.pem"), Path("/public/edge_public.pem"))
