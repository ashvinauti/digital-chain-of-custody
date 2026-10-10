"""Ed25519 signing for audit entries, anchors and certificates.

The private key lives in a file outside the database (SIGNING_KEY_PATH), so
someone who can write to the database but cannot read the key cannot forge
a valid entry, even if they recompute every hash in the chain.
"""

import hashlib
import os
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class Signer:
    def __init__(self, private_key):
        self._private = private_key
        self.public_key = private_key.public_key()
        raw = self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(raw).hexdigest()[:16]

    @classmethod
    def load_or_create(cls, path, create=True):
        if not os.path.exists(path):
            if not create:
                raise RuntimeError(f"signing key {path} not found")
            _create_key_file(path)
        with open(path, "rb") as fh:
            return cls(serialization.load_pem_private_key(fh.read(), password=None))

    def sign(self, data: bytes) -> str:
        return self._private.sign(data).hex()

    def verify(self, signature_hex: str, data: bytes) -> bool:
        return verify_with(self.public_key, signature_hex, data)

    def public_pem(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()


def verify_with(public_key: Ed25519PublicKey, signature_hex: str, data: bytes) -> bool:
    try:
        public_key.verify(bytes.fromhex(signature_hex or ""), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def _create_key_file(path):
    """Write a new key atomically. If two processes race, the first link
    wins and the other simply loads that key."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        os.chmod(tmp, 0o600)
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass
        except (AttributeError, OSError):
            # Filesystems without hard links: fall back to an exclusive create.
            try:
                with open(path, "xb") as fh:
                    fh.write(pem)
                os.chmod(path, 0o600)
            except FileExistsError:
                pass
    finally:
        os.remove(tmp)
