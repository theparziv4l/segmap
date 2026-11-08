"""Credentials at rest: Fernet with key from SEGMAP_KEY or a generated 0600 key file."""
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet


def load_key(data_dir: Path) -> bytes:
    env = os.environ.get("SEGMAP_KEY")
    if env:
        return env.encode()
    path = data_dir / "secret.key"
    if not path.exists():
        data_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    if path.stat().st_mode & 0o077:
        raise RuntimeError(f"{path} must not be group/world accessible (chmod 600)")
    return path.read_bytes().strip()


class Vault:
    def __init__(self, key: bytes):
        self.f = Fernet(key)

    def seal(self, secret: dict) -> bytes:
        return self.f.encrypt(json.dumps(secret).encode())

    def open(self, blob: bytes) -> dict:
        return json.loads(self.f.decrypt(blob))
