from __future__ import annotations

import os
import base64
import hashlib

from cryptography.fernet import Fernet


def _kdf_scrypt(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key using scrypt and return urlsafe base64."""
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2 ** 14,
        r=8,
        p=1,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def encrypt_data(data: bytes, password: str) -> bytes:
    """Encrypt bytes with a password using a versioned envelope."""
    salt = os.urandom(16)
    f = Fernet(_kdf_scrypt(password, salt))
    token = f.encrypt(data)
    return b"v1." + base64.urlsafe_b64encode(salt) + b"." + token


def decrypt_data(token: bytes, password: str) -> bytes:
    """Decrypt bytes produced by :func:`encrypt_data`. Supports legacy format."""
    try:
        prefix, b64salt, inner = token.split(b".", 2)
        if prefix != b"v1":
            raise ValueError("Unsupported token format")
        salt = base64.urlsafe_b64decode(b64salt)
        f = Fernet(_kdf_scrypt(password, salt))
        return f.decrypt(inner)
    except Exception:
        legacy_key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        return Fernet(legacy_key).decrypt(token)
