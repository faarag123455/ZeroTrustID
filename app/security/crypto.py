import hashlib
import hmac

from cryptography.fernet import Fernet
from flask import current_app


def _fernet():
    return Fernet(current_app.config["DATA_KEY"])


def encrypt(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt(token: bytes) -> bytes:
    return _fernet().decrypt(token)


def sign(data: bytes) -> str:
    """HMAC-SHA256 en hexadécimal, avec la clé HMAC_KEY."""
    return hmac.new(current_app.config["HMAC_KEY"], data,
                    hashlib.sha256).hexdigest()


def verify(data: bytes, tag: str) -> bool:
    """Comparaison en temps constant (évite les attaques par chronométrage)."""
    return hmac.compare_digest(sign(data).encode(), (tag or "").encode())