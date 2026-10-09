from cryptography.fernet import Fernet
from flask import current_app


def _fernet():
    return Fernet(current_app.config["DATA_KEY"])


def encrypt(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt(token: bytes) -> bytes:
    return _fernet().decrypt(token)