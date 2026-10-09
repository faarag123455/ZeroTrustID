import base64
import io

import pyotp
import qrcode

from app.security.crypto import decrypt, encrypt

ISSUER = "ZeroTrustID"


def new_secret():
    return pyotp.random_base32()


def encrypt_secret(secret: str) -> bytes:
    return encrypt(secret.encode())


def _format_ok(code):
    return code.isdigit() and len(code) == 6


def verify_code(encrypted_secret: bytes, code: str) -> bool:
    code = (code or "").strip()
    if not _format_ok(code):
        return False
    secret = decrypt(encrypted_secret).decode()
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def verify_plain(secret: str, code: str) -> bool:
    code = (code or "").strip()
    if not _format_ok(code):
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def qr_data_uri(secret: str, email: str) -> str:
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()