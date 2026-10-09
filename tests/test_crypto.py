import pytest
from cryptography.fernet import InvalidToken

from app import create_app
from app.models.db import init_db
from app.security.crypto import decrypt, encrypt, sign, verify
from tests.helpers import db_exec, events, make_client


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False})
    with app.app_context():
        init_db()
    return app


def test_sign_and_verify_ok(app):
    with app.app_context():
        assert verify(b"message", sign(b"message"))


# T15 : altération d'une donnée signée
def test_altered_data_fails_hmac(app):
    with app.app_context():
        tag = sign(b"virement:100")
        assert not verify(b"virement:900", tag)


def test_altered_tag_fails(app):
    with app.app_context():
        tag = sign(b"message")
        bad = ("0" if tag[0] != "0" else "1") + tag[1:]
        assert not verify(b"message", bad)


def test_empty_tag_fails(app):
    with app.app_context():
        assert not verify(b"message", "")
        assert not verify(b"message", None)


def test_fernet_roundtrip(app):
    with app.app_context():
        token = encrypt(b"donnee sensible")
        assert b"donnee sensible" not in token
        assert decrypt(token) == b"donnee sensible"


def test_fernet_detects_tampering(app):
    with app.app_context():
        token = bytearray(encrypt(b"donnee sensible"))
        token[10] ^= 1
        with pytest.raises(InvalidToken):
            decrypt(bytes(token))


def test_document_stores_hmac(app):
    c = make_client(app, "a@test.com")
    c.post("/documents/new", data={"content": "secret A"})
    tag = db_exec(app, "SELECT hmac FROM encrypted_data")[0][0]
    assert len(tag) == 64          # SHA-256 en hexadécimal


def test_tampered_ciphertext_is_detected(app):
    c = make_client(app, "a@test.com")
    c.post("/documents/new", data={"content": "secret A"})
    with app.app_context():
        fake = encrypt(b"contenu falsifie")
    db_exec(app, "UPDATE encrypted_data SET ciphertext = ?", (fake,))
    r = c.get("/documents/1")
    assert r.status_code == 500
    assert b"falsifie" not in r.data
    assert "INTEGRITY_FAILED" in events(app)


def test_tampered_hmac_is_detected(app):
    c = make_client(app, "a@test.com")
    c.post("/documents/new", data={"content": "secret A"})
    db_exec(app, "UPDATE encrypted_data SET hmac = ?", ("0" * 64,))
    assert c.get("/documents/1").status_code == 500
    assert "INTEGRITY_FAILED" in events(app)


def test_document_moved_to_other_user_is_detected(app):
    a = make_client(app, "a@test.com")
    a.post("/documents/new", data={"content": "secret A"})
    b = make_client(app, "b@test.com")
    db_exec(app, "UPDATE encrypted_data SET user_id = 2")   # id de b
    assert b.get("/documents/1").status_code == 500
    assert "INTEGRITY_FAILED" in events(app)