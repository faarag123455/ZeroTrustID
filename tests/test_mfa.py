import sqlite3
import pyotp
import pytest
from app import create_app
from app.models.db import init_db

EMAIL = "m@test.com"
PW = "Str0ng!Password#2026"


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False})
    with app.app_context():
        init_db()
    return app


@pytest.fixture
def client(app):
    c = app.test_client()
    c.post("/register", data={"email": EMAIL, "password": PW})
    return c


def login(c, pw=PW):
    return c.post("/login", data={"email": EMAIL, "password": pw})


def enable_mfa(client):
    """Active la MFA via l'interface et retourne le secret."""
    login(client)
    client.get("/mfa/setup")
    with client.session_transaction() as s:
        secret = s["mfa_pending_secret"]
    r = client.post("/mfa/setup", data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 302
    client.post("/logout")
    return secret


def events(app):
    c = sqlite3.connect(app.config["DATABASE"])
    return [r[0] for r in c.execute(
        "SELECT event_type FROM security_logs ORDER BY id")]


def test_setup_page_shows_qr(client):
    login(client)
    r = client.get("/mfa/setup")
    assert r.status_code == 200
    assert b"data:image/png;base64" in r.data


def test_setup_requires_login(client):
    assert client.get("/mfa/setup").status_code == 302


def test_setup_with_wrong_code_does_not_enable(app, client):
    login(client)
    client.get("/mfa/setup")
    client.post("/mfa/setup", data={"code": "000000"})
    c = sqlite3.connect(app.config["DATABASE"])
    assert c.execute("SELECT mfa_secret FROM users").fetchone()[0] is None


def test_secret_is_encrypted_in_database(app, client):
    secret = enable_mfa(client)
    c = sqlite3.connect(app.config["DATABASE"])
    stored = c.execute("SELECT mfa_secret FROM users").fetchone()[0]
    assert stored is not None
    assert secret.encode() not in stored


def test_password_alone_is_not_enough_with_mfa(client):
    enable_mfa(client)
    r = login(client)
    assert r.status_code == 302
    assert "/login/otp" in r.headers["Location"]
    assert client.get("/dashboard").status_code == 302


def test_valid_otp_opens_dashboard(client):
    secret = enable_mfa(client)
    login(client)
    r = client.post("/login/otp", data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 302
    assert client.get("/dashboard").status_code == 200


def test_wrong_otp_is_refused_and_logged(app, client):
    enable_mfa(client)
    login(client)
    client.post("/login/otp", data={"code": "000000"})
    assert "MFA_FAILED" in events(app)
    assert client.get("/dashboard").status_code == 302


def test_otp_page_without_password_redirects(client):
    r = client.get("/login/otp")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_non_numeric_otp_is_refused(client):
    enable_mfa(client)
    login(client)
    client.post("/login/otp", data={"code": "abcdef"})
    assert client.get("/dashboard").status_code == 302


# T05 : force brute sur l'OTP (mot de passe connu de l'attaquant)
def test_otp_bruteforce_locks_account(app, client):
    secret = enable_mfa(client)
    for _ in range(5):
        login(client)
        client.post("/login/otp", data={"code": "000000"})
    assert "ACCOUNT_LOCKED" in events(app)
    login(client)
    client.post("/login/otp", data={"code": pyotp.TOTP(secret).now()})
    assert client.get("/dashboard").status_code == 302