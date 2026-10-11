import re

import pyotp
import pytest

from app import create_app
from app.models.db import init_db
from tests.helpers import PW, db_exec, events, make_client


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False})
    with app.app_context():
        init_db()
    return app


def enable_mfa(c):
    c.get("/mfa/setup")
    with c.session_transaction() as s:
        secret = s["mfa_pending_secret"]
    r = c.post("/mfa/setup", data={"code": pyotp.TOTP(secret).now()})
    codes = re.findall(r"[A-Z2-9]{4}-[A-Z2-9]{4}", r.get_data(as_text=True))
    return secret, codes


def start_otp_login(app, email="a@test.com"):
    d = app.test_client()
    d.post("/login", data={"email": email, "password": PW})
    return d


def test_activation_shows_eight_codes(app):
    c = make_client(app, "a@test.com")
    _, codes = enable_mfa(c)
    assert len(codes) == 8 and len(set(codes)) == 8


def test_codes_are_stored_hashed(app):
    c = make_client(app, "a@test.com")
    _, codes = enable_mfa(c)
    dump = str(db_exec(app, "SELECT code_hash FROM backup_codes"))
    for code in codes:
        assert code not in dump and code.replace("-", "") not in dump


def test_backup_code_logs_in(app):
    c = make_client(app, "a@test.com")
    _, codes = enable_mfa(c)
    d = start_otp_login(app)
    r = d.post("/login/otp", data={"code": codes[0]})
    assert r.status_code == 302
    assert d.get("/dashboard").status_code == 200


def test_backup_code_is_single_use(app):
    c = make_client(app, "a@test.com")
    _, codes = enable_mfa(c)
    start_otp_login(app).post("/login/otp", data={"code": codes[0]})
    d2 = start_otp_login(app)
    d2.post("/login/otp", data={"code": codes[0]})
    assert d2.get("/dashboard").status_code == 302


def test_lowercase_and_no_dash_accepted(app):
    c = make_client(app, "a@test.com")
    _, codes = enable_mfa(c)
    d = start_otp_login(app)
    d.post("/login/otp", data={"code": codes[1].replace("-", "").lower()})
    assert d.get("/dashboard").status_code == 200


def test_wrong_backup_code_counts_as_failure(app):
    c = make_client(app, "a@test.com")
    enable_mfa(c)
    d = start_otp_login(app)
    d.post("/login/otp", data={"code": "AAAA-AAAA"})
    assert "MFA_FAILED" in events(app)
    assert d.get("/dashboard").status_code == 302


def test_bruteforce_backup_codes_locks_account(app):
    c = make_client(app, "a@test.com")
    _, codes = enable_mfa(c)
    for _ in range(5):
        start_otp_login(app).post("/login/otp", data={"code": "AAAA-AAAA"})
    assert "ACCOUNT_LOCKED" in events(app)
    d = start_otp_login(app)
    d.post("/login/otp", data={"code": codes[0]})
    assert d.get("/dashboard").status_code == 302


def test_regenerate_needs_password_and_invalidates_old(app):
    c = make_client(app, "a@test.com")
    _, old = enable_mfa(c)
    c.post("/profile/mfa/backup-codes", data={"password": "Wrong!Password#1"})
    assert "BACKUP_CODES_FAILED" in events(app)
    r = c.post("/profile/mfa/backup-codes", data={"password": PW})
    new = re.findall(r"[A-Z2-9]{4}-[A-Z2-9]{4}", r.get_data(as_text=True))
    assert len(new) == 8 and not set(new) & set(old)
    d = start_otp_login(app)
    d.post("/login/otp", data={"code": old[0]})
    assert d.get("/dashboard").status_code == 302


def test_disabling_mfa_deletes_codes(app):
    c = make_client(app, "a@test.com")
    enable_mfa(c)
    c.post("/profile/mfa/disable", data={"password": PW})
    assert db_exec(app, "SELECT COUNT(*) FROM backup_codes")[0][0] == 0