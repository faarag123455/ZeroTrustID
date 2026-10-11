import pyotp
import pytest

from app import create_app
from app.models.db import init_db
from tests.helpers import PW, db_exec, events, make_client

NEW = "N3w!Password#2027x"


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False})
    with app.app_context():
        init_db()
    return app


def change(c, current=PW, new=NEW, confirm=None):
    return c.post("/profile/password", data={
        "current_password": current,
        "new_password": new,
        "confirm_password": new if confirm is None else confirm})


def pw_hash(app, email="a@test.com"):
    return db_exec(app, "SELECT password_hash FROM users WHERE email = ?",
                   (email,))[0][0]


def enable_mfa(c):
    c.get("/mfa/setup")
    with c.session_transaction() as s:
        secret = s["mfa_pending_secret"]
    r = c.post("/mfa/setup", data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200
    assert b"Codes de secours" in r.data
    return secret


# ---- Page profil ----
def test_profile_requires_login(app):
    r = app.test_client().get("/profile/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_profile_shows_email_but_no_hash(app):
    c = make_client(app, "a@test.com")
    r = c.get("/profile/")
    assert r.status_code == 200
    assert b"a@test.com" in r.data
    assert b"scrypt" not in r.data


def test_change_password_requires_login(app):
    r = app.test_client().post("/profile/password", data={
        "current_password": PW, "new_password": NEW,
        "confirm_password": NEW})
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


# ---- Changement de mot de passe ----
def test_change_password_success(app):
    c = make_client(app, "a@test.com")
    old_hash = pw_hash(app)
    assert change(c).status_code == 302
    assert pw_hash(app) != old_hash
    assert NEW not in pw_hash(app)

    fresh = app.test_client()
    assert fresh.post("/login", data={"email": "a@test.com",
                                      "password": NEW}).status_code == 302
    assert fresh.get("/dashboard").status_code == 200

    old = app.test_client()
    r = old.post("/login", data={"email": "a@test.com", "password": PW})
    assert r.status_code == 200          # ancien mot de passe refusé


def test_wrong_current_password_is_refused(app):
    c = make_client(app, "a@test.com")
    old_hash = pw_hash(app)
    change(c, current="Wrong!Password#1")
    assert pw_hash(app) == old_hash
    assert "PASSWORD_CHANGE_FAILED" in events(app)


def test_weak_new_password_is_refused(app):
    c = make_client(app, "a@test.com")
    old_hash = pw_hash(app)
    r = change(c, new="abc")
    assert pw_hash(app) == old_hash
    assert "Au moins 12 caractères".encode() in r.data


def test_confirmation_mismatch_is_refused(app):
    c = make_client(app, "a@test.com")
    old_hash = pw_hash(app)
    change(c, confirm="Autre!Password#2027")
    assert pw_hash(app) == old_hash


def test_same_password_is_refused(app):
    c = make_client(app, "a@test.com")
    old_hash = pw_hash(app)
    change(c, new=PW)
    assert pw_hash(app) == old_hash


def test_change_is_logged_without_password(app):
    c = make_client(app, "a@test.com")
    change(c)
    assert "PASSWORD_CHANGED" in events(app)
    dump = str(db_exec(app, "SELECT * FROM security_logs"))
    assert PW not in dump and NEW not in dump


# ---- Révocation des sessions ----
def test_other_sessions_are_revoked(app):
    a = make_client(app, "a@test.com")
    b = app.test_client()                       # 2e appareil
    b.post("/login", data={"email": "a@test.com", "password": PW})
    assert b.get("/dashboard").status_code == 200

    change(a)
    assert b.get("/dashboard").status_code == 302    # déconnecté
    assert a.get("/dashboard").status_code == 200    # appareil courant gardé


def test_session_id_is_renewed(app):
    c = make_client(app, "a@test.com")
    before = db_exec(app, "SELECT id FROM sessions")[0][0]
    change(c)
    rows = db_exec(app, "SELECT id FROM sessions")
    assert len(rows) == 1
    assert rows[0][0] != before


# ---- Force brute sur le mot de passe actuel ----
def test_bruteforce_on_current_password_locks_account(app):
    c = make_client(app, "a@test.com")
    old_hash = pw_hash(app)
    for _ in range(5):
        change(c, current="Wrong!Password#1")
    assert "ACCOUNT_LOCKED" in events(app)
    change(c)                                   # le bon mot de passe aussi
    assert pw_hash(app) == old_hash


# ---- MFA ----
def test_mfa_setup_blocked_when_already_enabled(app):
    c = make_client(app, "a@test.com")
    enable_mfa(c)
    r = c.get("/mfa/setup")
    assert r.status_code == 302
    assert "/profile" in r.headers["Location"]

def test_disable_mfa_needs_password(app):
    c = make_client(app, "a@test.com")
    enable_mfa(c)

    c.post("/profile/mfa/disable", data={"password": "Wrong!Password#1"})
    assert db_exec(app, "SELECT mfa_secret FROM users")[0][0] is not None
    assert "MFA_DISABLE_FAILED" in events(app)

    c.post("/profile/mfa/disable", data={"password": PW})
    assert db_exec(app, "SELECT mfa_secret FROM users")[0][0] is None
    assert "MFA_DISABLED" in events(app)