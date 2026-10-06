import sqlite3
import pytest
from app import create_app
from app.extensions import limiter
from app.models.db import init_db

EMAIL = "u@test.com"
PW = "Str0ng!Password#2026"
BAD = "Wrong!Password#1"


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


def login(client, password=PW, email=EMAIL):
    return client.post("/login", data={"email": email, "password": password})


def events(app):
    c = sqlite3.connect(app.config["DATABASE"])
    return [r[0] for r in c.execute(
        "SELECT event_type FROM security_logs ORDER BY id")]


def user_row(app):
    c = sqlite3.connect(app.config["DATABASE"])
    return c.execute(
        "SELECT failed_attempts, locked_until FROM users WHERE email = ?",
        (EMAIL,)).fetchone()


# T04 : blocage après 5 échecs
def test_account_locked_after_5_failures(app, client):
    for _ in range(5):
        login(client, BAD)
    assert "ACCOUNT_LOCKED" in events(app)
    assert user_row(app)[1] is not None


def test_not_locked_after_4_failures(app, client):
    for _ in range(4):
        login(client, BAD)
    assert "ACCOUNT_LOCKED" not in events(app)


def test_correct_password_refused_while_locked(app, client):
    for _ in range(5):
        login(client, BAD)
    r = login(client, PW)
    assert r.status_code == 200
    assert client.get("/dashboard").status_code == 302


def test_locked_message_same_as_wrong_password(app, client):
    r_wrong = login(client, BAD)
    for _ in range(5):
        login(client, BAD)
    r_locked = login(client, PW)
    assert b"Identifiants invalides" in r_wrong.data
    assert b"Identifiants invalides" in r_locked.data
    assert b"bloqu" not in r_locked.data.lower()


def test_lock_expires(app, client):
    for _ in range(5):
        login(client, BAD)
    c = sqlite3.connect(app.config["DATABASE"])
    c.execute("UPDATE users SET locked_until = '2000-01-01T00:00:00+00:00'")
    c.commit()
    c.close()
    assert login(client, PW).status_code == 302


def test_success_resets_counter(app, client):
    for _ in range(3):
        login(client, BAD)
    login(client, PW)
    assert user_row(app)[0] == 0


def test_unknown_email_never_locks_anything(app, client):
    for _ in range(10):
        login(client, BAD, email="nobody@test.com")
    assert "ACCOUNT_LOCKED" not in events(app)


def test_rate_limit_blocks_after_10_requests(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "rl.db"),
                      "RATELIMIT_ENABLED": True})
    with app.app_context():
        init_db()
    limiter.reset()
    c = app.test_client()
    codes = [login(c, BAD, email=f"x{i}@test.com").status_code
             for i in range(12)]
    assert 429 in codes