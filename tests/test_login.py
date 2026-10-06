import sqlite3
import pytest
from app import create_app
from app.models.db import init_db

EMAIL = "u@test.com"
PW = "Str0ng!Password#2026"


def make_app(tmp_path, **extra):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"), **extra})
    with app.app_context():
        init_db()
    return app


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def user(client):
    client.post("/register", data={"email": EMAIL, "password": PW})


def login(client, email=EMAIL, password=PW):
    return client.post("/login", data={"email": email, "password": password})


def test_login_success_opens_dashboard(client, user):
    r = login(client)
    assert r.status_code == 302
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert EMAIL.encode() in page.data


def test_dashboard_requires_login(client):
    r = client.get("/dashboard")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


# T06 : même réponse pour mauvais mot de passe et email inconnu
def test_wrong_password_and_unknown_email_look_the_same(client, user):
    r1 = login(client, password="Wrong!Password#1")
    r2 = login(client, email="nobody@test.com")
    assert r1.status_code == r2.status_code == 200
    assert b"Identifiants invalides" in r1.data
    assert b"Identifiants invalides" in r2.data


# T10 : attributs du cookie
def test_cookie_is_httponly_and_samesite(client, user):
    r = login(client)
    cookie = " ".join(r.headers.getlist("Set-Cookie"))
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_cookie_has_secure_flag_when_enabled(tmp_path):
    app = make_app(tmp_path, SESSION_COOKIE_SECURE=True)
    c = app.test_client()
    c.post("/register", data={"email": EMAIL, "password": PW})
    r = login(c)
    assert "Secure" in " ".join(r.headers.getlist("Set-Cookie"))


# T11 : rejeu du cookie après déconnexion
def test_cookie_replay_after_logout_fails(client, user):
    login(client)
    assert client.get("/dashboard").status_code == 200
    old_cookie = client.get_cookie("session").value

    client.post("/logout")
    client.set_cookie("session", old_cookie)   # l'attaquant rejoue l'ancien cookie

    r = client.get("/dashboard")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


# T12 : fixation de session
def test_session_is_reset_at_login(client, user):
    with client.session_transaction() as s:
        s["donnee_attaquant"] = "x"            # session posée avant connexion
    login(client)
    with client.session_transaction() as s:
        assert "donnee_attaquant" not in s
        assert "sid" in s


def test_expired_session_is_rejected(app, client, user):
    login(client)
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00+00:00'")
    conn.commit()
    conn.close()
    r = client.get("/dashboard")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_logout_requires_post(client, user):
    login(client)
    assert client.get("/logout").status_code == 405


def test_logout_deletes_server_session(app, client, user):
    login(client)
    client.post("/logout")
    conn = sqlite3.connect(app.config["DATABASE"])
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0