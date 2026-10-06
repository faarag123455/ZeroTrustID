import sqlite3
import pytest
from app import create_app
from app.models.db import init_db

PW = "Str0ng!Password#2026"


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db")})
    with app.app_context():
        init_db()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def events(app):
    c = sqlite3.connect(app.config["DATABASE"])
    return [r[0] for r in c.execute(
        "SELECT event_type FROM security_logs ORDER BY id")]


def make_user(client, email):
    client.post("/register", data={"email": email, "password": PW})


def make_admin(app, email):
    c = sqlite3.connect(app.config["DATABASE"])
    c.execute("UPDATE users SET role_id = 2 WHERE email = ?", (email,))
    c.commit()
    c.close()


def login(client, email, password=PW):
    return client.post("/login", data={"email": email, "password": password})


def test_login_success_is_logged(app, client):
    make_user(client, "a@test.com")
    login(client, "a@test.com")
    assert "LOGIN_SUCCESS" in events(app)


def test_login_failed_is_logged(app, client):
    make_user(client, "a@test.com")
    login(client, "a@test.com", "Wrong!Password#1")
    assert "LOGIN_FAILED" in events(app)


def test_logout_is_logged(app, client):
    make_user(client, "a@test.com")
    login(client, "a@test.com")
    client.post("/logout")
    assert "LOGOUT" in events(app)


def test_password_never_appears_in_logs(app, client):
    make_user(client, "a@test.com")
    login(client, "a@test.com", "Wrong!Password#1")
    c = sqlite3.connect(app.config["DATABASE"])
    dump = str(c.execute("SELECT * FROM security_logs").fetchall())
    assert "Wrong!Password#1" not in dump
    assert PW not in dump


# T07 : un user simple ne peut pas lire les logs
def test_user_cannot_read_logs(app, client):
    make_user(client, "a@test.com")
    login(client, "a@test.com")
    assert client.get("/admin/logs").status_code == 403
    assert "ACCESS_DENIED" in events(app)


def test_anonymous_is_redirected_from_logs(client):
    r = client.get("/admin/logs")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_admin_can_read_logs(app, client):
    make_user(client, "admin@test.com")
    make_admin(app, "admin@test.com")
    login(client, "admin@test.com")
    r = client.get("/admin/logs")
    assert r.status_code == 200
    assert b"LOGIN_SUCCESS" in r.data


# T13 : XSS dans les logs
def test_script_in_log_is_escaped(app, client):
    make_user(client, "admin@test.com")
    make_admin(app, "admin@test.com")
    client.post("/login", data={"email": "<script>alert(1)</script>",
                                "password": "x"})
    login(client, "admin@test.com")
    r = client.get("/admin/logs")
    assert b"<script>alert(1)</script>" not in r.data
    assert b"&lt;script&gt;" in r.data


def test_log_injection_newlines_are_removed(app, client):
    client.post("/login", data={"email": "x\nLOGIN_SUCCESS fake",
                                "password": "x"})
    c = sqlite3.connect(app.config["DATABASE"])
    details = c.execute("SELECT details FROM security_logs").fetchone()[0]
    assert "\n" not in details

    