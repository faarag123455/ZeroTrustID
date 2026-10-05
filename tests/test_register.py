import sqlite3
import pytest
from app import create_app
from app.models.db import init_db

STRONG = "Str0ng!Password#2026"


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
    })
    with app.app_context():
        init_db()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def get_user(app, email):
    conn = sqlite3.connect(app.config["DATABASE"])
    return conn.execute(
        "SELECT email, password_hash, role_id FROM users WHERE email = ?",
        (email,)).fetchone()


def test_register_page_loads(client):
    assert client.get("/register").status_code == 200


# T01 : mot de passe faible refusé
def test_weak_password_is_rejected(app, client):
    r = client.post("/register",
                    data={"email": "a@test.com", "password": "abc"},
                    follow_redirects=True)
    assert "Au moins 12 caractères".encode() in r.data
    assert get_user(app, "a@test.com") is None


# T02 : aucun mot de passe en clair, hachage salé
def test_password_is_hashed_not_plaintext(app, client):
    client.post("/register",
                data={"email": "b@test.com", "password": STRONG})
    user = get_user(app, "b@test.com")
    assert user is not None
    assert user[1] != STRONG
    assert STRONG not in user[1]
    assert user[1].startswith(("scrypt:", "pbkdf2:"))


def test_same_password_gives_different_hashes(app, client):
    client.post("/register", data={"email": "c@test.com", "password": STRONG})
    client.post("/register", data={"email": "d@test.com", "password": STRONG})
    assert get_user(app, "c@test.com")[1] != get_user(app, "d@test.com")[1]


def test_invalid_email_is_rejected(app, client):
    client.post("/register", data={"email": "pas-un-email", "password": STRONG})
    assert get_user(app, "pas-un-email") is None


def test_new_user_always_gets_user_role(app, client):
    client.post("/register",
                data={"email": "e@test.com", "password": STRONG,
                      "role_id": "2", "role": "admin"})
    assert get_user(app, "e@test.com")[2] == 1


def test_duplicate_email_gives_generic_message(app, client):
    client.post("/register", data={"email": "f@test.com", "password": STRONG})
    r = client.post("/register",
                    data={"email": "f@test.com", "password": STRONG},
                    follow_redirects=True)
    assert b"deja" not in r.data.lower()
    assert b"existe" not in r.data.lower()
    assert "Inscription impossible".encode() in r.data