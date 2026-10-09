import pytest
from app import create_app
from app.models.db import init_db
from tests.helpers import db_exec, events, make_client


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False})
    with app.app_context():
        init_db()
    return app


def test_user_can_create_and_read_own_document(app):
    c = make_client(app, "a@test.com")
    c.post("/documents/new", data={"content": "secret A"})
    r = c.get("/documents/1")
    assert r.status_code == 200
    assert b"secret A" in r.data


def test_document_is_encrypted_in_database(app):
    c = make_client(app, "a@test.com")
    c.post("/documents/new", data={"content": "secret A"})
    blob = db_exec(app, "SELECT ciphertext FROM encrypted_data")[0][0]
    assert b"secret A" not in blob


# T08 : IDOR
def test_user_cannot_read_other_users_document(app):
    a = make_client(app, "a@test.com")
    a.post("/documents/new", data={"content": "secret A"})
    b = make_client(app, "b@test.com")
    r = b.get("/documents/1")
    assert r.status_code == 404
    assert b"secret A" not in r.data
    assert "ACCESS_DENIED" in events(app)


def test_documents_list_only_shows_own(app):
    a = make_client(app, "a@test.com")
    a.post("/documents/new", data={"content": "secret A"})
    b = make_client(app, "b@test.com")
    r = b.get("/documents/")
    assert b"Document 1" not in r.data


def test_documents_require_login(app):
    assert app.test_client().get("/documents/1").status_code == 302