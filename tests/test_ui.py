import pytest

from app import create_app
from app.models.db import init_db
from tests.helpers import make_client


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False})
    with app.app_context():
        init_db()
    return app


def test_anonymous_nav_shows_login_and_register(app):
    r = app.test_client().get("/login")
    assert b"Inscription" in r.data
    assert "Se déconnecter".encode() not in r.data
    assert b"Administration" not in r.data


def test_user_nav_has_no_admin_links(app):
    c = make_client(app, "a@test.com")
    r = c.get("/dashboard")
    assert "Se déconnecter".encode() in r.data
    assert b"Administration" not in r.data
    assert "Journaux".encode() not in r.data


def test_admin_nav_shows_admin_links(app):
    c = make_client(app, "admin@test.com", admin=True)
    r = c.get("/dashboard")
    assert b"Administration" in r.data
    assert "Journaux".encode() in r.data


def test_no_inline_style_for_csp(app):
    c = make_client(app, "a@test.com")
    for url in ("/login", "/register", "/dashboard", "/profile/"):
        html = c.get(url).get_data(as_text=True)
        assert 'style="' not in html
        assert "<style" not in html
        assert "<script" not in html


def test_stylesheet_is_served(app):
    r = app.test_client().get("/static/style.css")
    assert r.status_code == 200
    assert b"--primary" in r.data


def test_404_page_is_generic(app):
    c = make_client(app, "a@test.com")
    r = c.get("/documents/999")
    assert r.status_code == 404
    assert b"Page introuvable" in r.data
    assert b"Traceback" not in r.data


def test_403_page_is_generic(app):
    c = make_client(app, "a@test.com")
    r = c.get("/admin/logs")
    assert r.status_code == 403
    assert "Accès refusé".encode() in r.data