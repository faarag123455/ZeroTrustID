import re

import pytest

from app import create_app
from app.models.db import init_db
from tests.helpers import PW, events, make_client


def build(tmp_path, **extra):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False, **extra})
    with app.app_context():
        init_db()
    return app


@pytest.fixture
def app(tmp_path):
    return build(tmp_path)


@pytest.fixture
def csrf_app(tmp_path):
    return build(tmp_path, WTF_CSRF_ENABLED=True)


def csrf_token(client, url):
    html = client.get(url).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


# ---- En-têtes ----
def test_security_headers_present(app):
    h = app.test_client().get("/").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in h
    assert h["Referrer-Policy"] == "no-referrer"


def test_csp_is_strict(app):
    csp = app.test_client().get("/").headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp


def test_hsts_absent_over_http(app):
    r = app.test_client().get("/")
    assert "Strict-Transport-Security" not in r.headers


def test_hsts_present_over_https(app):
    r = app.test_client().get("/", base_url="https://localhost")
    assert "max-age" in r.headers["Strict-Transport-Security"]


def test_dynamic_pages_are_not_cached(app):
    c = make_client(app, "a@test.com")
    assert "no-store" in c.get("/dashboard").headers["Cache-Control"]


# ---- T13 : XSS ----
def test_script_in_document_is_escaped(app):
    c = make_client(app, "a@test.com")
    c.post("/documents/new", data={"content": "<script>alert(1)</script>"})
    r = c.get("/documents/1")
    assert b"<script>alert(1)</script>" not in r.data
    assert b"&lt;script&gt;" in r.data


# ---- T14 : CSRF ----
def test_post_without_token_is_rejected(csrf_app):
    c = csrf_app.test_client()
    assert c.post("/login", data={"email": "a@test.com",
                                  "password": PW}).status_code == 400
    assert c.post("/register", data={"email": "a@test.com",
                                     "password": PW}).status_code == 400
    assert c.post("/logout").status_code == 400
    assert "CSRF_FAILED" in events(csrf_app)


def test_post_with_wrong_token_is_rejected(csrf_app):
    c = csrf_app.test_client()
    c.get("/login")
    r = c.post("/login", data={"email": "a@test.com", "password": PW,
                               "csrf_token": "faux-jeton"})
    assert r.status_code == 400


def test_post_with_valid_token_is_accepted(csrf_app):
    c = csrf_app.test_client()
    tok = csrf_token(c, "/register")
    r = c.post("/register", data={"email": "a@test.com", "password": PW,
                                  "csrf_token": tok})
    assert r.status_code == 302


def test_login_with_valid_token_reaches_the_view(csrf_app):
    c = csrf_app.test_client()
    tok = csrf_token(c, "/login")
    r = c.post("/login", data={"email": "x@test.com", "password": "Bad!Pass#1",
                               "csrf_token": tok})
    assert r.status_code == 200
    assert b"Identifiants invalides" in r.data


def test_all_forms_contain_a_token(csrf_app):
    c = csrf_app.test_client()
    for url in ("/login", "/register"):
        assert b'name="csrf_token"' in c.get(url).data