import pytest

from app import create_app
from app.account.routes import _ref
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


def second_device(app, email="a@test.com"):
    d = app.test_client()
    d.post("/login", data={"email": email, "password": PW})
    return d


def sids(app, email):
    return [r[0] for r in db_exec(
        app, "SELECT s.id FROM sessions s JOIN users u ON u.id = s.user_id "
             "WHERE u.email = ? ORDER BY s.created_at", (email,))]


def test_sessions_page_requires_login(app):
    r = app.test_client().get("/profile/sessions")
    assert r.status_code == 302


def test_sessions_page_lists_devices(app):
    a = make_client(app, "a@test.com")
    second_device(app)
    r = a.get("/profile/sessions")
    assert r.status_code == 200
    assert b"Cet appareil" in r.data
    assert b"Autre" in r.data


def test_full_session_id_is_never_displayed(app):
    a = make_client(app, "a@test.com")
    r = a.get("/profile/sessions")
    for sid in sids(app, "a@test.com"):
        assert sid.encode() not in r.data


def test_revoke_other_session(app):
    a = make_client(app, "a@test.com")
    b = second_device(app)
    first, second = sids(app, "a@test.com")
    a.post(f"/profile/sessions/{_ref(second)}/revoke")
    assert b.get("/dashboard").status_code == 302
    assert a.get("/dashboard").status_code == 200
    assert "SESSION_REVOKED" in events(app)


def test_revoke_current_session_logs_out(app):
    a = make_client(app, "a@test.com")
    current = sids(app, "a@test.com")[0]
    r = a.post(f"/profile/sessions/{_ref(current)}/revoke")
    assert r.status_code == 302
    assert a.get("/dashboard").status_code == 302


def test_cannot_revoke_another_users_session(app):
    a = make_client(app, "a@test.com")
    c = make_client(app, "c@test.com")
    other = sids(app, "c@test.com")[0]
    r = a.post(f"/profile/sessions/{_ref(other)}/revoke")
    assert r.status_code == 404
    assert c.get("/dashboard").status_code == 200


def test_unknown_reference_gives_404(app):
    a = make_client(app, "a@test.com")
    assert a.post("/profile/sessions/0123456789abcdef/revoke").status_code == 404


def test_revoke_all_others_keeps_current(app):
    a = make_client(app, "a@test.com")
    b = second_device(app)
    c = second_device(app)
    a.post("/profile/sessions/revoke-others")
    assert a.get("/dashboard").status_code == 200
    assert b.get("/dashboard").status_code == 302
    assert c.get("/dashboard").status_code == 302
    assert len(sids(app, "a@test.com")) == 1
    assert "SESSIONS_REVOKED_OTHERS" in events(app)