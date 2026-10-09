import pytest
from app import create_app
from app.models.db import init_db
from tests.helpers import PW, db_exec, events, make_client, user_id


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False})
    with app.app_context():
        init_db()
    return app


# T07 : escalade verticale
def test_user_cannot_access_admin_pages(app):
    c = make_client(app, "a@test.com")
    for url in ("/admin/users", "/admin/logs"):
        assert c.get(url).status_code == 403
    assert "ACCESS_DENIED" in events(app)


def test_admin_can_list_users(app):
    c = make_client(app, "admin@test.com", admin=True)
    r = c.get("/admin/users")
    assert r.status_code == 200
    assert b"admin@test.com" in r.data


# T09 : rôle imposé par le client
def test_role_field_in_request_is_ignored_at_register(app):
    c = app.test_client()
    c.post("/register", data={"email": "x@test.com", "password": PW,
                              "role": "admin", "role_id": "2"})
    assert db_exec(app, "SELECT role_id FROM users")[0][0] == 1


def test_user_cannot_change_roles(app):
    a = make_client(app, "a@test.com")
    uid = user_id(app, "a@test.com")
    r = a.post(f"/admin/users/{uid}/role", data={"role": "admin"})
    assert r.status_code == 403
    assert db_exec(app, "SELECT role_id FROM users")[0][0] == 1


def test_admin_can_change_another_role_and_it_is_logged(app):
    admin = make_client(app, "admin@test.com", admin=True)
    make_client(app, "b@test.com")
    bid = user_id(app, "b@test.com")
    admin.post(f"/admin/users/{bid}/role", data={"role": "admin"})
    assert db_exec(app, "SELECT role_id FROM users WHERE id = ?",
                   (bid,))[0][0] == 2
    assert "ROLE_CHANGED" in events(app)


def test_admin_cannot_change_own_role(app):
    admin = make_client(app, "admin@test.com", admin=True)
    aid = user_id(app, "admin@test.com")
    admin.post(f"/admin/users/{aid}/role", data={"role": "user"})
    assert db_exec(app, "SELECT role_id FROM users WHERE id = ?",
                   (aid,))[0][0] == 2


def test_invalid_role_value_is_rejected(app):
    admin = make_client(app, "admin@test.com", admin=True)
    make_client(app, "b@test.com")
    bid = user_id(app, "b@test.com")
    r = admin.post(f"/admin/users/{bid}/role", data={"role": "superadmin"})
    assert r.status_code == 400


def test_admin_cannot_delete_self(app):
    admin = make_client(app, "admin@test.com", admin=True)
    aid = user_id(app, "admin@test.com")
    admin.post(f"/admin/users/{aid}/delete")
    assert db_exec(app, "SELECT COUNT(*) FROM users WHERE id = ?",
                   (aid,))[0][0] == 1


def test_admin_delete_user_keeps_logs(app):
    admin = make_client(app, "admin@test.com", admin=True)
    make_client(app, "b@test.com")
    bid = user_id(app, "b@test.com")
    admin.post(f"/admin/users/{bid}/delete")
    assert db_exec(app, "SELECT COUNT(*) FROM users WHERE id = ?",
                   (bid,))[0][0] == 0
    assert db_exec(app, "SELECT COUNT(*) FROM security_logs "
                        "WHERE user_id = ?", (bid,))[0][0] > 0


def test_permission_revoked_takes_effect_immediately(app):
    admin = make_client(app, "admin@test.com", admin=True)
    assert admin.get("/admin/logs").status_code == 200
    db_exec(app, "UPDATE users SET role_id = 1 WHERE email = 'admin@test.com'")
    assert admin.get("/admin/logs").status_code == 403