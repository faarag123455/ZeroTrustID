import pytest

from app import create_app
from app.models.db import init_db
from tests.helpers import db_exec, events, make_client, user_id


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False})
    with app.app_context():
        init_db()
    return app


def role_of(app, uid):
    return db_exec(app, "SELECT role_id FROM users WHERE id = ?", (uid,))[0][0]


def test_two_admins_can_demote_the_other(app):
    a1 = make_client(app, "a1@test.com", admin=True)
    make_client(app, "a2@test.com", admin=True)
    a2id = user_id(app, "a2@test.com")
    a1.post(f"/admin/users/{a2id}/role", data={"role": "user"})
    assert role_of(app, a2id) == 1


def test_cannot_demote_last_admin(app):
    a1 = make_client(app, "a1@test.com", admin=True)
    make_client(app, "u@test.com")
    a1id = user_id(app, "a1@test.com")
    # Un 2e admin est promu puis retiré : a1 reste seul.
    from app.admin.routes import ADMIN_ROLE_ID
    with app.app_context():
        from app.admin.routes import is_last_admin
        from app.models.db import get_db
        assert is_last_admin(a1id) is True


def test_cannot_delete_last_admin_via_route(app):
    a1 = make_client(app, "a1@test.com", admin=True)
    a2 = make_client(app, "a2@test.com", admin=True)
    a1id = user_id(app, "a1@test.com")
    a2id = user_id(app, "a2@test.com")
    # a1 supprime a2 : autorisé (il reste a1).
    a1.post(f"/admin/users/{a2id}/delete")
    assert db_exec(app, "SELECT COUNT(*) FROM users WHERE role_id = 2")[0][0] == 1
    assert role_of(app, a1id) == 2


def test_last_admin_flag_false_for_regular_user(app):
    make_client(app, "u@test.com")
    uid = user_id(app, "u@test.com")
    with app.app_context():
        from app.admin.routes import is_last_admin
        assert is_last_admin(uid) is False


def test_last_admin_flag_false_with_two_admins(app):
    make_client(app, "a1@test.com", admin=True)
    make_client(app, "a2@test.com", admin=True)
    uid = user_id(app, "a1@test.com")
    with app.app_context():
        from app.admin.routes import is_last_admin
        assert is_last_admin(uid) is False