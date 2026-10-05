import sqlite3
import pytest
from app import create_app
from app.models.db import init_db, get_db


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
    })
    with app.app_context():
        init_db()
    return app


def test_all_tables_exist(app):
    conn = sqlite3.connect(app.config["DATABASE"])
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    expected = {"users", "roles", "permissions", "role_permissions",
                "sessions", "security_logs", "encrypted_data"}
    assert expected <= tables


def test_roles_exist(app):
    conn = sqlite3.connect(app.config["DATABASE"])
    roles = {r[0] for r in conn.execute("SELECT name FROM roles")}
    assert roles == {"user", "admin"}


def test_admin_has_more_permissions_than_user(app):
    conn = sqlite3.connect(app.config["DATABASE"])

    def count(role):
        return conn.execute(
            "SELECT COUNT(*) FROM role_permissions rp "
            "JOIN roles r ON r.id = rp.role_id WHERE r.name = ?", (role,)
        ).fetchone()[0]

    assert count("user") == 2
    assert count("admin") == 5


def test_user_cannot_have_logs_permission(app):
    conn = sqlite3.connect(app.config["DATABASE"])
    row = conn.execute(
        "SELECT 1 FROM role_permissions rp "
        "JOIN roles r ON r.id = rp.role_id "
        "JOIN permissions p ON p.id = rp.permission_id "
        "WHERE r.name = 'user' AND p.code = 'logs:read'").fetchone()
    assert row is None


def test_foreign_keys_are_enforced(app):
    with app.app_context():
        db = get_db()
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO users (email, password_hash, role_id) "
                "VALUES ('a@b.com', 'x', 999)")